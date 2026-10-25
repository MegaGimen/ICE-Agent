"""ICE 守护进程 —— 冻结的跨端接口契约（colab.md §3）。

这是两端并行开发的前提：intake 侧（本文件作者）产出 ChangeEntry / Case、消费
safety_gate() 与 run_backward()；decision 侧消费 ChangeEntry/Case、实现 safety_gate()
/run_backward()，并复用本文件作者提供的 judge()。

原则：
  * 纯标准库，零三方依赖 —— 两端、沙箱、测试都能无条件 import。
  * 每个契约对象都能 JSON 往返（to_dict / from_dict），因为它们要穿过 MCP 消息、
    Kev 调用、审计日志、跨主机情报。
  * 改任何契约都要先在 colab.md §6 记一笔并通知对方（见文件末尾 CONTRACT_VERSION）。

契约清单（与 colab.md §3 一一对应）：
  1. ChangeEntry        结构化变化条目（感知层产出）
  2. MCP 工具签名        host_query / graph_query / host_exec / explain_for_human
  3. judge() 接口        题型+选项 -> 概率+置信度（Kev-27B/9B 可互换）
  4. Case                固定格式案件
  5. SafetyVerdict       安全闸输出 AUTO/ASK/DENY + 分数 + request_id
"""
from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field as dcfield, asdict
from enum import Enum
from typing import Any, Dict, List, Optional


CONTRACT_VERSION = "1.0.0"  # 改契约时 bump，并在 colab.md §6 记录


# ---------------------------------------------------------------------------
# 工具函数
# ---------------------------------------------------------------------------
def now_iso() -> str:
    """UTC ISO8601 时间戳（秒级），全系统统一。"""
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def new_id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:8]}"


# ===========================================================================
# 1. 结构化变化条目（colab.md §3.1；plan.md §2.2 / §6.3）
# ===========================================================================
class ChangeType(str, Enum):
    """变化条目大类。感知层把 osquery 快照差异 / 日志事件归到这些类型。"""
    # 稳定类（与上一张快照比，有任何变化就报）
    CRON = "cron"                 # 定时任务
    AUTOSTART = "autostart"       # 开机自启服务
    ACCOUNT = "account"           # 用户账号
    SUDOERS = "sudoers"           # sudo 权限
    SSH_KEY = "ssh_key"           # SSH 授权密钥
    LISTEN_PORT = "listen_port"   # 监听端口
    SYSTEM_FILE = "system_file"   # 系统关键文件指纹
    # 流动类（与"见过的清单"比，只报没见过的组合）
    PROCESS = "process"           # 进程
    CONNECTION = "connection"     # 网络连接
    # 日志/事件流（补快照之间一闪而过的动作）
    LOGIN = "login"               # 登录（失败聚合等）
    PROC_EVENT = "proc_event"     # 进程启动审计事件


class Direction(str, Enum):
    INBOUND = "inbound"
    OUTBOUND = "outbound"
    NA = "na"


@dataclass
class Provenance:
    """谁启动的 —— 决策模型分善恶的关键上下文。字段未知时留 None。"""
    who: Optional[str] = None       # 发起进程名 / 可执行路径
    pid: Optional[int] = None
    ppid: Optional[int] = None      # 父进程
    parent: Optional[str] = None    # 父进程名 / 路径
    user: Optional[str] = None      # 运行用户


@dataclass
class ChangeEntry:
    """一条结构化变化条目。必须带上下文，否则决策模型分不开善恶。

    attacker 可控的原始字符串（用户名、User-Agent、命令、文件名）**原样**放进
    `untrusted` 字典，不拼进自由文本；下游消息会明确声明 untrusted 不是指令
    （plan.md §6.3 的 prompt-injection 防线）。
    """
    type: ChangeType
    table: str                                  # 来源 osquery 表 / 日志源
    field: str = ""                             # 具体字段（可选）
    value: str = ""                             # 新值 / 摘要（已清洗，可信）
    provenance: Provenance = dcfield(default_factory=Provenance)
    seen_before: bool = False                    # 这个组合以前见过吗
    src_ip: Optional[str] = None                 # 来源 IP（已归网段/运营商）
    direction: Direction = Direction.NA
    host: str = "localhost"                      # 哪台主机上观察到
    ts: str = dcfield(default_factory=now_iso)     # 观察时间
    entry_id: str = dcfield(default_factory=lambda: new_id("chg"))
    untrusted: Dict[str, str] = dcfield(default_factory=dict)  # 攻击者可控原文，逐字保留

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["type"] = self.type.value
        d["direction"] = self.direction.value
        return d

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "ChangeEntry":
        prov = d.get("provenance") or {}
        return cls(
            type=ChangeType(d["type"]),
            table=d.get("table", ""),
            field=d.get("field", ""),
            value=d.get("value", ""),
            provenance=Provenance(**prov) if isinstance(prov, dict) else Provenance(),
            seen_before=bool(d.get("seen_before", False)),
            src_ip=d.get("src_ip"),
            direction=Direction(d.get("direction", "na")),
            host=d.get("host", "localhost"),
            ts=d.get("ts") or now_iso(),
            entry_id=d.get("entry_id") or new_id("chg"),
            untrusted=dict(d.get("untrusted") or {}),
        )


# ===========================================================================
# 2. MCP 工具签名（colab.md §3.2；plan.md §6.1/6.2）
# ===========================================================================
# intake 侧（mcp_server.py）实现这些；decision 侧的实时链路必须原样透传名字/参数。
#
#   host_query(sql_or_log: str)            -> ToolResult   只读, 直接执行
#   graph_query(cypher: str)               -> ToolResult   只读, 转 decision 侧图谱
#   host_exec(command: str, intent: str)   -> ToolResult   必过安全闸（异步可返回 request_id）
#   explain_for_human(request_id, explanation: str) -> ToolResult
#
# 工具名是固定字符串常量，供 mcp_server 注册与 NemoClaw --deny-tool 对齐。
TOOL_HOST_QUERY = "host_query"
TOOL_GRAPH_QUERY = "graph_query"
TOOL_HOST_EXEC = "host_exec"
TOOL_EXPLAIN = "explain_for_human"

READ_ONLY_TOOLS = frozenset({TOOL_HOST_QUERY, TOOL_GRAPH_QUERY, TOOL_EXPLAIN})


@dataclass
class ToolResult:
    """所有 MCP 工具的统一返回。ok=False 时 error 说明原因。

    host_exec 判 ASK 时 ok=True、pending=True、带 request_id（异步，人批准后
    结果再回灌到 case session）。
    """
    ok: bool
    tool: str
    content: Any = None                 # 查询结果 / 执行输出（JSON 可序列化）
    error: Optional[str] = None
    pending: bool = False               # host_exec ASK：等待人工审批
    request_id: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "ToolResult":
        return cls(
            ok=bool(d.get("ok")),
            tool=d.get("tool", ""),
            content=d.get("content"),
            error=d.get("error"),
            pending=bool(d.get("pending", False)),
            request_id=d.get("request_id"),
        )


# ===========================================================================
# 3. judge() 接口（colab.md §3.3；plan.md §7.2）—— Kev /v1/systemone 封装
# ===========================================================================
# judge() 由 intake 侧（judge.py）实现，decision 侧的 safety_gate/backward 复用。
# 题型三种：choice / score / noul。选项顺序固定（顺序会影响 Kev 的答案）。
class JudgeKind(str, Enum):
    CHOICE = "choice"   # 多选一：返回每个选项的概率
    SCORE = "score"     # 打分：返回 0..1 的分数
    NOUL = "noul"       # 判断/抽取，无选项约束


@dataclass
class JudgeQuery:
    kind: JudgeKind
    question: str
    context: str = ""                       # 结构化上下文（变化条目/动作内容等）
    options: List[str] = dcfield(default_factory=list)  # choice 必填，顺序固定

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["kind"] = self.kind.value
        return d


@dataclass
class JudgeResult:
    """Kev 返回。

    * choice: `probs` = {选项: 概率}；`choice` = argmax 选项。
    * score:  `score`  = 0..1。
    * noul:   `text`   = 自由文本结论。
    三种都带 `confidence`（0..1）。`raw` 保留原始响应便于审计。
    """
    kind: JudgeKind
    confidence: float = 0.0
    probs: Dict[str, float] = dcfield(default_factory=dict)
    choice: Optional[str] = None
    score: Optional[float] = None
    text: Optional[str] = None
    model: str = ""                         # 实际应答的模型（27b/9b），审计用
    raw: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["kind"] = self.kind.value
        return d

    def prob_of(self, option: str) -> float:
        return float(self.probs.get(option, 0.0))


# ===========================================================================
# 4. Case 固定格式（colab.md §3.4；plan.md §3.2）
# ===========================================================================
class CaseStatus(str, Enum):
    OPEN = "open"                   # 刚建, 调查中
    INVESTIGATING = "investigating"
    PROPOSED = "proposed"           # 已提出处置动作, 待安全闸/审批
    MITIGATING = "mitigating"       # 处置执行中
    VERIFYING = "verifying"         # backward 评估中
    RESOLVED = "resolved"           # 已确认清除
    DISMISSED = "dismissed"         # 判为误报/正常


@dataclass
class ProposedAction:
    """LLM 提出的处置动作 —— 完整实际内容，不是意图摘要（安全闸审查对象）。"""
    command: str                    # 完整命令 / 文件改动描述
    intent: str                     # 人话意图（给 explain_for_human 用）
    targets: List[str] = dcfield(default_factory=list)  # 受影响对象（文件/IP/服务）
    action_id: str = dcfield(default_factory=lambda: new_id("act"))


@dataclass
class Case:
    """一个安全案件。字段顺序即 colab.md §3.4 契约。"""
    case_id: str = dcfield(default_factory=lambda: new_id("case"))
    timeline: List[Dict[str, Any]] = dcfield(default_factory=list)  # [{ts, event}]
    hosts: List[str] = dcfield(default_factory=list)
    attck: List[str] = dcfield(default_factory=list)   # ATT&CK 技术 ID, 如 T1053.003
    confidence: float = 0.0                           # 0..1
    ioc: List[str] = dcfield(default_factory=list)      # IP/哈希/域名等
    reason: str = ""                                  # 判断理由（攻击故事）
    proposed_actions: List[ProposedAction] = dcfield(default_factory=list)
    blast_radius: List[str] = dcfield(default_factory=list)  # 影响范围清单（backward 核对）
    status: CaseStatus = CaseStatus.OPEN
    created: str = dcfield(default_factory=now_iso)
    updated: str = dcfield(default_factory=now_iso)
    # 溯源：触发本 case 的变化条目（供图谱写入、backward 参照）
    triggers: List[Dict[str, Any]] = dcfield(default_factory=list)

    def add_timeline(self, event: str, ts: Optional[str] = None) -> None:
        self.timeline.append({"ts": ts or now_iso(), "event": event})
        self.updated = now_iso()

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["status"] = self.status.value
        return d

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "Case":
        actions = [ProposedAction(**a) for a in d.get("proposed_actions", [])]
        return cls(
            case_id=d.get("case_id") or new_id("case"),
            timeline=list(d.get("timeline", [])),
            hosts=list(d.get("hosts", [])),
            attck=list(d.get("attck", [])),
            confidence=float(d.get("confidence", 0.0)),
            ioc=list(d.get("ioc", [])),
            reason=d.get("reason", ""),
            proposed_actions=actions,
            blast_radius=list(d.get("blast_radius", [])),
            status=CaseStatus(d.get("status", "open")),
            created=d.get("created") or now_iso(),
            updated=d.get("updated") or now_iso(),
            triggers=list(d.get("triggers", [])),
        )


# ===========================================================================
# 5. 安全闸输出（colab.md §3.5；plan.md §3.3）
# ===========================================================================
class GateDecision(str, Enum):
    AUTO = "AUTO"   # 正当且代价低 -> 自动执行
    ASK = "ASK"     # 正当但代价大 -> Slack 人工批准（异步, 立刻返回 request_id）
    DENY = "DENY"   # 不正当 -> 拒绝


@dataclass
class SafetyScores:
    """安全闸的审查维度（plan.md §3.3）。各项 0..1。"""
    legit: float = 0.0          # 正当性
    needs_human: float = 0.0    # 需要人介入程度（代价高低）
    reversible: float = 0.0     # 可逆性
    scope_match: float = 0.0    # 实际影响是否匹配声明意图（抓误操作）
    safety: str = "risky"       # safe / risky / destructive


@dataclass
class SafetyVerdict:
    """safety_gate() 的返回（decision 侧实现，intake 侧 orchestrator/mcp 消费）。

    ASK 时立刻返回 request_id（异步）；审批由沙箱外 ICE Gate 接收，Agent 无法伪造。
    """
    decision: GateDecision
    scores: SafetyScores = dcfield(default_factory=SafetyScores)
    request_id: Optional[str] = None     # ASK 时必填
    reason: str = ""                     # 给人看的简短理由（可被 explain 覆盖）
    action_id: Optional[str] = None      # 对应的 ProposedAction

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["decision"] = self.decision.value
        return d

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "SafetyVerdict":
        sc = d.get("scores") or {}
        return cls(
            decision=GateDecision(d["decision"]),
            scores=SafetyScores(**sc) if isinstance(sc, dict) else SafetyScores(),
            request_id=d.get("request_id"),
            reason=d.get("reason", ""),
            action_id=d.get("action_id"),
        )


# ===========================================================================
# backward 结果（colab.md §4）—— decision 侧实现 run_backward()，intake 侧消费
# ===========================================================================
class CleanupVerdict(str, Enum):
    CLEARED = "cleared"             # 彻底清除
    PARTIAL = "partial"            # 部分清除
    NOT_CLEARED = "not_cleared"    # 未清除
    CLEARED_COLLATERAL = "cleared_collateral"  # 清除但误伤


@dataclass
class BackwardResult:
    verdict: CleanupVerdict
    total_score: float = 0.0        # 探针分 70% + Kev 质量分 30%
    probe_score: float = 0.0
    kev_score: float = 0.0
    residuals: List[Dict[str, Any]] = dcfield(default_factory=list)  # 残留条目+逐条解释
    business_impact: str = ""
    recurrence: bool = False
    # 清单之外的残留 = forward 漏看了 -> 进化错题
    missed_by_forward: List[Dict[str, Any]] = dcfield(default_factory=list)
    case_id: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["verdict"] = self.verdict.value
        return d


__all__ = [
    "CONTRACT_VERSION", "now_iso", "new_id",
    "ChangeType", "Direction", "Provenance", "ChangeEntry",
    "TOOL_HOST_QUERY", "TOOL_GRAPH_QUERY", "TOOL_HOST_EXEC", "TOOL_EXPLAIN",
    "READ_ONLY_TOOLS", "ToolResult",
    "JudgeKind", "JudgeQuery", "JudgeResult",
    "CaseStatus", "ProposedAction", "Case",
    "GateDecision", "SafetyScores", "SafetyVerdict",
    "CleanupVerdict", "BackwardResult",
]
