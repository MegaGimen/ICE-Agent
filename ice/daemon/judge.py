"""judge() —— Kev `/v1/systemone` 封装（plan.md §7.2；colab.md §3.3）。

本文件由 intake 侧拥有，作为**共享工具**：decision 侧的 safety_gate / backward 也
通过它调用 Kev。Kev-27B / Kev-9B 可互换（同一个 TypeSafe 接口，换服务即可）。

真实 Kev 接口（读 bundle/kev/kev/{api,serve}.py 核对）：

  POST /v1/systemone
    { "state": <JSONContent 上下文>,
      "model": "kev-latest",
      "questions": { "<qid>": <Question>, ... } }      # 可一次问多题

  Question:
    noul   : {"type":"noul",   "instructions": <题干>}            答案 = p(true)
    choice : {"type":"choice", "instructions": <题干>,
              "criteria": {"选项名": "描述"|""}}                  选项顺序 = dict 插入序（固定！）
    score  : {"type":"score",  "instructions": <题干>,
              "criteria": ["档位0描述","档位1描述",...]}           答案 = 期望档位 0..L-1

  Response answers[qid]:
    noul   : {"type":"noul","noul": p_true}
    choice : {"type":"choice","choice": 名, "confidence": c, "probabilities": {名: p}}
    score  : {"type":"score","score": 期望档位, "legend":..., "probabilities": {"i": p}, "confidence": c}

设计要点：
  * 纯标准库（urllib）—— 两端、沙箱、测试都能 import，不引 requests。
  * choice 的选项顺序会影响 Kev 的答案（plan.md §3.1），因此全程保持传入顺序。
  * 支持**一次多题**（judge_batch）：检测门控 6 个属性一次调用拿回（省一轮往返）。
"""
from __future__ import annotations

import json
import os
import urllib.request
import urllib.error
from typing import Dict, List, Optional

from ice.daemon.contracts import JudgeKind, JudgeQuery, JudgeResult


DEFAULT_URL = os.environ.get("KEV_URL", "http://127.0.0.1:8010")
DEFAULT_TIMEOUT = float(os.environ.get("KEV_TIMEOUT", "30"))


class KevError(RuntimeError):
    pass


class KevClient:
    """最薄的 Kev HTTP 客户端。judge() / judge_batch() 是主入口。"""

    def __init__(self, url: str = DEFAULT_URL, timeout: float = DEFAULT_TIMEOUT,
                 api_key: Optional[str] = None):
        self.url = url.rstrip("/")
        self.timeout = timeout
        self.api_key = api_key or os.environ.get("KEV_API_KEY")

    # -- 底层 --------------------------------------------------------------
    def _post(self, path: str, body: dict) -> dict:
        data = json.dumps(body).encode()
        req = urllib.request.Request(self.url + path, data=data, method="POST")
        req.add_header("content-type", "application/json")
        if self.api_key:
            req.add_header("authorization", f"Bearer {self.api_key}")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                return json.loads(r.read().decode())
        except urllib.error.HTTPError as e:
            detail = e.read().decode(errors="replace")[:500]
            raise KevError(f"Kev HTTP {e.code} on {path}: {detail}") from e
        except urllib.error.URLError as e:
            raise KevError(f"Kev unreachable at {self.url}{path}: {e}") from e

    def health(self) -> dict:
        """GET /v1/models —— 模型加载完成后才可用。"""
        req = urllib.request.Request(self.url + "/v1/models")
        if self.api_key:
            req.add_header("authorization", f"Bearer {self.api_key}")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                return json.loads(r.read().decode())
        except Exception as e:  # noqa: BLE001
            raise KevError(f"Kev health failed: {e}") from e

    def model_name(self) -> str:
        try:
            m = self.health().get("models") or [{}]
            return m[0].get("run") or m[0].get("name") or ""
        except Exception:  # noqa: BLE001
            return ""

    # -- 问题构造 -----------------------------------------------------------
    @staticmethod
    def _question_payload(q: JudgeQuery) -> dict:
        if q.kind is JudgeKind.NOUL:
            return {"type": "noul", "instructions": q.question}
        if q.kind is JudgeKind.CHOICE:
            if not q.options:
                raise ValueError("choice question needs options (fixed order)")
            # 顺序固定：按传入顺序建 criteria；描述留空 -> Kev 只看选项名
            criteria = {opt: "" for opt in q.options}
            return {"type": "choice", "instructions": q.question, "criteria": criteria}
        if q.kind is JudgeKind.SCORE:
            if not q.options:
                raise ValueError("score question needs level descriptions")
            return {"type": "score", "instructions": q.question, "criteria": list(q.options)}
        raise ValueError(f"unknown kind {q.kind}")

    @staticmethod
    def _parse_answer(q: JudgeQuery, ans: dict, model: str) -> JudgeResult:
        kind = q.kind
        if kind is JudgeKind.NOUL:
            p = float(ans.get("noul", 0.0))
            return JudgeResult(
                kind=kind, score=p,
                probs={"true": round(p, 4), "false": round(1 - p, 4)},
                choice="true" if p >= 0.5 else "false",
                confidence=round(max(p, 1 - p), 4),
                model=model, raw=ans,
            )
        if kind is JudgeKind.CHOICE:
            probs = {k: float(v) for k, v in (ans.get("probabilities") or {}).items()}
            return JudgeResult(
                kind=kind, probs=probs, choice=ans.get("choice"),
                confidence=float(ans.get("confidence", 0.0)),
                model=model, raw=ans,
            )
        # SCORE：把期望档位 0..L-1 归一到 0..1
        levels = max(len(q.options), 1)
        raw_score = float(ans.get("score", 0.0))
        norm = raw_score / (levels - 1) if levels > 1 else raw_score
        probs = {k: float(v) for k, v in (ans.get("probabilities") or {}).items()}
        return JudgeResult(
            kind=kind, score=round(norm, 4), probs=probs,
            confidence=float(ans.get("confidence", 0.0)),
            model=model, raw={"raw_score": raw_score, "levels": levels, **ans},
        )

    # -- 主入口 -------------------------------------------------------------
    def judge(self, query: JudgeQuery) -> JudgeResult:
        """问一道题。"""
        return self.judge_batch(query.context, {"q": query})["q"]

    def judge_batch(self, context: str, queries: Dict[str, JudgeQuery]) -> Dict[str, JudgeResult]:
        """一次问多道题，共享同一 state=context。返回 {qid: JudgeResult}。

        检测门控用它一次拿回 6 个属性分（§3.1），省往返。
        """
        if not queries:
            return {}
        body = {
            "state": context,
            "model": "kev-latest",
            "questions": {qid: self._question_payload(q) for qid, q in queries.items()},
        }
        resp = self._post("/v1/systemone", body)
        model = resp.get("model", "")
        answers = resp.get("answers") or {}
        out: Dict[str, JudgeResult] = {}
        for qid, q in queries.items():
            ans = answers.get(qid)
            if ans is None:
                raise KevError(f"Kev response missing answer for {qid}: {resp}")
            out[qid] = self._parse_answer(q, ans, model)
        return out


# 进程级单例（守护进程里到处用同一个客户端）
_default: Optional[KevClient] = None


def get_judge() -> KevClient:
    global _default
    if _default is None:
        _default = KevClient()
    return _default


def set_judge(client: KevClient) -> None:
    """测试/集成时注入 mock 或指向别处的 Kev。"""
    global _default
    _default = client


def judge(query: JudgeQuery) -> JudgeResult:
    return get_judge().judge(query)


def judge_batch(context: str, queries: Dict[str, JudgeQuery]) -> Dict[str, JudgeResult]:
    return get_judge().judge_batch(context, queries)


__all__ = [
    "KevClient", "KevError",
    "get_judge", "set_judge", "judge", "judge_batch",
    "DEFAULT_URL", "DEFAULT_TIMEOUT",
]
