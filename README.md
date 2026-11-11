# ICE-Agent

ICE-Agent 研究红蓝对抗是否有助于提升双方能力，当前重点是蓝队的实际保护与处置效果。新实验框架独立位于 [`arena/`](arena/README.md)，复用已有模型服务，在操作者准备的隔离 QEMU 中执行真实操作、记录证据，并由裁判 Agent 评分。

当前裁判版本为 **`host-agent-impact-v4`**。旧版应用演示、规则评分与早期 ICE 组件保留用于历史核验，不能把它们的分数当成当前裁判结果。

## 当前架构

| 部分 | 当前职责与实现 |
|---|---|
| 环境与控制器 | 操作者准备独立 QEMU 副本；控制器管理行动窗口、权限、时间记录、取证和结果封存。主入口是 [`arena/round_match.py`](arena/round_match.py)。 |
| 红队 | 当前使用受控脚本作为测试对手，执行部署、读取资产等实际操作，并记录取得数据的证据。尚未接入自主探测的 PentestGPT/红队模型。 |
| 蓝队 Agent | 在分配的虚拟机中调查、处置和复查，使用 shell、Brave `websearch` 和公共网页 `fetchurl`。机器状态与会话跨回合保留。 |
| 证据层 | 独立记录业务探针、文件与服务状态、进程计数、资产取得区间，以及双方的行动窗口。记录绑定同一 `match_id`；采集失败也保留。 |
| 分轴裁判 Agent | 分别调查保密性、完整性、可用性／资源、残留控制，输出定性影响、证据引用和不确定性。取证工具见 [`arena/judge_tools.py`](arena/judge_tools.py)。 |
| 综合裁判 Agent | 独立核对关键证据，结合分轴意见，直接给出每轮红、蓝 reward 和理由。当前实现见 [`arena/impact_judge.py`](arena/impact_judge.py)。 |
| 交付与校验 | 校验证据引用、格式与哈希，绑定原始轨迹、裁判记录及 reward，并生成可核验的 case。入口见 [`arena/round_scoring.py`](arena/round_scoring.py)。 |

实际执行发生在指定 guest 中，模型调用和搜索凭据保存在外部控制器。当前主机调查入口使用模型 API 适配器，并不是完整 ICE daemon 的全量集成。

## 回合与责任时间

一场比赛包含多轮“红队窗口 → 蓝队窗口”。双方交替发起前台动作，已经启动的进程、持久化机制和正常业务持续运行。这是**交替行动、连续环境状态**，尚不是双方完全并发决策。

控制器确认前台操作结束后交接窗口。整个比赛保留同一台机器和蓝队会话，不能把每轮视为独立样本或偷偷恢复健康状态。

蓝队第一次获得观察和行动权限时，控制器建立唯一的接管边界。责任从这个时刻开始，之后红队窗口内仍持续有效，不能等蓝队首次操作才开始计时，也不能每轮重置。

裁判按实际取得数据的时间区间判断，不能用提交报告的时间替代。例如，接管前已读走、第二轮才报告的数据仍属于历史泄露；接管后首次发生的新泄露，可能同时构成红队收益和蓝队责任期内的保护失败。

## 当前如何评分

红队根据可归因于其攻击的实际成果获得评价；蓝队根据接管后的保护、处置和恢复效果获得评价。两份账目可以重叠，**不设 `R_red = -R_blue`**。蓝队自身造成的业务损害不自动计为红队收益，后来恢复也不代表历史损害没有发生。

CPU、文件、进程、业务状态与时间记录都是证据。当前裁判不使用 CPU 秒数／核数／时长归一化、对象数量比例、固定等级映射或等权加总生成 reward。分轴 Agent 不给数值损失；综合裁判直接评级。`0..1` 仅为输出接口范围，不表示损失百分比。

固定程序负责调度、取证工具、证据完整性、输出校验和轨迹绑定，不替裁判决定影响大小。每轮增量与折扣回报只是对 Agent 已给 reward 的审计派生值。裁判无法完成有效判断时，不回退到规则评分。

## 运行与重判

需要 Python 3.10+。完整对局还需要操作者准备可恢复的隔离 guest、回环 SSH 转发、guest SSH key、业务／资产及实验配置、可用的模型 API。`round_match` 不会自动租赁机器或搭建 QEMU。实际样本验证使用独立 qcow2 overlay、无共享宿主目录、QEMU `restrict=on` 和仅回环的 SSH 转发；模型与搜索由控制器代理。QEMU 默认 user 网络允许主动出站，不能仅凭虚拟机边界就宣称已阻断外联。

模型连接沿用 `ICE_AGENT_BASE_URL`、`ICE_AGENT_MODEL`、`ICE_AGENT_API_KEY` 等已有设置。裁判可通过 `ICE_JUDGE_BASE_URL`、`ICE_JUDGE_MODEL`、`ICE_JUDGE_API_KEY` 单独配置；本机可选模型配置文件为 `/root/.config/ice-arena/judge.json`，环境变量优先。Brave 使用 `BRAVE_SEARCH_API_KEY` 或私有 key 文件。密钥不应写入配置示例或提交。

实验 JSON 声明业务要求、资产、探针范围、`round_plan`、行动窗口和受控红队操作。配置字段及工具说明见 [arena/README.md](arena/README.md)。不要把测试答案或处置示范放进运行提示词。

```bash
# 长任务在控制器的 tmux 中启动；准备好环境变量和 experiment.json 后执行：
tmux new -s ice-experiment
mkdir -p output
python3 -m arena.round_match --config experiment.json --port 2291 \
  --key /path/to/guest-key --out output/new-match > output/new-match.job.log 2>&1
echo $? > output/new-match.job.exit

# 核验已有结果，不重新调用模型或执行攻防
python3 -m arena.round_scoring verify output/new-match

# 用当前裁判重新评价原始证据，另存新版本，不重跑攻防
python3 -m arena.judge_agent output/new-match \
  --revision-out output/new-match-impact-review

# 同模型、指南和证据下恢复中断的裁判检查点
python3 -m arena.judge_agent output/interrupted-match --resume \
  --revision-out output/interrupted-match-judge-retry

python3 -m pytest -q tests/arena
```

输出目录必须是新目录。新判断不能覆盖旧判断；旧指标量表的检查点不能恢复成 v4，需要另建无旧分数输入的审判版本。对话或 SSH 中断后，先检查 tmux、日志、状态与已完成检查点，避免重复执行对局。

## 轨迹、reward 与 case

| 产物 | 内容 |
|---|---|
| `match.json`、`completion.json`、`outcomes.jsonl` | 场景声明、控制器事件、时间边界及采集状态。 |
| `red_trajectory.jsonl`、`blue_trajectory.jsonl` | 各自的原始行动／模型轨迹，包含回合与动作关联信息。 |
| `impact_findings/`、`impact_checkpoints/` | 各调查阶段的定性意见、综合判断与恢复检查点。 |
| `judge_trajectory.jsonl`、`judge_verdict.json`、`judge_seal.json` | 裁判实际调用、原始结论、证据引用及来源哈希。 |
| `score.json`、`red_reward.json`、`blue_reward.json`、`incident_outcome.json` | Agent 直接给出的奖励与事件影响说明，不是固定公式的分项损失表。 |
| `training_binding.json`、同级 `<run>.case/` | 将对应轨迹、证据、裁判版本和 reward 绑定，并打包核验。 |

整场多轮比赛是一条有状态 episode，当前以整场 reward 作为学习接口，回合增量用于审计。Token IDs、行为概率、动作 mask 和优化器由 learner 负责；完成案例评分不等于已经进行了 GRPO/PPO 参数训练。

生成数据位于 gitignored 的 `output/` 等目录。原始证据可能包含凭据及恶意样本，case 是私有证据包，不是公开脱敏导出。

## 当前验证与边界

已用留存的真实 XMRig 二进制验证两轮部署与处置、正常业务保留、接管前后泄露及延迟报告；也验证了蓝队误停业务和明确授权运行同一计算程序的对照。该实验采用离线计算模式和脚本化初始权限，不是原始 CVE 入侵链重放，也不代表红队模型已经具备自主攻击能力。裁判重判只更换评价版本，原始攻防轨迹保持不变。

当前证据采集覆盖实验声明的对象和通道，包含周期采样；它不是完整历史全盘快照服务。SSH 观测信任 guest OS/toolchain，尚未解决 root 对手伪造取证环境的问题。裁判应说明采样空隙、无法确认的因果关系与范围限制，不能用后来的健康状态补造历史事实。

自主红队／PentestGPT 接入、完整并发网络对抗、长期 graph／记忆学习和模型参数优化仍是后续阶段。评估双方能力提升还需要固定独立对手、未见场景及训练对照。

旧 [`ice/`](ice/) 组件、历史应用级 HTTP/SQLite 演示和旧量表保留用于参考与回归。历史分数及旧无害 episode 的 0.8 解释不被重写；当前新架构与评分口径以本页及 [arena 文档的 v4 说明](arena/README.md) 为准。
