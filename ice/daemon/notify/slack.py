"""Slack output (plan.md §3.3, §4, §6.1).

Two apps, two trust levels:
  * the ICE app bot (the same Slack app OpenClaw uses) posts case alerts and progress —
    one top-level message per case, everything else in its thread;
  * the ICE Gate app posts approval cards and receives the button clicks over Socket Mode,
    on the host, outside the sandbox — the agent cannot forge an approval.

Socket Mode has no request signature; the websocket itself is authenticated with the
ICE Gate app token. The click handler applies the same origin checks as the teammate's
HTTP adapter (safety/approval.py): block_actions only, exact team, exact channel, known
action ids, then ApprovalStore.decide() enforces approver, expiry, replay, and policy.
"""
from __future__ import annotations

import logging
import threading
from typing import Any, Callable, Dict, List, Optional

from slack_sdk import WebClient
from slack_sdk.socket_mode import SocketModeClient
from slack_sdk.socket_mode.request import SocketModeRequest
from slack_sdk.socket_mode.response import SocketModeResponse

from ice.daemon.backward.cards import slack_report_card
from ice.daemon.config import Config, secret
from ice.daemon.contracts import Case
from ice.daemon.detect.gate import GateResult
from ice.daemon.orchestrator import Notifier
from ice.daemon.runtime import PendingAction, Runtime
from ice.daemon.safety.cards import approval_card
from ice.daemon.safety.gate import ApprovalRequest

log = logging.getLogger("ice.slack")

_ASSESS = {"malicious": ":rotating_light: 确认攻击", "uncertain": ":warning: 待确认", "benign": ":white_check_mark: 判定为正常活动",
           None: ":grey_question: 调查未产出结论"}
_DECISION = {"AUTO": ":zap: AUTO 自动执行", "ASK": ":raised_hand: ASK 等待人工批准", "DENY": ":no_entry: DENY 已拒绝",
             "APPROVED": ":white_check_mark: 已批准并执行", "DENIED": ":x: 人工拒绝"}


def _esc(s: str) -> str:
    return (s or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _clip(s: str, n: int) -> str:
    s = s or ""
    return s if len(s) <= n else s[: n - 1] + "…"


class SlackNotifier(Notifier):
    def __init__(self, conf: Config):
        self.conf = conf
        self.ice = WebClient(token=secret("slack-bot-token", "SLACK_BOT_TOKEN"))
        self.gate = WebClient(token=secret("slack-icegate-bot-token", "ICE_GATE_BOT_TOKEN"))
        self.channel = conf.slack_alert_channel
        self._threads: Dict[str, str] = {}      # case_id -> thread ts
        self._cards: Dict[str, str] = {}        # request_id -> card ts

    # -- helpers ------------------------------------------------------------------
    def _post(self, client: WebClient, **kw: Any) -> Optional[str]:
        try:
            return client.chat_postMessage(channel=self.channel, **kw)["ts"]
        except Exception:  # noqa: BLE001 — Slack being down must not stop the pipeline
            log.exception("Slack post failed")
            return None

    def _thread(self, case_id: str) -> Optional[str]:
        return self._threads.get(case_id)

    # -- Notifier -----------------------------------------------------------------
    def case_alert(self, case: Case, assessment: Optional[str], results: List[GateResult]) -> None:
        signals = "\n".join(
            f"• `{_clip(r.entry.table, 20)}` {_esc(_clip(r.entry.value, 140))}  — {', '.join(r.reasons[:4])}"
            for r in results[:8])
        actions = "\n".join(f"{i + 1}. `{_esc(_clip(a.command, 200))}` — {_esc(_clip(a.intent, 160))}"
                            for i, a in enumerate(case.proposed_actions)) or "_无_"
        blocks = [
            {"type": "header", "text": {"type": "plain_text", "text": _clip(f"ICE {case.case_id} · {_ASSESS.get(assessment, assessment)}", 150), "emoji": True}},
            {"type": "section", "text": {"type": "mrkdwn", "text": _clip(_esc(case.reason) or "_（无攻击故事）_", 2900)}},
            {"type": "section", "fields": [
                {"type": "mrkdwn", "text": f"*ATT&CK*\n{', '.join(case.attck) or '—'}"},
                {"type": "mrkdwn", "text": f"*置信度*\n{case.confidence:.0%}"},
                {"type": "mrkdwn", "text": f"*主机*\n{', '.join(case.hosts)}"},
                {"type": "mrkdwn", "text": f"*IOC*\n{_esc(_clip(', '.join(case.ioc[:6]), 300)) or '—'}"},
            ]},
            {"type": "section", "text": {"type": "mrkdwn", "text": _clip(f"*检测信号（检测门控）*\n{signals}", 2900)}},
            {"type": "section", "text": {"type": "mrkdwn", "text": _clip(f"*建议处置（逐条过安全闸）*\n{actions}", 2900)}},
            {"type": "context", "elements": [{"type": "mrkdwn", "text": "本地推理 · 数据不离开本机 · 处置动作由沙箱外安全闸独立审查"}]},
        ]
        ts = self._post(self.ice, text=f"ICE {case.case_id}: {assessment}", blocks=blocks)
        if ts:
            self._threads[case.case_id] = ts

    def action_update(self, case: Case, command: str, decision: str, detail: str) -> None:
        self._post(self.ice, thread_ts=self._thread(case.case_id),
                   text=f"{_DECISION.get(decision, decision)}  `{_esc(_clip(command, 300))}`\n{_esc(_clip(detail, 500))}")

    def approval_request(self, p: PendingAction) -> None:
        if p.request_id in self._cards:
            return
        s = p.verdict.get("scores", {})
        req = ApprovalRequest(p.request_id, p.command, self.conf.hostname, p.intent, p.verdict.get("reason", ""),
                              {k: float(s.get(k, 0)) for k in ("legit", "needs_human", "reversible", "scope_match")}, True)
        card = approval_card(req, _clip(p.explanation or p.intent, 2400))
        blocks = list(card["blocks"])
        blocks.insert(1, {"type": "context", "elements": [{"type": "mrkdwn", "text": f"Case `{p.case_id}` · request `{p.request_id}`"}]})
        ts = self._post(self.gate, text=card["text"], blocks=blocks, thread_ts=self._thread(p.case_id or ""))
        if ts:
            self._cards[p.request_id] = ts

    def backward_report(self, case: Case, report: Any) -> None:
        card = slack_report_card(report)
        self._post(self.ice, thread_ts=self._thread(case.case_id), text=card["text"], blocks=card["blocks"])

    def mark_decided(self, request_id: str, approved: bool, user_id: str) -> None:
        ts = self._cards.get(request_id)
        if not ts:
            return
        try:
            self.gate.chat_update(channel=self.channel, ts=ts, text=f"ICE Gate {request_id} decided",
                                  blocks=[{"type": "section", "text": {"type": "mrkdwn", "text":
                                           f"{'✅ 已批准' if approved else '❌ 已拒绝'} by <@{user_id}> · request `{request_id}`"}}])
        except Exception:  # noqa: BLE001
            log.exception("card update failed")


class IceGateListener:
    """Receives ICE Gate button clicks over Socket Mode and hands verified decisions on."""

    def __init__(self, rt: Runtime, notifier: SlackNotifier,
                 on_decision: Callable[[str, bool, str], None]):
        self.rt = rt
        self.notifier = notifier
        self.on_decision = on_decision
        self.client = SocketModeClient(app_token=secret("slack-icegate-app-token", "ICE_GATE_APP_TOKEN"),
                                       web_client=notifier.gate)
        self.client.socket_mode_request_listeners.append(self._handle)

    def start(self) -> None:
        self.client.connect()
        log.info("ICE Gate socket mode connected")

    def _handle(self, client: SocketModeClient, req: SocketModeRequest) -> None:
        client.send_socket_mode_response(SocketModeResponse(envelope_id=req.envelope_id))  # ack within 3s
        if req.type != "interactive":
            return
        payload = req.payload or {}
        try:
            request_id, approved, user_id = self._verify(payload)
        except PermissionError as e:
            self.rt.audit.write("icegate.rejected", reason=str(e), user=(payload.get("user") or {}).get("id"))
            log.warning("ICE Gate click rejected: %s", e)
            return
        threading.Thread(target=self._decide, args=(request_id, approved, user_id), daemon=True).start()

    def _verify(self, payload: Dict[str, Any]):
        store = self.rt.approvals
        if store is None:
            raise PermissionError("approval store not configured")
        if payload.get("type") != "block_actions":
            raise PermissionError("not a block action")
        team = (payload.get("team") or {}).get("id")
        channel = (payload.get("channel") or {}).get("id") or (payload.get("container") or {}).get("channel_id")
        user = (payload.get("user") or {}).get("id")
        if team != store.policy.team_id or channel != store.policy.channel_id:
            raise PermissionError("click from an unexpected workspace or channel")
        actions = payload.get("actions") or []
        if len(actions) != 1 or actions[0].get("action_id") not in {"ice_gate_approve", "ice_gate_deny"}:
            raise PermissionError("unexpected action")
        request_id = actions[0].get("value") or ""
        return request_id, actions[0]["action_id"] == "ice_gate_approve", user

    def _decide(self, request_id: str, approved: bool, user_id: str) -> None:
        try:
            decision = self.rt.approvals.decide(request_id, approved, user_id)   # approver, expiry, replay, policy
        except (PermissionError, ValueError) as e:
            self.rt.audit.write("icegate.refused", request_id=request_id, user=user_id, reason=str(e))
            p = self.rt.pending.get(request_id)
            self.notifier._post(self.notifier.gate, text=f":no_entry: ICE Gate 拒绝了 <@{user_id}> 对 `{request_id}` 的操作：{e}",
                                thread_ts=self.notifier._thread(p.case_id) if p and p.case_id else None)
            return
        self.notifier.mark_decided(request_id, decision.approved, user_id)
        self.on_decision(request_id, decision.approved, user_id)
