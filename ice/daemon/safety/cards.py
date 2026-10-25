"""Build a human approval card without sending it to Slack."""

from __future__ import annotations

from collections.abc import Mapping

from .gate import ApprovalRequest


def approval_card(
    request: ApprovalRequest,
    human_explanation: str,
    agent_assessment: Mapping[str, float] | None = None,
) -> dict[str, object]:
    """Return Slack Block Kit data for the trusted ICE Gate app to send.

    The callback must fetch and validate the original pending request by ID;
    the button value alone is never proof of approval.
    """
    if len(request.command) > 2500 or len(request.target) > 250 or len(human_explanation) > 2500:
        raise ValueError("Approval content is too long for a complete Slack card")
    scores = request.scores
    independent = (
        f"Legitimacy: {scores['legit']:.2f} · "
        f"Needs human: {scores['needs_human']:.2f} · "
        f"Reversible: {scores['reversible']:.2f} · "
        f"Scope match: {scores['scope_match']:.2f}"
    ) if request.scored else "Unavailable; human review required"
    warning = bool(agent_assessment) and any(
        abs(float(agent_assessment.get(name, scores[name])) - scores[name]) >= 0.35
        for name in ("legit", "needs_human", "reversible", "scope_match")
    )
    return {
        "text": f"ICE Gate approval request {request.request_id}",
        "blocks": [
            {"type": "header", "text": {"type": "plain_text", "text": "ICE Gate: approval required"}},
            {"type": "section", "text": {"type": "mrkdwn", "text": _escape(human_explanation or request.reason)}},
            {"type": "section", "text": {"type": "mrkdwn", "text": f"*Independent safety scores*\n{independent}"}},
            *([{"type": "context", "elements": [{"type": "mrkdwn", "text": ":warning: Explanation and scores need review."}]}] if warning else []),
            {"type": "section", "text": {"type": "plain_text", "text": f"Target: {request.target}\nExact command: {request.command}"}},
            {"type": "actions", "elements": [
                {"type": "button", "action_id": "ice_gate_approve", "text": {"type": "plain_text", "text": "Approve"}, "style": "primary", "value": request.request_id},
                {"type": "button", "action_id": "ice_gate_deny", "text": {"type": "plain_text", "text": "Deny"}, "style": "danger", "value": request.request_id},
            ]},
        ],
    }


def _escape(value: str) -> str:
    return value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
