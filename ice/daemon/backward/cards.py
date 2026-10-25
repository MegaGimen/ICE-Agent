"""Build a concise Slack report without exposing raw host snapshots."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .verify import VerificationReport


def slack_report_card(report: VerificationReport) -> dict[str, object]:
    result = report.result
    residual_count = len(result.residuals)
    missed_count = len(result.missed_by_forward)
    summary = (
        f"Case {report.case_id}: {report.outcome.replace('_', ' ')}"
        f" (confidence {report.confidence:.0%})"
    )
    if len(summary) > 3000:
        raise ValueError("Case summary is too long for a Slack card")
    score_line = (
        f"Probes {report.deterministic_score:.0%} × 70% + "
        f"Kev quality {report.quality_score:.0%} × 30% = "
        f"{report.overall_score:.0%}"
    )
    finding_line = (
        f"Residual or unexplained findings: {residual_count} · "
        f"Missed by forward: {missed_count} · "
        f"Recurrence: {'yes' if result.recurrence else 'no'}"
    )
    next_steps = ", ".join(report.deeper_checks) if report.deeper_checks else "No extended checks requested"
    return {
        "text": summary,
        "blocks": [
            {"type": "header", "text": {"type": "plain_text", "text": "ICE remediation verification"}},
            {"type": "section", "text": {"type": "plain_text", "text": summary}},
            {"type": "section", "text": {"type": "plain_text", "text": score_line}},
            {"type": "section", "text": {"type": "plain_text", "text": finding_line}},
            {"type": "context", "elements": [{"type": "plain_text", "text": f"Next: {next_steps}"}]},
        ],
    }
