"""Detection gate (plan.md §3.1, step ② of the forward flow).

One Kev call per change entry asks every attribute question plus the overall verdict.
Escalation is deliberately noisy — normal activity that looks like an attack goes up too —
and the investigation layer clears it. The attribute scores do the real work; Kev's
verdict is softer and only adds to them.
"""
from __future__ import annotations

import json
import logging
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from ice.daemon.contracts import ChangeEntry, JudgeKind, JudgeQuery
from ice.daemon.detect.questions import (
    ATTRIBUTE_THRESHOLD, ATTRIBUTES, STATE_PREAMBLE, VERDICT_OPTIONS, VERDICT_QUESTION,
)
from ice.daemon.judge import judge_batch

log = logging.getLogger("ice.detect")


@dataclass
class GateResult:
    entry: ChangeEntry
    attributes: Dict[str, float] = field(default_factory=dict)
    verdict: str = "normal"
    verdict_probs: Dict[str, float] = field(default_factory=dict)
    escalate: bool = False
    # "high": Kev's verdict is not normal. "low": escalated only by an attribute while the verdict is
    # normal (e.g. a routine cron trips `persistence`). Both go to investigation; the orchestrator folds
    # a cycle's low-priority entries into one case so look-alike noise costs one agent run.
    priority: str = "none"
    reasons: List[str] = field(default_factory=list)
    error: Optional[str] = None

    def to_dict(self) -> Dict:
        return {"entry": self.entry.to_dict(), "attributes": self.attributes, "verdict": self.verdict,
                "verdict_probs": self.verdict_probs, "escalate": self.escalate, "priority": self.priority,
                "reasons": self.reasons,
                "error": self.error}


def build_state(entry: ChangeEntry) -> str:
    """Kev's `state`: structured, trusted fields separated from attacker-controllable text."""
    d = entry.to_dict()
    untrusted = d.pop("untrusted", {})
    d.pop("entry_id", None)
    facts = getattr(entry, "facts", None)
    state = {"note": STATE_PREAMBLE, "change": d}
    if facts:
        state["observed_fields"] = facts
    if untrusted:
        state["untrusted"] = untrusted
    return json.dumps(state, ensure_ascii=False)


def _queries() -> Dict[str, JudgeQuery]:
    qs = {aid: JudgeQuery(JudgeKind.NOUL, q) for aid, q in ATTRIBUTES}
    qs["verdict"] = JudgeQuery(JudgeKind.CHOICE, VERDICT_QUESTION, options=list(VERDICT_OPTIONS))
    return qs


def evaluate(entry: ChangeEntry) -> GateResult:
    res = GateResult(entry=entry)
    try:
        answers = judge_batch(build_state(entry), _queries())
    except Exception as e:  # noqa: BLE001 — Kev down must not drop the signal
        # Fail open toward investigation: an unjudged change is escalated, not ignored.
        res.error = f"{type(e).__name__}: {e}"
        res.escalate, res.priority = True, "high"
        res.reasons.append("Kev unavailable; escalated unjudged")
        log.warning("gate: Kev failed for %s: %s", entry.entry_id, res.error)
        return res
    for aid, _ in ATTRIBUTES:
        p = float(answers[aid].score or 0.0)
        res.attributes[aid] = round(p, 4)
        if p >= ATTRIBUTE_THRESHOLD:
            res.reasons.append(f"{aid}={p:.2f}")
    v = answers["verdict"]
    res.verdict, res.verdict_probs = v.choice or "normal", v.probs
    if res.verdict != "normal":
        res.reasons.append(f"verdict={res.verdict}")
    res.escalate = bool(res.reasons)
    res.priority = "high" if res.verdict != "normal" else ("low" if res.escalate else "none")
    return res


def evaluate_many(entries: List[ChangeEntry], workers: int = 4) -> List[GateResult]:
    """Kev batches concurrent requests on the GPU, so a few parallel calls cut wall time."""
    if not entries:
        return []
    with ThreadPoolExecutor(max_workers=min(workers, len(entries))) as pool:
        return list(pool.map(evaluate, entries))
