"""Compare full T0/T1/T2 host snapshots after a proposed remediation.

Snapshot collection and Kev judgment are injected at daemon startup. This
module performs no shell commands and makes no changes to the host.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from typing import Any
import json

from ice.daemon.contracts import BackwardResult, CleanupVerdict, JudgeKind, JudgeQuery
from ice.daemon.judge import judge


Snapshot = Mapping[str, Any]
SnapshotProvider = Callable[[object, str], Snapshot]
QualityJudge = Callable[[object, list[dict[str, Any]]], Mapping[str, Any]]
ObservationProvider = Callable[[object], Iterable[Snapshot]]


@dataclass(frozen=True)
class VerificationReport:
    result: BackwardResult
    case_id: str
    outcome: str
    confidence: float
    deterministic_score: float
    quality_score: float
    overall_score: float
    evidence: tuple[dict[str, Any], ...]
    extend_observation: bool
    deeper_checks: tuple[str, ...]
    report_card: dict[str, Any]
    observation_pending: bool = False


@dataclass
class BackwardVerifier:
    snapshot_provider: SnapshotProvider
    quality_judge: QualityJudge | None = None
    observation_provider: ObservationProvider | None = None

    def run_backward(self, case: object) -> BackwardResult:
        return self.verify(case).result

    def verify(self, case: object) -> VerificationReport:
        case_id = str(_field(case, "case_id", "unknown"))
        t0 = _flatten(self.snapshot_provider(case, "T0"))
        t1 = _flatten(self.snapshot_provider(case, "T1"))
        t2 = _flatten(self.snapshot_provider(case, "T2"))
        observations = [_flatten(snapshot) for snapshot in (self.observation_provider(case) if self.observation_provider else ())]
        evidence: list[dict[str, Any]] = []
        failures = 0
        probes = 0
        residue = False
        collateral = False
        recurrence = False
        unexplained_flow = False
        coverage_gap = False
        missing = object()

        # Examine every field, including those absent from the case's IOC list.
        for path in sorted(t0.keys() | t1.keys() | t2.keys()):
            before, detected, after = (snapshot.get(path, missing) for snapshot in (t0, t1, t2))
            if detected == before and after == before:
                continue
            is_flow = path.startswith("flow.")
            if is_flow and before is not missing and after is missing:
                # A baseline process or connection ending is routine flow
                # churn, even if its row changed briefly at T1.
                continue
            probes += 1
            if after != before:
                failures += 1
                if is_flow and before is missing and detected is missing:
                    kind = "unexplained_t2_flow"
                    unexplained_flow = True
                elif detected != before:
                    kind = "residual_change"
                    residue = True
                else:
                    kind = "unexplained_t2_change"
                    collateral = True
            else:
                kind = "restored"
            evidence.append({"probe": "full_snapshot", "path": path, "result": kind,
                             "t0": _show(before, missing), "t1": _show(detected, missing), "t2": _show(after, missing)})

        for indicator in _indicators(_field(case, "ioc", ())):
            probes += 1
            present = _observed(indicator, t2)
            failures += int(present)
            residue |= present
            evidence.append({"probe": "ioc_cleanup", "indicator": indicator,
                             "result": "present" if present else "absent"})

        for path, value in t2.items():
            if "service" not in path.lower() or not path.lower().endswith(("health", "healthy", "status")):
                continue
            probes += 1
            healthy = value is True or (isinstance(value, str) and value.lower() in {"active", "healthy", "running", "ok"})
            failures += int(not healthy)
            collateral |= not healthy
            evidence.append({"probe": "service_health", "path": path,
                             "result": "healthy" if healthy else "unhealthy", "value": value})

        attacked_paths = {
            path for path in t0.keys() | t1.keys()
            if t1.get(path, missing) != t0.get(path, missing)
            and (not path.startswith("flow.") or t1.get(path, missing) is not missing)
        }
        for index, observed in enumerate(observations):
            for path in attacked_paths:
                if t2.get(path, missing) == t0.get(path, missing) and observed.get(path, missing) != t0.get(path, missing):
                    recurrence = True
                    evidence.append({"probe": "recurrence", "observation": index, "path": path, "result": "reappeared"})
        if observations:
            probes += 1
            failures += int(recurrence)

        for item in _indicators(_field(case, "blast_radius", ())):
            # Observable in any snapshot: the probes above cover it. Absent from all of T0/T1/T2: forward
            # named an object the snapshots never saw, which backward cannot verify.
            if not any(_observed(item, snapshot) for snapshot in (t0, t1, t2)):
                coverage_gap = True
                evidence.append({"probe": "coverage", "target": item, "result": "unobserved"})

        deterministic_score = max(0.0, 1 - failures / probes) if probes else 0.0
        quality_score = 0.0
        judge_confidence = 0.0
        if self.quality_judge:
            try:
                judgment = self.quality_judge(case, evidence)
                quality_score = _unit(judgment.get("quality_score", 0))
                judge_confidence = _unit(judgment.get("confidence", 0))
                for item in judgment.get("explanations", ()):
                    if isinstance(item, Mapping):
                        evidence.append({**dict(item), "probe": "judge_explanation"})
            except (TypeError, ValueError, KeyError, RuntimeError):
                evidence.append({"probe": "judge_quality", "result": "unavailable"})

        attack_observed = bool(attacked_paths) or any(
            _observed(indicator, t1)
            for indicator in _indicators(_field(case, "ioc", ()))
        )
        if not attack_observed or coverage_gap:
            deterministic_score = 0.0
        if not attack_observed or coverage_gap:
            outcome = "indeterminate"
        elif recurrence or residue:
            outcome = "partial" if failures < probes else "not_cleared"
        elif unexplained_flow:
            outcome = "indeterminate"
        elif collateral:
            outcome = "cleared_with_collateral_impact"
        else:
            outcome = "fully_cleared" if probes else "indeterminate"
        confidence = min(1.0, (0.65 if probes else 0.0) + 0.35 * judge_confidence)
        if not observations:
            confidence = min(confidence, 0.75)
        if not attack_observed or coverage_gap or unexplained_flow:
            confidence = min(confidence, 0.4)
        extend = confidence < 0.70 or residue or recurrence or outcome == "indeterminate"
        deeper = ("verify_system_files", "check_deleted_running_processes", "inspect_recent_system_changes") if extend else ()
        overall = 0.7 * deterministic_score + 0.3 * quality_score
        indeterminate_reason = (
            "No case-linked change was observable at T1" if not attack_observed else
            "Case impact was not covered by snapshots" if coverage_gap else
            "A new flow appeared only after detection" if unexplained_flow else ""
        )
        card = {
            "case_id": case_id,
            "outcome": outcome,
            "confidence": round(confidence, 3),
            "score": round(overall, 3),
            "summary": f"Post-remediation verification: {outcome.replace('_', ' ')}",
            # Slack transport receives only structural evidence; raw snapshot
            # values and IOCs stay in the local result/audit store.
            "evidence": [
                {key: item[key] for key in ("probe", "result") if key in item}
                for item in evidence
            ],
            "next_steps": list(deeper),
            "observation_pending": not bool(observations),
            "reason": indeterminate_reason,
        }
        verdict = {
            "fully_cleared": CleanupVerdict.CLEARED,
            "partial": CleanupVerdict.PARTIAL,
            "not_cleared": CleanupVerdict.NOT_CLEARED,
            "cleared_with_collateral_impact": CleanupVerdict.CLEARED_COLLATERAL,
            "indeterminate": CleanupVerdict.PARTIAL,
        }[outcome]
        residuals = [item for item in evidence if item.get("result") in {
            "residual_change", "present", "reappeared", "unobserved", "unexplained_t2_change",
            "unexplained_t2_flow",
        }]
        explicitly_listed = set(_indicators(_field(case, "blast_radius", ()))) | set(
            _indicators(_field(case, "ioc", ()))
        )
        trigger_paths = {
            f"flow.{item['table']}.{item['field']}"
            for item in _field(case, "triggers", ())
            if isinstance(item, Mapping) and item.get("table") in {"processes", "connections"}
            and isinstance(item.get("field"), str)
        }
        missed = [item for item in residuals if item.get("probe") == "full_snapshot"
                  and item.get("path") not in explicitly_listed
                  and item.get("path") not in trigger_paths]
        contract_result = BackwardResult(
            verdict=verdict,
            total_score=overall,
            probe_score=deterministic_score,
            kev_score=quality_score,
            residuals=residuals,
            business_impact="unexplained post-remediation change" if collateral else "indeterminate" if coverage_gap else "none observed",
            recurrence=recurrence,
            missed_by_forward=missed,
            case_id=case_id,
        )
        return VerificationReport(contract_result, case_id, outcome, confidence, deterministic_score,
                                  quality_score, overall, tuple(evidence), extend, deeper, card,
                                  not bool(observations))


_configured: BackwardVerifier | None = None


def configure_backward(verifier: BackwardVerifier) -> None:
    """Bind host-owned snapshot and judge adapters during daemon startup."""
    global _configured
    _configured = verifier


def run_backward(case: object) -> BackwardResult:
    """Orchestrator entry point; never runs without configured observations."""
    if _configured is None:
        raise RuntimeError("Backward verifier is not configured")
    return _configured.run_backward(case)


def judge_quality_provider(case: object, evidence: list[dict[str, Any]]) -> Mapping[str, Any]:
    """Score response quality with the frozen intake-side judge() helper."""
    # Full flow views can contain many volatile rows. Keep Kev context bounded;
    # deterministic probes still inspect every field before this summary.
    relevant = [item for item in evidence if item.get("result") in {
        "residual_change", "unexplained_t2_change", "unexplained_t2_flow", "present", "reappeared", "unobserved"
    }]
    summary = [
        {key: str(item[key])[:200] for key in ("probe", "path", "result", "indicator") if key in item}
        for item in relevant[:80]
    ]
    context = json.dumps({"case_id": _field(case, "case_id", "unknown"),
                          "finding_count": len(relevant), "findings": summary},
                         ensure_ascii=False, default=str)
    response = judge(JudgeQuery(
        kind=JudgeKind.SCORE,
        question="How complete was the remediation, accounting for residue, recurrence, and business impact?",
        context=context,
        options=["failed", "mostly failed", "partial", "mostly complete", "complete without collateral impact"],
    ))
    if response.score is None:
        raise ValueError("Kev omitted backward quality score")
    explanations = []
    for item in relevant[:12]:
        if item.get("result") not in {"residual_change", "unexplained_t2_change", "unexplained_t2_flow"}:
            continue
        choice = judge(JudgeQuery(
            kind=JudgeKind.CHOICE,
            question="What best explains this remaining change?",
            context=json.dumps({key: str(item[key])[:200] for key in ("probe", "path", "result") if key in item},
                               ensure_ascii=False),
            options=["attack_residue", "normal_change", "remediation_side_effect", "uncertain"],
        ))
        explanations.append({"path": item.get("path"), "explanation": choice.choice,
                             "confidence": choice.confidence})
    return {"quality_score": response.score, "confidence": response.confidence,
            "explanations": explanations}


def _field(case: object, name: str, default: Any) -> Any:
    return case.get(name, default) if isinstance(case, Mapping) else getattr(case, name, default)


def _flatten(snapshot: Snapshot, prefix: str = "") -> dict[str, Any]:
    if not isinstance(snapshot, Mapping):
        raise TypeError("Snapshot must be a mapping")
    result: dict[str, Any] = {}
    for key, value in snapshot.items():
        path = f"{prefix}.{key}" if prefix else str(key)
        if isinstance(value, Mapping):
            result.update(_flatten(value, path))
        else:
            result[path] = value
    return result


def _indicators(value: Any) -> tuple[str, ...]:
    if isinstance(value, str):
        return (value,) if value else ()
    if not isinstance(value, (list, tuple, set)):
        return ()
    return tuple(str(item) for item in value if isinstance(item, (str, int)) and str(item))


def _observed(item: str, flat: dict[str, Any]) -> bool:
    """Item names a snapshot object: a path segment, a natural key before its '#hash' suffix, or a value."""
    for path, value in flat.items():
        # Flattening joins keys with "." so a key like /etc/ld.so.preload spans several segments.
        if item.startswith("/") and (f".{item}." in f".{path}." or f".{item}#" in f".{path}"):
            return True
        if len(item) >= 6 and item in path:
            return True
        for segment in path.split("."):
            if segment == item or segment.split("#", 1)[0] == item:
                return True
        if _contains_indicator(value, item):
            return True
    return False


def _contains_indicator(value: Any, indicator: str) -> bool:
    if isinstance(value, Mapping):
        return any(_contains_indicator(part, indicator) for part in value.values())
    if isinstance(value, (list, tuple, set)):
        return any(_contains_indicator(part, indicator) for part in value)
    text = str(value)
    # Long indicators also match inside values (an IP inside a cron command); short ones only exactly,
    # so "1" or "sh" cannot match everything.
    return text == indicator or (len(indicator) >= 6 and indicator in text)


def _unit(value: Any) -> float:
    score = float(value)
    if not 0 <= score <= 1:
        raise ValueError("Score is outside [0, 1]")
    return score


def _show(value: Any, missing: object) -> Any:
    return "<absent>" if value is missing else value
