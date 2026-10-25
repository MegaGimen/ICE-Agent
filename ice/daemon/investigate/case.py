"""Turn the agent's reply into a fixed-format Case (plan.md §3.2, colab §3.4).

The agent ends its reply with one ```json block. Parsing is defensive: the model's output
is untrusted too, so every field is type-checked and clipped, and a reply without usable
JSON still yields a Case (status investigating) carrying the raw text for a human.
"""
from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional, Tuple

from ice.daemon.contracts import Case, CaseStatus, ProposedAction, now_iso

_FENCE = re.compile(r"```(?:json)?\s*(\{.*?\})\s*```", re.S)
_ATTCK = re.compile(r"^T\d{4}(?:\.\d{3})?$")
MAX_ACTIONS = 8


def extract_json(text: str) -> Optional[Dict[str, Any]]:
    """Last fenced JSON object in the text, else the last balanced {...} that parses."""
    for m in reversed(_FENCE.findall(text or "")):
        try:
            obj = json.loads(m)
            if isinstance(obj, dict):
                return obj
        except json.JSONDecodeError:
            continue
    # Fallback: scan for a trailing top-level object.
    depth, start = 0, None
    candidates: List[Tuple[int, int]] = []
    for i, ch in enumerate(text or ""):
        if ch == "{":
            if depth == 0:
                start = i
            depth += 1
        elif ch == "}" and depth:
            depth -= 1
            if depth == 0 and start is not None:
                candidates.append((start, i + 1))
    for s, e in reversed(candidates):
        try:
            obj = json.loads(text[s:e])
            if isinstance(obj, dict):
                return obj
        except json.JSONDecodeError:
            continue
    return None


def _strs(v: Any, limit: int = 50, width: int = 500) -> List[str]:
    if isinstance(v, str):
        v = [v]
    if not isinstance(v, list):
        return []
    return [str(x)[:width] for x in v if isinstance(x, (str, int, float)) and str(x).strip()][:limit]


def _float(v: Any) -> float:
    try:
        return max(0.0, min(1.0, float(v)))
    except (TypeError, ValueError):
        return 0.0


def build_case(case_id: str, host: str, reply_text: str, triggers: List[Dict[str, Any]],
               created: Optional[str] = None) -> Tuple[Case, Optional[str]]:
    """Returns (case, assessment). assessment is malicious/benign/uncertain, or None if unparseable."""
    case = Case(case_id=case_id, hosts=[host], triggers=triggers, created=created or now_iso())
    obj = extract_json(reply_text)
    if obj is None:
        case.status = CaseStatus.INVESTIGATING
        case.reason = (reply_text or "").strip()[-4000:] or "Agent returned no case."
        case.add_timeline("investigation reply had no parseable case JSON")
        return case, None
    assessment = str(obj.get("assessment", "uncertain")).strip().lower()
    if assessment not in ("malicious", "benign", "uncertain"):
        assessment = "uncertain"
    case.confidence = _float(obj.get("confidence"))
    case.attck = [t for t in _strs(obj.get("attck"), 20, 12) if _ATTCK.match(t)]
    case.ioc = _strs(obj.get("ioc"))
    case.reason = str(obj.get("reason", ""))[:4000]
    case.blast_radius = _strs(obj.get("blast_radius"))
    hosts = _strs(obj.get("hosts"), 10, 255)
    if hosts:
        case.hosts = sorted(set(hosts) | {host})
    for item in (obj.get("timeline") or [])[:50]:
        if isinstance(item, dict) and item.get("event"):
            case.timeline.append({"ts": str(item.get("ts", ""))[:40], "event": str(item["event"])[:500]})
    for a in (obj.get("proposed_actions") or [])[:MAX_ACTIONS]:
        if isinstance(a, dict) and isinstance(a.get("command"), str) and a["command"].strip():
            case.proposed_actions.append(ProposedAction(
                command=a["command"].strip()[:1000], intent=str(a.get("intent", ""))[:1000],
                targets=_strs(a.get("targets"), 10, 300)))
    if assessment == "benign":
        case.status = CaseStatus.DISMISSED
        case.proposed_actions = []
    elif case.proposed_actions:
        case.status = CaseStatus.PROPOSED
    else:
        case.status = CaseStatus.INVESTIGATING
    case.add_timeline(f"investigation complete: assessment={assessment} confidence={case.confidence:.2f}")
    return case, assessment
