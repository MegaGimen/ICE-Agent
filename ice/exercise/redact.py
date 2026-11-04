"""Keeping the agent's own words out of what the judge reads.

The judge's verdict is worth something because the agent cannot address it: the prompt is built from
the machine-written audit's commands and from disk snapshots, and `tests/test_judge_inputs.py` holds
that shut for all seven runs. The tools are a second channel, and they were open. The judge reads any
absolute path out of a snapshot, and the machine under test is the one ICE runs on, so
`/root/ice-state/cases/case-*.json` carries the agent's `reason` and the audit carries its
`explanation`, `intent` and `query`. The T2 - T0 change list *names* the case file -- it appears in
all seven prompts, labelled `added`, which is an invitation.

Blocking those paths outright was the obvious move and is the wrong one: an episode that deleted
ICE's own state is real damage and has to stay visible. So the filter is on fields, not on paths.
The file is still read, its size and hash are still right, a deletion or a truncation still shows --
only the agent-authored values are replaced, and the result says which and how many, so a reader can
see the filter worked rather than having to trust it.

What counts as the product's own state is derived from the same environment the recorder uses, not
from a list of paths kept here.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Dict, List, Tuple

# Fields whose value is something the agent wrote in prose. The names come from what the daemon
# actually emits: `tool.explanation`, `tool.query` and `host_exec.verdict.intent` in the audit, and
# `reason` in a case file.
AUTHORED = frozenset({"explanation", "intent", "query", "reason", "assessment", "rationale",
                      "notes", "summary", "justification", "analysis", "thought", "message",
                      "content", "text"})

PLACEHOLDER = "<removed: the agent's own words are not evidence>"


def state_paths() -> Tuple[str, ...]:
    """Where the product keeps its own state on the machine under test."""
    home = os.environ.get("ICE_TARGET_HOME", "/root")
    return tuple(sorted({
        os.environ.get("ICE_STATE_DIR", "/root/ice-state"),
        os.environ.get("OPENCLAW_HOME", "") or f"{home}/.openclaw",
    }))


def is_product_state(path: str) -> bool:
    """Is this path inside the product's own state, where agent-authored text lives?"""
    try:
        p = Path(path).as_posix()
    except (TypeError, ValueError):
        return False
    return any(p == base or p.startswith(base.rstrip("/") + "/") for base in state_paths())


def _strip(obj: Any, removed: List[str], prefix: str = "") -> Any:
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            where = f"{prefix}.{k}" if prefix else k
            if k in AUTHORED and isinstance(v, str):
                out[k] = PLACEHOLDER
                removed.append(where)
            else:
                out[k] = _strip(v, removed, where)
        return out
    if isinstance(obj, list):
        return [_strip(v, removed, f"{prefix}[]") for v in obj]
    return obj


def text(path: str, body: str) -> Tuple[str, List[str]]:
    """The body with the agent's prose taken out, and the field paths that were taken.

    Handles a JSON document and a JSONL log, because those are the two shapes this material comes
    in. Anything under the product's state that parses as neither cannot be filtered field by field,
    so it is withheld whole rather than passed through -- withholding one unparsable file is a
    smaller cost than leaking the channel this exists to close.
    """
    if not is_product_state(path):
        return body, []
    removed: List[str] = []
    try:
        obj = json.loads(body)
    except json.JSONDecodeError:
        pass
    else:
        return json.dumps(_strip(obj, removed), ensure_ascii=False, indent=1), removed

    lines = body.splitlines()
    out: List[str] = []
    parsed = 0
    for line in lines:
        if not line.strip():
            out.append(line)
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            out.append(line)
            continue
        parsed += 1
        out.append(json.dumps(_strip(obj, removed), ensure_ascii=False))
    if parsed:
        return "\n".join(out), removed
    return (f"{PLACEHOLDER}\n(this file is inside the product's own state and is neither JSON nor "
            f"JSONL, so agent-authored text cannot be removed field by field. Its size, hash and "
            f"existence are reported above and are unaffected.)"), ["<whole file>"]


def record(result: Dict[str, Any], path: str) -> Dict[str, Any]:
    """Apply the filter to one tool result in place, and say on the result what was removed."""
    body = result.get("text")
    if not isinstance(body, str):
        return result
    cleaned, removed = text(path, body)
    if removed or cleaned != body:
        result["text"] = cleaned
        result["redacted_fields"] = sorted(set(removed))
        result["redacted"] = ("agent-authored fields removed: the agent's own account of what it "
                              "did is not evidence about the machine")
    return result
