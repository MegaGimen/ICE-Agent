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

Nothing is withheld whole. That was the first answer for text no parser would take, and on a real
episode it swallowed a flag file containing no prose at all and the osquery snapshots, which are
facts the judge needs and which failed to parse only because they are larger than the read cap.

What counts as the product's own state is derived from the same environment the recorder uses, not
from a list of paths kept here.
"""
from __future__ import annotations

import json
import os
import re
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


# A JSON string value, escapes and all, for the keys above. This is the fallback for text that no
# parser will take: a document truncated at the read cap is not valid JSON, and a diff's own header
# lines are not JSON at all. Withholding such a file whole was the first answer and it was wrong --
# it hid a flag file with no prose in it and the osquery snapshots, which are facts the judge needs
# and which only failed to parse because they are larger than the read cap.
_VALUE = re.compile(r'"(' + "|".join(sorted(AUTHORED)) + r')"(\s*:\s*)"(?:[^"\\]|\\.)*"')


def _sweep(body: str, removed: List[str]) -> str:
    """Replace the authored keys' values wherever they appear in text, parser or no parser."""
    def sub(m: "re.Match[str]") -> str:
        removed.append(m.group(1) + " (text)")
        return f'"{m.group(1)}"{m.group(2)}"{PLACEHOLDER}"'
    return _VALUE.sub(sub, body)


_MARKS = (" ", "+", "-")


def _split_mark(line: str) -> Tuple[str, str]:
    """A unified diff prefixes every line. Take the mark off so the rest can be parsed.

    This is the whole reason the filter missed what it was built for. json.loads ignores leading
    whitespace, so a context line ` {...}` parsed and was filtered, while an added line `+{...}`
    did not parse and went through untouched -- and the agent's own words are in the added lines by
    definition. The header lines (---, +++, @@) still fail to parse and fall to the sweep.
    """
    if line[:1] in _MARKS and line[1:2] in ("{", "["):
        return line[0], line[1:]
    return "", line


def text(path: str, body: str) -> Tuple[str, List[str]]:
    """The body with the agent's prose taken out, and the field paths that were taken.

    Three passes, strongest first, and nothing is ever withheld whole:

      1. the body as one JSON document -- structural, so a key is only matched as a key;
      2. line by line, with any unified-diff mark taken off first, for a JSONL log or its diff;
      3. a textual sweep over whatever neither pass could parse, for a document cut off at the read
         cap or a diff's own header lines.
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

    out: List[str] = []
    for line in body.splitlines():
        mark, rest = _split_mark(line)
        try:
            obj = json.loads(rest)
        except json.JSONDecodeError:
            out.append(_sweep(line, removed))
        else:
            out.append(mark + json.dumps(_strip(obj, removed), ensure_ascii=False))
    return "\n".join(out), removed


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
