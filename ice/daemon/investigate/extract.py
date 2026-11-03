"""Recover a structured case from an investigation reply that came back as prose.

The agentic loop cannot be JSON-constrained: the model has to emit tool calls, so `response_format`
is unavailable for the investigation itself. A smaller model therefore sometimes does a perfectly
good investigation and then writes it up as markdown, and build_case gets no JSON to parse -- the
whole episode lands as `assessment=None`. Measured on qwen3.6-flash: a real tool-using
investigation, a coherent evidence chain, no JSON, and a tail that degenerated into a repeated
paragraph.

This module re-asks for the same content as one short constrained call with
`response_format={"type":"json_object"}`, which the endpoint honours. It is only invoked when
build_case found nothing, so a model that already complies costs nothing extra.

The extraction is not a second opinion and must not add findings: it reformats what the reply
already said. Keep it on a cheap model; the judgement was made upstream.
"""
from __future__ import annotations

import json
import logging
import os
import urllib.error
import urllib.request
from typing import Optional

log = logging.getLogger("ice.extract")

BASE_URL = os.environ.get("ICE_AGENT_BASE_URL", "").rstrip("/")
MODEL = os.environ.get("ICE_EXTRACT_MODEL") or os.environ.get("ICE_AGENT_MODEL", "")
API_KEY = os.environ.get("ICE_EXTRACT_API_KEY") or os.environ.get("ICE_AGENT_API_KEY", "")
TIMEOUT = float(os.environ.get("ICE_EXTRACT_TIMEOUT", "300"))
MAX_TOKENS = int(os.environ.get("ICE_EXTRACT_MAX_TOKENS", "40960"))

PROMPT = """Reformat the security investigation report below into a single JSON object. Do not add,
remove or soften any finding: carry over only what the report already states. If the report does not
state something, leave that field empty or omit it.

Required shape:
{{
  "assessment": "malicious" | "benign" | "uncertain",
  "confidence": <number 0..1>,
  "attck": ["T1053.003", ...],
  "ioc": ["<bare identifier, no label or commentary>", ...],
  "blast_radius": ["<bare identifier of each affected object>", ...],
  "reason": "<why, in the report's own terms>",
  "timeline": [{{"ts": "<iso or empty>", "event": "<what happened>"}}],
  "proposed_actions": [{{"command": "<single shell-free command>", "intent": "<why>",
                        "targets": ["<object the command acts on>"]}}]
}}

REPORT:
{report}"""


def to_case_json(reply_text: str) -> Optional[str]:
    """JSON text build_case can parse, or None if extraction is unavailable or fails."""
    text = (reply_text or "").strip()
    if not text or not BASE_URL or not MODEL:
        return None
    body = {
        "model": MODEL,
        "max_tokens": MAX_TOKENS,
        "response_format": {"type": "json_object"},
        "messages": [{"role": "user", "content": PROMPT.format(report=text[-12000:])}],
    }
    req = urllib.request.Request(BASE_URL + "/chat/completions", data=json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json",
                                          "Authorization": "Bearer " + API_KEY})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
            resp = json.load(r)
    except urllib.error.HTTPError as e:
        log.warning("case extraction failed: HTTP %s %s", e.code, e.read()[:200])
        return None
    except Exception as e:  # noqa: BLE001 - extraction is best-effort
        log.warning("case extraction failed: %s: %s", type(e).__name__, e)
        return None
    content = ((resp.get("choices") or [{}])[0].get("message") or {}).get("content") or ""
    try:
        obj = json.loads(content)
    except json.JSONDecodeError:
        log.warning("case extraction returned non-JSON despite response_format")
        return None
    if not isinstance(obj, dict) or not obj.get("assessment"):
        return None
    log.info("case extraction recovered assessment=%s attck=%s", obj.get("assessment"), obj.get("attck"))
    return content
