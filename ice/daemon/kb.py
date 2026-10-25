"""Knowledge base + experience base client (plan.md §3.2: retrieve before investigating).

Talks to ice/kb/embed_service.py (bge-m3 on CPU, 127.0.0.1:8020). Collections:
  attack      MITRE ATT&CK techniques that apply to Linux (ice/kb/attack_build.py)
  experience  lessons from past cases (error book, plan §5) — empty until evolution writes to it
Retrieval is best effort: if the service is down, investigation proceeds without references.
"""
from __future__ import annotations

import json
import logging
import os
import urllib.request
from typing import Any, Dict, List

log = logging.getLogger("ice.kb")

URL = os.environ.get("ICE_EMBED_URL", "http://127.0.0.1:8020")
MIN_SCORE = float(os.environ.get("ICE_KB_MIN_SCORE", "0.45"))
REL_MARGIN = float(os.environ.get("ICE_KB_REL_MARGIN", "0.05"))


def _post(path: str, body: Dict[str, Any], timeout: float = 20.0) -> Dict[str, Any]:
    req = urllib.request.Request(URL + path, data=json.dumps(body).encode(), method="POST",
                                 headers={"content-type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.load(r)


def search(collection: str, text: str, k: int = 3) -> List[Dict[str, Any]]:
    try:
        res = _post("/search", {"collection": collection, "text": text[:2000], "k": k}).get("results", [])
    except Exception as e:  # noqa: BLE001
        log.warning("kb search failed: %s", e)
        return []
    return [r for r in res if r.get("score", 0) >= MIN_SCORE]


def upsert(collection: str, items: List[Dict[str, Any]]) -> bool:
    try:
        _post("/upsert", {"collection": collection, "items": items}, timeout=120)
        return True
    except Exception as e:  # noqa: BLE001
        log.warning("kb upsert failed: %s", e)
        return False


def technique_notes(text: str, k: int = 3) -> List[str]:
    """Short reference notes for the wake message (kept small: every tool round resends the context)."""
    notes = []
    hits = search("attack", text, k)
    # Keep only hits close to the best one: a weak second match costs context on every tool round.
    top = hits[0]["score"] if hits else 0.0
    for r in [h for h in hits if h["score"] >= top - REL_MARGIN]:
        p = r.get("payload") or {}
        desc = (p.get("description") or "")[:280]
        det = (p.get("detection") or "")[:180]
        notes.append(f"- {p.get('id')} {p.get('name')} ({', '.join(p.get('tactics') or [])}): {desc}"
                     + (f" Detection: {det}" if det else ""))
    return notes


def experience_notes(text: str, k: int = 3) -> List[str]:
    return [f"- {(r.get('payload') or {}).get('lesson') or r['id']}" for r in search("experience", text, k)]
