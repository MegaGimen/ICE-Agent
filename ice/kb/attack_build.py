"""Build the ATT&CK technique knowledge base (plan.md §3.2 "本地知识库") from MITRE's
enterprise-attack STIX bundle. Standard library only.

  python3 -m ice.kb.attack_build ~/ice-data/attack/enterprise-attack.json ~/ice-data/kb/attack.jsonl

Keeps non-revoked, non-deprecated techniques that apply to Linux (or name no platform),
one JSON line each: {id, text, payload}. `text` is what gets embedded; `payload` is what
the agent sees (name, tactics, short description, detection hints).
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

_CITE = re.compile(r"\(Citation:[^)]*\)")
_LINK = re.compile(r"\[([^\]]+)\]\([^)]+\)")


def _clean(s: str, n: int) -> str:
    s = _LINK.sub(r"\1", _CITE.sub("", s or ""))
    s = re.sub(r"<[^>]+>", "", s)
    s = re.sub(r"\s+", " ", s).strip()
    return s if len(s) <= n else s[: n - 1].rsplit(" ", 1)[0] + "…"


def build(src: Path, dst: Path) -> int:
    bundle = json.loads(src.read_text())
    n = 0
    dst.parent.mkdir(parents=True, exist_ok=True)
    with dst.open("w") as out:
        for o in bundle["objects"]:
            if o.get("type") != "attack-pattern" or o.get("revoked") or o.get("x_mitre_deprecated"):
                continue
            platforms = o.get("x_mitre_platforms") or []
            if platforms and "Linux" not in platforms:
                continue
            ext = next((r for r in o.get("external_references", []) if r.get("source_name") == "mitre-attack"), None)
            if not ext:
                continue
            tid = ext["external_id"]
            tactics = [p["phase_name"] for p in o.get("kill_chain_phases", []) if p.get("kill_chain_name") == "mitre-attack"]
            desc = _clean(o.get("description", ""), 700)
            detection = _clean(o.get("x_mitre_detection", ""), 400)
            payload = {"id": tid, "name": o.get("name", ""), "tactics": tactics, "description": desc,
                       "detection": detection}
            text = f"{tid} {o.get('name', '')}. Tactics: {', '.join(tactics)}. {desc} Detection: {detection}"
            out.write(json.dumps({"id": tid, "text": text, "payload": payload}, ensure_ascii=False) + "\n")
            n += 1
    return n


if __name__ == "__main__":
    src = Path(sys.argv[1] if len(sys.argv) > 1 else Path.home() / "ice-data/attack/enterprise-attack.json")
    dst = Path(sys.argv[2] if len(sys.argv) > 2 else Path.home() / "ice-data/kb/attack.jsonl")
    print(f"{build(src, dst)} techniques -> {dst}")
