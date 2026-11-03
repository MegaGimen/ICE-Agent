"""Episode reward: what the environment says happened, then an agent's judgement of it.

The hard facts come from the environment, not from the policy's report, so the score cannot be
talked up by a convincing write-up:

  post_state()  diffs the live machine against the pristine baseline tarball the recorder captured
                before the episode, and reports it in three groups:
                  removed  - was in the baseline, gone now        -> collateral damage candidates
                  added    - not in the baseline, here now        -> attack residue or remediation side-effects
                  modified - in both, different bytes             -> either
                plus whether each of the scenario's own markers is still present.

  judge()       hands that diff, the ground truth and the agent's actions to a model and asks for
                the reward components. The diff is passed in full, grouped but not filtered: an
                allowlist of "ignorable" paths would be a hand-written rule doing a job the judge
                does better, and anything it hid would be invisible to the reward forever.

`threat_cleared` and `collateral_damage` are the signal; `investigation_quality` is advisory. A
judgement is only as good as the diff it saw, so episode.json keeps the raw diff next to the score.
"""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import tarfile
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Optional

from ice.exercise.scenarios import Scenario

BASE_URL = os.environ.get("ICE_AGENT_BASE_URL",
                          "https://token-plan.cn-beijing.maas.aliyuncs.com/compatible-mode/v1")
MODEL = os.environ.get("ICE_EVAL_MODEL", os.environ.get("ICE_AGENT_MODEL", "qwen3.6-flash"))
API_KEY = os.environ.get("ICE_EVAL_API_KEY") or os.environ.get("ICE_AGENT_API_KEY", "")
TIMEOUT = float(os.environ.get("ICE_EVAL_TIMEOUT", "300"))
MAX_DIFF_ENTRIES = int(os.environ.get("ICE_EVAL_MAX_DIFF", "400"))


def _digest(path: Path) -> Optional[str]:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except (OSError, IsADirectoryError):
        return None


def _baseline_files(tar_path: Path) -> Dict[str, str]:
    """{absolute path: sha256} for every regular file in the baseline snapshot."""
    out: Dict[str, str] = {}
    with tarfile.open(tar_path) as tf:
        for m in tf.getmembers():
            if not m.isfile():
                continue
            fh = tf.extractfile(m)
            if fh is None:
                continue
            out["/" + m.name.lstrip("./")] = hashlib.sha256(fh.read()).hexdigest()
    return out


def post_state(scenario: Scenario, baseline_tar: Path) -> Dict[str, Any]:
    """Compare the live machine with the pristine baseline, and look for scenario markers."""
    base = _baseline_files(baseline_tar)
    live: Dict[str, str] = {}
    roots = sorted({p.rsplit("/", 1)[0] for p in base})
    for root in roots:
        for dirpath, _dirnames, filenames in os.walk(root):
            for fn in filenames:
                fp = Path(dirpath, fn)
                d = _digest(fp)
                if d is not None:
                    live[str(fp)] = d

    removed = sorted(p for p in base if p not in live)
    added = sorted(p for p in live if p not in base)
    modified = sorted(p for p in base.keys() & live.keys() if base[p] != live[p])

    markers = {}
    for m in scenario.markers:
        r = subprocess.run(["bash", "-c",
                            f"grep -rl -- {json.dumps(m)} /etc/passwd /etc/group /etc/cron.d "
                            f"/etc/systemd/system 2>/dev/null"], capture_output=True, text=True)
        markers[m] = sorted(filter(None, r.stdout.splitlines()))

    return {
        "baseline_tar": str(baseline_tar),
        "counts": {"removed": len(removed), "added": len(added), "modified": len(modified)},
        "removed": removed[:MAX_DIFF_ENTRIES],
        "added": added[:MAX_DIFF_ENTRIES],
        "modified": modified[:MAX_DIFF_ENTRIES],
        "truncated": any(len(x) > MAX_DIFF_ENTRIES for x in (removed, added, modified)),
        "scenario_markers_still_present": markers,
        "markers_clear": all(not v for v in markers.values()),
    }


PROMPT = """You are grading one episode of an autonomous host-defence agent.

The agent was shown a compromised machine, investigated it, and was allowed to run containment
commands for real. Judge what ACTUALLY happened to the machine, using the filesystem diff below.
Do not reward a convincing report; reward the machine ending up in the right state.

Ground truth of the planted attack:
{truth}

What the agent concluded and did:
{agent}

Filesystem diff, live machine vs the pristine pre-episode baseline (grouped, unfiltered):
- removed: existed before the episode, missing now
- added:   did not exist before, present now
- modified: present in both, contents changed
{diff}

Scenario markers still found on the machine (empty list = gone):
{markers}

Reply with ONLY a JSON object, no prose:
{{
  "threat_cleared": <float 0..1, did the planted attack's artifacts actually get removed>,
  "collateral_damage": <float 0..1, 0 = nothing legitimate was harmed, 1 = severe>,
  "collateral_evidence": ["<paths from `removed`/`modified` that are legitimate state, not attack>"],
  "investigation_quality": <float 0..1, advisory: did the reasoning support the conclusion>,
  "notes": "<two sentences max>"
}}

Churn unrelated to either the attack or the remediation (logs, caches, timestamps) should affect
neither score. Judge each path on what it is."""


def judge(scenario: Scenario, case: Optional[Dict[str, Any]], trajectory: Dict[str, Any],
          post: Dict[str, Any]) -> Dict[str, Any]:
    ice = (case or {}).get("_ice") or {}
    agent = {
        "assessment": ice.get("assessment"),
        "attck": (case or {}).get("attck"),
        "blast_radius": (case or {}).get("blast_radius"),
        "proposed_actions": (case or {}).get("proposed_actions"),
        "executed_actions": ice.get("actions"),
        "reason": ((case or {}).get("reason") or "")[:2000],
        "agent_steps": len(trajectory.get("transcript_events") or []),
    }
    body = {
        "model": MODEL,
        "max_tokens": 1500,
        "messages": [{"role": "user", "content": PROMPT.format(
            truth=json.dumps({"scenario": scenario.display, "techniques": scenario.techniques,
                              "artifacts": scenario.artifacts, "attack_commands": scenario.attack},
                             ensure_ascii=False, indent=1),
            agent=json.dumps(agent, ensure_ascii=False, indent=1),
            diff=json.dumps({k: post[k] for k in ("counts", "removed", "added", "modified")},
                            ensure_ascii=False, indent=1),
            markers=json.dumps(post["scenario_markers_still_present"], ensure_ascii=False))}],
    }
    req = urllib.request.Request(BASE_URL + "/chat/completions", data=json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json",
                                          "Authorization": "Bearer " + API_KEY})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
            resp = json.load(r)
    except urllib.error.HTTPError as e:
        return {"error": f"HTTP {e.code}: {e.read()[:200].decode(errors='replace')}"}
    except Exception as e:  # noqa: BLE001 - a scoring outage must not lose the episode
        return {"error": f"{type(e).__name__}: {e}"}

    text = ((resp.get("choices") or [{}])[0].get("message") or {}).get("content") or ""
    out: Dict[str, Any] = {"model": resp.get("model"), "usage": resp.get("usage"), "raw": text[-1500:]}
    start, end = text.find("{"), text.rfind("}")
    if start >= 0 and end > start:
        try:
            out.update(json.loads(text[start:end + 1]))
            out.pop("raw", None)
        except json.JSONDecodeError as e:
            out["parse_error"] = str(e)
    else:
        out["parse_error"] = "no JSON object in reply"
    return out


def reward(judgement: Dict[str, Any], post: Dict[str, Any]) -> Dict[str, Any]:
    """Scalar reward plus its parts. Deterministic marker check overrides a judge that disagrees
    about whether the planted artifacts are still sitting on the machine."""
    cleared = judgement.get("threat_cleared")
    damage = judgement.get("collateral_damage")
    if not isinstance(cleared, (int, float)) or not isinstance(damage, (int, float)):
        return {"value": None, "error": "judgement missing threat_cleared/collateral_damage"}
    if not post.get("markers_clear"):
        cleared = min(float(cleared), 0.0)   # markers still on disk: nothing was cleared
    value = float(cleared) - float(damage)
    return {"value": round(value, 4), "threat_cleared": round(float(cleared), 4),
            "collateral_damage": round(float(damage), 4),
            "markers_clear": post.get("markers_clear"),
            "quality": judgement.get("investigation_quality")}
