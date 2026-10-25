"""Exercise harness (plan.md §5): run an authorized attack simulation, grade ICE against the
known answer, and when ICE under-calls it, learn — record the miss, promote a lesson into the
error book, feed it to the investigation, and re-run to confirm detection improved.

Must run as root (runs useradd/systemctl, reads root-only /var/lib/ice). The live ICE daemon
must be running: the harness triggers the attack and observes the case the daemon produces.

  sudo ICE_STATE_DIR=/var/lib/ice ~/ice-envs/daemon-env/bin/python -m ice.exercise.drill persistence
  sudo ... -m ice.exercise.drill persistence --no-learn      # grade only, no error-book changes
"""
from __future__ import annotations

import argparse
import glob
import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional

from ice.daemon import kb
from ice.daemon.evolve.error_book import ErrorBook
from ice.exercise.scenarios import SCENARIOS, Scenario

STATE = Path(os.environ.get("ICE_STATE_DIR", "/var/lib/ice"))
CASES = STATE / "cases"
ERRORBOOK = STATE / "errorbook.sqlite3"
INVESTIGATE_TIMEOUT = 360


def _run(cmds: List[str], label: str) -> None:
    for c in cmds:
        r = subprocess.run(["bash", "-c", c], capture_output=True, text=True)
        tag = "ok" if r.returncode == 0 else f"rc={r.returncode} {r.stderr.strip()[:80]}"
        print(f"  [{label}] {c[:80]} -> {tag}")


def _wait_for_case(markers: List[str], since: float) -> Optional[Dict[str, Any]]:
    """Poll for the investigated case whose triggers mention any marker (created after `since`)."""
    deadline = time.time() + INVESTIGATE_TIMEOUT
    while time.time() < deadline:
        for p in sorted(glob.glob(str(CASES / "case-*.json")), key=os.path.getmtime, reverse=True):
            if os.path.getmtime(p) < since - 2:
                continue
            try:
                d = json.loads(Path(p).read_text())
            except (OSError, json.JSONDecodeError):
                continue
            trig = " ".join(t.get("value", "") + " " + t.get("field", "") for t in d.get("triggers", []))
            if any(m in trig for m in markers) and "assessment" in d.get("_ice", {}):
                return d
        time.sleep(5)
    return None


def grade(scenario: Scenario, case: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    if case is None:
        return {"detected": False, "verdict": None, "miss": True, "reasons": ["no case: detection gate did not escalate"]}
    assessment = case.get("_ice", {}).get("assessment")
    attck = set(case.get("attck", []))
    blast = " ".join(case.get("blast_radius", []))
    reasons = []
    verdict_ok = assessment in ("malicious", "uncertain")
    if not verdict_ok:
        reasons.append(f"verdict={assessment} (expected malicious/uncertain)")
    tech_hit = sorted(attck & set(scenario.techniques))
    if not tech_hit:
        reasons.append(f"no expected technique mapped (got {sorted(attck) or 'none'})")
    scope_missed = [a for a in scenario.artifacts if a not in blast]
    if scope_missed:
        reasons.append(f"blast_radius missed: {scope_missed}")
    miss = not verdict_ok   # the headline miss is calling a real attack benign
    return {"detected": True, "case_id": case["case_id"], "verdict": assessment,
            "confidence": case.get("confidence"), "techniques": tech_hit, "scope_missed": scope_missed,
            "miss": miss, "reasons": reasons}


def run_once(scenario: Scenario, phase: str) -> Dict[str, Any]:
    """Run one attack (phase: 'attack' or 'variant'), observe ICE, grade, clean up."""
    cmds = scenario.variant if phase == "variant" else scenario.attack
    cleanup = scenario.variant_cleanup if phase == "variant" else scenario.cleanup
    since = time.time()
    print(f"\n=== [{scenario.id}/{phase}] launch attack at {time.strftime('%H:%M:%SZ', time.gmtime())} ===")
    _run(cmds, "attack")
    print(f"  waiting up to {INVESTIGATE_TIMEOUT}s for ICE to detect + investigate …")
    case = _wait_for_case(scenario.markers, since)
    result = grade(scenario, case)
    print(f"  grade: {'MISS' if result['miss'] else 'DETECTED'} — "
          + (f"verdict={result.get('verdict')} techniques={result.get('techniques')} " if case else "")
          + ("; ".join(result["reasons"]) or "verdict and technique correct"))
    print("  cleanup:")
    _run(cleanup, "cleanup")
    return result


def make_lesson(scenario: Scenario, case: Dict[str, Any]) -> str:
    wrong = (case.get("reason") or "").strip().replace("\n", " ")[:300]
    tech = ", ".join(scenario.techniques)
    return (
        f"Exercise lesson ({scenario.display}; ATT&CK {tech}). ICE previously dismissed this as "
        f"'{case.get('_ice', {}).get('assessment')}'. A newly added privileged account (e.g. a user in the "
        f"root group / gid 0), a new cron or /etc/cron.d entry, or a new autostart systemd unit is a "
        f"persistence or privilege foothold and must be judged malicious or uncertain — never benign — "
        f"regardless of who created it, whether sudo was used, or how harmless its current payload looks. "
        f"Clear it as benign only with a concrete package-manager (dpkg/apt) or config-management trail. "
        f"Prior wrong reasoning to avoid: \"{wrong}\"")


def lesson_detector(note: str, scenario_facts: Mapping[str, Any]) -> bool:
    """Does this lesson apply to a scenario? Fires on the artifact CLASS, not on names/payloads.
    Used by ErrorBook.retest: must hit original + variant, must not hit the normal control."""
    tags = ("new_privileged_account", "new_cron", "new_autostart_unit")
    return any(scenario_facts.get(t) for t in tags)


def learn(scenario: Scenario, case: Dict[str, Any]) -> Dict[str, Any]:
    """Record the miss, propose a lesson, three-way retest, promote, and index it for retrieval."""
    note = make_lesson(scenario, case)
    book = ErrorBook(ERRORBOOK)
    try:
        miss_id = book.record_miss(case["case_id"], f"exercise:{scenario.id}",
                                   {"techniques": scenario.techniques, "assessment": case.get("_ice", {}).get("assessment")})
        cand = book.propose(miss_id, note)
        eligible = book.retest(cand, scenario.facts, scenario.variant_facts, scenario.normal_facts, lesson_detector)
        if eligible:
            book.promote(cand)
        active = book.active_notes()
    finally:
        book.close()
    # Also index the lesson in the bge-m3 experience base (semantic retrieval at scale, plan §5/§7.3).
    kb.upsert("experience", [{"id": f"lesson-{scenario.id}", "text": note,
                              "payload": {"lesson": note, "scenario": scenario.id}}])
    print(f"  learned: miss#{miss_id} candidate#{cand} retest_eligible={eligible} promoted={eligible} "
          f"| active lessons now {len(active)}")
    return {"miss_id": miss_id, "candidate": cand, "promoted": eligible, "active": len(active)}


def main() -> None:
    ap = argparse.ArgumentParser(description="ICE exercise harness")
    ap.add_argument("scenario", nargs="?", default="persistence", choices=sorted(SCENARIOS))
    ap.add_argument("--no-learn", action="store_true", help="grade only; do not touch the error book")
    a = ap.parse_args()
    if os.geteuid() != 0:
        sys.exit("run as root: sudo ICE_STATE_DIR=/var/lib/ice <py> -m ice.exercise.drill")
    sc = SCENARIOS[a.scenario]
    print(f"### Exercise '{sc.id}': {sc.display}")
    print(f"### ground truth: techniques {sc.techniques}, artifacts {sc.artifacts}")

    r1 = run_once(sc, "attack")
    report = {"scenario": sc.id, "round1": r1}
    if not r1["miss"]:
        print("\n### round 1 already detected — no lesson needed. Coverage: 1/1.")
        print(json.dumps(report, indent=1))
        return
    if a.no_learn:
        print("\n### round 1 MISSED; --no-learn set, stopping.")
        print(json.dumps(report, indent=1))
        return
    print("\n### round 1 MISSED → learning")
    report["learn"] = learn(sc, _load(r1["case_id"]))
    print("\n### round 2 (same attack, lesson now active) …")
    r2 = run_once(sc, "attack")
    report["round2"] = r2
    improved = r1["miss"] and not r2["miss"]
    print(f"\n### RESULT: round1={'miss' if r1['miss'] else 'detected'} -> "
          f"round2={'miss' if r2['miss'] else 'detected'} | self-learning {'WORKED' if improved else 'did not change the verdict'}")
    print(json.dumps(report, indent=1))


def _load(case_id: str) -> Dict[str, Any]:
    return json.loads((CASES / f"{case_id}.json").read_text())


if __name__ == "__main__":
    main()
