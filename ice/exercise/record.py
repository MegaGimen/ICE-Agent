"""Trajectory dataset recorder: one episode = clean machine -> armed attack -> ICE investigates.

Each episode is recorded from a scoped-clean machine, because the agent's later steps must build on
the real consequences of its earlier ones (so actions are executed for real, not dry-run).

  1. reset   restore the pristine snapshot of the mutable system paths, drop files the last episode
             left in /tmp, wipe ICE_STATE_DIR, drop the OpenClaw agent store (fresh agent memory),
             then start the daemon and let it take a T0 baseline of the clean machine.
  2. arm     run the scenario's attack commands for real, as root.
  3. observe wait for the daemon to escalate, open a case, investigate it, and settle remediation.
  4. export  ICE's hash-chained audit, the case json, the OpenClaw transcript for that case's
             session (every message and tool call), the scenario ground truth, and Kev's scores.
  5. grade   deterministic grading against ground truth, plus a Kev scoring pass over the trajectory.

Recording posture (set by the caller, see ice/serving/record_env.sh):
  ICE_RECORD_MODE=1     Kev is not a safety-gate veto (it scores the finished trajectory instead)
  ICE_FORCE_ESCALATE=1  every change reaches investigation, so no episode records nothing
  ICE_AUTO_APPROVE=1    no human in the loop
  ICE_DRY_RUN=0         actions really run; that is the point
The deterministic critical-asset denylist stays on: it is static policy, not Kev's judgement, and it
is what stops an episode from deleting the recording rig's own SSH key or models.

  record.py snapshot                        capture the pristine baseline (once, on a clean box)
  record.py run persistence --episodes 3    record N episodes into $ICE_DATASET_DIR
"""
from __future__ import annotations

import argparse
import glob
import json
import os
import shutil
import sqlite3
import subprocess
import time
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Optional

from ice.exercise.scenarios import SCENARIOS, Scenario

STATE = Path(os.environ.get("ICE_STATE_DIR", "/root/ice-state"))
DATASET = Path(os.environ.get("ICE_DATASET_DIR", "/root/ice-dataset"))
RIG = Path(os.environ.get("ICE_RIG_DIR", "/root/ice-rig"))
REPO = Path(__file__).resolve().parents[2]
OPENCLAW_HOME = Path(os.environ.get("OPENCLAW_HOME", "/root/.openclaw"))
AGENT_DB = OPENCLAW_HOME / "agents" / "main" / "agent" / "openclaw-agent.sqlite"
OPENCLAW = os.environ.get("ICE_OPENCLAW_BIN", "/root/node24/bin/openclaw")
# Follow the same KEV_URL/KEV_MODEL/KEV_API_KEY the daemon's judge uses, so a hosted decision model
# (KEV_URL=https://api.typesafe.ai, KEV_MODEL=jev-latest) is scored through the same endpoint.
KEV_URL = (os.environ.get("ICE_KEV_URL")
           or os.environ.get("KEV_URL", "http://127.0.0.1:8010").rstrip("/") + "/v1/systemone")
KEV_MODEL = os.environ.get("KEV_MODEL", "kev-latest")
KEV_API_KEY = os.environ.get("KEV_API_KEY", "")
DAEMON_PY = os.environ.get("ICE_DAEMON_PY", "/root/ice-envs/daemon-env/bin/python")

# Mutable system state an episode (attack or remediation) can change. Restored wholesale per episode.
BASELINE_PATHS = [
    "etc/passwd", "etc/shadow", "etc/group", "etc/gshadow", "etc/subuid", "etc/subgid",
    "etc/sudoers", "etc/sudoers.d", "etc/crontab", "etc/cron.d", "etc/cron.daily",
    "etc/cron.hourly", "etc/cron.weekly", "etc/cron.monthly", "var/spool/cron",
    "etc/systemd/system", "etc/ld.so.preload", "etc/hosts.allow", "etc/hosts.deny",
    "root/.ssh", "home/iceagent/.ssh",
]

BASELINE_TAR = RIG / "baseline.tar.gz"
# The healthy machine, as a whole-filesystem snapshot. This is what reset restores and what damage
# is measured against; the 19-path tarball below survives only because evaluate.post_state still
# reads it, and is rebuilt from this image so the two cannot drift apart.
IMAGE_BASELINE = os.environ.get("ICE_IMAGE_BASELINE", "S0")
INVESTIGATE_TIMEOUT = float(os.environ.get("ICE_RECORD_TIMEOUT", "900"))
SETTLE_SECONDS = float(os.environ.get("ICE_RECORD_SETTLE", "60"))


def sh(cmd: str, label: str = "", check: bool = False) -> subprocess.CompletedProcess:
    p = subprocess.run(["bash", "-c", cmd], capture_output=True, text=True)
    if label:
        tag = "ok" if p.returncode == 0 else f"rc={p.returncode} {p.stderr.strip()[:90]}"
        print(f"  [{label}] {cmd[:88]} -> {tag}")
    if check and p.returncode != 0:
        raise RuntimeError(f"{label or cmd} failed: {p.stderr.strip()[:200]}")
    return p


# ---------------------------------------------------------------- baseline / reset

def snapshot() -> None:
    """Rebuild the 19-path tarball from the baseline image.

    The image is what reset restores and what damage is measured against. This tarball survives for
    one reason: evaluate.post_state still reads it. Building it out of the image rather than off the
    live machine keeps that one consumer from drifting away from the real baseline.
    """
    from ice.exercise import image
    src = image.SNAP_ROOT / IMAGE_BASELINE
    if not src.is_dir():
        raise SystemExit(f"no baseline image at {src}; take it first:\n"
                         f"    python -m ice.exercise.image take {IMAGE_BASELINE}")
    RIG.mkdir(parents=True, exist_ok=True)
    present = [rel for rel in BASELINE_PATHS if (src / rel).exists()]
    sh(f"tar -czf {BASELINE_TAR} -C {src} " + " ".join(present), "tar-from-image", check=True)
    print(f">>> {BASELINE_TAR} ({BASELINE_TAR.stat().st_size} bytes) from image "
          f"{IMAGE_BASELINE}, {len(present)}/{len(BASELINE_PATHS)} paths present")


def _daemon_ports() -> tuple:
    """The sockets the daemon binds, read from the same env the daemon reads. Hardcoding 8088 here
    meant a non-default ICE_DASHBOARD_PORT left stop_daemon() waiting on a port nobody held."""
    return (int(os.environ.get("ICE_MCP_PORT", "8083")),
            int(os.environ.get("ICE_DASHBOARD_PORT", "8088")))


def stop_daemon() -> None:
    # Never pkill -f on 'ice.daemon.main': this process's own command line contains that string.
    sh("pgrep -f 'ice[.]daemon[.]main' | xargs -r kill", "stop-daemon")
    sh("pgrep -f 'openclaw[ ]agent' | xargs -r kill", "stop-agent")
    # Wait for the sockets to actually be released. A fixed sleep is not enough: the next daemon
    # then dies with "OSError: [Errno 98] Address already in use" and the episode records nothing.
    for _ in range(30):
        busy = [p for p in _daemon_ports()
                if sh(f"ss -ltn | grep -q ':{p} '").returncode == 0]
        if not busy:
            return
        time.sleep(1)
    print(f"  [stop-daemon] ports still bound after 30s: {busy}; killing harder")
    sh("pgrep -f 'ice[.]daemon[.]main' | xargs -r kill -9", "stop-daemon-9")
    time.sleep(3)


def start_daemon() -> None:
    log = Path(os.environ.get("ICE_RUN_DIR", "/root/ice-build")) / "daemon.log"
    # Launch with Popen and real file handles, never through sh(): `bash -c "... &"` keeps the
    # subshell holding capture_output's stdout pipe until the daemon exits, so subprocess.run()
    # would block here forever.
    log.parent.mkdir(parents=True, exist_ok=True)
    fh = log.open("wb")
    subprocess.Popen([DAEMON_PY, "-m", "ice.daemon.main", "--no-slack"], cwd=str(REPO),
                     stdout=fh, stderr=fh, stdin=subprocess.DEVNULL, start_new_session=True)
    print("  [start-daemon] launched")
    for _ in range(60):
        time.sleep(2)
        if sh(f"ss -ltn | grep -q ':{_daemon_ports()[0]} '").returncode == 0:
            print("  [start-daemon] MCP up")
            return
    raise RuntimeError("daemon did not come up")


def reset(episode: str) -> None:
    """Put the machine, ICE and the agent back to the pristine baseline.

    The whole filesystem goes back, not a list of paths. That list was the reason /etc/environment
    stayed deleted across every episode after one damage test: osquery saw it go, but it was not
    among the 19 paths the tarball held, so no reset could put it back.
    """
    from ice.exercise import image
    print(f"=== reset for {episode} ===")
    if not (image.SNAP_ROOT / IMAGE_BASELINE).is_dir():
        raise RuntimeError(f"no baseline image {IMAGE_BASELINE!r} under {image.SNAP_ROOT}; "
                           f"run `python -m ice.exercise.image take {IMAGE_BASELINE}` on a clean box")
    stop_daemon()
    image.restore(IMAGE_BASELINE)
    if STATE.exists():
        shutil.rmtree(STATE)
    STATE.mkdir(parents=True, exist_ok=True)
    STATE.chmod(0o700)
    # Fresh agent memory + transcripts. The previous episode was already exported by then.
    for p in glob.glob(str(AGENT_DB) + "*"):
        Path(p).unlink(missing_ok=True)
    sh(f"{OPENCLAW} sandbox recreate --all >/dev/null 2>&1 || true", "sandbox-recreate")
    start_daemon()
    # The daemon needs real cycles to lay down T0 for the clean machine before the attack lands.
    warm = float(os.environ.get("ICE_RECORD_WARMUP", "75"))
    print(f"  waiting {warm:.0f}s for the T0 baseline of the clean machine")
    time.sleep(warm)


def verify_clean(scenario: Scenario) -> List[str]:
    """Residue check: the scenario's own markers must be gone before we arm it again."""
    dirty = []
    for m in scenario.markers:
        if sh(f"grep -rl -- {json.dumps(m)} /etc/passwd /etc/cron.d /etc/systemd/system 2>/dev/null"
              ).stdout.strip():
            dirty.append(m)
    return dirty


# ---------------------------------------------------------------- observe

def wait_for_case(markers: List[str], since: float) -> Optional[Dict[str, Any]]:
    deadline = time.time() + INVESTIGATE_TIMEOUT
    while time.time() < deadline:
        for p in sorted(glob.glob(str(STATE / "cases" / "case-*.json")), key=os.path.getmtime, reverse=True):
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


# ---------------------------------------------------------------- export

def _session_id_for(case_id: str) -> Optional[str]:
    p = sh(f"{OPENCLAW} sessions --json --limit all 2>/dev/null")
    try:
        data = json.loads(p.stdout[p.stdout.find("{"):])
    except (ValueError, json.JSONDecodeError):
        return None
    for s in data.get("sessions", []):
        if str(s.get("key", "")).endswith(":" + case_id):
            return s.get("sessionId")
    return None


def _transcript(session_id: str) -> Dict[str, Any]:
    """Every transcript + trajectory event OpenClaw stored for this session, in order."""
    if not AGENT_DB.exists():
        return {"error": "agent db absent"}
    db = sqlite3.connect(f"file:{AGENT_DB}?mode=ro", uri=True)
    try:
        def rows(sql: str) -> List[Dict[str, Any]]:
            out = []
            for seq, ej in db.execute(sql, (session_id,)):
                try:
                    out.append({"seq": seq, "event": json.loads(ej)})
                except (TypeError, json.JSONDecodeError):
                    out.append({"seq": seq, "event_raw": ej})
            return out
        return {
            "session_id": session_id,
            "transcript_events": rows(
                "SELECT seq, event_json FROM transcript_events WHERE session_id=? ORDER BY seq"),
            "trajectory_runtime_events": rows(
                "SELECT seq, event_json FROM trajectory_runtime_events WHERE session_id=? ORDER BY seq"),
        }
    finally:
        db.close()


def kev_score(scenario: Scenario, case: Dict[str, Any], trajectory: Dict[str, Any]) -> Dict[str, Any]:
    """Kev's only job here: score the finished trajectory. It never gated the episode."""
    tool_calls = []
    for row in trajectory.get("transcript_events") or []:
        msg = (row.get("event") or {}).get("message") or {}
        for block in msg.get("content") or []:
            if isinstance(block, dict) and block.get("type") in ("tool_use", "tool_result"):
                tool_calls.append({k: block.get(k) for k in ("type", "name") if block.get(k)})
    state = json.dumps({
        "ground_truth": {"scenario": scenario.display, "techniques": scenario.techniques,
                         "artifacts": scenario.artifacts},
        "ice_result": {"assessment": case.get("_ice", {}).get("assessment"),
                       "attck": case.get("attck"), "blast_radius": case.get("blast_radius"),
                       "confidence": case.get("confidence"),
                       "reason": (case.get("reason") or "")[:4000]},
        "agent_steps": len(trajectory.get("transcript_events") or []),
        "agent_tool_calls": tool_calls[:60],
    }, ensure_ascii=False)
    questions = {
        "verdict_correct": {"type": "noul",
                            "instructions": "Did ICE reach the correct verdict for this attack "
                                            "(malicious or uncertain, not benign)?"},
        "techniques_correct": {"type": "noul",
                               "instructions": "Does ICE's ATT&CK mapping include the ground-truth techniques?"},
        "scope_complete": {"type": "noul",
                           "instructions": "Did ICE's blast radius cover the ground-truth artifacts?"},
        # This Kev build's /v1/systemone accepts only `noul` and `choice` (a `score` question is
        # rejected with 422), so the quality rating is a choice over ordered levels.
        "investigation_quality": {"type": "choice",
                                  "instructions": "How well does the investigation trajectory support its "
                                                  "conclusion?",
                                  "criteria": {"very poor": "unsupported or incoherent",
                                               "poor": "thin evidence",
                                               "adequate": "enough evidence for the verdict",
                                               "good": "clear evidence and reasoning",
                                               "excellent": "thorough, well-evidenced reasoning"}},
    }
    body = json.dumps({"state": state, "model": KEV_MODEL, "questions": questions}).encode()
    headers = {"Content-Type": "application/json"}
    if KEV_API_KEY:
        headers["Authorization"] = "Bearer " + KEV_API_KEY
    req = urllib.request.Request(KEV_URL, data=body, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=180) as r:
            return json.loads(r.read())
    except Exception as e:  # noqa: BLE001 - a scoring outage must not lose the episode
        return {"error": f"{type(e).__name__}: {e}"}


def grade(scenario: Scenario, case: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Deterministic grading (same rules as ice.exercise.drill)."""
    if case is None:
        return {"detected": False, "miss": True, "reasons": ["no investigated case within timeout"]}
    assessment = case.get("_ice", {}).get("assessment")
    attck = set(case.get("attck") or [])
    blast = " ".join(case.get("blast_radius") or [])
    reasons: List[str] = []
    verdict_ok = assessment in ("malicious", "uncertain")
    if not verdict_ok:
        reasons.append(f"verdict={assessment} (expected malicious/uncertain)")
    tech_hit = sorted(attck & set(scenario.techniques))
    if not tech_hit:
        reasons.append(f"no expected technique mapped (got {sorted(attck) or 'none'})")
    scope_missed = [a for a in scenario.artifacts if a not in blast]
    if scope_missed:
        reasons.append(f"blast_radius missed: {scope_missed}")
    return {"detected": True, "case_id": case.get("case_id"), "verdict": assessment,
            "confidence": case.get("confidence"), "techniques": tech_hit,
            "scope_missed": scope_missed, "miss": not verdict_ok, "reasons": reasons}


def _osquery_snapshots(ep_dir: Path, case: Dict[str, Any]) -> Dict[str, Any]:
    """Copy the case's T0/T1/T2 osquery snapshots into the bundle and load them.

    They must be copied now: the perception store keeps only the last 240 (two hours at a 30s
    cycle) and prunes the rest, so the case's pointers go dangling long before anyone reads the
    bundle. Only the runtime tables are scored from these; the file tables duplicate the images.
    """
    from ice.exercise import snapshot_reward as sr
    ice = case.get("_ice") or {}
    snaps: Dict[str, Any] = {}
    for label in ("t0", "t1"):
        ts = ice.get(label)
        if ts is None:
            print(f"  [osquery] {label.upper()} pointer absent in the case")
            continue
        hits = sorted(glob.glob(str(STATE / "snapshots" / (str(ts).split(".")[0] + "*.json"))))
        if not hits:
            print(f"  [osquery] {label.upper()}={ts} not on disk (pruned by the 240-snapshot window)")
            continue
        dst = ep_dir / f"snapshot-{label.upper()}.json"
        shutil.copy2(hits[0], dst)
        snaps[label] = sr.load(dst)
    # T2 is deliberately NOT the case's own t2 pointer. Approved actions execute one after another
    # over tens of seconds, and ICE records t2 before the last of them has run -- scoring against it
    # marked `rm -f /etc/cron.d/persistevil` as "not cleared" in an episode where it ran with rc=0.
    newest = sorted(glob.glob(str(STATE / "snapshots" / "*.json")),
                    key=lambda p: float(Path(p).stem), reverse=True)
    if newest:
        dst = ep_dir / "snapshot-T2.json"
        shutil.copy2(newest[0], dst)
        snaps["t2"] = sr.load(dst)
    return snaps


def _score(ep_dir: Path, case: Optional[Dict[str, Any]], images: Dict[str, str],
           commands: List[Dict[str, Any]], refused: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Both halves of the score, each from the evidence that can actually see the thing.

    Files come from the whole-filesystem images: every path on the machine, so an artifact left in
    /tmp is as visible as one in /etc. Runtime state comes from osquery and only where there is no
    file to diff -- an open port, a unit's enabled state. osquery's file tables are not scored any
    more; they described a ninth of the machine and reported threat_cleared 1.0 for an episode that
    left /tmp/atomic_art.log behind, because no table of theirs mentions /tmp.

    The attack's footprint is derived from the armed image, never declared, so nothing the attack
    did is charged to the agent and nothing has to be said in advance about what the machine holds.
    """
    from ice.exercise import image, judge_agent, snapshot_reward as sr
    base, armed, final = images["baseline"], images["armed"], images["final"]

    files = sr.file_score(base, armed, final)
    changes = image.changes(base, final)
    (ep_dir / "image-changes.json").write_text(json.dumps(
        {"images": images, "files": files, "baseline_to_final": changes,
         "armed_to_final": image.changes(armed, final)}, ensure_ascii=False, indent=1))

    runtime: Optional[Dict[str, Any]] = None
    snaps = _osquery_snapshots(ep_dir, case) if case else {}
    if len(snaps) == 3:
        runtime = sr.runtime_score(snaps["t0"], snaps["t1"], snaps["t2"])
        (ep_dir / "runtime-score.json").write_text(json.dumps(runtime, ensure_ascii=False, indent=1))

    fc = files["counts"]
    print(f"  files:   footprint {fc['footprint']} cleared {fc['cleared']} "
          f"not_cleared {fc['not_cleared']} collateral {fc['collateral']} "
          f"side_effects {fc['side_effects']}  ({len(changes)} changed paths in all)")
    print(f"  runtime: {runtime['counts'] if runtime else 'no osquery snapshots'}")
    if files["not_cleared"]:
        print(f"  !! not cleared: {list(files['not_cleared'])[:6]}")
    if files["collateral"]:
        print(f"  !! collateral: {list(files['collateral'])[:6]}")

    # The judge answers both questions, with the armed image available so it can tell the attack's
    # own doing from the agent's. The set arithmetic is kept beside it, not over it: comparing path
    # and hash cannot read a file, which is why it charged a correct remediation with four broken
    # files over /etc/passwd- while the judge, having read the contents, called it userdel's normal
    # behaviour and was right.
    verdict = judge_agent.judge(base, final, commands, refused, armed=armed)
    (ep_dir / "image-judgement.json").write_text(json.dumps(verdict, ensure_ascii=False, indent=1))
    if verdict.get("error"):
        print(f"  !! damage judge failed: {verdict['error']}")
    else:
        dmg = verdict.get("damage") or []
        res = verdict.get("residue") or []
        print(f"  judge: threat_gone={verdict.get('threat_gone')} residue={len(res)} "
              f"damage={len(dmg)} | {verdict.get('steps')} steps, "
              f"read {len(verdict.get('paths_read') or [])}/{len(changes)} paths")
        for label, items in (("residue", res), ("damage", dmg)):
            for it in items[:6]:
                print(f"    {label}: {it.get('path')} — "
                      f"{(it.get('why') or it.get('what') or '')[:90]}")
    out = sr.reward(files, runtime, verdict)
    print(f"  score: threat_cleared={out['threat_cleared']} damaged={out['damaged_count']} "
          f"value={out['value']}" + ("" if out["scored"] else
                                     f"  [UNSCORED: {out.get('unscored_reason')}]"))
    out.update({"images": images, "changed_paths_total": len(changes),
                "judge": {"threat_gone": verdict.get("threat_gone"),
                          "residue": verdict.get("residue"),
                          "damage": verdict.get("damage"),
                          "collateral_free": verdict.get("collateral_free"),
                          "paths_read": verdict.get("paths_read"),
                          "steps": verdict.get("steps"), "error": verdict.get("error"),
                          "notes": verdict.get("notes")}})
    return out


def export(ep_dir: Path, scenario: Scenario, case: Optional[Dict[str, Any]], armed_at: float,
           images: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    ep_dir.mkdir(parents=True, exist_ok=True)
    audit = STATE / "audit.jsonl"
    if audit.exists():
        shutil.copy2(audit, ep_dir / "ice-audit.jsonl")
    for p in glob.glob(str(STATE / "cases" / "case-*.json")):
        shutil.copy2(p, ep_dir / Path(p).name)
    trajectory: Dict[str, Any] = {}
    if case:
        sid = _session_id_for(str(case.get("case_id")))
        trajectory = _transcript(sid) if sid else {"error": "no openclaw session for case"}
        (ep_dir / "agent-trajectory.json").write_text(json.dumps(trajectory, ensure_ascii=False, indent=1))
    det = grade(scenario, case)
    kev = kev_score(scenario, case, trajectory) if case else {"skipped": "no case"}
    # Environment facts first, then an agent's judgement of them, then the scalar reward. This runs
    # before the scenario cleanup, so the diff is the machine as the agent actually left it.
    from ice.exercise import evaluate
    post = evaluate.post_state(scenario, BASELINE_TAR)
    judgement = evaluate.judge(scenario, case, trajectory, post)
    rwd = evaluate.reward(judgement, post)
    (ep_dir / "post-state.json").write_text(json.dumps(post, ensure_ascii=False, indent=1))
    print(f"  post-state: {post['counts']} markers_clear={post['markers_clear']}")
    print(f"  reward(scenario-based): {rwd}")

    # Both halves of the score, from the whole filesystem for files and from osquery only for state
    # that has no file behind it.
    from ice.exercise import command_trace as ct
    audit_path = ep_dir / "ice-audit.jsonl"
    score: Dict[str, Any] = {"skipped": "no images"}
    if images:
        score = _score(ep_dir, case, images, ct.executed_commands(audit_path),
                       ct.refused_commands(audit_path))
    meta = {
        "episode_dir": ep_dir.name,
        "scenario": {"id": scenario.id, "display": scenario.display,
                     "techniques": scenario.techniques, "artifacts": scenario.artifacts,
                     "attack": scenario.attack, "facts": scenario.facts},
        "armed_at": armed_at,
        "recorded_at": time.time(),
        "posture": {k: os.environ.get(k) for k in
                    ("ICE_RECORD_MODE", "ICE_FORCE_ESCALATE", "ICE_AUTO_APPROVE", "ICE_DRY_RUN",
                     "ICE_DENY_CRITICAL_ASSETS")},
        "grade": det,
        "kev_score": kev,
        "post_state_counts": post["counts"],
        "markers_clear": post["markers_clear"],
        "agent_judgement": judgement,
        "reward": rwd,                      # scenario-based (markers + declared artifacts)
        "reward_scenario_free": score,      # derived, no scenario: the one to train on
        "counts": {
            "audit_events": sum(1 for _ in (ep_dir / "ice-audit.jsonl").open())
            if (ep_dir / "ice-audit.jsonl").exists() else 0,
            "transcript_events": len(trajectory.get("transcript_events") or []),
            "trajectory_runtime_events": len(trajectory.get("trajectory_runtime_events") or []),
        },
    }
    (ep_dir / "episode.json").write_text(json.dumps(meta, ensure_ascii=False, indent=1))
    return meta


# ---------------------------------------------------------------- episode loop

def run_episode(scenario: Scenario, index: int) -> Dict[str, Any]:
    ep = f"{scenario.id}-{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())}-{index:03d}"
    reset(ep)
    dirty = verify_clean(scenario)
    if dirty:
        print(f"  !! residue after reset: {dirty} — recording anyway, flagged in episode.json")
    print(f"=== arm {scenario.id} ({'; '.join(scenario.attack)[:100]}) ===")
    armed = time.time()
    # Only force escalation from here on: before this point the only changes are reset/warmup noise.
    flag = os.environ.get("ICE_FORCE_ESCALATE_FLAG")
    if flag:
        Path(flag).parent.mkdir(parents=True, exist_ok=True)
        Path(flag).touch()
        print(f"  [arm] force-escalate flag on ({flag})")
    for c in scenario.attack:
        sh(c, "attack")
    from ice.exercise import image
    # Two images bracket the agent: the machine with the attack on it but before the agent has
    # acted, and the machine it left behind. The first makes the attack's own footprint derivable,
    # so a change belonging to the attack is never charged to the agent.
    images = {"baseline": IMAGE_BASELINE, "armed": f"{ep}-armed", "final": f"{ep}-final"}
    image.take(images["armed"])
    print(f"  waiting up to {INVESTIGATE_TIMEOUT:.0f}s for escalation + investigation")
    case = wait_for_case(scenario.markers, armed)
    if flag:
        Path(flag).unlink(missing_ok=True)   # stop forcing; remediation/backward noise need not escalate
    if case:
        print(f"  case {case.get('case_id')} assessment={case.get('_ice', {}).get('assessment')} "
              f"attck={case.get('attck')}")
        print(f"  settling {SETTLE_SECONDS:.0f}s for remediation + backward")
        time.sleep(SETTLE_SECONDS)
    else:
        print("  NO case within timeout")
    image.take(images["final"])
    meta = export(DATASET / ep, scenario, case, armed, images)
    if dirty:
        meta["reset_residue"] = dirty
        (DATASET / ep / "episode.json").write_text(json.dumps(meta, ensure_ascii=False, indent=1))
    print(f">>> {ep}: grade={'MISS' if meta['grade'].get('miss') else 'OK'} "
          f"counts={meta['counts']}")
    for c in scenario.cleanup:
        sh(c, "cleanup")
    return meta


def main() -> None:
    ap = argparse.ArgumentParser(description="ICE trajectory dataset recorder")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("snapshot", help="rebuild the post_state tarball from the baseline image")
    r = sub.add_parser("run", help="record episodes")
    r.add_argument("scenario", choices=sorted(SCENARIOS))
    r.add_argument("--episodes", type=int, default=1)
    a = ap.parse_args()
    if a.cmd == "snapshot":
        snapshot()
        return
    if os.environ.get("ICE_RECORD_MODE") != "1":
        raise SystemExit("set the recording posture first: source ice/serving/record_env.sh")
    DATASET.mkdir(parents=True, exist_ok=True)
    scenario = SCENARIOS[a.scenario]
    results = []
    for i in range(1, a.episodes + 1):
        print(f"\n########## episode {i}/{a.episodes} ##########")
        results.append(run_episode(scenario, i))
    ok = sum(1 for m in results if not m["grade"].get("miss"))
    print(f"\n>>> {len(results)} episodes recorded into {DATASET} — {ok} detected, {len(results) - ok} missed")


if __name__ == "__main__":
    main()
