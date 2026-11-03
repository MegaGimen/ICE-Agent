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
# Docker bind-mounts /etc/hosts, /etc/hostname and /etc/resolv.conf, and tar cannot replace a bind
# mount ("Cannot open: File exists"). They are skipped automatically by _snapshot_paths().
# Volatile roots: not worth restoring byte-for-byte, but worth *listing*, so a deletion under them
# can be ruled on. /var/mail and /var/spool/mail are here because `userdel -r` deletes a user's mail
# spool, and nothing else records that those paths existed.
SCRATCH = ["tmp", "var/tmp", "var/mail", "var/spool/mail"]
BASELINE_TAR = RIG / "baseline.tar.gz"
SCRATCH_MANIFEST = RIG / "scratch-manifest.txt"
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

def _mount_points() -> set:
    try:
        return {l.split()[1] for l in Path("/proc/mounts").read_text().splitlines() if len(l.split()) > 1}
    except OSError:
        return set()


def _snapshot_paths() -> List[str]:
    """Paths that exist and are not themselves bind mounts (tar cannot replace a bind mount)."""
    mounts = _mount_points()
    out = []
    for p in BASELINE_PATHS:
        if not Path("/", p).exists():
            continue
        if "/" + p in mounts:
            print(f"  [snapshot] skipping bind mount /{p}")
            continue
        out.append(p)
    return out


SCRATCH_DEPTH = 3


def write_scratch_manifest() -> int:
    """List the volatile roots of the clean machine. Reset deletes whatever is not in here, and
    verification reads it as existence evidence for paths no other source records."""
    RIG.mkdir(parents=True, exist_ok=True)
    with SCRATCH_MANIFEST.open("w") as fh:
        for d in SCRATCH:
            cmd = f"find /{d} -mindepth 1 -maxdepth {SCRATCH_DEPTH} 2>/dev/null"
            for line in sh(cmd).stdout.splitlines():
                fh.write(line + "\n")
    n = sum(1 for _ in SCRATCH_MANIFEST.open())
    print(f">>> scratch manifest {SCRATCH_MANIFEST}: {n} entries over {SCRATCH}")
    return n


def snapshot() -> None:
    """Capture the pristine machine. Run once, on a box with no scenario residue."""
    RIG.mkdir(parents=True, exist_ok=True)
    present = _snapshot_paths()
    sh(f"tar -czf {BASELINE_TAR} -C / " + " ".join(present), "snapshot", check=True)
    n = write_scratch_manifest()
    print(f">>> baseline {BASELINE_TAR} ({BASELINE_TAR.stat().st_size} bytes), "
          f"{len(present)} paths, scratch manifest {n} entries")


def _restore_scratch() -> None:
    keep = {l.strip() for l in SCRATCH_MANIFEST.open()} if SCRATCH_MANIFEST.exists() else set()
    # A stale manifest would be read as proof that a path existed on the clean machine, so an entry
    # that is simply gone turns into phantom damage. 20 of this box's 573 entries carry a
    # boot-specific id (systemd-private-<random>), which is exactly what a reboot invalidates.
    stale = [k for k in keep if not Path(k).exists()]
    if stale:
        print(f"  [scratch] {len(stale)} manifest entries no longer exist "
              f"(e.g. {stale[0]}); refresh with `record.py manifest` or they read as damage")
    for d in SCRATCH:
        for line in sh(f"find /{d} -mindepth 1 -maxdepth {SCRATCH_DEPTH} 2>/dev/null").stdout.splitlines():
            if line.strip() and line.strip() not in keep:
                sh(f"rm -rf -- {json.dumps(line.strip())}")


DAEMON_PORTS = (8083, 8088)   # MCP server, dashboard


def stop_daemon() -> None:
    # Never pkill -f on 'ice.daemon.main': this process's own command line contains that string.
    sh("pgrep -f 'ice[.]daemon[.]main' | xargs -r kill", "stop-daemon")
    sh("pgrep -f 'openclaw[ ]agent' | xargs -r kill", "stop-agent")
    # Wait for the sockets to actually be released. A fixed sleep is not enough: the next daemon
    # then dies with "OSError: [Errno 98] Address already in use" and the episode records nothing.
    for _ in range(30):
        busy = [p for p in DAEMON_PORTS
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
        if sh("ss -ltn | grep -q :8083").returncode == 0:
            print("  [start-daemon] MCP up")
            return
    raise RuntimeError("daemon did not come up")


def reset(episode: str) -> None:
    """Put the machine, ICE and the agent back to the pristine baseline."""
    print(f"=== reset for {episode} ===")
    if not BASELINE_TAR.exists():
        raise RuntimeError(f"no baseline at {BASELINE_TAR}; run `record.py snapshot` on a clean box first")
    stop_daemon()
    sh(f"tar -xzf {BASELINE_TAR} -C / --overwrite", "restore", check=True)
    _restore_scratch()
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


def _lens_paths(snapshot: Dict[str, Any]) -> List[str]:
    """What ICE's eyes cover, so damage can be labelled in- or out-of-lens.

    The authoritative part is the collector's own scan roots (`snapshot.lens_globs()`): the declared
    critical files plus the directory globs its queries read. That is a property of the sensor, not a
    description of this host, and unlike enumerating a snapshot's rows it still covers a directory
    the attack was the first to put a file in. The rows of the given snapshot are added on top, since
    osquery resolves some paths (home directories, extra cron roots) that no pattern spells out.
    """
    from ice.daemon.perception.snapshot import lens_globs
    paths: List[str] = list(lens_globs())
    stable = ((snapshot or {}).get("data") or {}).get("stable") or {}
    for table, rows in stable.items():
        if not isinstance(rows, dict):
            continue
        for key in rows:
            p = str(key).split("#", 1)[0]       # cron/sudoers keys are "<path>#<content hash>"
            if p.startswith("/"):
                paths.append(p)
    return sorted(set(paths))


def _snapshot_reward(ep_dir: Path, case: Dict[str, Any], trajectory: Dict[str, Any]) -> Dict[str, Any]:
    """Copy the case's T0/T1/T2 snapshots into the bundle and score them without the scenario."""
    from ice.exercise import evaluate, snapshot_reward as sr
    ice = case.get("_ice") or {}
    snaps: Dict[str, Any] = {}
    for label in ("t0", "t1"):
        ts = ice.get(label)
        if ts is None:
            print(f"  [snapshot] {label.upper()} pointer absent in the case")
            continue
        hits = sorted(glob.glob(str(STATE / "snapshots" / (str(ts).split(".")[0] + "*.json"))))
        if not hits:
            print(f"  [snapshot] {label.upper()}={ts} not on disk (pruned by the 240-snapshot window)")
            continue
        dst = ep_dir / f"snapshot-{label.upper()}.json"
        shutil.copy2(hits[0], dst)
        snaps[label] = sr.load(dst)
    # T2 is deliberately NOT the case's own t2 pointer. Approved actions execute one after another
    # over tens of seconds, and ICE records t2 before the last of them has run -- scoring against it
    # marked `rm -f /etc/cron.d/persistevil` as "not cleared" in an episode where it ran with rc=0.
    # Export happens after the settle window, so the newest snapshot on disk is the honest T2.
    newest = sorted(glob.glob(str(STATE / "snapshots" / "*.json")),
                    key=lambda p: float(Path(p).stem), reverse=True)
    if newest:
        dst = ep_dir / "snapshot-T2.json"
        shutil.copy2(newest[0], dst)
        snaps["t2"] = sr.load(dst)
        print(f"  [snapshot] T2 = newest after settle ({Path(newest[0]).stem}), "
              f"case pointer was {ice.get('t2')}")
    if len(snaps) < 3:
        return {"error": f"need T0/T1/T2, got {sorted(snaps)}"}
    d = sr.diff(snaps["t0"], snaps["t1"], snaps["t2"])
    (ep_dir / "snapshot-diff.json").write_text(json.dumps(d, ensure_ascii=False, indent=1))

    # The commands are facts from the audit, and they have no lens limit: `rm -f /var/log/foo` is
    # recorded even though /var/log is in no snapshot table. A judge turns them into paths to look
    # at, then every path it names is checked on disk. Pointers from the model, facts from the host.
    from ice.exercise import command_trace as ct
    audit = ep_dir / "ice-audit.jsonl"
    commands, refused = ct.executed_commands(audit), ct.refused_commands(audit)
    lens = _lens_paths(snaps["t0"])
    judgement = evaluate.judge_commands(d, commands, refused, trajectory)
    # The scratch manifest is the only record of /tmp and /var/tmp -- they are in neither the
    # tarball nor any osquery table, so without it a deletion there cannot be ruled on either way.
    scratch = ct.Scratch(SCRATCH_MANIFEST, roots=["/" + d for d in SCRATCH], depth=SCRATCH_DEPTH)
    checked = ct.verify_paths(judgement.get("paths_to_check") or [], BASELINE_TAR, lens,
                              t0=snaps["t0"], t1=snaps["t1"], scratch=scratch)
    trace = {"executed": commands, "refused": refused, "judgement": judgement,
             "verified": checked, "snapshot_lens_size": len(lens),
             "scratch_manifest_size": len(scratch.paths)}
    (ep_dir / "command-trace.json").write_text(json.dumps(trace, ensure_ascii=False, indent=1))

    out = sr.reward(d, judgement)
    out["commands_run"] = len(commands)
    out["paths_checked"] = checked["checked"]
    out["provable_damage"] = checked["provable_damage"]
    out["outside_lens_damage"] = checked["outside_lens_damage"]
    out["unverifiable_paths"] = checked["unverifiable"]
    out["attack_artifacts_removed"] = checked["attack_artifacts_removed"]
    out["unexplained"] = judgement.get("unexplained")
    out["judgement"] = judgement
    print(f"  snapshot diff: {d['counts']}")
    print(f"  commands: {len(commands)} run, {len(refused)} refused | judge named "
          f"{len(judgement.get('paths_to_check') or [])} paths -> verified {checked['counts']}")
    if checked["outside_lens_damage"]:
        print(f"  !! damage outside the snapshot lens: {checked['outside_lens_damage']}")
    print(f"  reward(scenario-free): value={out.get('value')} cleared={out.get('threat_cleared')} "
          f"collateral={out.get('collateral_damage')} ({out.get('collateral_count')} artifacts)")
    return out


def export(ep_dir: Path, scenario: Scenario, case: Optional[Dict[str, Any]], armed_at: float) -> Dict[str, Any]:
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

    # Scenario-free reward from ICE's own T0/T1/T2 snapshots. These must be copied out now: the
    # perception store keeps only the last 240 snapshots (2h at a 30s cycle) and prunes the rest,
    # so the case's t0/t1/t2 pointers go dangling long before anyone reads the bundle.
    snap_reward: Dict[str, Any] = {"skipped": "no case"}
    if case:
        snap_reward = _snapshot_reward(ep_dir, case, trajectory)
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
        "reward_scenario_free": snap_reward,  # derived from T1-T0; the one to train on
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
    meta = export(DATASET / ep, scenario, case, armed)
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
    sub.add_parser("snapshot", help="capture the pristine baseline (run on a clean box)")
    sub.add_parser("manifest", help="refresh only the scratch manifest, leaving the tarball alone")
    r = sub.add_parser("run", help="record episodes")
    r.add_argument("scenario", choices=sorted(SCENARIOS))
    r.add_argument("--episodes", type=int, default=1)
    a = ap.parse_args()
    if a.cmd == "snapshot":
        snapshot()
        return
    if a.cmd == "manifest":
        # Separate from `snapshot` on purpose: widening the listed roots must not silently rewrite
        # the tarball, which is what defines the healthy bytes every episode is scored against.
        write_scratch_manifest()
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
