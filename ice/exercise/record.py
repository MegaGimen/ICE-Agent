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
import json
import os
import sqlite3
import shutil
import subprocess
import time
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Optional

from ice.exercise.scenarios import SCENARIOS, Scenario

STATE = Path(os.environ.get("ICE_STATE_DIR", "/root/ice-state"))
DATASET = Path(os.environ.get("ICE_DATASET_DIR", "/root/ice-dataset"))
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

INVESTIGATE_TIMEOUT = float(os.environ.get("ICE_RECORD_TIMEOUT", "900"))
SETTLE_SECONDS = float(os.environ.get("ICE_RECORD_SETTLE", "60"))


def vsh(script: str, label: str = "", check: bool = False,
        timeout: float = 300) -> "subprocess.CompletedProcess":
    """Run a shell snippet on the target machine, i.e. inside this episode's VM."""
    from ice.exercise import vm
    return vm.run_script(script, label=label, check=check, timeout=timeout)


def _mcp_port() -> int:
    return int(os.environ.get("ICE_MCP_PORT", "8083"))


# Variables that configure the recorder itself and mean nothing to the daemon inside the VM. The
# judge's credentials are the important ones: they stay on the host, which is the point of running
# the episode in a VM at all.
_HOST_ONLY = ("ICE_VM_", "ICE_IMAGE_", "ICE_JUDGE_", "ICE_DATASET_DIR", "ICE_RIG_DIR",
              "ICE_RECORD_TIMEOUT", "ICE_RECORD_SETTLE", "ICE_RECORD_WARMUP", "ICE_KEEP_LIVE")


def push_posture() -> List[str]:
    """Write the recording posture into the VM as a systemd EnvironmentFile.

    The daemon used to inherit the recorder's own environment, because they were the same process
    tree on the same machine. Now it is started over ssh, which carries almost nothing, so the
    posture has to be handed over explicitly or the daemon comes up with no model endpoints, no
    auto-approval and no force-escalate flag -- and silently records nothing.
    """
    keep = {k: v for k, v in os.environ.items()
            if (k.startswith("ICE_") or k.startswith("KEV_") or k.startswith("OPENCLAW_"))
            and not any(k.startswith(h) for h in _HOST_ONLY)}
    body = "".join(f"{k}={json.dumps(v)}\n" for k, v in sorted(keep.items()))
    vsh(f"cat > /root/ice-posture.env <<'ICEPOSTURE'\n{body}ICEPOSTURE\n"
        f"chmod 600 /root/ice-posture.env", label=f"posture ({len(keep)} vars)", check=True)
    return sorted(keep)


DAEMON_UNIT = """[Unit]
Description=ICE host daemon (recording)
After=network-online.target

[Service]
Type=simple
WorkingDirectory=/root/ICE
EnvironmentFile=/root/ice-posture.env
ExecStart=%s -m ice.daemon.main --no-slack
Restart=no
StandardOutput=append:/root/ice-build/daemon.log
StandardError=append:/root/ice-build/daemon.log
"""


def install_daemon_unit() -> None:
    """Hand the daemon to systemd inside the VM.

    Starting it over ssh with setsid and redirection hung the recorder for the full 300s ssh
    timeout: a backgrounded child keeps the session's file descriptors, and ssh will not close the
    channel while anything holds them. systemd is what the guest has for running a service, and it
    gives a clean stop and a log that outlives the process.
    """
    vsh(f"mkdir -p /root/ice-build && cat > /etc/systemd/system/ice-daemon.service <<'ICEUNIT'\n"
        f"{DAEMON_UNIT % DAEMON_PY}ICEUNIT\nsystemctl daemon-reload",
        label="daemon unit", check=True)


def start_daemon() -> None:
    """Start ICE inside the target VM and wait for its MCP socket."""
    vsh("systemctl restart ice-daemon", label="start-daemon", check=True, timeout=90)
    for _ in range(60):
        time.sleep(2)
        if vsh(f"ss -ltn | grep -q ':{_mcp_port()} '").returncode == 0:
            print("  [start-daemon] MCP up")
            return
    tail = vsh("tail -25 /root/ice-build/daemon.log").stdout
    raise RuntimeError(f"daemon did not come up inside the VM; log tail:\n{tail}")


def stop_daemon() -> None:
    """Stop ICE inside the VM, so the disk is quiet before it is snapshotted."""
    vsh("systemctl stop ice-daemon 2>/dev/null; pgrep -f openclaw | xargs -r kill; sleep 2",
        label="stop-daemon", timeout=120)


def sync_repo() -> None:
    """Put the host's current ICE code into the VM, so an episode records the code under test.

    The golden image carries a copy from when it was built; without this, every episode would be
    recorded against whatever ICE looked like that day.
    """
    from ice.exercise import vm
    rsync = ["rsync", "-a", "--delete",
             "--exclude", "__pycache__", "--exclude", ".git", "--exclude", "*.pyc",
             "-e", f"ssh -i {vm.KEY} -p {vm.SSH_PORT} " + " ".join(vm._SSH_OPTS),
             str(REPO) + "/", "root@127.0.0.1:/root/ICE/"]
    _p = subprocess.run(rsync, capture_output=True, text=True)
    print(f"  [sync-repo] {'ok' if _p.returncode == 0 else _p.stderr.strip()[:120]}")


def refuse_host_daemon() -> None:
    """Refuse to record while an ICE daemon is running on the host.

    The VM boundary covers the rig's files, not its network. qemu's user-mode networking means the
    guest's packets leave through the *host's* stack, so a daemon on the host sees the VM's model
    calls as the host contacting an unknown address -- and a leftover one did exactly that twice,
    running `iptables -I OUTPUT -d <relay> -j DROP` at 21:01 and again at 21:06, which took out the
    judge on the host and the agent inside the VM at the same time. The agent ran for 200 seconds,
    used no tools and produced no assessment, because it could not reach its model.

    ICE blocking an address from inside the VM is a result worth recording. ICE blocking one from
    the host is the recorder being eaten by its own subject.
    """
    out = subprocess.run(["pgrep", "-af", "ice[.]daemon[.]main"],
                         capture_output=True, text=True).stdout.strip()
    mine = [l for l in out.splitlines() if "ice.exercise" not in l]
    if mine:
        raise SystemExit(
            "an ICE daemon is running on the host:\n  " + "\n  ".join(mine) +
            "\nIt will act on the recording infrastructure -- the episode's machine is the VM, not "
            "this box. Stop it first:\n  pkill -f 'ice[.]daemon[.]main'")


def boot_target(episode: str) -> Dict[str, str]:
    """Give this episode a machine of its own and start ICE on it.

    There is nothing to reset. A fresh qcow2 overlay over the golden image *is* a clean machine, so
    the old sequence -- restore the filesystem, wipe the state directory, delete the agent's
    database, recreate its sandbox -- collapses into creating a file. The failure that sequence kept
    producing is gone with it: a path the baseline tarball did not contain, like /etc/environment,
    stayed deleted across every later episode because no reset could put back what it never held.
    """
    from ice.exercise import vm
    if not vm.BASE.exists():
        raise RuntimeError(f"no golden image at {vm.BASE}; build it with ice-vm/vm_build.sh")
    refuse_host_daemon()
    print(f"=== machine for {episode} ===")
    vm.umount_all()
    for stale in vm.overlays():
        if stale != vm.BASE_LABEL and (stale.startswith(episode) or vm.running(stale)):
            vm.shutdown(stale)
    live = f"{episode}-live"
    vm.drop(live)
    vm.create_overlay(live)
    vm.boot(live)
    print(f"  posture pushed: {len(push_posture())} variables")
    sync_repo()
    install_daemon_unit()   # idempotent; the golden image already carries it, so it costs no diff
    start_daemon()
    warm = float(os.environ.get("ICE_RECORD_WARMUP", "75"))
    print(f"  waiting {warm:.0f}s for the T0 baseline of the clean machine")
    time.sleep(warm)
    return {"baseline": vm.BASE_LABEL, "live": live}


def verify_clean(scenario: Scenario) -> List[str]:
    """Residue check on the target. A fresh overlay cannot carry residue, so this is a tripwire for
    the golden image itself having been contaminated."""
    dirty = []
    for m in scenario.markers:
        if vsh(f"grep -rl -- {json.dumps(m)} /etc/passwd /etc/cron.d /etc/systemd/system "
               f"2>/dev/null").stdout.strip():
            dirty.append(m)
    return dirty


def audit_counts(audit_path: Path) -> Dict[str, int]:
    """How many of each event ICE recorded. The audit is written by the daemon, not by the recorder,
    so it is the one account of the episode that the recorder's own bugs cannot shape."""
    counts: Dict[str, int] = {}
    try:
        lines = audit_path.read_text().splitlines()
    except OSError:
        return counts
    for ln in lines:
        try:
            e = json.loads(ln)
        except json.JSONDecodeError:
            continue
        name = str(e.get("event"))
        counts[name] = counts.get(name, 0) + 1
    return counts


def cross_check(ep_dir: Path, case: Optional[Dict[str, Any]],
                score: Dict[str, Any]) -> List[str]:
    """Does what the recorder collected agree with what ICE says it did?

    Every failure in this rig so far has looked like a result rather than an error. A leftover
    daemon blackholed the model and the episode read as "the agent did nothing". ssh dropped the
    quoting on a directory listing and the episode read as "no case" and was graded a miss, while
    ICE had detected the attack, run three commands and verified them. Neither was caught by
    checking for errors, because there were none to check: the calls succeeded and answered a
    different question.

    The audit is the lever, because the daemon inside the VM writes it and nothing the recorder gets
    wrong can change it. If it says cases were investigated, cases exist; if it says commands ran,
    the machine changed. A disagreement means the recording is wrong, not that ICE failed.
    """
    counts = audit_counts(ep_dir / "ice-audit.jsonl")
    collected = len(list(ep_dir.glob("case-*.json")))
    problems: List[str] = []

    investigated = counts.get("case.investigated", 0)
    if investigated and not collected:
        problems.append(f"the audit records {investigated} investigated case(s) and none were "
                        f"collected: the bundle is missing the trajectory, not ICE the attack")
    if investigated and case is None:
        problems.append(f"the audit records {investigated} investigated case(s) but none matched "
                        f"the scenario's markers, so this is not a detection miss")
    executed = counts.get("host_exec.executed", 0)
    if executed and score.get("changed_paths_total") == 0:
        problems.append(f"the audit records {executed} executed command(s) and the snapshots show "
                        f"no change at all: the images may not be this episode's")
    tools = counts.get("tool", 0)
    traj = ep_dir / "agent-trajectory.json"
    events = 0
    if traj.exists():
        try:
            events = len(json.loads(traj.read_text()).get("transcript_events") or [])
        except (OSError, json.JSONDecodeError):
            events = 0
    if tools and not events:
        problems.append(f"the audit records {tools} agent tool call(s) and no trajectory was "
                        f"collected: the investigation happened and was not saved")
    if not counts:
        problems.append("no audit was collected at all; nothing about this episode is verifiable")
    if problems:
        print("  !! the recording disagrees with the audit:")
        for p_ in problems:
            print(f"     - {p_}")
        print(f"     audit says: {counts}")
    return problems


def _listed_paths(out: str) -> List[str]:
    """Absolute paths from an `ls` inside the VM, and nothing else.

    When the listing silently became a bare `ls` of the home directory, the recorder copied the
    bare names it printed -- scp resolved them against the remote home and succeeded, so a posture
    file ended up in the bundle looking like evidence. A path that is not absolute did not come
    from the listing that was asked for.
    """
    return [w for w in out.split() if w.startswith("/")]


def pull(remote: str, local: Path) -> bool:
    """Copy one file out of the VM."""
    from ice.exercise import vm
    local.parent.mkdir(parents=True, exist_ok=True)
    return vm.get(remote, local)


def pull_json(remote: str) -> Optional[Dict[str, Any]]:
    """Read one JSON file out of the VM without keeping a copy."""
    from ice.exercise import vm
    p = vm.ssh(["cat", remote], check=False, timeout=60)
    if p.returncode != 0:
        return None
    try:
        return json.loads(p.stdout)
    except json.JSONDecodeError:
        return None


# ---------------------------------------------------------------- observe

class TargetLost(RuntimeError):
    """The episode's machine stopped answering. Not a detection failure -- an infrastructure one."""


def wait_for_case(markers: List[str], since: float, live: str) -> Optional[Dict[str, Any]]:
    """Wait for ICE, inside the VM, to produce a case whose triggers mention the attack.

    Every ssh call here used to be best-effort, so when the VM stopped answering mid-investigation
    the loop polled a dead machine for the full 900 seconds and reported "NO case" -- which reads as
    ICE having failed to detect the attack, when nothing had been running to detect it. That is the
    worst kind of failure in a recorder: it looks like a result.
    """
    from ice.exercise import vm
    deadline = time.time() + INVESTIGATE_TIMEOUT
    misses = 0
    while time.time() < deadline:
        listing = vsh(f"ls -t {STATE}/cases/case-*.json 2>/dev/null | head -20", timeout=60)
        if listing.returncode != 0:
            misses += 1
            if not vm.running(live):
                raise TargetLost(f"{live} is no longer running "
                                 f"(console: {vm.VM_DIR}/{live}.console.log)")
            if misses >= 5:
                raise TargetLost(
                    f"{live} stopped answering ssh after {misses} tries: "
                    f"{(listing.stderr or '').strip()[:160]} "
                    f"(console: {vm.VM_DIR}/{live}.console.log)")
            print(f"  [wait] no answer from the target ({misses}/5): "
                  f"{(listing.stderr or '').strip()[:90]}")
            time.sleep(15)
            continue
        misses = 0
        for path in _listed_paths(listing.stdout):
            d = pull_json(path)
            if not d or "assessment" not in (d.get("_ice") or {}):
                continue
            trig = " ".join(t.get("value", "") + " " + t.get("field", "")
                            for t in d.get("triggers", []))
            if any(m in trig for m in markers):
                return d
        time.sleep(15)
    return None


# ---------------------------------------------------------------- export

def _session_id_for(case_id: str) -> Optional[str]:
    p = vsh(f"PATH=/root/node24/bin:$PATH HOME=/root {OPENCLAW} sessions --json --limit all "
            f"2>/dev/null")
    try:
        data = json.loads(p.stdout[p.stdout.find("{"):])
    except (ValueError, json.JSONDecodeError):
        return None
    for sess in data.get("sessions", []):
        if str(sess.get("key", "")).endswith(":" + case_id):
            return sess.get("sessionId")
    return None


def _transcript(session_id: str, ep_dir: Path) -> Dict[str, Any]:
    """Every transcript and trajectory event OpenClaw stored, read out of the VM.

    The database is copied to the host first rather than queried over ssh: it is a few megabytes,
    and sqlite over a pipe is not worth the trouble.
    """
    # sqlite keeps its WAL and shared-memory files beside the database, and copying the database
    # alone can miss commits that are still only in the WAL. Take all three, read, then remove all
    # three -- leaving the -shm and -wal behind put two files in the bundle that look like evidence.
    local = ep_dir / "openclaw-agent.sqlite"
    companions = [local.with_name(local.name + suffix) for suffix in ("-wal", "-shm")]
    if not pull(str(AGENT_DB), local):
        return {"error": f"could not copy {AGENT_DB} out of the VM"}
    for c in companions:
        pull(str(AGENT_DB) + c.name[len(local.name):], c)
    db = sqlite3.connect(f"file:{local}?mode=ro", uri=True)
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
    except sqlite3.DatabaseError as e:
        return {"error": f"agent db unreadable: {e}"}
    finally:
        db.close()
        for f in [local, *companions]:
            f.unlink(missing_ok=True)


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
    """Load the T0/T1/T2 osquery snapshots collect() pulled out of the VM.

    T2 is deliberately not the case's own t2 pointer. Approved actions execute one after another
    over tens of seconds and ICE records t2 before the last of them has run, which once scored
    `rm -f /etc/cron.d/persistevil` as not cleared in an episode whose audit shows it ran with rc=0.
    The newest snapshot taken before the machine was shut down is the honest one.
    """
    from ice.exercise import snapshot_reward as sr
    ice = case.get("_ice") or {}
    files = sorted(ep_dir.glob("osq-*.json"), key=lambda p: p.stem)
    if not files:
        print("  [osquery] no snapshots were pulled out of the VM")
        return {}
    by_stamp = {f.stem.replace("osq-", "").split(".")[0]: f for f in files}
    snaps: Dict[str, Any] = {}
    for label in ("t0", "t1"):
        ts = ice.get(label)
        hit = by_stamp.get(str(ts).split(".")[0]) if ts is not None else None
        if hit is None:
            print(f"  [osquery] {label.upper()}={ts} not among the pulled snapshots")
            continue
        snaps[label] = sr.load(hit)
    newest = max(files, key=lambda p: float(p.stem.replace("osq-", "")))
    snaps["t2"] = sr.load(newest)
    return snaps


EVIDENCE_DIFF_CAP = int(os.environ.get("ICE_EVIDENCE_DIFF_CAP", "20000"))


def write_evidence(ep_dir: Path, images: Dict[str, str],
                   changes: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Store the evidence as the judge's tools return it, so the bundle stands on its own.

    Two reasons, and the second is the one that shapes the format. The disks are qcow2 overlays that
    will be pruned, and an episode whose evidence has been deleted cannot be re-scored -- the same
    way early episodes became unscorable once the osquery snapshots their pointers named had aged
    out of a 240-snapshot window. And if this data is ever used to train a judge, its inputs have to
    be the inputs a judge is scored on; the way to make that true by construction is to store the
    exact objects `list_changes` and `read_diff` hand over, rather than a summary of them.

    Diffs are capped per path. A log that grew by megabytes says nothing more in its ten-thousandth
    line, and the cap is recorded alongside so a reader knows the text was cut rather than short.
    """
    from ice.exercise import image
    base, final = images["baseline"], images["final"]
    diffs: Dict[str, Any] = {}
    for row in changes:
        if row["kind"] == "dir":
            continue
        diffs[row["path"]] = image.show(base, final, row["path"],
                                        max_diff_bytes=EVIDENCE_DIFF_CAP)
    payload = {
        "images": images,
        "diff_cap_bytes": EVIDENCE_DIFF_CAP,
        "list_changes": changes,                 # exactly what the list_changes tool returns
        "read_diff": diffs,                      # exactly what read_diff returns, per path
    }
    (ep_dir / "evidence.json").write_text(json.dumps(payload, ensure_ascii=False, indent=1))
    size = (ep_dir / "evidence.json").stat().st_size
    print(f"  evidence: {len(diffs)} path diffs, {size / 1024:.0f} KiB "
          f"(the bundle can be re-judged without the disks)")
    return payload


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
    write_evidence(ep_dir, images, changes)

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
    # The verdict and the conversation that produced it are stored apart: one is the result, the
    # other is the training pair -- the messages the judge saw and the tool results it was given.
    transcript = verdict.pop("transcript", None)
    (ep_dir / "image-judgement.json").write_text(json.dumps(verdict, ensure_ascii=False, indent=1))
    if transcript is not None:
        (ep_dir / "judge-transcript.json").write_text(json.dumps(
            {"model": verdict.get("model"), "steps": verdict.get("steps"),
             "usage": verdict.get("usage"), "messages": transcript},
            ensure_ascii=False, indent=1))
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


def collect(ep_dir: Path, case: Optional[Dict[str, Any]]) -> None:
    """Copy what ICE wrote inside the VM into the bundle, while the VM is still up.

    The osquery snapshots in particular cannot wait: the perception store keeps only the last 240,
    two hours at a 30 second cycle, and prunes the rest.
    """
    ep_dir.mkdir(parents=True, exist_ok=True)
    pull(f"{STATE}/audit.jsonl", ep_dir / "ice-audit.jsonl")
    listing = vsh(f"ls {STATE}/cases/case-*.json 2>/dev/null", timeout=60)
    for path in _listed_paths(listing.stdout):
        pull(path, ep_dir / Path(path).name)
    ice = (case or {}).get("_ice") or {}
    wanted = [str(ice.get(k)).split(".")[0] for k in ("t0", "t1") if ice.get(k)]
    snaps = vsh(f"ls -t {STATE}/snapshots/*.json 2>/dev/null | head -1; "
                + "; ".join(f"ls {STATE}/snapshots/{w}*.json 2>/dev/null" for w in wanted),
                timeout=60)
    for path in dict.fromkeys(_listed_paths(snaps.stdout)):
        pull(path, ep_dir / ("osq-" + Path(path).name))
    pull("/root/ice-build/daemon.log", ep_dir / "daemon.log")

    # The trajectory has to be fetched here, not in export(). export() runs after the machine has
    # been shut down to be snapshotted, so every ssh it made failed and every episode so far
    # recorded transcript_events: 0 -- the agent's investigation, which is the point of the
    # dataset, was the one thing not being saved.
    if case:
        sid = _session_id_for(str(case.get("case_id")))
        traj = _transcript(sid, ep_dir) if sid else {"error": "no openclaw session for case"}
        (ep_dir / "agent-trajectory.json").write_text(json.dumps(traj, ensure_ascii=False, indent=1))
        n = len(traj.get("transcript_events") or [])
        print(f"  trajectory: {n} transcript events"
              + (f", {len(traj.get('trajectory_runtime_events') or [])} runtime events"
                 if n else f" ({traj.get('error', 'empty')})"))


def collect_host_side(ep_dir: Path, live: str) -> None:
    """Copy what the host holds about the VM. This works even when the VM has stopped answering,
    which is exactly when it matters: the bundle for the episode that lost its target held nothing
    but the diff, because every ssh in collect() failed silently."""
    from ice.exercise import vm
    ep_dir.mkdir(parents=True, exist_ok=True)
    console = vm.VM_DIR / f"{live}.console.log"
    if console.exists():
        shutil.copy2(console, ep_dir / "vm-console.log")


def export(ep_dir: Path, scenario: Scenario, case: Optional[Dict[str, Any]], armed_at: float,
           images: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    # collect() has already copied the audit, the cases and the osquery snapshots out of the VM.
    ep_dir.mkdir(parents=True, exist_ok=True)
    # Already fetched by collect(), while the machine was still up.
    trajectory: Dict[str, Any] = {}
    traj_file = ep_dir / "agent-trajectory.json"
    if traj_file.exists():
        try:
            trajectory = json.loads(traj_file.read_text())
        except json.JSONDecodeError as e:
            trajectory = {"error": f"unreadable trajectory: {e}"}
    det = grade(scenario, case)
    kev = kev_score(scenario, case, trajectory) if case else {"skipped": "no case"}

    # Both halves of the score, from the whole filesystem for files and from osquery only for state
    # that has no file behind it.
    from ice.exercise import command_trace as ct
    audit_path = ep_dir / "ice-audit.jsonl"
    score: Dict[str, Any] = {"skipped": "no images"}
    if images:
        score = _score(ep_dir, case, images, ct.executed_commands(audit_path),
                       ct.refused_commands(audit_path))

    inconsistent = cross_check(ep_dir, case, score)
    if inconsistent:
        # A recording that contradicts its own audit is not a result about ICE. Say so where the
        # grade goes, so nothing downstream reads it as a detection failure.
        det = {"detected": None, "miss": None, "reasons": inconsistent,
               "inconclusive": "the recording disagrees with the audit"}
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
        "audit_counts": audit_counts(ep_dir / "ice-audit.jsonl"),
        "kev_score": kev,
        # One reward, derived from two snapshots of this episode's own machine. The scenario-based
        # one that used to sit here is gone: it graded against declarations, and its deterministic
        # backstop grepped file *contents* for markers, so `persistevil` -- a filename -- never
        # matched and it read clean while the file was on disk. Nothing is lost by its removal;
        # whatever the scenario declares is still in episode.json under "scenario".
        "reward": score,
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
    """One episode: a machine of its own, the attack, ICE's response, then two snapshots of it.

    The attack and the response happen inside the VM. The recorder, the judge and the snapshots stay
    out here, which is why there is no longer a list of files the agent must be stopped from
    touching: it cannot reach them. An episode that cuts its own model access, as one did by
    blackholing the relay with iptables, now only cuts its own VM's -- a result to record rather
    than a rig to repair.
    """
    from ice.exercise import image, vm
    ep = f"{scenario.id}-{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())}-{index:03d}"
    images = boot_target(ep)
    images.update({"baseline": f"{ep}-clean", "armed": f"{ep}-armed",
                   "final": f"{ep}-final"})
    live = images["live"]
    try:
        dirty = verify_clean(scenario)
        if dirty:
            print(f"  !! the golden image carries scenario residue: {dirty} — flagged in the bundle")
        # The baseline has to be the machine as the attack found it, which means after the recorder
        # has finished preparing it. Scoring against the golden image instead charged the attack
        # with the recorder's own setup: the systemd unit, and every file sync_repo() had just
        # updated, showed up as attack footprint and then as "not cleared".
        print("  snapshotting the prepared machine as the baseline")
        stop_daemon()
        vm.shutdown(live)
        vm.snapshot(images["baseline"], of=live)
        vm.boot(live)
        start_daemon()
        time.sleep(float(os.environ.get("ICE_RECORD_WARMUP", "75")))

        print(f"=== arm {scenario.id} ({'; '.join(scenario.attack)[:100]}) ===")
        armed = time.time()
        # Force escalation only from here on. Before this point the only changes are the warmup's.
        flag = os.environ.get("ICE_FORCE_ESCALATE_FLAG")
        if flag:
            vsh(f"mkdir -p {json.dumps(str(Path(flag).parent))} && touch {json.dumps(flag)}",
                label="force-escalate on")
        for c in scenario.attack:
            vsh(c, "attack")

        # The machine has to be still to be photographed: qcow2 cannot freeze a disk that is being
        # written. Stopping ICE and shutting down is what makes the armed image a real before-state
        # rather than a smear, and booting again costs about 17 seconds.
        print("  snapshotting the armed machine")
        stop_daemon()
        vm.shutdown(live)
        vm.snapshot(images["armed"], of=live)
        vm.boot(live)
        start_daemon()

        print(f"  waiting up to {INVESTIGATE_TIMEOUT:.0f}s for escalation + investigation")
        case = wait_for_case(scenario.markers, armed, live)
        if flag:
            vsh(f"rm -f {json.dumps(flag)}")
        if case:
            print(f"  case {case.get('case_id')} "
                  f"assessment={case.get('_ice', {}).get('assessment')} attck={case.get('attck')}")
            print(f"  settling {SETTLE_SECONDS:.0f}s for remediation + backward")
            time.sleep(SETTLE_SECONDS)
        else:
            print("  NO case within timeout")

        ep_dir = DATASET / ep
        collect(ep_dir, case)
        collect_host_side(ep_dir, live)
        stop_daemon()
        vm.shutdown(live)
        vm.snapshot(images["final"], of=live)
        meta = export(ep_dir, scenario, case, armed, images)
        if dirty:
            meta["golden_image_residue"] = dirty
            (ep_dir / "episode.json").write_text(json.dumps(meta, ensure_ascii=False, indent=1))
        print(f">>> {ep}: grade={'MISS' if meta['grade'].get('miss') else 'OK'} "
              f"counts={meta['counts']}")
        return meta
    except TargetLost as e:
        ep_dir = DATASET / ep
        collect_host_side(ep_dir, live)
        print(f"!! target lost: {e}")
        (ep_dir / "episode.json").write_text(json.dumps(
            {"episode_dir": ep, "scenario": scenario.id, "images": images,
             "aborted": "target lost", "detail": str(e),
             "grade": {"detected": False, "miss": None,
                       "reasons": ["the episode's machine stopped answering; nothing was running "
                                   "to detect the attack, so this is not a detection result"]},
             "reward": {"scored": False, "value": None, "unscored_reason": f"target lost: {e}"}},
            ensure_ascii=False, indent=1))
        return {"episode_dir": ep, "aborted": "target lost",
                "grade": {"miss": None}, "counts": {}}
    finally:
        image.release()
        vm.shutdown(live)
        if os.environ.get("ICE_KEEP_LIVE_OVERLAY") != "1":
            vm.drop(live)       # the snapshots are the evidence; the working disk is not
        prune_disks()


def prune_disks() -> None:
    """Keep the newest few episodes' disks and drop the rest.

    Safe only because evidence.json carries the diffs the judge is given, so an episode whose disks
    are gone can still be re-judged. Without that this would be the osquery pruning mistake again:
    evidence deleted out from under bundles that pointed at it.
    """
    from ice.exercise import vm
    keep = int(os.environ.get("ICE_KEEP_EPISODE_DISKS", "5"))
    groups: Dict[str, List[str]] = {}
    for label in vm.overlays():
        if label == vm.BASE_LABEL:
            continue
        groups.setdefault(label.rsplit("-", 1)[0], []).append(label)
    order = sorted(groups, key=lambda g: max(vm.taken_at(l) for l in groups[g]), reverse=True)
    dropped = 0
    for stem in order[keep:]:
        for label in groups[stem]:
            vm.drop(label)
            dropped += 1
    if dropped:
        print(f"  [prune] dropped {dropped} disk(s) from {len(order) - keep} older episode(s); "
              f"their bundles keep evidence.json and stay re-judgeable")


def main() -> None:
    ap = argparse.ArgumentParser(description="ICE trajectory dataset recorder")
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run", help="record episodes")
    r.add_argument("scenario", choices=sorted(SCENARIOS))
    r.add_argument("--episodes", type=int, default=1)
    a = ap.parse_args()
    if os.environ.get("ICE_RECORD_MODE") != "1":
        raise SystemExit("set the recording posture first: source ice/serving/record_env.sh")
    DATASET.mkdir(parents=True, exist_ok=True)
    scenario = SCENARIOS[a.scenario]
    results = []
    for i in range(1, a.episodes + 1):
        print(f"\n########## episode {i}/{a.episodes} ##########")
        results.append(run_episode(scenario, i))
    lost = [m for m in results if m.get("aborted")]
    graded = [m for m in results if not m.get("aborted")]
    ok = sum(1 for m in graded if not m["grade"].get("miss"))
    print(f"\n>>> {len(graded)} episodes recorded into {DATASET} — {ok} detected, "
          f"{len(graded) - ok} missed"
          + (f"; {len(lost)} aborted (target lost, not a detection result)" if lost else ""))


if __name__ == "__main__":
    main()
