"""Trajectory dataset recorder: one episode = clean machine -> armed attack -> ICE investigates.

Each episode runs in a VM of its own, because the agent's later steps must build on the real
consequences of its earlier ones -- actions execute for real -- and because what it breaks then has
to be its own machine rather than the recorder's.

  1. boot    a fresh overlay over the golden image, which already carries ICE installed and
             enabled. T0 is that image: shared by every episode, prepared by nobody.
  2. arm     run the arm's commands for real, as root, then snapshot the running machine as T1.
  3. observe the recorder hands the daemon the case, which investigates and remediates.
  4. close   snapshot what the agent left as T2, and collect the audit, the case, the trajectory and
             the osquery snapshots -- over ssh if the machine still answers, off the final disk if
             it does not.
  5. score   seven axes, one judge run each, over the three snapshots (ice.exercise.reward).

Recording posture (ice/serving/record_env_vm.sh):
  ICE_NO_PERCEPTION=1      no perception loop and no detection. The recorder takes its own osquery
                           readings at T0, T1 and T2 and hands the daemon the case complete, so the
                           machine never has a snapshot written into it for the recording's file
                           diff to pick up. The decision model is not consulted either.
  ICE_AUTO_APPROVE=1       no human in the loop
  ICE_DRY_RUN=0            actions really run; that is the point
  ICE_DENY_CRITICAL_ASSETS=0
                           no safety gate. A deployment has one; a recording of what the agent would
                           do must not, or the trajectory is of something else -- one episode chose
                           `rm -f /root/.ssh/authorized_keys`, was refused, and its machine showed
                           what the gate allowed. What the agent breaks is its own VM, and
                           collection no longer needs that VM to answer.

What is deliberately kept from the product: the daemon's own perception loop, every 30 seconds, as
deployed. A recording of ICE with its perception changed would not be a recording of ICE.

  record.py snapshot                        capture the pristine baseline (once, on a clean box)
  record.py run persistence --episodes 3    record N episodes into $ICE_DATASET_DIR
"""
from __future__ import annotations

import argparse
import io
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


# Two deliberate interferences, for testing the scoring rather than the agent. Both are off unless
# set, both are recorded in the bundle, and neither is visible to the judge -- it sees the commands
# that really ran, which is the truth either way.
#
#   ICE_STOP_AFTER_EXEC=1   stop the daemon the moment the audit shows this many executed commands,
#                           so the remediation is cut in half and the threat is only partly cleared.
#   ICE_PROBE_EXEC=cmd;cmd  after the agent is done, run these through the same host_exec path the
#                           agent uses, so they are gated, executed and written to the audit exactly
#                           as the agent's own are. Damage nobody has to attribute.
#
# Every episode so far has come back with seven answers of `none`, which cannot show whether the
# axes discriminate: a judge that always says `none` would look the same. These are how the damage
# scale and the partly-cleared rungs get exercised at all.
STOP_AFTER_EXEC = int(os.environ.get("ICE_STOP_AFTER_EXEC", "0"))
PROBE_EXEC = [c.strip() for c in os.environ.get("ICE_PROBE_EXEC", "").split(";") if c.strip()]


def executed_in_vm() -> int:
    """How many commands the daemon inside the VM has executed, read from its own audit."""
    out = vsh(f"grep -c '\"event\": \"host_exec.executed\"' {STATE}/audit.jsonl 2>/dev/null "
              f"|| echo 0", timeout=30)
    try:
        return int((out.stdout or "0").strip().splitlines()[-1])
    except (ValueError, IndexError):
        return 0


def stop_when_half_done(n: int, limit: float) -> int:
    """Wait until the agent has run n commands, then stop the daemon where it stands.

    This is the cheapest way to produce an episode that is genuinely half-remediated: no injection,
    no forging, and the audit is exactly true -- the agent really did run only those commands. What
    is being tested is whether the clearing axes notice what is still there.
    """
    deadline = time.time() + limit
    while time.time() < deadline:
        got = executed_in_vm()
        if got >= n:
            print(f"  [probe] {got} command(s) executed — stopping the daemon mid-remediation")
            stop_daemon()
            return got
        time.sleep(2)
    print(f"  [probe] gave up waiting for {n} command(s) after {limit:.0f}s "
          f"(only {executed_in_vm()} ran)")
    return executed_in_vm()


def probe_exec(commands: List[str]) -> List[Dict[str, Any]]:
    """Run commands through the daemon's own host_exec, inside the VM, with the daemon stopped.

    The audit's hash chain is read from the file when the writer is constructed, so a one-shot
    process appends to it validly. Going through host_exec rather than ssh is the point: the gate
    reviews it, the executor runs it, and `host_exec.executed` records it the same way it records
    the agent's own actions. To the judge it is an executed command, which is what it is.
    """
    out: List[Dict[str, Any]] = []
    for command in commands:
        # The daemon's own interpreter, not the system one: host_exec comes in through
        # ice.daemon.mcp_server, which imports the MCP server package, and that lives in the
        # daemon's virtualenv. With plain python3 every probe died on ModuleNotFoundError.
        # The daemon's own environment, from the EnvironmentFile its unit reads. Without it the
        # one-shot process has no ICE_RECORD_MODE, so the gate keeps its score provider and Kev
        # vetoed both probes with "Action lacks a legitimate basis" -- a veto the recording posture
        # exists to remove, and which the agent's own calls do not face.
        script = (
            "set -a; [ -f /root/.ice-env ] && . /root/.ice-env; "
            "cd /root/ICE && . ice/serving/env.vm.sh >/dev/null 2>&1; "
            "[ -f /root/ice-posture.env ] && . /root/ice-posture.env; set +a; "
            "\"${ICE_DAEMON_PY:-python3}\" - <<'EOF'\n"
            "import json\n"
            "from ice.daemon.mcp_server import IceTools\n"
            "from ice.daemon.runtime import get_runtime\n"
            "from ice.daemon.orchestrator import Orchestrator\n"
            "from ice.daemon.runtime import _AUTO_APPROVER\n"
            "rt = get_runtime()\n"
            f"res = IceTools(rt).host_exec({command!r}, 'probe: scoring test')\n"
            "out = res.to_dict()\n"
            # The gate puts a critical-asset command on the ASK path even with the score provider
            # off, and under ICE_AUTO_APPROVE the daemon's sweeper is what approves it and runs it.
            # The daemon is stopped while the probe runs -- deliberately, so the audit has one
            # writer -- so the probe finishes the same two steps the agent's own actions take.
            "if out.get('pending') and out.get('request_id'):\n"
            "    Orchestrator(rt).on_approval(out['request_id'], True, _AUTO_APPROVER)\n"
            "    p = rt.pending.get(out['request_id'])\n"
            "    out['after_approval'] = {'status': getattr(p, 'status', None),\n"
            "                             'result': getattr(p, 'result', None)}\n"
            "print(json.dumps(out, default=str))\n"
            "EOF\n")
        p_ = vsh(script, label=f"probe-exec {command}", timeout=120)
        # Whether the command ran, which is not the same as whether the probe script exited 0. Both
        # are kept: the first three attempts all exited 0 while changing nothing -- once on an
        # import error, once refused by the gate, once left pending with nobody to approve it.
        ran, detail = False, ""
        try:
            res = json.loads((p_.stdout or "")[(p_.stdout or "").find("{"):])
        except (ValueError, json.JSONDecodeError):
            detail = "the probe printed no result object"
        else:
            after = res.get("after_approval") or {}
            ran = (after.get("status") == "executed"
                   or (res.get("content") or {}).get("decision") == "AUTO")
            detail = (res.get("error") or after.get("status")
                      or (res.get("content") or {}).get("decision") or "")
        out.append({"command": command, "executed": ran, "outcome": str(detail)[:200],
                    "script_returncode": p_.returncode,
                    "stdout": (p_.stdout or "")[-400:], "stderr": (p_.stderr or "")[-200:]})
        print(f"  [probe] {command} -> {'EXECUTED' if ran else 'did not run'}: {detail}"[:200])
    return out


def prepare_image() -> None:
    """Install everything the episodes need into the golden image, once.

    T0 is the image, so whatever an episode would have had to install must already be in it: the
    daemon's unit, enabled so the product starts with the machine, the posture it reads, its state
    directory, and the code under test. Preparing inside an episode is what once charged the attack
    with the recorder's own setup, and even in the right order it gave every episode a baseline of
    its own, so no two bundles were measured against the same thing.

        python -m ice.exercise.record prepare      (after any change to ICE itself)
    """
    from ice.exercise import vm
    refuse_host_daemon()
    live = "prepare"
    if vm.overlay_path(live).exists():
        vm.drop(live)
    vm.create_overlay(live)
    vm.boot(live)
    try:
        pushed = push_posture()
        install_daemon_unit()
        sync_repo()
        ensure_mcp_token()
        vsh(f"mkdir -p {json.dumps(str(STATE))} && systemctl enable ice-daemon.service",
            label="enable the daemon at boot", check=True)
        # The link, not `is-enabled`: a unit with no [Install] section reports `static` rather than
        # failing, so enable looked like it had worked while nothing would start at boot.
        vsh("test -L /etc/systemd/system/multi-user.target.wants/ice-daemon.service",
            label="verify it will start at boot", check=True)
        print(f"  posture: {len(pushed)} var(s)")
    finally:
        vm.shutdown(live)
    # The prepared disk becomes the golden image, and the old one is kept beside it.
    base = vm.overlay_path(vm.BASE_LABEL)
    keep = base.with_name(base.name + f".before-{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())}")
    prepared = vm.overlay_path(live)
    print(f"  flattening {prepared.name} onto {base.name} (old image kept as {keep.name})")
    subprocess.run(["qemu-img", "convert", "-O", "qcow2", str(prepared), str(base) + ".new"],
                   check=True)
    base.rename(keep)
    Path(str(base) + ".new").rename(base)
    vm.drop(live)
    # One rollback copy, not one per prepare. Each is a flattened 4 GiB image and six of them filled
    # the box's disk, so the next convert died at "No space left on device" with the golden image
    # already renamed out of the way.
    older = sorted(base.parent.glob(base.name + ".before-*"))[:-1]
    for f in older:
        size = f.stat().st_size // (1024 * 1024)
        f.unlink()
        print(f"  dropped the older rollback image {f.name} ({size} MiB)")
    print(f"  the golden image is now T0: ICE installed, enabled, and the code under test in it")


def runtime_reading(ep_dir: Path, label: str) -> Optional[Dict[str, Any]]:
    """One osquery reading of the VM, taken by the recorder and kept on the host.

    The daemon used to do this every 30 seconds and keep the results inside the machine, which put a
    file into /root/ice-state/snapshots every cycle -- so a recording's own file diff carried thirty
    changes nobody made, and the judge had to be told to attribute them. The recorder knows which
    three moments matter, so it takes three readings and they live out here.
    """
    script = ("set -a; [ -f /root/.ice-env ] && . /root/.ice-env; "
              "cd /root/ICE && . ice/serving/env.vm.sh >/dev/null 2>&1; set +a; "
              "\"${ICE_DAEMON_PY:-python3}\" - <<'EOF'\n"
              "import json\n"
              "from ice.daemon.perception.snapshot import collect\n"
              "print(json.dumps(collect().to_dict()))\n"
              "EOF\n")
    p_ = vsh(script, label=f"reading {label}", timeout=180)
    try:
        got = json.loads(p_.stdout[p_.stdout.index("{"):])
    except (ValueError, json.JSONDecodeError) as e:
        print(f"  !! reading {label} failed: {e}; {(p_.stderr or '')[-200:]}")
        return None
    out = ep_dir / f"runtime-{label}.json"
    ep_dir.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(got, ensure_ascii=False))
    tables = sum(len(v) for v in (got.get("data") or {}).values())
    print(f"  [reading {label}] {tables} table(s), {out.stat().st_size // 1024} KiB on the host")
    return got


def hand_over_case(t0: Optional[Dict[str, Any]], t1: Dict[str, Any]) -> int:
    """Diff the two readings here, and hand the daemon the case complete.

    Detection is not what a recording measures -- the forced-escalation flag has always short
    circuited it -- so having the daemon rediscover an attack the recorder just armed buys nothing
    and costs a snapshot inside the machine every cycle.
    """
    from ice.daemon.perception.diff import diff as perception_diff
    from ice.daemon.perception.snapshot import Snapshot
    from ice.daemon.perception.store import Baseline

    prev = Snapshot.from_dict(t0) if t0 else None
    cur = Snapshot.from_dict(t1)
    entries = perception_diff(prev, cur, Baseline(), learning=False)
    # The baseline goes over with it. Without it the daemon has no T0 at all -- the perception loop
    # that used to leave one in the store does not run during a recording -- so the state diff in the
    # agent's prompt renders every row of every table as `+`, including root's own SSH key and the
    # 34 stock accounts. An agent reading that deletes root's key, correctly, from a false premise.
    payload = {"snapshot": t1, "baseline": t0, "entries": [e.to_dict() for e in entries]}
    body = json.dumps(payload, ensure_ascii=False)
    tmp = f"{STATE}/INVESTIGATE_NOW.tmp"
    vsh(f"mkdir -p {json.dumps(str(STATE))} && cat > {tmp} <<'ICEHANDOVER'\n{body}\nICEHANDOVER\n"
        f"mv {tmp} {STATE}/INVESTIGATE_NOW",
        label=f"hand over {len(entries)} change(s)", check=True, timeout=120)
    print(f"  [hand-over] {len(entries)} change(s) from the recorder's own two readings")
    return len(entries)


def ensure_mcp_token() -> None:
    """Make sure the daemon and the agent inside the image hold the same MCP bearer token.

    The daemon reads `deploy/local-secrets/mcp.token`; the agent sends a literal `Authorization`
    header out of its own config in the image. Nothing kept the two in step, and the file is
    gitignored, so it only existed on whichever machine happened to have run the deploy script --
    an image prepared anywhere else came up without it and the daemon exited 1 before taking its
    first breath.

    So: take the value from whatever the agent is already configured to send; only if there is no
    config at all, mint one and write it to both. The value is read and written inside the VM and
    never passes through the host.
    """
    script = (
        "set -e\n"
        "python3 - <<'ICETOKEN'\n"
        "import json, os, secrets\n"
        "tok_path = '/root/ICE/deploy/local-secrets/mcp.token'\n"
        "cfg_path = os.path.expanduser('~/.openclaw/openclaw.json')\n"
        "cfg = json.load(open(cfg_path)) if os.path.exists(cfg_path) else {}\n"
        "srv = (((cfg.get('mcp') or {}).get('servers') or {}).get('ice-host') or {})\n"
        "hdr = (srv.get('headers') or {}).get('Authorization') or ''\n"
        "tok = hdr.split(None, 1)[1].strip() if hdr.lower().startswith('bearer ') else hdr.strip()\n"
        "src = 'the agent config'\n"
        "if not tok:\n"
        "    tok, src = secrets.token_urlsafe(32), 'a fresh one'\n"
        "    srv.setdefault('headers', {})['Authorization'] = 'Bearer ' + tok\n"
        "    cfg.setdefault('mcp', {}).setdefault('servers', {})['ice-host'] = srv\n"
        "    if os.path.exists(cfg_path):\n"
        "        json.dump(cfg, open(cfg_path, 'w'), indent=1)\n"
        "os.makedirs(os.path.dirname(tok_path), mode=0o700, exist_ok=True)\n"
        "old = open(tok_path).read().strip() if os.path.exists(tok_path) else ''\n"
        "if old != tok:\n"
        "    os.umask(0o077)\n"
        "    open(tok_path, 'w').write(tok + chr(10))\n"
        "    os.chmod(tok_path, 0o600)\n"
        "print('mcp token: %d bytes from %s, %s' % (len(tok), src,\n"
        "      'written' if old != tok else 'already matched'))\n"
        "ICETOKEN\n")
    p_ = vsh(script, label="mcp token", check=True, timeout=60)
    print(f"  [mcp token] {(p_.stdout or '').strip().splitlines()[-1] if p_.stdout else 'ok'}")


def _mcp_port() -> int:
    return int(os.environ.get("ICE_MCP_PORT", "8083"))


# Variables that configure the recorder itself and mean nothing to the daemon inside the VM. The
# judge's credentials are the important ones: they stay on the host, which is the point of running
# the episode in a VM at all.
_HOST_ONLY = ("ICE_VM_", "ICE_IMAGE_", "ICE_JUDGE_", "ICE_INTAKE_", "ICE_DATASET_DIR",
              "ICE_RIG_DIR", "ICE_RECORD_TIMEOUT", "ICE_RECORD_SETTLE", "ICE_RECORD_WARMUP",
              "ICE_KEEP_LIVE", "ICE_EVIDENCE_")


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

[Install]
WantedBy=multi-user.target
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
    # The episode's own port, not the module default. Every VM now gets a free one, and this still
    # named 2222: with a leftover VM listening there the code went into the wrong machine and rsync
    # reported success, so the episode ran the golden image's ICE rather than the code under test --
    # which is the one thing this function exists to prevent. The same fixed port made a second VM a
    # silent impostor once before.
    port = vm.ssh_port(vm.live_label() if hasattr(vm, "live_label") else "")
    rsync = ["rsync", "-a", "--delete",
             # local-secrets is gitignored and machine-local: the daemon's MCP bearer token lives
             # there and the agent's config in the image carries the same value. A --delete sync
             # from a host that does not have it takes it out of the image, and then the daemon
             # exits 1 at boot on FileNotFoundError and the episode dies at "the daemon did not
             # come up with the machine".
             "--exclude", "deploy/local-secrets",
             "--exclude", "__pycache__", "--exclude", ".git", "--exclude", "*.pyc",
             "-e", f"ssh -i {vm.KEY} -p {port} " + " ".join(vm._SSH_OPTS),
             str(REPO) + "/", "root@127.0.0.1:/root/ICE/"]
    _p = subprocess.run(rsync, capture_output=True, text=True)
    if _p.returncode != 0:
        raise RuntimeError(f"sync_repo failed on port {port}: {_p.stderr.strip()[:200]}")
    # Proof, not a return code: read back a file the host just changed. rsync to the wrong machine
    # succeeds, and so does rsync of nothing.
    want = (REPO / "ice" / "daemon" / "investigate" / "prompts.py").stat().st_size
    got = vsh("stat -c %s /root/ICE/ice/daemon/investigate/prompts.py", timeout=30).stdout.strip()
    if got != str(want):
        raise RuntimeError(f"sync_repo went somewhere else: prompts.py is {got} bytes in the VM, "
                           f"{want} on the host (port {port})")
    print(f"  [sync-repo] ok on port {port}, verified {want} bytes")


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
    # Nothing is installed, pushed or synced here: the image carries it all and T0 is the image, so
    # anything done now would be a change against the baseline that the attack gets charged with.
    # There is no warmup either -- it existed to let the perception loop build its own reference,
    # and the recorder takes its own readings instead.
    if vsh("systemctl is-active ice-daemon.service", timeout=60).stdout.strip() != "active":
        raise RuntimeError("the daemon did not come up with the machine; re-run "
                           "`record.py prepare` to put it in the image")
    print("  the daemon came up with the machine")
    return {"baseline": vm.BASE_LABEL, "live": live}


# Which arm of the scenario to arm. `attack` is the original, `variant` reaches the same goal by
# another technique, and `normal` is a real package install -- benign, with a package trail and a
# systemd unit of its own. The arms were defined from the start and never wired up, so every episode
# so far has been the same three commands.
#
# `normal` is the test the reward most needs: there is no attack, so the right answer is that there
# is nothing to clear and nothing was broken. It asks whether the judge invents findings when there
# is nothing there, and whether an agent that "remediates" a legitimate package is charged for it.
ARM = os.environ.get("ICE_SCENARIO_ARM", "attack")


def arm_of(scenario: Scenario) -> Dict[str, Any]:
    """The commands, the markers that find the case, and whether this arm is an attack at all."""
    if ARM == "variant":
        return {"arm": "variant", "commands": scenario.variant, "benign": False,
                "markers": scenario.variant_markers or scenario.markers,
                "facts": scenario.variant_facts}
    if ARM == "normal":
        # No markers: there is no artifact to find a case by, and any investigated case is the
        # thing being measured rather than the thing being looked for.
        return {"arm": "normal", "commands": scenario.normal, "benign": True,
                "markers": [], "facts": scenario.normal_facts}
    return {"arm": "attack", "commands": scenario.attack, "benign": False,
            "markers": scenario.markers, "facts": scenario.facts}


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
    try:
        return _read_transcript(local, session_id)
    finally:
        for f in [local, *companions]:
            f.unlink(missing_ok=True)


def _read_transcript(db_path: Path, session_id: str) -> Dict[str, Any]:
    """The transcript and trajectory rows for one session, out of an agent database."""
    db = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
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


def grade(scenario: Scenario, case: Optional[Dict[str, Any]],
          arm: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Deterministic grading (same rules as ice.exercise.drill).

    On the benign arm the right answer is the opposite one: nothing happened, so no case is correct
    and calling it malicious is a false positive. Grading it by the attack's rules would have
    reported a clean machine and a quiet agent as a detection miss.
    """
    benign = bool((arm or {}).get("benign"))
    if case is None:
        if benign:
            return {"detected": False, "miss": False, "benign_arm": True,
                    "reasons": ["nothing was investigated, which is correct: no attack was armed"]}
        return {"detected": False, "miss": True, "reasons": ["no investigated case within timeout"]}
    if benign:
        assessment = case.get("_ice", {}).get("assessment")
        fp = assessment == "malicious"
        return {"detected": True, "benign_arm": True, "case_id": case.get("case_id"),
                "verdict": assessment, "confidence": case.get("confidence"),
                "false_positive": fp, "miss": fp,
                "reasons": ([f"a legitimate change was assessed {assessment}"] if fp else [])}
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


def _osquery_snapshots(ep_dir: Path) -> Dict[str, Any]:
    """The three runtime readings the recorder took, for the judge's GetRuntime.

    These are the recorder's own, taken at T0, T1 and T2 from outside. They used to be harvested
    from the daemon's own perception store, which meant the daemon had to be polling the machine
    every 30 seconds and writing a file inside it each time -- thirty changes in a recording's file
    diff that nobody made, and a case's own t0/t1 pointers that were wrong once besides.
    """
    from ice.exercise import snapshot_reward as sr
    out: Dict[str, Any] = {}
    for label in ("t0", "t1", "t2"):
        f = ep_dir / f"runtime-{label}.json"
        if f.exists():
            out[label] = sr.load(f)
    if not out:
        print("  [runtime] no readings were taken")
    elif len(out) < 3:
        print(f"  [runtime] only {sorted(out)}; the runtime tables will be partial")
    return out


EVIDENCE_DIFF_CAP = int(os.environ.get("ICE_EVIDENCE_DIFF_CAP", "20000"))


def write_evidence(ep_dir: Path, images: Dict[str, str],
                   diffs: Dict[str, Any]) -> Dict[str, Any]:
    """Store the evidence as the judge's tools return it, so the bundle stands on its own.

    Two reasons, and the second is the one that shapes the format. The disks are qcow2 overlays that
    will be pruned, and an episode whose evidence has been deleted cannot be re-scored -- the same
    way early episodes became unscorable once the osquery snapshots their pointers named had aged
    out of a 240-snapshot window. And if this data is ever used to train a judge, its inputs have to
    be the inputs a judge is scored on; the way to make that true by construction is to store the
    exact objects the tools hand over, rather than a summary of them.

    Both diffs are kept, under the names the judge is given. T2 - T0 alone would not be enough to
    re-judge from: it cannot tell an artifact the agent failed to clear from one it never had, and
    it is empty for a file the attack touched and the agent restored exactly.

    Diffs are capped per path. A log that grew by megabytes says nothing more in its ten-thousandth
    line, and the cap is recorded alongside so a reader knows the text was cut rather than short.
    """
    from ice.exercise import image
    t0, t1, t2 = images["baseline"], images["armed"], images["final"]
    bodies: Dict[str, Dict[str, Any]] = {"before": {}, "after": {}}
    for which, (a, b) in (("before", (t0, t1)), ("after", (t0, t2))):
        for row in diffs[which]:
            if row["kind"] == "dir":
                continue
            bodies[which][row["path"]] = image.show(a, b, row["path"],
                                                    max_diff_bytes=EVIDENCE_DIFF_CAP)
    payload = {
        "images": images,
        "snapshots": {"T0": t0, "T1": t1, "T2": t2},
        "diff_cap_bytes": EVIDENCE_DIFF_CAP,
        "change_lists": {"before": diffs["before"], "after": diffs["after"]},
        "GetDiff": bodies,                       # exactly what GetDiff returns, per path per side
    }
    (ep_dir / "evidence.json").write_text(json.dumps(payload, ensure_ascii=False, indent=1))
    size = (ep_dir / "evidence.json").stat().st_size
    print(f"  evidence: {len(bodies['before'])} attack diffs + {len(bodies['after'])} outcome "
          f"diffs, {size / 1024:.0f} KiB (what the judge was shown, readable without the disks)")
    return payload


def _cross_check_arithmetic(ep_dir: Path, images: Dict[str, str], verdict: Dict[str, Any],
                            runtime: Dict[str, Any]) -> Dict[str, Any]:
    """The set arithmetic, read alongside the judge and scoring nothing.

    It is kept for one reason: on /etc/passwd- the judge was right and the arithmetic wrong, and
    what surfaced the error was the two of them disagreeing. A disagreement here is a prompt to read
    that axis's transcript, and it changes no number.
    """
    from ice.exercise import snapshot_reward as sr
    files = sr.file_score(images["baseline"], images["armed"], images["final"])
    rt = None
    if all(runtime.get(k) for k in ("t0", "t1", "t2")):
        rt = sr.runtime_score(runtime["t0"], runtime["t1"], runtime["t2"])
    out = sr.disagreements(files, verdict, rt)
    out["files"] = files
    if rt:
        out["runtime"] = rt
    (ep_dir / "cross-check.json").write_text(json.dumps(out, ensure_ascii=False, indent=1))
    for note in out["disagreements"]:
        print(f"  ?? the arithmetic disagrees with the judge: {note}")
    return out


def _score(ep_dir: Path, case: Optional[Dict[str, Any]], images: Dict[str, str],
           commands: List[Dict[str, Any]], refused: List[Dict[str, Any]],
           arm: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Seven axes, each its own run of the judge, each answered with a severity.

    Files come from the whole-filesystem images: every path on the machine, so an artifact left in
    /tmp is as visible as one in /etc. Runtime state comes from osquery and only where there is no
    file to diff -- an open port, a unit's enabled state. osquery's file tables are not read at all
    any more; they described a ninth of the machine and once reported a clean sweep for an episode
    that left /tmp/atomic_art.log behind, because no table of theirs mentions /tmp.

    The attack's footprint is derived from the armed image, never declared, so nothing the attack
    did is charged to the agent and nothing has to be said in advance about what the machine holds.
    """
    from ice.exercise import image, judge_agent, reward as rw
    base, armed, final = images["baseline"], images["armed"], images["final"]

    diffs = image.named_diffs(base, armed, final)
    (ep_dir / "image-changes.json").write_text(json.dumps(
        {"images": images, "baseline_to_armed": diffs["before"],
         "baseline_to_final": diffs["after"]}, ensure_ascii=False, indent=1))
    write_evidence(ep_dir, images, diffs)

    runtime = _osquery_snapshots(ep_dir)
    if runtime:
        (ep_dir / "runtime-snapshots.json").write_text(json.dumps(
            {k: bool(v) for k, v in runtime.items()}, indent=1))
    print(f"  evidence: {len(diffs['before'])} paths the attack changed, "
          f"{len(diffs['after'])} changed at the end | runtime snapshots: "
          f"{sorted(k for k, v in runtime.items() if v) or 'none'}")

    verdict = judge_agent.judge(base, armed, final, commands, refused, runtime=runtime,
                                verbose=True)
    transcripts = {name: run.pop("transcript", None) for name, run in verdict["runs"].items()}
    (ep_dir / "image-judgement.json").write_text(json.dumps(verdict, ensure_ascii=False, indent=1))
    (ep_dir / "judge-transcript.json").write_text(json.dumps(
        {"model": verdict.get("model"), "usage": verdict.get("usage"),
         "runs": {name: {"severity": verdict["axes"][name].get("severity"),
                         "error": verdict["axes"][name].get("error"),
                         "messages": msgs}
                  for name, msgs in transcripts.items()}},
        ensure_ascii=False, indent=1))

    out = rw.score(verdict, benign=bool((arm or {}).get("benign")))
    for row in out["axes"]:
        a = rw.AXIS[row["axis"]]
        print(f"    {row['axis']:<12} {a['question']:<42} "
              f"{row['severity'] or '!! ' + str(verdict['axes'][row['axis']].get('error'))[:40]}"
              + ("" if row["contribution"] is None else f"  ({row['side']} {row['contribution']})"))
        if row["severity"] and row["severity"] != "none" and row.get("evidence"):
            print(f"                 {str(row['evidence'])[:160]}")
    print(f"  score: cleared={out['cleared']} damage={out['damage']} value={out['value']}"
          + ("" if out["scored"] else f"  [UNSCORED: {out.get('unscored_reason')}]"))

    looked = verdict.get("product_state_reads") or {}
    if looked:
        # Not a failure, and nothing is adjusted for it. But the judge's independence rests on the
        # agent having no way to address it, and this is the one place its own words live, so an
        # episode where the judge went there is one to read before it is used.
        print("  ?? the judge read the product's own state (agent-authored fields were filtered):")
        for axis, reads in looked.items():
            for r in reads:
                print(f"     - {axis}: {r['tool']} {r['path']} "
                      f"(removed {r.get('redacted_fields') or 'nothing'})")

    arithmetic = _cross_check_arithmetic(ep_dir, images, verdict, runtime)
    out.update({"images": images,
                "changed_paths_total": len(diffs["after"]),
                "attack_paths_total": len(diffs["before"]),
                "runtime_snapshots": sorted(k for k, v in runtime.items() if v),
                "product_state_reads": looked,
                "cross_check": arithmetic["disagreements"]})
    return out


def collect(ep_dir: Path, case: Optional[Dict[str, Any]], armed_at: float = 0.0) -> None:
    """Copy what ICE wrote inside the VM into the bundle, while the VM is still up.

    The osquery snapshots in particular cannot wait: the perception store keeps only the last 240,
    two hours at a 30 second cycle, and prunes the rest.

    Which snapshots to take used to come from the case's own t0/t1 pointers, which has two faults.
    An episode with no case got none at all -- which is every benign episode, and the judge's
    runtime axis then had nothing to work with and burned its whole step budget on a tool that
    errored. And the pointers were wrong once already: ICE records t2 before the last approved
    action has finished running. The arming time is something the recorder knows for itself, so the
    snapshots are chosen by it instead: the last one before the attack was armed, the first one
    after, and the newest of all.
    """
    ep_dir.mkdir(parents=True, exist_ok=True)
    pull(f"{STATE}/audit.jsonl", ep_dir / "ice-audit.jsonl")
    listing = vsh(f"ls {STATE}/cases/case-*.json 2>/dev/null", timeout=60)
    for path in _listed_paths(listing.stdout):
        pull(path, ep_dir / Path(path).name)
    # ICE's own perception store is not harvested any more: with no perception loop there is
    # nothing in it, and the runtime readings are the recorder's own (runtime_reading).
    pull("/root/ice-build/daemon.log", ep_dir / "daemon.log")

    # The trajectory has to be fetched here, not in export(). export() runs after the machine has
    # been shut down to be snapshotted, so every ssh it made failed and every episode so far
    # recorded transcript_events: 0 -- the agent's investigation, which is the point of the
    # dataset, was the one thing not being saved.
    if case:                                             # a trajectory needs a case to belong to
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


def collect_from_snapshot(ep_dir: Path, label: str, case: Optional[Dict[str, Any]],
                          armed_at: float = 0.0) -> Dict[str, str]:
    """Fill in whatever ssh could not pull, by reading the episode's final disk on the host.

    Everything the recorder takes out of the VM -- the audit, the cases, the osquery snapshots, the
    daemon log, the agent's own database -- is on that disk, and the disk is mounted read-only here
    with the machine shut down. So none of it actually requires the VM to be reachable.

    That matters because the recorder's dependence on ssh was the last argument for keeping a safety
    gate in a recording. The gate's only remaining veto was a list of paths and services the agent
    was refused -- sshd and osqueryd among them -- and the comment in the daemon said plainly that
    it was what kept the rig alive. It also distorted what was being recorded: in one episode the
    agent chose `rm -f /root/.ssh/authorized_keys`, was refused, and the machine therefore does not
    show what the agent did. With this, an agent that breaks its own sshd costs the episode nothing
    but a slower collection, so the gate can come off and the trajectory is still the agent's own.

    The database is read where it lies rather than copied: the VM is shut down before the snapshot
    is taken, so sqlite has checkpointed its WAL and closed cleanly, which is a better copy than the
    live one this falls back from.
    """
    from ice.exercise import image
    recovered: Dict[str, str] = {}
    try:
        root = image.root(label)
    except Exception as e:                                  # noqa: BLE001 - report, never raise
        print(f"  !! could not mount {label} to recover from: {e}")
        return {"error": f"{type(e).__name__}: {e}"}

    def want(local: Path) -> bool:
        return not local.exists() or local.stat().st_size == 0

    def take(src: Path, local: Path, what: str) -> None:
        if not want(local) or not src.exists():
            return
        try:
            local.write_bytes(src.read_bytes())
        except OSError as e:
            print(f"  !! {what}: {e}")
            return
        recovered[what] = str(src)[len(str(root)):]

    take(root / "root/ice-state/audit.jsonl", ep_dir / "ice-audit.jsonl", "audit")
    take(root / "root/ice-build/daemon.log", ep_dir / "daemon.log", "daemon.log")
    cases = sorted((root / "root/ice-state/cases").glob("case-*.json"))
    for src in cases:
        take(src, ep_dir / src.name, f"case {src.stem}")
    if not list(ep_dir.glob("osq-*.json")):
        snaps = sorted((root / "root/ice-state/snapshots").glob("*.json"))
        stamps = [(float(x.stem), x) for x in snaps if x.stem.replace(".", "", 1).isdigit()]
        pick = ([max((s for s in stamps if s[0] <= armed_at), default=(0, None))[1]]
                + [min((s for s in stamps if s[0] > armed_at), default=(0, None))[1]]
                + [stamps[-1][1] if stamps else None]) if armed_at else [x for _, x in stamps[-3:]]
        for src in dict.fromkeys(x for x in pick if x is not None):
            take(src, ep_dir / ("osq-" + src.name), f"osquery {src.stem}")

    traj = ep_dir / "agent-trajectory.json"
    if case and want_traj(traj):
        db = root / "root/.openclaw/agents/main/agent/openclaw-agent.sqlite"
        sid = _session_from_db(db, str(case.get("case_id")))
        if sid:
            got = _read_transcript(db, sid)
            traj.write_text(json.dumps(got, ensure_ascii=False, indent=1))
            recovered["trajectory"] = f"{len(got.get('transcript_events') or [])} events from {sid}"
        else:
            print(f"  !! no session for {case.get('case_id')} in the snapshot's agent database")
    if recovered:
        print(f"  [recover] read off the final disk without ssh: {sorted(recovered)}")
    return recovered


def want_traj(traj: Path) -> bool:
    """Is the trajectory missing, empty, or an error record from a failed pull?"""
    if not traj.exists() or traj.stat().st_size == 0:
        return True
    try:
        got = json.loads(traj.read_text())
    except (OSError, json.JSONDecodeError):
        return True
    return bool(got.get("error")) or not got.get("transcript_events")


def _session_from_db(db_path: Path, case_id: str) -> Optional[str]:
    """The agent session for one case, resolved out of the database instead of over ssh.

    `session_nodes` keys a session by `agent:main:<case id>`, which is the same association the
    openclaw CLI reports; reading it here removes the last reason collection needed the VM up.
    """
    if not db_path.exists():
        return None
    db = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    try:
        for key, sid in db.execute("SELECT session_key, current_session_id FROM session_nodes"):
            if str(key).endswith(":" + case_id):
                return sid
    except sqlite3.DatabaseError:
        return None
    finally:
        db.close()
    return None


def export(ep_dir: Path, scenario: Scenario, case: Optional[Dict[str, Any]], armed_at: float,
           images: Optional[Dict[str, str]] = None,
           probe: Optional[Dict[str, Any]] = None,
           arm: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
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
    det = grade(scenario, case, arm)
    # No decision-model score. It judged the episode against the scenario's declared ground truth,
    # which is the thing the seven axes were built to stop needing, and it put a second model
    # between the recording and the data for no reward anyone uses.
    kev = {"removed": "the decision model is not consulted while recording"}

    # Both halves of the score, from the whole filesystem for files and from osquery only for state
    # that has no file behind it.
    from ice.exercise import command_trace as ct
    audit_path = ep_dir / "ice-audit.jsonl"
    score: Dict[str, Any] = {"skipped": "no images"}
    if images:
        score = _score(ep_dir, case, images, ct.executed_commands(audit_path),
                       ct.refused_commands(audit_path), arm=arm)

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
                     "arm": (arm or {}).get("arm", "attack"),
                     "benign": bool((arm or {}).get("benign")),
                     "armed_commands": (arm or {}).get("commands") or scenario.attack,
                     "attack": scenario.attack, "facts": scenario.facts},
        "armed_at": armed_at,
        "recorded_at": time.time(),
        "posture": {k: os.environ.get(k) for k in
                    ("ICE_RECORD_MODE", "ICE_NO_PERCEPTION", "ICE_AUTO_APPROVE", "ICE_DRY_RUN",
                     "ICE_DENY_CRITICAL_ASSETS")},
        "grade": det,
        # Any deliberate interference with this episode, so a bundle is never mistaken for one the
        # agent produced on its own. Empty for an ordinary recording.
        "probe": probe or {},
        "audit_counts": audit_counts(ep_dir / "ice-audit.jsonl"),
        "decision_model": kev,
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
    # The baseline is the golden image itself, shared by every episode, so T1 - T0 and T2 - T0 are
    # measured against the same thing in every bundle.
    images.update({"baseline": vm.BASE_LABEL, "armed": f"{ep}-armed", "final": f"{ep}-final"})
    live = images["live"]
    try:
        arm = arm_of(scenario)
        if not arm["commands"]:
            raise SystemExit(f"scenario {scenario.id!r} has no {arm['arm']!r} arm defined")
        dirty = verify_clean(scenario)
        if dirty:
            print(f"  !! the golden image carries scenario residue: {dirty} — flagged in the bundle")

        # T0 is the golden image. Nothing is prepared inside the episode and nothing is snapshotted
        # for it: the image already carries ICE installed and enabled, so what boots is a healthy
        # machine with the product running on it, which is what a deployment looks like. Preparing
        # inside the episode is what once charged the attack with the recorder's own setup -- the
        # systemd unit and every file a repo sync had touched -- and even done in the right order it
        # left every episode with a baseline of its own, so no two were measured against the same
        # thing.
        ep_dir = DATASET / ep
        t0_reading = runtime_reading(ep_dir, "t0")

        print(f"=== arm {scenario.id}/{arm['arm']} "
              f"({'; '.join(arm['commands'])[:100]}) ===")
        armed = time.time()
        for c in arm["commands"]:
            vsh(c, arm["arm"])

        # T1 is taken from the running machine. Shutting down for it cost more than the 17 seconds:
        # the reboot between the attack and the investigation destroyed the attack's runtime state,
        # so a process it started or a socket it held was gone before the agent ever looked, and
        # `execution` -- is the attack still running -- could only ever be answered `none`, not
        # because the agent had cleaned anything but because the reboot had.
        print("  snapshotting the armed machine without stopping it")
        vm.snapshot_live(images["armed"], of=live)
        t1_reading = runtime_reading(ep_dir, "t1")
        # And the case is handed over complete rather than discovered: the recorder armed it and
        # knows when, and the daemon's own polling would write a snapshot into the machine every
        # cycle for a diff the recorder can take from outside.
        if t1_reading:
            hand_over_case(t0_reading, t1_reading)

        print(f"  waiting up to {INVESTIGATE_TIMEOUT:.0f}s for escalation + investigation")
        case = wait_for_case(arm["markers"], armed, live)
        probe: Dict[str, Any] = {}
        if case:
            print(f"  case {case.get('case_id')} "
                  f"assessment={case.get('_ice', {}).get('assessment')} attck={case.get('attck')}")
            if STOP_AFTER_EXEC:
                probe["stop_after_exec"] = STOP_AFTER_EXEC
                probe["executed_before_stop"] = stop_when_half_done(STOP_AFTER_EXEC,
                                                                    SETTLE_SECONDS)
            else:
                print(f"  settling {SETTLE_SECONDS:.0f}s for remediation + backward")
                time.sleep(SETTLE_SECONDS)
        else:
            print("  NO case within timeout")
        if PROBE_EXEC:
            # After the agent is done and its daemon is stopped, so the one-shot writer owns the
            # audit while it appends.
            stop_daemon()
            probe["exec"] = probe_exec(PROBE_EXEC)

        t2_reading = runtime_reading(ep_dir, "t2")
        collect(ep_dir, case, armed_at=armed)
        collect_host_side(ep_dir, live)
        stop_daemon()
        vm.shutdown(live)
        vm.snapshot(images["final"], of=live)
        probe["recovered_without_ssh"] = collect_from_snapshot(ep_dir, images["final"], case, armed)
        meta = export(ep_dir, scenario, case, armed, images, probe=probe, arm=arm)
        if dirty:
            meta["golden_image_residue"] = dirty
            (ep_dir / "episode.json").write_text(json.dumps(meta, ensure_ascii=False, indent=1))
        print(f">>> {ep}: grade={'MISS' if meta['grade'].get('miss') else 'OK'} "
              f"counts={meta['counts']}")
        upload_bundle(ep_dir)
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
        upload_bundle(ep_dir)
        return {"episode_dir": ep, "aborted": "target lost",
                "grade": {"miss": None}, "counts": {}}
    finally:
        image.release()
        vm.shutdown(live)
        if os.environ.get("ICE_KEEP_LIVE_OVERLAY") != "1":
            vm.drop(live)       # the snapshots are the evidence; the working disk is not
        prune_disks()


def upload_bundle(ep_dir: Path) -> None:
    """Push the finished bundle to the intake service, so it does not only exist on a rented disk.

    Failure here is reported and ignored: a bundle that is on this box and not yet uploaded is still
    a bundle, and losing an episode to a network hiccup at the very end would be worse than the
    thing this guards against. The token is host-only (see _HOST_ONLY) and never reaches the VM --
    the machine inside it is the one under attack.
    """
    url = os.environ.get("ICE_INTAKE_URL")
    if not url:
        return
    import tarfile
    import urllib.error
    import urllib.request
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for f in sorted(ep_dir.iterdir()):
            if f.is_file():
                tf.add(f, arcname=f.name)
    body = buf.getvalue()
    req = urllib.request.Request(
        f"{url.rstrip('/')}/upload?episode={ep_dir.name}", data=body, method="POST",
        headers={"Content-Type": "application/gzip",
                 "X-Ice-Token": os.environ.get("ICE_INTAKE_TOKEN", "")})
    try:
        with urllib.request.urlopen(req, timeout=120) as r:
            got = json.loads(r.read() or b"{}")
        print(f"  [upload] {len(got.get('written') or [])} files, {len(body) / 1024:.0f} KiB "
              f"-> {url}")
    except urllib.error.HTTPError as e:
        print(f"  !! upload refused: HTTP {e.code} {e.read()[:200].decode(errors='replace')}")
    except Exception as e:                        # noqa: BLE001 - never lose an episode over this
        print(f"  !! upload failed ({type(e).__name__}: {e}); the bundle is still at {ep_dir}")


def prune_disks() -> None:
    """Keep the newest few episodes' disks and drop the rest.

    An episode whose disks are gone can no longer be re-judged: evidence.json shows what the judge
    was given and is enough to read a verdict against, but the tools read mounted snapshots, not
    that file. One episode was pruned while carrying a score the rules had since corrected, and the
    correction could not be reproduced. Without that this would be the osquery pruning mistake again:
    evidence deleted out from under bundles that pointed at it.
    """
    from ice.exercise import vm
    keep = int(os.environ.get("ICE_KEEP_EPISODE_DISKS", "20"))
    groups: Dict[str, List[str]] = {}
    for label in vm.overlays():
        if label == vm.BASE_LABEL:
            continue
        groups.setdefault(label.rsplit("-", 1)[0], []).append(label)
    order = sorted(groups, key=lambda g: max(vm.taken_at(l) for l in groups[g]), reverse=True)
    dropped = 0
    held = []
    for stem in order[keep:]:
        if not scored_already(stem):
            held.append(stem)
            continue
        for label in groups[stem]:
            vm.drop(label)
            dropped += 1
    if held:
        print(f"  [prune] kept the disks of {len(held)} unscored episode(s), which are the ones "
              f"that may still need re-judging: {held}")
    if dropped:
        print(f"  [prune] dropped {dropped} disk(s) from {len(order) - keep} older episode(s); "
              f"their evidence.json still shows what the judge was given, but re-judging them "
              f"needs the disks and is no longer possible")


def scored_already(stem: str) -> bool:
    """Does this episode's bundle carry a score? An unscored one is the one still worth its disks.

    The retention rule dropped an episode whose 0.14 had already been shown wrong on the same
    evidence -- the re-judge gave 0.70 -- before the correction could be written back, and the
    judge's tools read mounted disks rather than evidence.json, so it can never be recovered.
    """
    ep = DATASET / stem / "episode.json"
    try:
        return (json.loads(ep.read_text()).get("reward") or {}).get("value") is not None
    except (OSError, json.JSONDecodeError):
        return False


def main() -> None:
    ap = argparse.ArgumentParser(description="ICE trajectory dataset recorder")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("prepare", help="install ICE into the golden image, so T0 is the image")
    r = sub.add_parser("run", help="record episodes")
    r.add_argument("scenario", choices=sorted(SCENARIOS))
    r.add_argument("--episodes", type=int, default=1)
    a = ap.parse_args()
    if os.environ.get("ICE_RECORD_MODE") != "1":
        raise SystemExit("set the recording posture first: source ice/serving/record_env.sh")
    if a.cmd == "prepare":
        prepare_image()
        return
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
