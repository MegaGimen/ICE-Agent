"""The machine an episode runs inside, as a real VM.

The recorder, the judge and the snapshot store stay on the host; only the machine under attack is in
here. That is the whole point of the boundary. Protecting the rig's own components used to be a
policy -- a list of paths and addresses the safety gate refused to let a command name -- and a policy
is only as good as its string matching. Now they are not in the blast radius at all.

It has to be a VM rather than a container because the target has to behave like a real machine: a
full kernel, systemd, working iptables, and docker that can itself run docker. A container cannot
offer that, and osquery looking at a container's /proc is not looking at a host.

Snapshots are qcow2 overlays over one golden image, so taking one is instant and costs only the
blocks that changed. The host reads them through qemu-nbd, read-only, which yields an ordinary
directory tree -- the same shape ice.exercise.image already diffs, so the comparison and the judge's
three tools are unchanged by any of this.

One thing is honestly not outside the boundary: the agent's own model credentials have to be inside,
because openclaw runs in there and has to reach its model. An attacker with root in the scenario
could read them.
"""
from __future__ import annotations

import json
import os
import shlex
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

VM_DIR = Path(os.environ.get("ICE_VM_DIR", "/root/ice-vm"))
BASE = VM_DIR / "base.qcow2"
KEY = VM_DIR / "id_ed25519"
SEED = VM_DIR / "seed.iso"
OVERLAYS = VM_DIR / "overlays"
MOUNTS = VM_DIR / "mnt"

SSH_PORT = int(os.environ.get("ICE_VM_SSH_PORT", "2222"))
_PORT: Dict[str, int] = {}


def _free_port(start: int = SSH_PORT) -> int:
    """A loopback port nothing is listening on.

    qemu does not fail when `hostfwd` cannot bind -- it prints a warning and runs on without the
    forward. With a fixed port that turns a second VM into a silent impostor: ssh on 2222 reaches
    whichever machine got there first, so the posture, the repo sync and the daemon all land on the
    wrong one and the episode looks like it worked.
    """
    import socket as _s
    for port in range(start, start + 64):
        with _s.socket(_s.AF_INET, _s.SOCK_STREAM) as sock:
            sock.setsockopt(_s.SOL_SOCKET, _s.SO_REUSEADDR, 1)
            try:
                sock.bind(("127.0.0.1", port))
            except OSError:
                continue
        if port not in _PORT.values():
            return port
    raise RuntimeError(f"no free loopback port in {start}..{start + 64}")


def ssh_port(label: str = "") -> int:
    """The port this VM's ssh is forwarded to. Set when it boots.

    With no label this used to answer with the *first* VM the process ever booted, because that is
    what `next(iter(...))` means on a dict. In a run of several episodes every VM after the first one
    was therefore probed on the previous episode's port -- a machine that had just been shut down --
    so `wait_for_ssh` timed out on a VM that was up and answering, and only the first episode of a
    batch was ever recorded. Unlabelled now means the newest, and `forget_port` drops a VM that is
    gone so it can never be addressed again.
    """
    if label and label in _PORT:
        return _PORT[label]
    return next(reversed(_PORT.values())) if _PORT else SSH_PORT
MEM_MB = int(os.environ.get("ICE_VM_MEM", "4096"))
CPUS = int(os.environ.get("ICE_VM_CPUS", "4"))
# 240s was not enough on a cold page cache: a 4 GiB image on a box that had just rebooted reached the login prompt and had sshd up, but after the wait had already given up -- and the episode was lost to a machine that was fine.
BOOT_TIMEOUT = float(os.environ.get("ICE_VM_BOOT_TIMEOUT", "480"))

# One multiplexed connection per VM instead of one per call. Waiting for a case opens an ssh every
# few seconds for up to fifteen minutes, and the episode that lost its target failed with
# "Connection timed out during banner exchange" -- which is what sshd says once MaxStartups
# (10:30:100 by default) starts refusing. Sharing a connection removes the churn rather than
# raising the guest's limit to tolerate it.
# A probe has to outlast the connect timeout, or it reports a machine down that was only slow to
# answer: raising ConnectTimeout to 10 while wait_for_ssh still gave the probe 8 seconds made every
# boot fail. Anything that asks "is it up" waits PROBE_TIMEOUT, which is derived rather than typed.
CONNECT_TIMEOUT = int(os.environ.get("ICE_VM_CONNECT_TIMEOUT", "10"))
PROBE_TIMEOUT = CONNECT_TIMEOUT + 10


def _ctl(label: str = "") -> str:
    return str(VM_DIR / f".ssh-{label or 'vm'}.sock")


_SSH_OPTS = ["-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
             "-o", f"ConnectTimeout={CONNECT_TIMEOUT}",
             "-o", "LogLevel=ERROR",
             "-o", "ServerAliveInterval=15", "-o", "ServerAliveCountMax=4",
             "-o", "ControlMaster=auto", "-o", "ControlPersist=120"]


def _ssh_base(label: str = "") -> List[str]:
    return ["-i", str(KEY), "-p", str(ssh_port(label)), *_SSH_OPTS,
            "-o", f"ControlPath={_ctl(label or _current_label())}"]


def _current_label() -> str:
    return next(reversed(_PORT), "vm") if _PORT else "vm"


def forget_port(label: str) -> None:
    """This VM is gone: stop letting "the VM" mean it."""
    _PORT.pop(label, None)


def adopt_port(label: str, port: int) -> None:
    """Take over a VM this process did not boot.

    `_PORT` is filled in by boot(), so a second process -- the T1 half of a hand-armed episode --
    starts with an empty registry and would address whatever is on the module default. The port is
    carried over in the episode's state file and handed back here.
    """
    _PORT[label] = int(port)


def live_label() -> str:
    """The episode's own VM, by name. Anything addressing "the VM" by a module default addresses
    whatever happens to be on port 2222, which has twice been a different machine."""
    for label in reversed(_PORT):
        if label.endswith("-live"):
            return label
    return _current_label()


def close_connection(label: str = "") -> None:
    """Drop the shared connection, so a VM that is being shut down does not leave it dangling."""
    name = label or _current_label()
    subprocess.run(["ssh", *_ssh_base(name), "-O", "exit", "root@127.0.0.1"],
                   capture_output=True)
    Path(_ctl(name)).unlink(missing_ok=True)


def _run(cmd: List[str], label: str = "", check: bool = True,
         timeout: Optional[float] = None) -> subprocess.CompletedProcess:
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    if label:
        tag = "ok" if p.returncode == 0 else f"rc={p.returncode} {p.stderr.strip()[:160]}"
        print(f"  [{label}] {tag}")
    if check and p.returncode != 0:
        raise RuntimeError(f"{label or cmd[0]} failed: {p.stderr.strip()[:300]}")
    return p


# ------------------------------------------------------------------ overlays

BASE_LABEL = "base"
DISK_ID = "disk0"          # so QMP can name the disk when snapshotting a running VM


def overlay_path(label: str) -> Path:
    """The disk behind a label. The golden image answers to "base" so it can be diffed against
    like any snapshot -- it is the healthy machine, which is one side of every comparison.

    A label usually names its own file, but not after a live snapshot. Taking one from a running VM
    inverts the chain: qemu starts writing to a *new* overlay and the file it was writing to becomes
    the frozen one, and it cannot be renamed while qemu holds it open. So the snapshot's sidecar
    records which file it actually is, and that wins over the name.
    """
    if label == BASE_LABEL:
        return BASE
    meta = OVERLAYS / f"{label}.meta.json"
    try:
        got = json.loads(meta.read_text()).get("path")
    except (OSError, json.JSONDecodeError, AttributeError):
        got = None
    return Path(got) if got else OVERLAYS / f"{label}.qcow2"


def qmp_socket(label: str) -> Path:
    return VM_DIR / f"{label}.qmp"


def _qmp(label: str, command: str, **args: Any) -> Dict[str, Any]:
    """One QMP command to a running VM. This is how a snapshot is taken without stopping it."""
    import socket as _socket
    sock = qmp_socket(label)
    if not sock.exists():
        raise RuntimeError(f"{label} has no QMP socket at {sock}; it was booted without one")
    with _socket.socket(_socket.AF_UNIX, _socket.SOCK_STREAM) as c:
        c.settimeout(30)
        c.connect(str(sock))
        f = c.makefile("rwb")
        f.readline()                                    # the greeting
        for payload in ({"execute": "qmp_capabilities"}, {"execute": command, "arguments": args}):
            f.write(json.dumps(payload).encode() + b"\n")
            f.flush()
            while True:
                line = f.readline()
                if not line:
                    raise RuntimeError(f"QMP closed while running {command}")
                reply = json.loads(line)
                if "event" in reply:                    # events interleave with replies
                    continue
                if "error" in reply:
                    raise RuntimeError(f"QMP {command} failed: {reply['error']}")
                break
        return reply


def snapshot_live(label: str, of: str) -> Path:
    """Freeze a running VM's disk under a new label, without stopping it.

    The old way shut the machine down, moved the overlay aside and booted again -- correct, and it
    cost more than the 17 seconds. The reboot between the attack and the investigation destroyed the
    attack's runtime state: a process it started, a socket it held, gone before the agent ever
    looked. `execution` -- is the attack still running -- could then only ever be answered `none`,
    not because the agent had cleaned anything but because the reboot had.

    qemu does this itself: blockdev-snapshot-sync hands the guest a fresh overlay and leaves what it
    was writing to as that overlay's read-only backing. The image is crash-consistent rather than
    clean, which is what "the machine as it was at that instant" means; the audit and the trajectory
    are collected over ssh and do not depend on it.
    """
    live = overlay_path(of)
    if not live.exists():
        raise RuntimeError(f"no overlay named {of!r}")
    if not running(of):
        raise RuntimeError(f"{of} is not running; use snapshot() for a stopped VM")
    if (OVERLAYS / f"{label}.meta.json").exists():
        raise RuntimeError(f"{label} already exists")
    gen = 1
    while (OVERLAYS / f"{of}.g{gen}.qcow2").exists():
        gen += 1
    fresh = OVERLAYS / f"{of}.g{gen}.qcow2"
    # Flush the guest's page cache first, or the snapshot is missing whatever it had not written
    # yet. A benign episode downloaded a 1.9 MiB binary into /usr/local/bin seconds before T1, and
    # the snapshot had the directory empty: the judge's file evidence said /usr/local/bin held
    # nothing at T0, T1 and T2 while the runtime table showed that same binary running at T1.
    # Journal replay recovers metadata, not data that never left memory. Crash-consistent is the
    # point of a live snapshot; crash-consistent with a cold cache is not.
    p_ = ssh(["sync"], check=False, label=of, timeout=120)
    if p_.returncode != 0:
        print(f"  [snapshot-live {label}] !! sync failed rc={p_.returncode}: "
              f"{(p_.stderr or '').strip()[:120]} -- the image may be missing recent writes")
    _qmp(of, "blockdev-snapshot-sync", device=DISK_ID, **{"snapshot-file": str(fresh),
                                                          "format": "qcow2"})
    # The file qemu *was* writing to is now frozen: that is the snapshot, under its old name.
    (OVERLAYS / f"{label}.meta.json").write_text(json.dumps(
        {"label": label, "taken": time.time(), "of": of, "path": str(live), "live_snapshot": True,
         "now_live": str(fresh)}, indent=1))
    (OVERLAYS / f"{of}.meta.json").write_text(json.dumps(
        {"label": of, "taken": time.time(), "path": str(fresh), "frozen_as": label}, indent=1))
    print(f"  [snapshot-live {label}] {live.name} frozen, {of} now writing {fresh.name}")
    return live


def create_overlay(label: str, backing: Optional[Path] = None) -> Path:
    """A fresh disk for one episode, or a snapshot taken from another overlay.

    Backing a snapshot by the running disk is what makes `take` instant: nothing is copied, the new
    file holds only blocks written after it was made. The chain stays shallow -- base, episode disk,
    snapshot -- so reads do not walk a long list of files.
    """
    OVERLAYS.mkdir(parents=True, exist_ok=True)
    dst = overlay_path(label)
    if dst.exists():
        raise RuntimeError(f"{dst} exists; pick another label or call drop() first")
    src = backing or BASE
    if not src.exists():
        raise RuntimeError(f"no backing image at {src}")
    _run(["qemu-img", "create", "-q", "-f", "qcow2", "-b", str(src), "-F", "qcow2", str(dst)])
    return dst


def snapshot(label: str, of: str) -> Path:
    """Freeze the current contents of one overlay under a new label.

    The running disk keeps being written to, so the snapshot has to be the *backing* file and the
    live disk the overlay on top -- the other way round and the snapshot would keep changing. qcow2
    cannot re-point a live disk, so the VM is expected to be off when this is called.
    """
    live = overlay_path(of)
    if not live.exists():
        raise RuntimeError(f"no overlay named {of!r}")
    frozen = overlay_path(label)
    if frozen.exists():
        raise RuntimeError(f"{frozen} exists")
    # Move the written blocks aside as the snapshot, then give the episode a fresh overlay over it.
    shutil.move(str(live), str(frozen))
    _run(["qemu-img", "create", "-q", "-f", "qcow2", "-b", str(frozen), "-F", "qcow2", str(live)])
    (OVERLAYS / f"{label}.meta.json").write_text(json.dumps(
        {"label": label, "taken": time.time(), "of": of, "backing": str(frozen)}, indent=1))
    return frozen


def drop(label: str) -> None:
    if label == BASE_LABEL:
        raise RuntimeError("refusing to delete the golden image")
    forget_port(label)
    for p in (overlay_path(label), OVERLAYS / f"{label}.meta.json"):
        p.unlink(missing_ok=True)


def taken_at(label: str) -> float:
    """When a snapshot was made, from its sidecar metadata; the file's own mtime is the guest's."""
    try:
        return float(json.loads((OVERLAYS / f"{label}.meta.json").read_text())["taken"])
    except (OSError, KeyError, ValueError):
        try:
            return overlay_path(label).stat().st_mtime
        except OSError:
            return 0.0


def overlays() -> List[str]:
    found = [BASE_LABEL] if BASE.exists() else []
    if OVERLAYS.exists():
        found += sorted(p.stem for p in OVERLAYS.glob("*.qcow2"))
    return found


# ------------------------------------------------------------------ reading a snapshot from the host

_NBD_IN_USE: Dict[str, str] = {}


def _free_nbd() -> str:
    for i in range(16):
        dev = f"/dev/nbd{i}"
        if not Path(dev).exists():
            continue
        if dev in _NBD_IN_USE.values():
            continue
        # A device with a size of 0 is not connected to anything.
        size = Path(f"/sys/block/nbd{i}/size")
        try:
            if size.read_text().strip() == "0":
                return dev
        except OSError:
            continue
    raise RuntimeError("no free /dev/nbdN; run `modprobe nbd max_part=8`")


def _is_live_snapshot(label: str) -> bool:
    """Was this snapshot taken while the machine was running? Its sidecar says so."""
    try:
        return bool(json.loads((OVERLAYS / f"{label}.meta.json").read_text()).get("live_snapshot"))
    except (OSError, json.JSONDecodeError, AttributeError):
        return False


def mount(label: str) -> Path:
    """Mount a snapshot read-only on the host and return its root.

    Read-only all the way down: qemu-nbd itself, and the mount. Nothing the host does while looking
    at a snapshot can alter the evidence, and the same snapshot can be read again later.
    """
    if label in _NBD_IN_USE:
        return MOUNTS / label
    img = overlay_path(label)
    if not img.exists():
        raise RuntimeError(f"no snapshot named {label!r}")
    # A snapshot taken from a running machine is crash-consistent: its ext4 journal was never
    # replayed, so some inodes are mid-transaction and reading one fails with EUCLEAN (errno 117).
    # One such file -- a .pyc under __pycache__ -- killed an episode's scoring outright. The journal
    # is replayed into a scratch overlay instead, so the mount is consistent and the snapshot itself
    # is still never written to.
    live = _is_live_snapshot(label)
    if live:
        scratch = OVERLAYS / f"{label}.replay.qcow2"
        scratch.unlink(missing_ok=True)
        _run(["qemu-img", "create", "-q", "-f", "qcow2", "-b", str(img), "-F", "qcow2",
              str(scratch)])
        img = scratch
    subprocess.run(["modprobe", "nbd", "max_part=8"], capture_output=True)
    dev = _free_nbd()
    _run(["qemu-nbd", *([] if live else ["--read-only"]), "--connect", dev, str(img)])
    root = MOUNTS / label
    root.mkdir(parents=True, exist_ok=True)
    part = f"{dev}p1"
    for _ in range(40):                      # the kernel needs a moment to read the partition table
        if Path(part).exists():
            break
        time.sleep(0.25)
    target = part if Path(part).exists() else dev
    if live:
        # Read-write once, so the journal replays into the scratch overlay, then back to read-only.
        p = subprocess.run(["mount", target, str(root)], capture_output=True, text=True)
        if p.returncode == 0:
            subprocess.run(["mount", "-o", "remount,ro", str(root)], capture_output=True)
    else:
        p = subprocess.run(["mount", "-o", "ro,noload", target, str(root)],
                           capture_output=True, text=True)
        if p.returncode != 0:                # noload is ext4-only; fall back for other filesystems
            p = subprocess.run(["mount", "-o", "ro", target, str(root)],
                               capture_output=True, text=True)
    if p.returncode != 0:
        subprocess.run(["qemu-nbd", "--disconnect", dev], capture_output=True)
        raise RuntimeError(f"mount {target} failed: {p.stderr.strip()[:200]}")
    _NBD_IN_USE[label] = dev
    return root


def _drop_replay(label: str) -> None:
    """Remove the scratch overlay a live snapshot's journal was replayed into."""
    (OVERLAYS / f"{label}.replay.qcow2").unlink(missing_ok=True)


def umount(label: str) -> None:
    dev = _NBD_IN_USE.pop(label, None) or mounted().get(label, "").rstrip("p1") or None
    subprocess.run(["umount", str(MOUNTS / label)], capture_output=True)
    if dev:
        subprocess.run(["qemu-nbd", "--disconnect", dev], capture_output=True)
    _drop_replay(label)


def mounted() -> Dict[str, str]:
    """{label: device} for every snapshot mounted under MOUNTS, read from /proc/mounts.

    The in-memory registry is per process, so a mount outlives whatever made it and no later
    process can find it -- three were left behind by debugging scripts, and `du` walking into them
    reported the snapshot store as 17 GB when it held 4.8. Reading the real mount table is what
    makes a leak cleanable by anyone.
    """
    out: Dict[str, str] = {}
    try:
        lines = Path("/proc/mounts").read_text().splitlines()
    except OSError:
        return out
    for line in lines:
        parts = line.split()
        if len(parts) < 2:
            continue
        dev, point = parts[0], parts[1].replace("\\040", " ")
        if point.startswith(str(MOUNTS) + "/"):
            out[Path(point).name] = dev
    return out


def umount_all() -> None:
    """Unmount every snapshot and release every nbd device, whoever mounted it."""
    for label in set(list(_NBD_IN_USE) + list(mounted())):
        umount(label)
    # An nbd device can stay connected after its mount is gone, which quietly uses up the 16 the
    # module provides. Anything still holding a disk with nothing mounted on it is ours to release.
    live = set(mounted().values())
    for i in range(16):
        dev = f"/dev/nbd{i}"
        try:
            if Path(f"/sys/block/nbd{i}/size").read_text().strip() == "0":
                continue
        except OSError:
            continue
        if dev not in live and f"{dev}p1" not in live:
            subprocess.run(["qemu-nbd", "--disconnect", dev], capture_output=True)


# ------------------------------------------------------------------ running one

def pid_file(label: str) -> Path:
    return VM_DIR / f"{label}.pid"


def running(label: str) -> bool:
    pf = pid_file(label)
    try:
        pid = int(pf.read_text().strip())
    except (OSError, ValueError):
        return False
    return Path(f"/proc/{pid}").exists()


def boot(label: str, wait: bool = True) -> None:
    """Start the VM on one overlay, with ssh forwarded to the host's loopback."""
    img = overlay_path(label)
    if not img.exists():
        raise RuntimeError(f"no overlay named {label!r}")
    if running(label):
        raise RuntimeError(f"{label} is already running")
    console = VM_DIR / f"{label}.console.log"
    port = _PORT.get(label) or _free_port()
    _PORT[label] = port
    cmd = ["qemu-system-x86_64", "-enable-kvm", "-machine", "q35", "-cpu", "host",
           "-m", str(MEM_MB), "-smp", str(CPUS),
           "-drive", f"file={img},if=virtio,cache=writeback,id={DISK_ID}",
           "-drive", f"file={SEED},media=cdrom",
           "-netdev", f"user,id=n0,hostfwd=tcp:127.0.0.1:{port}-:22",
           "-device", "virtio-net-pci,netdev=n0",
           "-display", "none", "-serial", f"file:{console}",
           # A control socket, so a snapshot can be taken without shutting the machine down.
           "-qmp", f"unix:{qmp_socket(label)},server=on,wait=off",
           "-daemonize", "-pidfile", str(pid_file(label))]
    _run(cmd, f"boot {label} (ssh :{port})")
    if wait:
        wait_for_ssh(label)


def alive(label: str) -> bool:
    """Is this VM both running and answering ssh?"""
    return running(label) and ssh(["true"], check=False, label=label,
                                  timeout=PROBE_TIMEOUT).returncode == 0


def wait_for_ssh(label: str, timeout: float = BOOT_TIMEOUT) -> None:
    t0 = time.time()
    while time.time() - t0 < timeout:
        if ssh(["true"], check=False, label=label, timeout=PROBE_TIMEOUT).returncode == 0:
            print(f"  [boot {label}] ssh up after {time.time() - t0:.0f}s")
            return
        if not running(label):
            raise RuntimeError(f"{label} died while booting; see {VM_DIR}/{label}.console.log")
        waited = time.time() - t0
        if waited > 60 and int(waited) % 60 < 3:
            print(f"  [boot {label}] still no ssh after {waited:.0f}s (of {timeout:.0f}s)")
        time.sleep(3)
    raise RuntimeError(f"{label} never answered ssh in {timeout:.0f}s; "
                       f"see {VM_DIR}/{label}.console.log")


def ssh(argv: List[str], check: bool = True, timeout: Optional[float] = 300,
        capture: bool = True, label: str = "") -> subprocess.CompletedProcess:
    """Run one command inside the VM, with argv arriving as argv.

    ssh does not preserve argument boundaries: it concatenates everything after the host into one
    string and hands it to the remote shell, which re-splits it. Passing argv straight through
    therefore loses every quote, and
    `["bash", "-lc", "ls -t /root/ice-state/cases/case-*.json | head -20"]` arrived as
    `bash -lc ls -t ... | head -20` -- a bare `ls` of the home directory, with the rest as
    positional parameters. The recorder then waited out a full 900-second investigation reporting
    "NO case" while ICE had detected and remediated the attack, and copied whatever `ls` had
    listed in /root into the bundle. shlex.join is what makes the remote shell rebuild this argv.
    """
    cmd = ["ssh", *_ssh_base(label), "root@127.0.0.1", shlex.join(argv)]
    p = subprocess.run(cmd, capture_output=capture, text=True, timeout=timeout)
    if check and p.returncode != 0:
        raise RuntimeError(f"ssh {argv[:2]} failed rc={p.returncode}: {p.stderr.strip()[:300]}")
    return p


def sh(script: str, check: bool = True, timeout: Optional[float] = 300,
       label: str = "") -> subprocess.CompletedProcess:
    """Run a shell snippet inside the VM."""
    p = ssh(["bash", "-lc", script], check=False, timeout=timeout)
    if label:
        tag = "ok" if p.returncode == 0 else f"rc={p.returncode} {(p.stderr or p.stdout).strip()[:120]}"
        print(f"  [{label}] {script[:80]} -> {tag}")
    if check and p.returncode != 0:
        raise RuntimeError(f"{label or 'sh'} failed: {(p.stderr or p.stdout).strip()[:300]}")
    return p


def run_script(body: str, label: str = "", check: bool = True,
               timeout: Optional[float] = 300) -> subprocess.CompletedProcess:
    """Run a multi-line script inside the VM by sending it on stdin.

    Quoting a snippet through ssh, python's argv and the guest's bash in turn is how a useradd call
    arrived with its arguments mangled; stdin has no quoting layer to get wrong.
    """
    cmd = ["ssh", *_ssh_base(), "root@127.0.0.1", "bash", "-s"]
    p = subprocess.run(cmd, input=body, capture_output=True, text=True, timeout=timeout)
    if label:
        tag = "ok" if p.returncode == 0 else f"rc={p.returncode} {(p.stderr or p.stdout).strip()[:140]}"
        print(f"  [{label}] {tag}")
    if check and p.returncode != 0:
        raise RuntimeError(f"{label or 'script'} failed: {(p.stderr or p.stdout).strip()[:300]}")
    return p


def put(local: Path, remote: str) -> None:
    _run(["scp", "-q", "-i", str(KEY), "-P", str(ssh_port()), *_SSH_OPTS,
          "-o", f"ControlPath={_ctl(_current_label())}",
          str(local), f"root@127.0.0.1:{remote}"])


def get(remote: str, local: Path) -> bool:
    p = _run(["scp", "-q", "-i", str(KEY), "-P", str(ssh_port()), *_SSH_OPTS,
              "-o", f"ControlPath={_ctl(_current_label())}",
              f"root@127.0.0.1:{remote}", str(local)], check=False)
    return p.returncode == 0


def shutdown(label: str, timeout: float = 120) -> None:
    """Shut the VM down cleanly, so the disk is consistent before it is snapshotted."""
    if not running(label):
        close_connection(label)
        return
    ssh(["systemctl", "poweroff", "--no-block"], check=False, label=label, timeout=15)
    close_connection(label)
    t0 = time.time()
    while time.time() - t0 < timeout:
        if not running(label):
            print(f"  [shutdown {label}] off after {time.time() - t0:.0f}s")
            return
        time.sleep(2)
    try:
        pid = int(pid_file(label).read_text().strip())
        os.kill(pid, 9)
        print(f"  [shutdown {label}] did not stop in {timeout:.0f}s; killed")
    except (OSError, ValueError):
        pass


def main() -> None:
    import argparse
    ap = argparse.ArgumentParser(description="the VM an episode runs inside")
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name, helptext in (("boot", "start a VM on an overlay"),
                           ("shutdown", "stop it cleanly"),
                           ("drop", "delete an overlay"),
                           ("mount", "mount a snapshot read-only on the host"),
                           ("umount", "unmount it")):
        q = sub.add_parser(name, help=helptext)
        q.add_argument("label")
    c = sub.add_parser("create", help="a fresh overlay over the golden image")
    c.add_argument("label")
    c.add_argument("--from", dest="backing", default="", help="back it with this overlay instead")
    s = sub.add_parser("snapshot", help="freeze an overlay's contents under a new label")
    s.add_argument("label")
    s.add_argument("--of", required=True)
    sub.add_parser("list", help="list overlays")
    sub.add_parser("clean", help="unmount every snapshot and release every nbd device")
    pr = sub.add_parser("prune", help="delete the snapshots of all but the newest N episodes")
    pr.add_argument("--keep", type=int, default=5)
    pr.add_argument("--dry-run", action="store_true")
    e = sub.add_parser("exec", help="run a shell snippet inside")
    e.add_argument("script")
    a = ap.parse_args()

    if a.cmd == "create":
        print(create_overlay(a.label, overlay_path(a.backing) if a.backing else None))
    elif a.cmd == "snapshot":
        print(snapshot(a.label, a.of))
    elif a.cmd == "boot":
        boot(a.label)
    elif a.cmd == "shutdown":
        shutdown(a.label)
    elif a.cmd == "drop":
        drop(a.label)
    elif a.cmd == "mount":
        print(mount(a.label))
    elif a.cmd == "umount":
        umount(a.label)
    elif a.cmd == "list":
        for label in overlays():
            img = overlay_path(label)
            actual = _run(["du", "-sh", str(img)], check=False).stdout.split("\t")[0] or "?"
            print(f"  {label:<40} {actual:>8}  running={running(label)}")
    elif a.cmd == "clean":
        umount_all()
        print(f"  mounts left: {mounted() or 'none'}")
    elif a.cmd == "prune":
        # Episode snapshots are grouped by the label prefix the recorder gives them. The bundle
        # carries the diffs, so dropping the disks costs re-reading the machine, not the evidence.
        groups: Dict[str, List[str]] = {}
        for label in overlays():
            if label == BASE_LABEL:
                continue
            stem = label.rsplit("-", 1)[0]
            groups.setdefault(stem, []).append(label)
        order = sorted(groups, key=lambda g: max(taken_at(l) for l in groups[g]), reverse=True)
        for stem in order[a.keep:]:
            for label in groups[stem]:
                print(f"  {'would drop' if a.dry_run else 'dropping'} {label}")
                if not a.dry_run:
                    drop(label)
        print(f"  kept {min(len(order), a.keep)} of {len(order)} episodes")
    elif a.cmd == "exec":
        p = sh(a.script, check=False)
        print(p.stdout, end="")
        if p.stderr:
            print(p.stderr, end="")
        raise SystemExit(p.returncode)


if __name__ == "__main__":
    main()
