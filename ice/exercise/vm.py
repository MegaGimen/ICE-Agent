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
import shutil
import subprocess
import time
from pathlib import Path
from typing import Dict, List, Optional

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
    """The port this VM's ssh is forwarded to. Set when it boots."""
    if label and label in _PORT:
        return _PORT[label]
    return next(iter(_PORT.values())) if _PORT else SSH_PORT
MEM_MB = int(os.environ.get("ICE_VM_MEM", "4096"))
CPUS = int(os.environ.get("ICE_VM_CPUS", "4"))
BOOT_TIMEOUT = float(os.environ.get("ICE_VM_BOOT_TIMEOUT", "240"))

_SSH_OPTS = ["-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
             "-o", "LogLevel=ERROR", "-o", "ConnectTimeout=5"]


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


def overlay_path(label: str) -> Path:
    """The disk behind a label. The golden image answers to "base" so it can be diffed against
    like any snapshot -- it is the healthy machine, which is one side of every comparison."""
    return BASE if label == BASE_LABEL else OVERLAYS / f"{label}.qcow2"


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
    for p in (overlay_path(label), OVERLAYS / f"{label}.meta.json"):
        p.unlink(missing_ok=True)


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
    subprocess.run(["modprobe", "nbd", "max_part=8"], capture_output=True)
    dev = _free_nbd()
    _run(["qemu-nbd", "--read-only", "--connect", dev, str(img)])
    root = MOUNTS / label
    root.mkdir(parents=True, exist_ok=True)
    part = f"{dev}p1"
    for _ in range(40):                      # the kernel needs a moment to read the partition table
        if Path(part).exists():
            break
        time.sleep(0.25)
    target = part if Path(part).exists() else dev
    p = subprocess.run(["mount", "-o", "ro,noload", target, str(root)], capture_output=True, text=True)
    if p.returncode != 0:                    # noload is ext4-only; fall back for other filesystems
        p = subprocess.run(["mount", "-o", "ro", target, str(root)], capture_output=True, text=True)
    if p.returncode != 0:
        subprocess.run(["qemu-nbd", "--disconnect", dev], capture_output=True)
        raise RuntimeError(f"mount {target} failed: {p.stderr.strip()[:200]}")
    _NBD_IN_USE[label] = dev
    return root


def umount(label: str) -> None:
    dev = _NBD_IN_USE.pop(label, None)
    subprocess.run(["umount", str(MOUNTS / label)], capture_output=True)
    if dev:
        subprocess.run(["qemu-nbd", "--disconnect", dev], capture_output=True)


def umount_all() -> None:
    for label in list(_NBD_IN_USE):
        umount(label)


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
           "-drive", f"file={img},if=virtio,cache=writeback",
           "-drive", f"file={SEED},media=cdrom",
           "-netdev", f"user,id=n0,hostfwd=tcp:127.0.0.1:{port}-:22",
           "-device", "virtio-net-pci,netdev=n0",
           "-display", "none", "-serial", f"file:{console}",
           "-daemonize", "-pidfile", str(pid_file(label))]
    _run(cmd, f"boot {label} (ssh :{port})")
    if wait:
        wait_for_ssh(label)


def alive(label: str) -> bool:
    """Is this VM both running and answering ssh?"""
    return running(label) and ssh(["true"], check=False, timeout=10).returncode == 0


def wait_for_ssh(label: str, timeout: float = BOOT_TIMEOUT) -> None:
    t0 = time.time()
    while time.time() - t0 < timeout:
        if ssh(["true"], check=False, timeout=8).returncode == 0:
            print(f"  [boot {label}] ssh up after {time.time() - t0:.0f}s")
            return
        if not running(label):
            raise RuntimeError(f"{label} died while booting; see {VM_DIR}/{label}.console.log")
        time.sleep(3)
    raise RuntimeError(f"{label} never answered ssh in {timeout:.0f}s")


def ssh(argv: List[str], check: bool = True, timeout: Optional[float] = 300,
        capture: bool = True) -> subprocess.CompletedProcess:
    """Run a command inside the VM. argv is passed through, not shell-joined by us."""
    cmd = ["ssh", "-i", str(KEY), "-p", str(ssh_port()), *_SSH_OPTS, "root@127.0.0.1", *argv]
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
    cmd = ["ssh", "-i", str(KEY), "-p", str(ssh_port()), *_SSH_OPTS, "root@127.0.0.1",
           "bash", "-s"]
    p = subprocess.run(cmd, input=body, capture_output=True, text=True, timeout=timeout)
    if label:
        tag = "ok" if p.returncode == 0 else f"rc={p.returncode} {(p.stderr or p.stdout).strip()[:140]}"
        print(f"  [{label}] {tag}")
    if check and p.returncode != 0:
        raise RuntimeError(f"{label or 'script'} failed: {(p.stderr or p.stdout).strip()[:300]}")
    return p


def put(local: Path, remote: str) -> None:
    _run(["scp", "-q", "-i", str(KEY), "-P", str(ssh_port()), *_SSH_OPTS,
          str(local), f"root@127.0.0.1:{remote}"])


def get(remote: str, local: Path) -> bool:
    p = _run(["scp", "-q", "-i", str(KEY), "-P", str(ssh_port()), *_SSH_OPTS,
              f"root@127.0.0.1:{remote}", str(local)], check=False)
    return p.returncode == 0


def shutdown(label: str, timeout: float = 120) -> None:
    """Shut the VM down cleanly, so the disk is consistent before it is snapshotted."""
    if not running(label):
        return
    ssh(["systemctl", "poweroff", "--no-block"], check=False, timeout=15)
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
    elif a.cmd == "exec":
        p = sh(a.script, check=False)
        print(p.stdout, end="")
        if p.stderr:
            print(p.stderr, end="")
        raise SystemExit(p.returncode)


if __name__ == "__main__":
    main()
