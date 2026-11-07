"""Render one Atomic Red Team test to a runnable shell command, from its YAML.

Atomic Red Team ships every technique as a fixed-schema YAML (atomics/<T-id>/<T-id>.yaml): a list of
`atomic_tests`, each with a guid, supported platforms, `input_arguments` (named, with defaults), and
an `executor` whose `command` carries `#{arg}` placeholders. Rendering a test is mechanical --
pick the test by guid, substitute each `#{name}` with input_arguments[name].default -- and the
result is ART's own command, not a paraphrase.

Many tests also declare `dependencies`: a `prereq_command` that checks whether a prerequisite is in
place and a `get_prereq_command` that fetches/builds it (download a payload, compile a module, write
a file). ART runs the get command only when the check fails. We render those too, each in its own
subshell so a prereq's `exit 0/1` cannot terminate the whole arm, as

    ( <prereq_command> ) || ( <get_prereq_command> )
    <executor.command>

Paths in ART use the token `PathToAtomicsFolder` (bare, `$PathToAtomicsFolder`, or
`${PathToAtomicsFolder}`) for the atomics directory. We resolve it to where the atomics tree lives
inside the VM (ICE_ATOMICS_PATH, default /opt/ice/atomics) and also export it, so both forms work.

This is the resolve+prereq step atomic-operator does internally; we do it and run the result over
the recorder's own ssh, because atomic-operator's remote-ssh runner is broken in the packaged
version (it raised on ssh_key_path validation and then built a null command). Faithful and
reproducible without depending on that path.

    python -m ice.exercise.art_render <atomics_dir> <T-id> <guid>              # full arm (prereqs+cmd)
    python -m ice.exercise.art_render <atomics_dir> <T-id> <guid> --no-prereqs # executor command only
    python -m ice.exercise.art_render <atomics_dir> <T-id> --list              # list the tests
"""
from __future__ import annotations

import os
import re
import shlex
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import yaml

RUNNABLE = {"sh", "bash"}          # executors we can pipe into a Linux VM as-is
DEFAULT_ATOMICS_PATH = "/opt/ice/atomics"
_PTA = re.compile(r"\$?\{?PathToAtomicsFolder\}?")


def _load(atomics: str, technique: str) -> Dict[str, Any]:
    f = Path(atomics) / technique / f"{technique}.yaml"
    return yaml.safe_load(f.read_text())


def list_tests(atomics: str, technique: str) -> List[Dict[str, str]]:
    out = []
    for a in _load(atomics, technique).get("atomic_tests", []):
        ex = a.get("executor") or {}
        out.append({"guid": a.get("auto_generated_guid", ""), "name": a.get("name", ""),
                    "executor": ex.get("name", ""),
                    "platforms": ",".join(a.get("supported_platforms", [])),
                    "elevation": str(bool(ex.get("elevation_required", False)))})
    return out


def _find(atomics: str, technique: str, guid: str) -> Dict[str, Any]:
    for a in _load(atomics, technique).get("atomic_tests", []):
        if a.get("auto_generated_guid") == guid:
            return a
    raise SystemExit(f"no test {guid!r} in {technique}; use --list to see them")


def _resolve_pta(text: str, atomics_path: str) -> str:
    return _PTA.sub(atomics_path, text)


def render(atomics: str, technique: str, guid: str,
           args: Optional[Dict[str, str]] = None,
           *, with_prereqs: bool = True,
           atomics_path: Optional[str] = None) -> Tuple[str, str]:
    """Return (executor_name, script) for one test.

    `#{name}` placeholders are filled from input_arguments defaults (or `args`); with_prereqs adds
    each dependency's `( prereq ) || ( get_prereq )` ahead of the command; PathToAtomicsFolder is
    resolved to `atomics_path` (env ICE_ATOMICS_PATH, else /opt/ice/atomics) and exported.
    """
    atomics_path = atomics_path or os.environ.get("ICE_ATOMICS_PATH") or DEFAULT_ATOMICS_PATH
    a = _find(atomics, technique, guid)
    ex = a.get("executor") or {}
    name = ex.get("name", "")
    if name not in RUNNABLE:
        raise SystemExit(f"{technique} {guid}: executor is {name!r}, not one of {sorted(RUNNABLE)}; "
                         f"this renderer only runs sh/bash tests on the Linux VM")
    if "linux" not in (a.get("supported_platforms") or []):
        raise SystemExit(f"{technique} {guid}: not supported on linux ({a.get('supported_platforms')})")
    values = {k: str((v or {}).get("default", "")) for k, v in (a.get("input_arguments") or {}).items()}
    values.update(args or {})
    missing: List[str] = []

    def fill(text: str) -> str:
        def sub(m: "re.Match") -> str:
            key = m.group(1)
            if key not in values:
                missing.append(key)
                return m.group(0)
            return values[key]
        return re.sub(r"#\{([^}]+)\}", sub, text or "")

    parts: List[str] = []
    if with_prereqs:
        dep_exec = a.get("dependency_executor_name") or name
        for dep in (a.get("dependencies") or []):
            if dep_exec not in RUNNABLE:
                # a powershell prereq cannot run on the Linux VM; skip it and let the prereq check
                # (or the command itself) decide -- the no-op guard drops it if nothing landed.
                continue
            pre = fill(dep.get("prereq_command", "") or "").strip()
            get = fill(dep.get("get_prereq_command", "") or "").strip()
            if pre and get:
                parts.append(f"( {pre}\n) || ( {get}\n)")
            elif get:
                parts.append(f"( {get}\n)")
            elif pre:
                parts.append(f"( {pre}\n) || true")
    parts.append(fill(ex.get("command", "")))
    if missing:
        raise SystemExit(f"{technique} {guid}: no value for placeholder(s) {sorted(set(missing))}")

    script = _resolve_pta("\n".join(p for p in parts if p.strip()), atomics_path)
    header = f"export PathToAtomicsFolder={shlex.quote(atomics_path)}\n"
    return name, header + script


def main() -> None:
    if len(sys.argv) >= 4 and sys.argv[3] == "--list":
        for t in list_tests(sys.argv[1], sys.argv[2]):
            print(f"{t['guid']}  [{t['platforms']}/{t['executor']}"
                  f"{'/root' if t['elevation']=='True' else ''}]  {t['name']}")
        return
    if len(sys.argv) < 4:
        raise SystemExit("usage: art_render <atomics_dir> <T-id> <guid> [--no-prereqs] | "
                         "<atomics_dir> <T-id> --list")
    with_prereqs = "--no-prereqs" not in sys.argv[4:]
    _name, script = render(sys.argv[1], sys.argv[2], sys.argv[3], with_prereqs=with_prereqs)
    sys.stdout.write(script if script.endswith("\n") else script + "\n")


if __name__ == "__main__":
    main()
