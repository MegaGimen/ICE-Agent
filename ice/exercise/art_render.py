"""Render one Atomic Red Team test to a runnable shell command, from its YAML.

Atomic Red Team ships every technique as a fixed-schema YAML (atomics/<T-id>/<T-id>.yaml): a list of
`atomic_tests`, each with a guid, supported platforms, `input_arguments` (named, with defaults), and
an `executor` whose `command` carries `#{arg}` placeholders. Rendering a test is mechanical --
pick the test by guid, substitute each `#{name}` with input_arguments[name].default -- and the
result is ART's own command, not a paraphrase.

This is the resolve step atomic-operator does internally; we use it and run the command over the
recorder's own ssh, because atomic-operator's remote-ssh runner is broken in the packaged version
(it raised on ssh_key_path validation and then built a null command). Faithful and reproducible
without depending on that path.

    python -m ice.exercise.art_render <atomics_dir> <T-id> <guid>    # prints the command
    python -m ice.exercise.art_render <atomics_dir> <T-id> --list    # lists the tests
"""
from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import yaml

RUNNABLE = {"sh", "bash"}          # executors we can pipe into a Linux VM as-is


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


def render(atomics: str, technique: str, guid: str,
           args: Optional[Dict[str, str]] = None) -> Tuple[str, str]:
    """Return (executor_name, command) for one test, placeholders filled from defaults (or `args`)."""
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
    command = ex.get("command", "")
    missing = []

    def sub(m: "re.Match") -> str:
        key = m.group(1)
        if key not in values:
            missing.append(key)
            return m.group(0)
        return values[key]

    command = re.sub(r"#\{([^}]+)\}", sub, command)
    if missing:
        raise SystemExit(f"{technique} {guid}: no value for placeholder(s) {sorted(set(missing))}")
    return name, command


def main() -> None:
    if len(sys.argv) >= 4 and sys.argv[3] == "--list":
        for t in list_tests(sys.argv[1], sys.argv[2]):
            print(f"{t['guid']}  [{t['platforms']}/{t['executor']}"
                  f"{'/root' if t['elevation']=='True' else ''}]  {t['name']}")
        return
    if len(sys.argv) < 4:
        raise SystemExit("usage: art_render <atomics_dir> <T-id> <guid> | <atomics_dir> <T-id> --list")
    _name, command = render(sys.argv[1], sys.argv[2], sys.argv[3])
    sys.stdout.write(command if command.endswith("\n") else command + "\n")


if __name__ == "__main__":
    main()
