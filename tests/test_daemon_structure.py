"""The daemon's classes still have the methods the daemon calls on them.

    python3 -m pytest tests/test_daemon_structure.py

This machine cannot import ice.daemon.mcp_server -- the MCP dependency is not installed -- so every
test here reads the daemon as text, and a structural break is invisible to all of them. One was:
a module-level helper inserted above the `# -- host_exec` comment, which is inside the class body,
ended the class. `host_exec` and every method after it became module functions, the daemon raised
`AttributeError: 'IceTools' object has no attribute 'host_exec'` the moment it tried to run the
agent's first proposed action, and the episode recorded an agent that cleaned nothing.

ast.parse sees that without importing anything.
"""
from __future__ import annotations

import ast
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

ROOT = Path(__file__).resolve().parents[1]

# What the rest of the daemon calls on each class. Add to this when a caller starts depending on
# a new method; the point is that these names are reachable as attributes of the class.
EXPECTED = {
    "ice/daemon/mcp_server.py": {
        "IceTools": {"host_exec", "host_query", "graph_query", "explain_for_human"},
    },
    "ice/daemon/orchestrator.py": {
        "Orchestrator": {"run_forever", "run_case", "on_approval", "finish",
                         "investigate_handed_over", "investigate_file"},
    },
}


def _classes(path: Path) -> dict:
    tree = ast.parse(path.read_text())
    return {n.name: {m.name for m in n.body if isinstance(m, (ast.FunctionDef, ast.AsyncFunctionDef))}
            for n in tree.body if isinstance(n, ast.ClassDef)}


def test_every_expected_method_is_inside_its_class() -> None:
    for rel, classes in EXPECTED.items():
        found = _classes(ROOT / rel)
        for cls, methods in classes.items():
            assert cls in found, f"{rel}: class {cls} is gone"
            missing = methods - found[cls]
            assert not missing, f"{rel}: {cls} lost {sorted(missing)} -- indentation?"


def test_the_stop_after_exec_helper_is_module_level() -> None:
    """It has to be callable from the method, and it must not sit inside the class body."""
    tree = ast.parse((ROOT / "ice" / "daemon" / "mcp_server.py").read_text())
    top = {n.name for n in tree.body if isinstance(n, ast.FunctionDef)}
    assert "_stop_after_exec" in top
    for n in tree.body:
        if isinstance(n, ast.ClassDef):
            assert "_stop_after_exec" not in {m.name for m in n.body
                                              if isinstance(m, ast.FunctionDef)}


def test_host_exec_calls_it() -> None:
    tree = ast.parse((ROOT / "ice" / "daemon" / "mcp_server.py").read_text())
    for n in ast.walk(tree):
        if isinstance(n, ast.ClassDef) and n.name == "IceTools":
            for m in n.body:
                if isinstance(m, ast.FunctionDef) and m.name == "host_exec":
                    calls = {c.func.id for c in ast.walk(m)
                             if isinstance(c, ast.Call) and isinstance(c.func, ast.Name)}
                    assert "_stop_after_exec" in calls
                    return
    raise AssertionError("IceTools.host_exec not found")


if __name__ == "__main__":
    import pytest
    raise SystemExit(pytest.main([__file__, "-q"]))
