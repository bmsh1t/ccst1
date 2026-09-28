"""Dependency contracts include imports inside functions and direct-script fallbacks."""

import ast
from graphlib import TopologicalSorter
from pathlib import Path


def _tool_dependencies():
    sources = {path.stem: path for path in (Path(__file__).resolve().parents[1] / "tools").glob("*.py")}
    graph = {name: set() for name in sources}
    for name, path in sources.items():
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(node, ast.ImportFrom):
                module = (node.module or "").removeprefix("tools.")
                if module in sources:
                    graph[name].add(module)
                elif module in {"", "tools"}:
                    graph[name].update(alias.name for alias in node.names if alias.name in sources)
            elif isinstance(node, ast.Import):
                graph[name].update(
                    alias.name.removeprefix("tools.") for alias in node.names
                    if alias.name.removeprefix("tools.") in sources
                )
    return graph


def test_tool_dependencies_are_acyclic_and_foundations_do_not_import_consumers():
    graph = _tool_dependencies()
    # Raises CycleError with the actual path, including lazy imports.
    tuple(TopologicalSorter(graph).static_order())
    allowed = {
        "artifact_io": set(),
        "contracts": set(),
        "evidence_identity": set(),
        "target_paths": set(),
        "scope_context": {"target_paths"},
        "target_store": {"evidence_identity", "scope_context", "target_paths"},
        "browser_evidence": {"target_paths"},
        "request_diff": {"contracts", "evidence_identity"},
        "decision_scaffold": {"contracts", "target_paths"},
    }
    for name, dependencies in allowed.items():
        assert graph[name] <= dependencies, (name, graph[name] - dependencies)
    assert not graph["resume_read"] & {"resume", "checkpoint", "autopilot_state"}
