"""The ranker's documented queries read current owners without refreshing them."""

import json
import re
import shlex
import subprocess
import sys
from pathlib import Path

import pytest

from tools.surface_index import build_surface_index
from tools.target_store import TargetStore


REPO = Path(__file__).resolve().parents[1]
TARGET = "ranker.test"
COMMANDS = [
    shlex.split(line)
    for block in re.findall(r"```bash\n(.*?)```", (REPO / "agents/recon-ranker.md").read_text(), re.S)
    for line in block.splitlines() if line.strip()
]


def _run(root, command, *extra):
    assert command[0] == "python3"
    arguments = [TARGET if token == "TARGET" else token for token in command[2:]]
    root_args = ["--repo-root", str(root)]
    arguments = root_args + arguments if command[1] == "tools/surface_index.py" else arguments + root_args
    return subprocess.run(
        [sys.executable, "-B", str(REPO / command[1]), *arguments, *extra],
        cwd=root, capture_output=True, text=True, timeout=20,
    )


def _files(root):
    # SQLite may manage WAL/SHM on a read; domain changes are checked by binding.
    return {path.relative_to(root): path.read_bytes() for path in root.rglob("*")
            if path.is_file() and not path.name.startswith("metadata.sqlite3")}


@pytest.mark.parametrize("mode", ["current", "empty", "missing", "stale"])
def test_documented_ranker_queries_read_current_state_and_preserve_sources(tmp_path, mode):
    assert len(COMMANDS) == 5
    store = TargetStore(tmp_path, TARGET)
    if mode != "missing":
        store.initialize()
    urls = []
    if mode in {"current", "stale"}:
        for index in range(9):
            store.create_finding(command_id=f"claim-{index}", finding_id=f"F-{index}",
                                 endpoint=f"https://{TARGET}/api", method="GET", family="Authz",
                                 title=f"Current claim {index}", claim="Unassessed", actor="test")
            store.remember(command_id=f"note-{index}", kind="note", statement=f"Current note {index}",
                           conditions="cached evidence", reopen_when="", next_intent="",
                           evidence=[], actor="test")
        store.remember(command_id="handoff", kind="handoff", statement="Current handoff",
                       conditions="cached evidence", reopen_when="", next_intent="Review saved evidence",
                       evidence=[], actor="test")
        urls = [f"https://{TARGET}/api", f"https://{TARGET}/search?q=apple", f"https://{TARGET}/search?q=apple%27"]
        urls += [f"https://{TARGET}/items?id={index}&id=2%27" for index in range(51)]
    raw = tmp_path / "recon" / TARGET / "urls" / "with_params.txt"
    raw.parent.mkdir(parents=True)
    raw.write_text("\n".join(urls) + "\n")
    if mode != "missing":
        build_surface_index(tmp_path, TARGET)
    if mode == "stale":
        raw.write_text(raw.read_text() + f"https://{TARGET}/new-observation\n")
    for relative in (f"memory/goals/targets/{TARGET}.json", f"hunt-memory/targets/{TARGET}.json",
                     "hunt-memory/patterns.jsonl", f"findings/{TARGET}/findings.json"):
        path = tmp_path / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text('{"statement":"LEGACY_ONLY"}\n')
    before = _files(tmp_path)
    binding = store.binding() if mode != "missing" else None
    results = [_run(tmp_path, command) for command in COMMANDS]
    expected = [2, 2, 2, 0, 2] if mode == "missing" else [0, 0, 0, 0, 2 if mode == "stale" else 0]
    assert [result.returncode for result in results] == expected, [result.stderr for result in results]
    assert "LEGACY_ONLY" not in "".join(result.stdout for result in results)
    assert json.loads(results[3].stdout)["status"] == (mode if mode in {"missing", "stale"} else "valid")
    if mode == "missing":
        assert not store.path.exists()
    else:
        memory, findings, recall = [json.loads(result.stdout) for result in results[:3]]
        if mode == "empty":
            assert memory["target"]["current_handoff"] is None
            assert findings["items"] == recall["target_entries"] == []
            assert json.loads(results[4].stdout)["items"] == []
        else:
            assert memory["target"]["current_handoff"]["entry_id"] == "handoff"
            assert (len(findings["items"]), findings["remaining"]) == (8, 1)
            assert len(recall["target_entries"]) == 8 and recall["target_page"]["has_more"]
            tail = _run(tmp_path, COMMANDS[1], "--cursor", findings["next_cursor"])
            assert tail.returncode == 0, tail.stderr
            assert len(json.loads(tail.stdout)["items"]) == 1
        if mode == "current":
            first = json.loads(results[4].stdout)
            assert len(first["items"]) == 50 and first["next_cursor"]
            tail = _run(tmp_path, COMMANDS[4], "--cursor", first["next_cursor"])
            assert tail.returncode == 0, tail.stderr
            last = json.loads(tail.stdout)
            assert not last["next_cursor"]
            assert {item["url"] for item in first["items"] + last["items"]} == set(urls)
        assert store.binding() == binding
    assert _files(tmp_path) == before
