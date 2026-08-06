"""Target Memory publication and corruption contracts."""

from pathlib import Path
import multiprocessing

import pytest

from tools import target_memory
from tools.autopilot_state import load_target_goal_memory


def _append_target_memory_worker(targets_dir, sessions_dir, target, text, output):
    target_memory.TARGETS_DIR = Path(targets_dir)
    target_memory.SESSIONS_DIR = Path(sessions_dir)
    try:
        target_memory.append_entry(
            type("Args", (), {"target": target, "text": [text]})(),
            "next_actions",
            "NEXT",
        )
        output.put("ok")
    except Exception as exc:  # pragma: no cover - surfaced through parent assertion
        output.put(str(exc))


def test_corrupt_existing_target_memory_is_not_replaced_with_empty_state(tmp_path, monkeypatch):
    monkeypatch.setattr(target_memory, "TARGETS_DIR", tmp_path / "targets")
    path = target_memory.target_memory_path("target.com")
    path.parent.mkdir(parents=True)
    path.write_text("{broken", encoding="utf-8")

    with pytest.raises(ValueError, match="invalid target memory JSON"):
        target_memory.load_target_memory("target.com")

    assert path.read_text(encoding="utf-8") == "{broken"


def test_autopilot_target_memory_projection_rejects_corruption(tmp_path):
    path = tmp_path / "memory" / "goals" / "targets" / "target.com.json"
    path.parent.mkdir(parents=True)
    path.write_text("{broken", encoding="utf-8")

    with pytest.raises(ValueError, match="invalid target memory JSON"):
        load_target_goal_memory(str(tmp_path), "target.com")


def test_target_memory_cli_reports_corruption_without_traceback(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(target_memory, "TARGETS_DIR", tmp_path / "targets")
    path = target_memory.target_memory_path("target.com")
    path.parent.mkdir(parents=True)
    path.write_text("{broken", encoding="utf-8")

    assert target_memory.main(["show", "target.com"]) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "target memory command failed: invalid target memory JSON" in captured.err
    assert "Traceback" not in captured.err


def test_atomic_target_memory_write_preserves_previous_file_on_replace_failure(tmp_path, monkeypatch):
    path = tmp_path / "target.json"
    path.write_text('{"old": true}\n', encoding="utf-8")
    previous = path.read_bytes()
    original_replace = Path.replace

    def fail_replace(self, target):
        if Path(target) == path:
            raise OSError("synthetic replace failure")
        return original_replace(self, target)

    monkeypatch.setattr(Path, "replace", fail_replace)

    with pytest.raises(OSError, match="synthetic replace failure"):
        target_memory.write_json(path, {"new": True})

    assert path.read_bytes() == previous
    assert list(path.parent.glob(f".{path.name}.*.tmp")) == []


def test_target_memory_append_is_serialized_across_processes(tmp_path, monkeypatch):
    targets_dir = tmp_path / "targets"
    sessions_dir = tmp_path / "sessions"
    monkeypatch.setattr(target_memory, "TARGETS_DIR", targets_dir)
    monkeypatch.setattr(target_memory, "SESSIONS_DIR", sessions_dir)
    context = multiprocessing.get_context("fork")
    output = context.Queue()
    workers = [
        context.Process(
            target=_append_target_memory_worker,
            args=(str(targets_dir), str(sessions_dir), "target.com", f"next-{index}", output),
        )
        for index in range(12)
    ]
    for process in workers:
        process.start()
    results = [output.get(timeout=15) for _ in workers]
    for process in workers:
        process.join(timeout=15)

    payload = target_memory.load_target_memory("target.com")
    assert all(process.exitcode == 0 for process in workers)
    assert results.count("ok") == len(workers)
    assert {item["text"] for item in payload["next_actions"]} == {
        f"next-{index}" for index in range(12)
    }
