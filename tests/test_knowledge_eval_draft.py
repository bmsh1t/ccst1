from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from tools.knowledge_eval_draft import _action_linkage_counts
from tools.target_store import StoreError, TargetStore


@pytest.mark.parametrize("target", ["knowledge-target.test", "192.0.2.0/24"])
@pytest.mark.parametrize("legacy", [False, True])
def test_primary_action_linkage_uses_store_without_legacy_queue(tmp_path, target, legacy):
    store = TargetStore(tmp_path, target)
    store.initialize()
    store.create_action(
        command_id="knowledge-action",
        action_id="A-1",
        intent="review authz card",
        execution_key="work:knowledge",
        actor="ai",
        kind="work",
        subject={"target": target},
    )
    if legacy:
        (store.path.parent / "action_queue.json").write_text(
            json.dumps({"actions": [{"metadata": {"card": "archived-only"}}]}), encoding="utf-8",
        )

    counts = _action_linkage_counts(tmp_path, {"authz": {"authz"}, "archived": {"archived-only"}})

    assert counts["authz"] >= 1
    assert counts["archived"] == 0
    assert _action_linkage_counts(
        tmp_path / "state" / "..", {"authz": {"authz"}, "archived": {"archived-only"}},
    ) == counts


@pytest.mark.parametrize("damage", ["database", "fence", "invalid_fence"])
def test_action_linkage_cannot_turn_store_damage_into_zero_signals(tmp_path, damage):
    store = TargetStore(tmp_path, "knowledge-target.test")
    store.initialize()
    if damage == "database":
        store.path.unlink()
    elif damage == "fence":
        store.fence_path.unlink()
    else:
        store.fence_path.write_text("{broken")
    with pytest.raises(StoreError, match="cannot inspect action signals"):
        _action_linkage_counts(tmp_path, {"authz": {"authz"}})


def test_legacy_only_action_signals_are_not_current(tmp_path):
    state = tmp_path / "state" / "legacy.test"
    state.mkdir(parents=True)
    (state / "action_queue.json").write_text('{"intent": "authz"}')
    assert _action_linkage_counts(tmp_path, {"authz": {"authz"}}) == {"authz": 0}


@pytest.mark.parametrize("unsafe_path", ["fence_symlink", "directory_symlink", "fifo"])
def test_action_signal_discovery_rejects_unsafe_paths_without_blocking(tmp_path, unsafe_path):
    store = TargetStore(tmp_path, "knowledge-target.test")
    store.initialize()
    if unsafe_path == "directory_symlink":
        destination = tmp_path / "redirected"
        store.path.parent.rename(destination)
        store.path.parent.symlink_to(destination, target_is_directory=True)
    else:
        fence = store.fence_path.read_bytes()
        store.fence_path.unlink()
        if unsafe_path == "fence_symlink":
            destination = tmp_path / "redirected.json"
            destination.write_bytes(fence)
            store.fence_path.symlink_to(destination)
        else:
            os.mkfifo(store.fence_path)

    result = subprocess.run(
        [sys.executable, "-B", "-c", """
import sys
from pathlib import Path
from tools.knowledge_eval_draft import _action_linkage_counts
from tools.target_store import StoreError
try:
    _action_linkage_counts(Path(sys.argv[1]), {"authz": {"authz"}})
except StoreError as exc:
    print(exc)
else:
    raise AssertionError("unsafe discovery path was accepted")
""", str(tmp_path)],
        cwd=Path(__file__).resolve().parents[1],
        capture_output=True, text=True, timeout=5,
    )
    assert result.returncode == 0, result.stderr
    assert "cannot inspect action signals" in result.stdout
    assert ("regular file" if unsafe_path == "fifo" else "symlinks") in result.stdout
