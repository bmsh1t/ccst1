from __future__ import annotations

import pytest

from tools.intel_continuation import _final_queue_dispositions
from tools.intel_artifact import write_intel_artifact
from tools.target_store import StoreError, TargetStore


def test_intel_artifact_is_an_advisory_file_not_primary_domain_state(tmp_path):
    target = "intel-primary.test"
    store = TargetStore(tmp_path, target)
    store.initialize()
    before = store.context(limit=1)["revision"]

    path = write_intel_artifact(
        tmp_path,
        target,
        {
            "schema_version": 2,
            "target": target,
            "coverage_status": "unavailable",
            "inventory": {},
            "sources": [{"source": "fixture", "status": "unavailable"}],
            "advisories": [],
            "critical": [],
            "high": [],
            "info": [],
        },
    )

    assert path.is_file()
    assert store.context(limit=1)["revision"] == before
    assert store.context(limit=1)["counts"] == {
        "actions": 0, "attempts": 0, "operations": 0, "findings": 0, "experiences": 0
    }


def test_retired_intelligence_extractor_is_not_a_second_owner():
    from pathlib import Path
    assert not (Path(__file__).resolve().parents[1] / "tools/intelligence_extractor.py").exists()




def test_intel_continuation_rejects_missing_fenced_store(tmp_path):
    target = "intel-primary.test"
    store = TargetStore(tmp_path, target)
    store.initialize()
    store.path.rename(store.path.with_suffix(".offline"))

    with pytest.raises(StoreError, match="fenced target store missing"):
        _final_queue_dispositions(tmp_path, target)


def test_intel_continuation_rejects_legacy_without_implicit_initialization(tmp_path):
    target = "legacy-intel.test"
    queue_path = tmp_path / "state" / target / "action_queue.json"
    queue_path.parent.mkdir(parents=True)
    queue_path.write_text("{broken", encoding="utf-8")

    with pytest.raises(StoreError, match="not initialized"):
        _final_queue_dispositions(tmp_path, target)
    assert queue_path.read_text() == "{broken"
    assert not TargetStore(tmp_path, target).path.exists()
