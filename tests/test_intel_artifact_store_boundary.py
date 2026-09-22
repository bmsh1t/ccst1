from __future__ import annotations

from tools.intel_artifact import write_intel_artifact
from tools.intelligence_extractor import write_intelligence
from tools.target_store import TargetStore


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


def test_intelligence_projection_is_published_outside_primary_store(tmp_path):
    target = "intel-primary.test"
    store = TargetStore(tmp_path, target)
    store.initialize()
    before = store.context(limit=1)["revision"]

    path = write_intelligence(target, tmp_path)

    assert path == tmp_path / "evidence" / target / "intelligence.md"
    assert path.is_file()
    assert store.context(limit=1)["revision"] == before
