"""Primary Intel context must use the requested target's current owners."""

import json

from memory.target_profile import make_target_profile
from legacy_fixtures import write_legacy_profile
from tools import intel_engine
from tools.target_store import TargetStore


def test_primary_memory_context_ignores_retired_profile_and_journal(tmp_path):
    target = "intel-context.test"
    store = TargetStore(tmp_path, target)
    store.initialize()
    store.create_finding(
        command_id="finding-1", finding_id="finding-1",
        endpoint=f"https://{target}/current", method="GET", family="Authz",
        title="Current claim", claim="Review current boundary", actor="ai",
    )
    memory_dir = tmp_path / "hunt-memory"
    write_legacy_profile(memory_dir, make_target_profile(
        target, tech_stack=["retired-stack"], tested_endpoints=["/retired"],
        hunt_sessions=99,
    ))
    (memory_dir / "journal.jsonl").write_text(
        json.dumps({"target": target, "tags": ["CVE-2020-0001"]}) + "\n",
        encoding="utf-8",
    )

    context = intel_engine.load_memory_context(str(memory_dir), target, repo_root=tmp_path)

    assert context["tested_endpoints"] == []  # a saved claim is not an execution
    assert context["findings"][0]["endpoint"] == "/current"
    assert context["tech_stack"] == []
    assert context["hunt_sessions"] == 0
    assert context["tested_cves"] == []


def test_intel_cli_passes_requested_repo_root_to_memory_context(tmp_path, monkeypatch):
    seen = []

    def load_context(memory_dir, target, *, repo_root=None):
        seen.append(repo_root)
        return {}

    monkeypatch.setattr(intel_engine, "load_memory_context", load_context)
    monkeypatch.setattr(intel_engine, "resolve_tech_stack", lambda *_args, **_kwargs: [])

    assert intel_engine.main(["--target", "intel-context.test", "--repo-root", str(tmp_path)]) == 1
    assert seen == [str(tmp_path)]
