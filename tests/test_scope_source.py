"""Scope survives Profile retirement and refuses lost or changed configuration."""

import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest

from memory.target_profile import make_target_profile
from legacy_fixtures import write_legacy_profile
from tools.request_guard import preflight_request
from tools.scope_source import (
    load_scope_context, publish_scope_source,
    read_scope_source, scope_source_from_profile, scope_source_path,
)
from tools.target_migration import import_target_staged, preview_target, promote_target, publish_preview
from tools.target_store import TargetStore, initialize_target_store

TARGET = "scope.test"
TOOLS = Path(__file__).resolve().parents[1] / "tools"
SNAPSHOT = {
    "in_scope": ["api.scope.test", "partner.test"],
    "out_of_scope": ["admin.scope.test"],
    "excluded_classes": ["dos"],
    "recon_rps": 0.05,
    "test_rps": 0.025,
    "breaker_threshold": 2,
    "breaker_cooldown": 25,
    "fetched_at": "2026-09-24T00:00:00Z",
}


def _cli(tool, *args, cwd):
    return subprocess.run([sys.executable, "-B", str(TOOLS / tool), *map(str, args)],
                          cwd=cwd, capture_output=True, text=True, timeout=15)


def _configured(root):
    initialize_target_store(root, TARGET)
    before = read_scope_source(root, TARGET)
    manifest = scope_source_from_profile(make_target_profile(TARGET, scope_snapshot=SNAPSHOT), TARGET)
    return publish_scope_source(root, TARGET, manifest, expected_sha256=before["sha256"])


def test_fresh_init_scope_and_explicit_cli_profile_import(tmp_path):
    root = tmp_path / "space in root"
    root.mkdir()
    result = _cli("target_store.py", "init", "--store", "--target", TARGET, "--repo-root", root, cwd=root)
    assert result.returncode == 0, result.stderr
    initial = read_scope_source(root, TARGET)
    binding = TargetStore(root, TARGET).binding()
    assert load_scope_context(root, TARGET).allows_active(f"https://{TARGET}")
    assert not load_scope_context(root, TARGET).allows_active("https://partner.test")
    profile = root / "profile-export.json"
    profile.write_text(json.dumps(make_target_profile(TARGET, scope_snapshot=SNAPSHOT)))
    argv = ("publish", "--target", TARGET, "--repo-root", root, "--profile", profile,
            "--expected-sha256", initial["sha256"])
    published = _cli("scope_source.py", *argv, cwd=root)
    assert published.returncode == 0, published.stderr
    assert json.loads(published.stdout)["status"] == "published"
    replay = _cli("scope_source.py", *argv, cwd=root)
    assert replay.returncode == 0, replay.stderr
    assert json.loads(replay.stdout)["status"] == "deduplicated"
    profile.unlink()
    shown = _cli("scope_source.py", "show", "--target", TARGET, "--repo-root", root, cwd=root)
    assert shown.returncode == 0, shown.stderr
    assert json.loads(shown.stdout)["manifest"]["test_rps"] == 0.025
    assert TargetStore(root, TARGET).binding() == binding
    assert not (root / "hunt-memory").exists()


def test_migration_scope_remains_usable_without_profile_in_new_process(tmp_path, monkeypatch):
    monkeypatch.delenv("HUNT_MEMORY_DIR", raising=False)
    source = tmp_path / "source"
    profile = write_legacy_profile(source / "hunt-memory", make_target_profile(TARGET, scope_snapshot=SNAPSHOT))
    source_before = {p.relative_to(source): p.read_bytes() for p in source.rglob("*") if p.is_file()}
    preview = preview_target(source, TARGET)
    assert preview["scope"]["test_rps"] == 0.025
    assert {p.relative_to(source): p.read_bytes() for p in source.rglob("*") if p.is_file()} == source_before
    staging, active = tmp_path / "staging", tmp_path / "active root"
    imported = import_target_staged(source, staging, TARGET)
    assert imported["receipt"]["scope_sha256"] == read_scope_source(staging, TARGET)["sha256"]
    assert profile.relative_to(source).as_posix() in {p["path"] for p in imported["source_manifest"]["files"]}
    publish_preview(staging, active, TARGET)
    promote_target(active, TARGET)
    (active / profile.relative_to(source)).unlink()
    binding = TargetStore(active, TARGET).binding()
    # An unusable old owner and an external memory override must never influence primary Scope.
    (active / profile.relative_to(source)).write_text("{corrupt")
    monkeypatch.setenv("HUNT_MEMORY_DIR", str(tmp_path / "external-memory"))
    scope = load_scope_context(active, TARGET)
    assert scope.allows_active("https://partner.test")
    assert not scope.allows_active("https://admin.scope.test")
    assert not scope.allows_vulnerability_class("DOS")
    args = ("--repo-root", active, "--memory-dir", tmp_path / "telemetry", "--target", TARGET,
            "--url", "https://admin.scope.test/", "--method", "GET", "--json")
    result = _cli("request_guard.py", "preflight", *args, "--vuln-class", "dos", cwd=active)
    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload["scope_check"] == "fail"
    assert payload["scope"]["source"] == "scope"
    assert payload["settings"] == {key: SNAPSHOT[key] for key in
                                   ("test_rps", "recon_rps", "breaker_threshold", "breaker_cooldown")}
    assert set(payload["setting_sources"].values()) == {"scope"}
    status = _cli("request_guard.py", "status", "--repo-root", active,
                  "--memory-dir", tmp_path / "telemetry", "--target", TARGET, "--json", cwd=active)
    assert status.returncode == 0, status.stderr
    assert json.loads(status.stdout)["settings"]["test_rps"] == 0.025
    for _ in range(2):
        result = _cli("request_guard.py", "record", *args, "--status", 429, cwd=active)
        assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["just_tripped"]
    assert TargetStore(active, TARGET).binding() == binding
    assert {p.relative_to(source): p.read_bytes() for p in source.rglob("*") if p.is_file()} == source_before


@pytest.mark.parametrize("damage", ["missing", "corrupt", "foreign", "symlink", "public"])
def test_primary_scope_failure_never_uses_profile_or_reinitializes(tmp_path, damage):
    _configured(tmp_path)
    write_legacy_profile(tmp_path / "hunt-memory", make_target_profile(TARGET, scope_snapshot={}))
    path = scope_source_path(tmp_path, TARGET)
    if damage == "missing":
        path.unlink()
    elif damage == "corrupt":
        path.write_text("{")
    elif damage == "foreign":
        manifest = read_scope_source(tmp_path, TARGET)["manifest"]
        manifest["root_target"] = "another.test"
        path.write_text(json.dumps(manifest))
    elif damage == "symlink":
        backup = tmp_path / "saved-scope.json"
        path.rename(backup)
        path.symlink_to(backup)
    else:
        path.chmod(0o644)
    original = path.read_bytes() if path.exists() else None
    binding = TargetStore(tmp_path, TARGET).binding()
    for read in (lambda: load_scope_context(tmp_path, TARGET),
                 lambda: initialize_target_store(tmp_path, TARGET),
                 lambda: preflight_request(repo_root=tmp_path, memory_dir=tmp_path / "telemetry",
                                           target=TARGET, url="https://admin.scope.test/", method="GET")):
        with pytest.raises(ValueError, match="scope source"):
            read()
    assert (path.read_bytes() if path.exists() else None) == original
    assert TargetStore(tmp_path, TARGET).binding() == binding
    assert not (tmp_path / "telemetry").exists()


def test_scope_replace_conflict_and_interruption_preserve_old_configuration(tmp_path, monkeypatch):
    source = _configured(tmp_path)
    path = scope_source_path(tmp_path, TARGET)
    before = path.read_bytes()
    changed = {**source["manifest"], "out_of_scope": ["api.scope.test"]}
    with pytest.raises(ValueError, match="scope source changed"):
        publish_scope_source(tmp_path, TARGET, changed)
    with pytest.raises(ValueError, match="scope source changed"):
        publish_scope_source(tmp_path, TARGET, changed, expected_sha256="a" * 64)
    real_replace = Path.replace

    def fail_replace(self, destination):
        if destination == path:
            raise OSError("publication interrupted")
        return real_replace(self, destination)

    monkeypatch.setattr(Path, "replace", fail_replace)
    with pytest.raises(OSError, match="publication interrupted"):
        publish_scope_source(tmp_path, TARGET, changed, expected_sha256=source["sha256"])
    assert path.read_bytes() == before
    assert not list(path.parent.glob(".scope.*.tmp"))
    monkeypatch.setattr(Path, "replace", real_replace)
    publish_scope_source(tmp_path, TARGET, changed, expected_sha256=source["sha256"])
    assert not load_scope_context(tmp_path, TARGET).allows_active("https://api.scope.test")


@pytest.mark.parametrize("field,value", [
    ("root_target", None), ("root_target", 1), ("out_of_scope", "admin.scope.test"),
    ("test_rps", 0), ("test_rps", -1), ("test_rps", float("nan")),
    ("recon_rps", float("inf")), ("breaker_threshold", 1.5), ("breaker_threshold", True),
    ("breaker_cooldown", None), ("excluded_class", ["dos"]),
])
def test_invalid_scope_is_rejected_before_publication(tmp_path, field, value):
    manifest = {"schema_version": 1, "root_target": TARGET, field: value}
    with pytest.raises(ValueError):
        publish_scope_source(tmp_path, TARGET, manifest)
    assert not (tmp_path / "state").exists()


@pytest.mark.parametrize("stage", ["publish", "promote"])
def test_changed_migration_scope_cannot_activate(tmp_path, stage, monkeypatch):
    monkeypatch.delenv("HUNT_MEMORY_DIR", raising=False)
    source = tmp_path / "source"
    write_legacy_profile(source / "hunt-memory", make_target_profile(TARGET, scope_snapshot=SNAPSHOT))
    staging, active = tmp_path / "staging", tmp_path / "active"
    import_target_staged(source, staging, TARGET)
    if stage == "promote":
        publish_preview(staging, active, TARGET)
        staging = active
    path = scope_source_path(staging, TARGET)
    payload = json.loads(path.read_text())
    payload["out_of_scope"] = []
    path.write_text(json.dumps(payload))
    with pytest.raises(ValueError, match="Scope changed"):
        if stage == "publish":
            publish_preview(staging, active, TARGET)
        else:
            promote_target(active, TARGET)
    assert not (path.parent / "legacy-frozen.json").exists()


def test_explicit_repair_binds_corrupt_bytes_and_preserves_exclusions(tmp_path):
    configured = _configured(tmp_path)
    path = scope_source_path(tmp_path, TARGET)
    path.write_text('{"out_of_scope":')
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    with pytest.raises(ValueError, match="invalid scope source"):
        publish_scope_source(tmp_path, TARGET, configured["manifest"], expected_sha256=configured["sha256"])
    publish_scope_source(tmp_path, TARGET, configured["manifest"], expected_sha256=digest)
    assert not load_scope_context(tmp_path, TARGET).allows_active("https://admin.scope.test")
    path.unlink()
    publish_scope_source(tmp_path, TARGET, configured["manifest"])
    assert read_scope_source(tmp_path, TARGET)["manifest"] == configured["manifest"]


def test_recon_and_host_verification_read_published_scope(tmp_path, monkeypatch):
    from tools.recon_candidates import build_recon_candidates
    from tools import recon_host_verify
    from tools.runtime_state import inspect_recon_artifacts

    configured = _configured(tmp_path)
    exposure = tmp_path / "recon" / TARGET / "exposure"
    exposure.mkdir(parents=True)
    source = exposure / "asset_relation_observations.jsonl"
    source.write_text("\n".join(json.dumps({
        "schema_version": 1, "kind": "asset-relation-observation", "asset_type": "domain",
        "value": host, "relation": "ownership", "related": [TARGET],
        "source": "ownership-record", "source_ref": host, "confidence": "high",
    }) for host in ("admin.scope.test", "api.scope.test", "partner.test")) + "\n")
    page = build_recon_candidates(tmp_path, TARGET, asset_input=source, asset_limit=1)
    rows = [json.loads(line) for line in (exposure / "asset_relation_candidates.jsonl").read_text().splitlines()]
    cursor = page["asset_relation_next_cursor"]
    while cursor:
        next_page = build_recon_candidates(tmp_path, TARGET, asset_input=source,
                                          asset_limit=1, asset_cursor=cursor)
        rows.extend(json.loads(line) for line in (exposure / "asset_relation_candidates.jsonl").read_text().splitlines())
        cursor = next_page["asset_relation_next_cursor"]
    assert {row["value"]: row["scope_status"] for row in rows} == {
        "admin.scope.test": "excluded", "api.scope.test": "in_scope", "partner.test": "in_scope",
    }
    (exposure / "host_pivot_candidates.jsonl").write_text("\n".join(json.dumps({
        "value": host, "related": [], "signals": ["cname"],
    }) for host in ("admin.scope.test", "partner.test")) + "\n")
    calls = []

    def probe(host, **kwargs):
        calls.append(host)
        return {"status": 200}

    monkeypatch.setattr(recon_host_verify, "_probe", probe)
    result = recon_host_verify.verify(tmp_path, TARGET)
    assert result["probe_count"] == 1
    assert calls == ["partner.test"]
    changed = {**configured["manifest"], "out_of_scope": ["admin.scope.test", "partner.test"]}
    publish_scope_source(tmp_path, TARGET, changed, expected_sha256=configured["sha256"])
    assert "Scope changed" in inspect_recon_artifacts(tmp_path, TARGET)["asset_relations"]["error"]
    with pytest.raises(ValueError, match="cursor source changed"):
        build_recon_candidates(tmp_path, TARGET, asset_input=source, asset_limit=1,
                               asset_cursor=page["asset_relation_next_cursor"])
    scope_source_path(tmp_path, TARGET).unlink()
    with pytest.raises(ValueError, match="scope source unavailable"):
        recon_host_verify.verify(tmp_path, TARGET)
    assert calls == ["partner.test"]


def test_invalid_profile_and_external_scope_are_not_silently_lost_by_migration(tmp_path, monkeypatch):
    source = tmp_path / "source"
    source.mkdir()
    external = tmp_path / "external"
    write_legacy_profile(external, make_target_profile(TARGET, scope_snapshot=SNAPSHOT))
    monkeypatch.setenv("HUNT_MEMORY_DIR", str(external))
    with pytest.raises(ValueError, match="export the external target Profile"):
        import_target_staged(source, tmp_path / "destination", TARGET)
    assert not (tmp_path / "destination").exists()
    monkeypatch.delenv("HUNT_MEMORY_DIR")
    profile = write_legacy_profile(source / "hunt-memory", make_target_profile(TARGET, scope_snapshot=SNAPSHOT))
    profile.write_text("{broken")
    with pytest.raises(ValueError, match="invalid target profile"):
        import_target_staged(source, tmp_path / "destination", TARGET)
    assert not (tmp_path / "destination").exists()


def test_primary_scope_controls_bootstrap_continuation_and_state(tmp_path, monkeypatch):
    from tools import autopilot_bootstrap
    from tools.autopilot_continuation import create_continuation, load_continuation
    from tools.autopilot_state import _scope_identity

    configured = _configured(tmp_path)
    scope = load_scope_context(tmp_path, TARGET)
    binding = TargetStore(tmp_path, TARGET).binding()
    created = create_continuation(tmp_path, parent_target=TARGET, selected_target="partner.test")
    assert created["continuation"]["scope_ref"] == str(scope_source_path(tmp_path, TARGET))
    loaded = load_continuation(tmp_path, created["path"], selected_target="partner.test")
    assert loaded["scope_context"].scope_hash == scope.scope_hash
    assert _scope_identity(tmp_path, TARGET)["scope_hash"] == scope.scope_hash
    with pytest.raises(ValueError, match="not in parent Scope"):
        create_continuation(tmp_path, parent_target=TARGET, selected_target="admin.scope.test")

    monkeypatch.setattr(autopilot_bootstrap, "compare_runtime", lambda *args, **kwargs: {
        "clean": True, "critical_clean": True, "drift_count": 0, "kinds": [],
    })
    monkeypatch.setattr(autopilot_bootstrap, "build_capability_profile",
                        lambda *args: {"schema_version": 1, "checked": True, "status": "ready"})
    monkeypatch.setattr(autopilot_bootstrap, "build_autopilot_bootstrap_state",
                        lambda root, target: {"target": target, "target_kind": "domain", "next_action": "run_recon"})
    payload = autopilot_bootstrap.build_autopilot_bootstrap([TARGET], repo_root=tmp_path)
    assert payload["action"] == "continue"
    assert payload["scope"]["scope_hash"] == scope.scope_hash
    changed = {**configured["manifest"], "out_of_scope": ["admin.scope.test", "partner.test"]}
    publish_scope_source(tmp_path, TARGET, changed, expected_sha256=configured["sha256"])
    with pytest.raises(ValueError, match="Scope hash is stale"):
        load_continuation(tmp_path, created["path"], selected_target="partner.test")
    scope_source_path(tmp_path, TARGET).unlink()

    def reject_runtime(*args, **kwargs):
        raise AssertionError("invalid Scope reached runtime setup")

    monkeypatch.setattr(autopilot_bootstrap, "compare_runtime", reject_runtime)
    payload = autopilot_bootstrap.build_autopilot_bootstrap([TARGET], repo_root=tmp_path)
    assert payload["action"] == "stop_invalid_scope"
    assert _scope_identity(tmp_path, TARGET)["status"] == "invalid"
    assert TargetStore(tmp_path, TARGET).binding() == binding


def test_ffuf_cli_scope_exclusions_and_change_invalidate_rotation(tmp_path):
    from tools.recon_target_selector import load_rotation_status

    configured = _configured(tmp_path)
    directory = tmp_path / "recon" / TARGET / "dirs"
    directory.mkdir(parents=True)
    urls = directory / "urls.txt"
    urls.write_text("https://scope.test\nhttps://admin.scope.test\nhttps://partner.test\n")
    wordlist = directory / "wordlist.txt"
    wordlist.write_text("health\n")
    state, plan, selected = (directory / name for name in
                              ("ffuf_target_state.json", "ffuf_target_plan.json", "ffuf_targets.txt"))
    args = ("--repo-root", tmp_path, "--target", TARGET, "--state", state)
    selection_args = ("--select", *args, "--urls", urls, "--httpx", directory / "missing.txt",
                      "--wordlist", wordlist, "--plan", plan, "--targets", selected, "--limit", 3)
    result = _cli("recon_target_selector.py", *selection_args, cwd=tmp_path)
    assert result.returncode == 0, result.stdout + result.stderr
    assert set(selected.read_text().splitlines()) == {"https://scope.test", "https://partner.test"}
    results = directory / "results.tsv"
    results.write_text("https://scope.test\tok\n")
    recording_args = ("--record-results", *args, "--results", results)
    result = _cli("recon_target_selector.py", *recording_args, cwd=tmp_path)
    assert result.returncode == 0, result.stdout + result.stderr
    assert load_rotation_status(tmp_path, TARGET)["remaining"] == 1
    bound_state = state.read_bytes()
    unbound = json.loads(bound_state)
    unbound.pop("scope_hash")
    state.write_text(json.dumps(unbound))
    assert load_rotation_status(tmp_path, TARGET)["status"] == "invalid"
    result = _cli("recon_target_selector.py", *recording_args, cwd=tmp_path)
    assert result.returncode == 2
    assert "binding missing" in result.stdout
    state.write_bytes(bound_state)
    before = state.read_bytes()
    changed = {**configured["manifest"], "out_of_scope": ["admin.scope.test", "partner.test"]}
    publish_scope_source(tmp_path, TARGET, changed, expected_sha256=configured["sha256"])
    result = _cli("recon_target_selector.py", *recording_args, cwd=tmp_path)
    assert result.returncode == 2
    assert "Scope changed" in result.stdout
    assert state.read_bytes() == before
    assert load_rotation_status(tmp_path, TARGET)["status"] == "invalid"
    result = _cli("recon_target_selector.py", *selection_args, cwd=tmp_path)
    assert result.returncode == 0, result.stdout + result.stderr
    assert selected.read_text().splitlines() == ["https://scope.test"]
    assert json.loads(state.read_text())["completed"] == {}
    before = {path: path.read_bytes() for path in (state, plan, selected)}
    scope_source_path(tmp_path, TARGET).unlink()
    result = _cli("recon_target_selector.py", *selection_args, cwd=tmp_path)
    assert result.returncode == 2
    assert "scope source unavailable" in result.stdout
    assert {path: path.read_bytes() for path in before} == before


def test_publication_retry_finishes_interrupted_directory_sync(tmp_path, monkeypatch):
    from tools import scope_context

    configured = _configured(tmp_path)
    changed = {**configured["manifest"], "test_rps": 0.01}
    real_sync = scope_context._sync_scope_directory

    def failed_sync(path):
        raise OSError("directory sync interrupted")

    monkeypatch.setattr(scope_context, "_sync_scope_directory", failed_sync)
    for _ in range(2):
        with pytest.raises(OSError, match="directory sync interrupted"):
            publish_scope_source(tmp_path, TARGET, changed, expected_sha256=configured["sha256"])
    assert read_scope_source(tmp_path, TARGET)["manifest"]["test_rps"] == 0.01
    monkeypatch.setattr(scope_context, "_sync_scope_directory", real_sync)
    receipt = publish_scope_source(tmp_path, TARGET, changed, expected_sha256=configured["sha256"])
    assert receipt["status"] == "deduplicated"


@pytest.mark.parametrize("snapshot", [{"root_target": "other.test"}, {"schema_version": 2}])
def test_profile_scope_identity_is_not_silently_rewritten(snapshot):
    with pytest.raises(ValueError):
        scope_source_from_profile(make_target_profile(TARGET, scope_snapshot=snapshot), TARGET)


def test_fresh_scope_is_read_only_before_explicit_store_initialization(tmp_path):
    from tools.scope_source import load_scope_source
    source = load_scope_source(tmp_path, TARGET)
    assert source["source"] == "target"
    assert load_scope_context(tmp_path, TARGET).allows_active(f"https://{TARGET}/")
    assert not load_scope_context(tmp_path, TARGET).allows_active("https://elsewhere.test/")
    assert list(tmp_path.iterdir()) == []
    initialize_target_store(tmp_path, TARGET)
    assert load_scope_source(tmp_path, TARGET)["source"] == "scope"


def test_preinit_scope_never_ignores_legacy_profile_exclusions(tmp_path):
    write_legacy_profile(tmp_path / "hunt-memory", make_target_profile(TARGET, scope_snapshot=SNAPSHOT))
    with pytest.raises(ValueError, match="explicit import"):
        load_scope_context(tmp_path, TARGET)
    assert not (tmp_path / "state").exists()
