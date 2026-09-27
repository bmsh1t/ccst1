"""Scanner material survives Store registration without becoming a verdict."""

import json
import os
from contextlib import nullcontext
from pathlib import Path
import shutil
import subprocess

import pytest

import finding_index
import intel_engine
from tools.target_store import StoreError, TargetStore
from tools.runtime_state import runtime_phase_lock


def _scanner_material(tmp_path):
    store = TargetStore(tmp_path, "scanner.test")
    store.initialize()
    root = tmp_path / "findings/scanner.test"
    source = root / "cves/results.txt"
    source.parent.mkdir(parents=True)
    source.write_text("[CVE-2026-1234] [http] [high] https://scanner.test/item\n")
    return store, root, source


def test_scanner_registers_replayable_material_without_execution_or_legacy_writes(tmp_path):
    store, root, source = _scanner_material(tmp_path)
    legacy = root / "findings.json"
    legacy.write_text('{"target":"scanner.test","findings":[{"id":"old"}]}')
    before = legacy.read_bytes()
    first = finding_index.index_scanner_material(root)
    action = store.action(first["review_action_ids"][0])
    snapshot = tmp_path / action["subject_artifact"]["ref"]
    captured = snapshot.read_bytes()
    revision = store.binding()["revision"]
    second = finding_index.index_scanner_material(root)

    assert first["review_action_ids"] == second["review_action_ids"]
    assert store.binding()["revision"] == revision
    assert action["kind"] == "work"
    assert action["status"] == "ready"
    assert store.finding_page()["total"] == 0
    assert store.page("operations")["total"] == 0
    assert legacy.read_bytes() == before
    source.write_text("[CVE-2026-1234] [http] [high] https://scanner.test/other\n")
    third = finding_index.index_scanner_material(root)
    assert third["review_action_ids"] != first["review_action_ids"]
    assert snapshot.read_bytes() == captured
    assert json.loads(captured)["material"]["findings"][0]["template_id"] == "CVE-2026-1234"


def test_scanner_registration_failure_keeps_material_for_retry(tmp_path, monkeypatch):
    store, root, source = _scanner_material(tmp_path)
    before = source.read_bytes()
    original = TargetStore.create_action

    def fail_registration(*args, **kwargs):
        raise StoreError("injected registration failure")

    monkeypatch.setattr(TargetStore, "create_action", fail_registration)
    with pytest.raises(StoreError, match="injected"):
        finding_index.index_scanner_material(root)
    assert source.read_bytes() == before
    assert len(list(source.parent.glob("*.review-*.json"))) == 1
    assert not (root / "scanner_candidates.json").exists()
    monkeypatch.setattr(TargetStore, "create_action", original)
    result = finding_index.index_scanner_material(root)
    assert len(result["review_action_ids"]) == 1
    assert store.page("actions")["total"] == 1
    assert len(list(source.parent.glob("*.review-*.json"))) == 1


def test_uninitialized_scanner_does_not_publish_or_initialize(tmp_path):
    root = tmp_path / "findings/scanner.test"
    root.mkdir(parents=True)
    with pytest.raises(StoreError, match="not initialized"):
        finding_index.index_scanner_material(root)
    assert not TargetStore(tmp_path, "scanner.test").path.exists()
    assert not (root / "scanner_candidates.json").exists()


def test_scanner_refuses_legacy_index_destination(tmp_path):
    _, root, _ = _scanner_material(tmp_path)
    with pytest.raises(StoreError, match="scanner_candidates.json"):
        finding_index.index_scanner_material(root, output=root / "findings.json")
    assert not (root / "findings.json").exists()


def test_intel_local_cve_signal_uses_raw_material_not_legacy_finding(tmp_path):
    store, root, _ = _scanner_material(tmp_path)
    (root / "findings.json").write_text("broken retired index")
    before = store.binding()
    signal = intel_engine.load_local_advisory_signals(tmp_path, store.target)
    assert signal["status"] == "ok"
    assert list(signal["items"]) == ["CVE-2026-1234"]
    assert signal["items"]["CVE-2026-1234"][0]["validation_status"] == "unvalidated"
    assert store.binding() == before


def test_scanner_session_material_uses_target_owner_and_distinct_source(tmp_path):
    store, root, source = _scanner_material(tmp_path)
    first = finding_index.index_scanner_material(root)
    session = root / "sessions" / "one"
    nested = session / "cves/results.txt"
    nested.parent.mkdir(parents=True)
    nested.write_bytes(source.read_bytes())
    second = finding_index.index_scanner_material(session)
    assert second["target"] == store.target
    assert second["review_action_ids"] != first["review_action_ids"]
    action = store.action(second["review_action_ids"][0])
    assert "sessions/one/" in action["subject_artifact"]["ref"]
    assert (session / "scanner_candidates.json").is_file()


def test_root_claims_remain_raw_complete_material_without_fabricated_facts(tmp_path):
    store, root, _ = _scanner_material(tmp_path)
    claim = {"kind": "finding_claim", "title": "incomplete observation",
             "description": "Preserve this detail for manual review", "status": "validated"}
    (root / "a-claim.json").write_text(json.dumps(claim))
    (root / "findings.json").write_text("broken retired index")
    payload = finding_index.index_scanner_material(root)
    assert payload["root_claims"][0]["claim_status"] == "incomplete"
    assert payload["root_claims"][0]["validation_status"] == "candidate"
    assert payload["root_claims"][0]["claim_payload"] == claim
    snapshots = [tmp_path / store.action(action)["subject_artifact"]["ref"]
                 for action in payload["review_action_ids"]]
    assert any(json.loads(path.read_text())["material"]["findings"][0].get("claim_payload") == claim
               for path in snapshots)
    revision = store.binding()["revision"]
    assert len(finding_index.list_root_finding_claims(root, target=store.target)) == 1
    assert finding_index.index_scanner_material(root)["review_action_ids"] == payload["review_action_ids"]
    assert store.binding()["revision"] == revision
    assert store.finding_page()["total"] == 0
    assert store.page("operations")["total"] == 0


def test_direct_scanner_refuses_uninitialized_before_material(tmp_path):
    repo = Path(__file__).resolve().parents[1]
    scripts = tmp_path / "tools"
    scripts.mkdir()
    for name in ("vuln_scanner.sh", "_auth_helper.sh"):
        shutil.copyfile(repo / "tools" / name, scripts / name)
    recon = tmp_path / "recon/scanner.test"
    recon.mkdir(parents=True)
    env = {**os.environ, "PYTHONPATH": str(repo), "BBHUNT_RUNTIME_PHASE_LOCKED": "scan",
           "BBHUNT_RUNTIME_LOCK_TARGET": "scanner.test", "BBHUNT_AUTH_HEADERS": ""}
    result = subprocess.run(["bash", str(scripts / "vuln_scanner.sh"), str(recon)],
                            env=env, capture_output=True, text=True, timeout=10)
    assert result.returncode == 2
    assert "not initialized" in result.stderr
    assert "Traceback" not in result.stderr
    assert not (tmp_path / "findings").exists()
    assert not TargetStore(tmp_path, "scanner.test").path.exists()


@pytest.mark.parametrize("manifest_target", ["https://SCANNER.test/app?view=1#tab", "scanner.test", None])
@pytest.mark.parametrize("busy", [False, True])
def test_direct_scanner_startup_uses_canonical_lock_identity(tmp_path, manifest_target, busy):
    repo = Path(__file__).resolve().parents[1]
    scripts = tmp_path / "tools"
    scripts.mkdir()
    for name in ("vuln_scanner.sh", "_auth_helper.sh", "runtime_phase_exec.py"):
        shutil.copyfile(repo / "tools" / name, scripts / name)
    store = TargetStore(tmp_path, "scanner.test")
    store.initialize()
    before = store.binding()
    recon = tmp_path / "recon" / store.key
    recon.mkdir(parents=True)
    if manifest_target is not None:
        (recon / "recon_manifest.jsonl").write_text(json.dumps({"target": manifest_target}) + "\n")
    env = {key: value for key, value in os.environ.items()
           if not key.startswith(("BBHUNT_", "BB_", "NUCLEI_")) and key != "FINDINGS_OUT_DIR"}
    env["PYTHONPATH"] = str(repo)
    with runtime_phase_lock(tmp_path, store.target, "scan") if busy else nullcontext():
        result = subprocess.run(
            ["bash", str(scripts / "vuln_scanner.sh"), str(recon), "--quick", "--skip", "cves"],
            env=env, capture_output=True, text=True, timeout=10,
        )
    if busy:
        assert result.returncode == 75, result.stdout + result.stderr
        assert "runtime phase busy" in result.stderr
        assert not (tmp_path / "findings").exists()
        assert not (tmp_path / "state" / store.key / "session.json").exists()
    else:
        # Empty recon stops before network I/O, after real wrapper/lock/admission startup.
        assert result.returncode == 1, result.stdout + result.stderr
        assert "No live hosts data found" in result.stdout, result.stdout + result.stderr
        assert "Mode: quick" in result.stdout and "Skip: cves" in result.stdout
        assert "runtime phase busy" not in result.stderr
    assert store.binding() == before
