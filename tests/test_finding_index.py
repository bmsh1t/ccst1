"""Tests for structured scanner finding index."""

import json
import hashlib
import subprocess
import sys
from contextlib import contextmanager
from pathlib import Path

import finding_index
import pytest
import report_generator
import validate
import validation_runner
from target_paths import canonical_target_value, target_storage_key
from target_store import TargetStore


def _bind_report_runner_witness(findings_dir: Path, finding: dict) -> None:
    """Attach the minimum canonical replay bundle required by report generation."""
    repo_root = findings_dir.parent.parent
    payload = json.loads((findings_dir / "findings.json").read_text(encoding="utf-8"))
    target = canonical_target_value(
        str(finding.get("target") or "")
        or str(payload.get("target") or findings_dir.name)
    )
    finding_id = str(finding.get("id") or "fixture-finding")
    endpoint = str(finding.get("url") or finding.get("endpoint") or f"https://{target}/")
    method = str(finding.get("method") or "GET").upper()
    vuln_class = str(
        finding.get("vuln_class")
        or finding.get("type")
        or finding.get("category")
        or "SQLi"
    )
    bundle = (
        repo_root
        / "evidence"
        / target_storage_key(target)
        / "validation"
        / finding_id
        / "fixture-1"
    )
    bundle.mkdir(parents=True, exist_ok=True)
    request_path = bundle / "request.txt"
    response_path = bundle / "response.txt"
    request_path.write_text(
        f"{method} {endpoint} HTTP/1.1\nHost: {target}\n\n",
        encoding="utf-8",
    )
    response_path.write_text(
        "HTTP/1.1 200 OK\nContent-Type: application/json\n\n{\"fixture\":true}\n",
        encoding="utf-8",
    )

    request_ref = str(request_path.relative_to(repo_root))
    response_ref = str(response_path.relative_to(repo_root))
    summary_ref = str((bundle / "summary.json").relative_to(repo_root))
    operation_material = {
        "target": target,
        "lane": "test-fixture",
        "finding_id": finding_id,
        "vuln_class": vuln_class,
        "artifact_bindings": validation_runner._artifact_digest_material([
            {"kind": "baseline_request", "sha256": hashlib.sha256(request_path.read_bytes()).hexdigest()},
            {"kind": "baseline_response", "sha256": hashlib.sha256(response_path.read_bytes()).hexdigest()},
        ]),
    }
    operation_id = validation_runner._runner_operation_id(operation_material)
    event_id = "ledger:" + hashlib.sha256(operation_id.encode("utf-8")).hexdigest()[:24]
    summary = {
        "schema_version": 1,
        "lane": "test-fixture",
        "target": target,
        "finding_id": finding_id,
        "url": endpoint,
        "method": method,
        "vuln_class": vuln_class,
        "result": "tested_finding",
        "candidate_ready": True,
        "operation_id": operation_id,
        "operation_material": operation_material,
        "summary_path": summary_ref,
        "artifact_bindings": [
            {
                "kind": "baseline_request",
                "ref": request_ref,
                "sha256": hashlib.sha256(request_path.read_bytes()).hexdigest(),
            },
            {
                "kind": "baseline_response",
                "ref": response_ref,
                "sha256": hashlib.sha256(response_path.read_bytes()).hexdigest(),
            },
        ],
        "ledger_record": {
            "operation_id": operation_id,
            "event_id": event_id,
            "replayed": True,
            "evidence_ref": response_ref,
        },
    }
    (bundle / "summary.json").write_text(json.dumps(summary), encoding="utf-8")

    ledger_path = repo_root / "memory" / "evidence" / target_storage_key(target) / "ledger.jsonl"
    ledger_path.parent.mkdir(parents=True, exist_ok=True)
    existing = ledger_path.read_text(encoding="utf-8") if ledger_path.is_file() else ""
    if event_id not in existing:
        ledger_path.write_text(
            existing
            + json.dumps({
                "target": target,
                "endpoint": endpoint,
                "method": method,
                "vuln_class": vuln_class,
                "result": "tested_finding",
                "operation_id": operation_id,
                "event_id": event_id,
                "replayed": True,
                "evidence_ref": response_ref,
            })
            + "\n",
            encoding="utf-8",
        )

    updated = finding_index.update_finding_status(
        findings_dir,
        finding_id,
        validation_status=finding.get("validation_status", "unvalidated"),
        report_status=finding.get("report_status", "not_generated"),
        runner_summary=summary_ref,
        runner_operation_id=operation_id,
    )
    assert updated is not None


def _record_owner_provenance(findings_dir: Path, finding_id: str) -> None:
    """Make a fixture's lifecycle assertion originate from the canonical owner."""
    payload = json.loads((findings_dir / "findings.json").read_text(encoding="utf-8"))
    finding = next(item for item in payload["findings"] if item.get("id") == finding_id)
    _bind_report_runner_witness(findings_dir, finding)


@pytest.mark.parametrize("scheme", ["ws", "wss"])
def test_report_runner_endpoint_scope_rejects_off_target_protocol(scheme):
    assert not report_generator._runner_endpoint_matches(
        f"{scheme}://target.example/socket",
        f"{scheme}://other.example/socket",
        "target.example",
    )
    assert not report_generator._runner_endpoint_matches(
        f"{scheme}://other.example/socket",
        f"{scheme}://other.example/socket",
        "target.example",
    )


def test_report_runner_witness_recomputes_operation_id_from_current_artifacts(tmp_path):
    findings_dir = tmp_path / "findings" / "example.com"
    created = finding_index.upsert_finding(
        findings_dir,
        {
            "id": "runner-material-drift",
            "type": "sqli",
            "url": "https://example.com/search?q=1",
            "validation_status": "validated",
            "report_status": "not_generated",
        },
        target="example.com",
    )
    _bind_report_runner_witness(findings_dir, created["finding"])
    finding = finding_index.find_finding(findings_dir, "runner-material-drift")
    assert finding is not None
    summary_path = tmp_path / finding["runner_summary"]
    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    response_binding = next(
        item for item in summary["artifact_bindings"] if item["kind"] == "baseline_response"
    )
    response_path = tmp_path / response_binding["ref"]
    response_path.write_text("tampered response\n", encoding="utf-8")
    response_binding["sha256"] = hashlib.sha256(response_path.read_bytes()).hexdigest()
    material_binding = next(
        item
        for item in summary["operation_material"]["artifact_bindings"]
        if item["kind"] == "baseline_response"
    )
    material_binding["sha256"] = response_binding["sha256"]
    summary_path.write_text(json.dumps(summary), encoding="utf-8")

    witness = report_generator._canonical_runner_witness(
        finding,
        findings_dir=findings_dir,
        target="example.com",
    )
    assert witness["valid"] is False
    assert "operation ID" in witness["reason"]


def test_load_finding_index_migrates_legacy_list_without_trusting_finality(tmp_path):
    findings_dir = tmp_path / "findings" / "example.com"
    findings_dir.mkdir(parents=True)
    legacy = [
        {
            "id": "legacy-validated",
            "endpoint": "/api/orders/1",
            "vuln_class": "IDOR",
            "severity": "high",
            "validation_status": "validated",
            "report_status": "generated",
            "report_id": "idor_001",
            "report_file": "reports/example.com/idor_001.md",
        },
        {
            "id": "legacy-validated",
            "endpoint": "/api/orders/1",
            "vuln_class": "IDOR",
            "severity": "medium",
        },
        {
            "endpoint": "/api/orders/2",
            "vuln_class": "IDOR",
            "severity": "medium",
        },
    ]
    path = findings_dir / "findings.json"
    path.write_text(json.dumps(legacy), encoding="utf-8")

    payload = finding_index.load_finding_index(findings_dir)
    persisted = json.loads(path.read_text(encoding="utf-8"))

    assert payload == persisted
    assert persisted["schema_version"] == 1
    assert persisted["total"] == 2
    assert isinstance(persisted["findings"], list)
    by_id = {item["id"]: item for item in persisted["findings"]}
    assert by_id["legacy-validated"]["validation_status"] == "needs_owner_revalidation"
    assert by_id["legacy-validated"]["report_status"] == "not_generated"
    assert by_id["legacy-validated"]["claimed_validation_status"] == "validated"
    assert by_id["legacy-validated"]["claimed_report_status"] == "generated"
    assert by_id["legacy-validated"]["report_id"] == "idor_001"
    generated = next(item for item in persisted["findings"] if item["id"] != "legacy-validated")
    assert generated["id"].startswith("idor_")
    assert generated["url"] == "/api/orders/2"


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("schema_version", 2, "schema_version"),
        ("target", "other.example", "target mismatch"),
    ],
)
def test_load_finding_index_rejects_invalid_bound_payload(tmp_path, field, value, message):
    findings_dir = tmp_path / "findings" / "example.com"
    findings_dir.mkdir(parents=True)
    payload = {
        "schema_version": 1,
        "target": "example.com",
        "findings": [],
    }
    payload[field] = value
    (findings_dir / "findings.json").write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ValueError, match=message):
        finding_index.load_finding_index(findings_dir, target="example.com")


def test_load_finding_index_rejects_malformed_row_at_owner_boundary(tmp_path):
    findings_dir = tmp_path / "findings" / "example.com"
    findings_dir.mkdir(parents=True)
    (findings_dir / "findings.json").write_text(
        json.dumps({
            "schema_version": 1,
            "target": "example.com",
            "findings": [{"type": "sqli"}],
        }),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match=r"findings\[0\]"):
        finding_index.load_finding_index(findings_dir, target="example.com")


def test_legacy_object_projection_is_in_memory_and_quarantines_finality(tmp_path):
    findings_dir = tmp_path / "findings" / "example.com"
    findings_dir.mkdir(parents=True)
    path = findings_dir / "findings.json"
    path.write_text(
        json.dumps(
            {
                "findings": [
                    {
                        "type": "sqli",
                        "url": "https://example.com/search?q=1",
                        "validation_status": "validated",
                        "report_status": "generated",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    original = path.read_bytes()

    projected = finding_index.load_finding_index(
        findings_dir,
        target="example.com",
        migrate_legacy=False,
        allow_legacy=True,
    )

    assert projected["target"] == "example.com"
    assert projected["findings"][0]["id"]
    assert projected["findings"][0]["validation_status"] == "needs_owner_revalidation"
    assert path.read_bytes() == original


def test_upsert_finding_uses_semantic_identity_and_preserves_advanced_lifecycle(tmp_path):
    findings_dir = tmp_path / "findings" / "example.com"
    first = finding_index.upsert_finding(
        findings_dir,
        {
            "id": "runner-id",
            "endpoint": "/api/orders/1",
            "vuln_class": "IDOR",
            "severity": "low",
            "validation_status": "validated",
            "report_status": "generated",
            "report_id": "idor_001",
        },
        target="example.com",
    )
    second = finding_index.upsert_finding(
        findings_dir,
        {
            "endpoint": "/api/orders/1",
            "vuln_class": "IDOR",
            "severity": "high",
            "validation_status": "unvalidated",
            "report_status": "not_generated",
        },
        target="example.com",
    )

    assert first["created"] is True
    assert second["created"] is False
    payload = finding_index.load_finding_index(findings_dir)
    assert payload["total"] == 1
    finding = payload["findings"][0]
    assert finding["id"] == "runner-id"
    assert finding["severity"] == "high"
    assert finding["validation_status"] == "validated"
    assert finding["report_status"] == "generated"
    assert finding["report_id"] == "idor_001"


def test_upsert_finding_semantic_identity_keeps_case_dimensions_distinct(tmp_path):
    findings_dir = tmp_path / "findings" / "example.com"
    common = {
        "endpoint": "/api/orders/1?view=summary",
        "vuln_class": "IDOR",
        "severity": "medium",
    }

    finding_index.upsert_finding(
        findings_dir,
        {
            **common,
            "method": "GET",
            "actor": "owner",
            "object_scope": "own_object",
            "variant": "baseline",
        },
        target="example.com",
    )
    finding_index.upsert_finding(
        findings_dir,
        {
            **common,
            "method": "POST",
            "actor": "peer",
            "object_scope": "other_object_same_org",
            "variant": "id_swap",
        },
        target="example.com",
    )

    payload = finding_index.load_finding_index(findings_dir)
    assert payload["total"] == 2
    assert {item["method"] for item in payload["findings"]} == {"GET", "POST"}


def test_concurrent_finding_upserts_do_not_lose_updates(tmp_path):
    findings_dir = tmp_path / "findings" / "target.com"
    code = """
import sys
from tools.finding_index import upsert_finding

root, finding_id = sys.argv[1:]
upsert_finding(
    root,
    {
        "id": finding_id,
        "url": f"https://target.com/{finding_id}",
        "type": "exposure",
        "severity": "medium",
    },
    target="target.com",
)
"""
    repo_root = Path(__file__).resolve().parents[1]
    processes = [
        subprocess.Popen(
            [sys.executable, "-c", code, str(findings_dir), finding_id],
            cwd=repo_root,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        for finding_id in ("F-ONE", "F-TWO")
    ]
    for process in processes:
        stdout, stderr = process.communicate(timeout=10)
        assert process.returncode == 0, stdout + stderr

    payload = finding_index.load_finding_index(findings_dir)
    assert {item["id"] for item in payload["findings"]} == {"F-ONE", "F-TWO"}


def test_owner_mutation_provenance_round_trips_and_detects_direct_row_edit(tmp_path):
    findings_dir = tmp_path / "findings" / "example.com"
    result = finding_index.upsert_finding(
        findings_dir,
        {
            "id": "sqli-owner-event",
            "type": "sqli",
            "url": "https://example.com/rest/products/search?q=test",
            "source_file": "evidence/example.com/validation/sqli/summary.json",
            "validation_status": "validated",
            "report_status": "not_generated",
        },
        target="example.com",
    )
    finding = result["finding"]
    event_path = findings_dir / finding_index.MUTATION_EVENTS_FILENAME

    verified = finding_index.verify_finding_owner_provenance(
        findings_dir,
        finding,
        target="example.com",
    )

    assert event_path.is_file()
    assert finding["owner_provenance"]["owner"] == finding_index.FINDING_OWNER
    assert verified["valid"] is True
    assert verified["operation"] == "upsert"

    tampered = dict(finding)
    tampered["summary"] = "direct JSON mutation after the owner event"
    invalid = finding_index.verify_finding_owner_provenance(
        findings_dir,
        tampered,
        target="example.com",
    )
    assert invalid["valid"] is False
    assert invalid["reason"] == "row-fingerprint-mismatch"

    forged_provenance = dict(finding)
    forged_provenance["owner_provenance"] = dict(finding["owner_provenance"])
    forged_provenance["owner_provenance"]["operation"] = "direct-json-edit"
    invalid_provenance = finding_index.verify_finding_owner_provenance(
        findings_dir,
        forged_provenance,
        target="example.com",
    )

    assert invalid_provenance["valid"] is False
    assert invalid_provenance["reason"] == "operation-mismatch"


def test_legacy_list_migration_records_owner_provenance(tmp_path):
    findings_dir = tmp_path / "findings" / "example.com"
    findings_dir.mkdir(parents=True)
    (findings_dir / "findings.json").write_text(
        json.dumps(
            [
                {
                    "id": "legacy-row",
                    "type": "idor",
                    "url": "https://example.com/api/orders/1",
                    "validation_status": "validated",
                    "report_status": "generated",
                }
            ]
        ),
        encoding="utf-8",
    )

    payload = finding_index.load_finding_index(findings_dir)
    finding = payload["findings"][0]

    assert finding_index.verify_finding_owner_provenance(
        findings_dir,
        finding,
        target="example.com",
    )["valid"] is True
    assert finding["owner_provenance"]["operation"] == "legacy_migration"
    assert finding["validation_status"] == "needs_owner_revalidation"
    assert finding["report_status"] == "not_generated"
    assert finding["claimed_validation_status"] == "validated"
    assert finding["claimed_report_status"] == "generated"


@pytest.mark.parametrize("backend", ["primary", "preview", "frozen"])
@pytest.mark.parametrize("target", ["example.com", "http://127.0.0.1:8080"])
def test_legacy_list_migration_refuses_nonlegacy_backend(tmp_path, backend, target):
    store = TargetStore(tmp_path, target)
    store.initialize(allow_legacy=backend == "preview")
    if backend == "frozen":
        store.path.unlink()
    findings_dir = tmp_path / "findings" / target_storage_key(target)
    findings_dir.mkdir(parents=True)
    path = findings_dir / "findings.json"
    path.write_text(json.dumps([{"id": "old", "type": "idor", "url": "/orders/1"}]))
    events = finding_index.mutation_events_path(findings_dir)
    events.write_text('{"historical":true}\n')
    before = {file: file.read_bytes() for file in (path, events)}

    projected = finding_index.load_finding_index(findings_dir, migrate_legacy=False)
    assert projected["findings"][0]["id"] == "old"
    assert not (findings_dir / ".locks").exists()
    with pytest.raises(finding_index.StoreError):
        finding_index.load_finding_index(findings_dir)
    assert {file: file.read_bytes() for file in before} == before


@pytest.mark.parametrize("writer", ["migration", "upsert", "rebuild", "status"])
def test_finding_writer_rechecks_backend_after_cutover_interposition(tmp_path, monkeypatch, writer):
    target = "example.com"
    findings_dir = tmp_path / "findings" / target
    findings_dir.mkdir(parents=True)
    path = findings_dir / "findings.json"
    path.write_text(json.dumps([{"id": "old", "type": "idor", "url": "/orders/1"}]))
    before = path.read_bytes()
    original_lock = finding_index.target_switch_lock

    @contextmanager
    def publish_before_lock(repo_root, resolved_target):
        TargetStore(repo_root, resolved_target).initialize(allow_legacy=True)
        with original_lock(repo_root, resolved_target):
            yield

    monkeypatch.setattr(finding_index, "target_switch_lock", publish_before_lock)
    with pytest.raises(finding_index.StoreError, match="legacy finding writer"):
        if writer == "migration":
            finding_index.load_finding_index(findings_dir)
        elif writer == "upsert":
            finding_index.upsert_finding(findings_dir, {"id": "new", "type": "idor"}, target=target)
        elif writer == "rebuild":
            finding_index.write_finding_index(findings_dir, target=target)
        else:
            finding_index.update_finding_status(findings_dir, "old", validation_status="candidate")
    assert path.read_bytes() == before
    assert not finding_index.mutation_events_path(findings_dir).exists()


def test_rebuild_quarantines_direct_finality_instead_of_reauthorizing_it(tmp_path):
    findings_dir = tmp_path / "findings" / "example.com"
    sqli_dir = findings_dir / "sqli"
    sqli_dir.mkdir(parents=True)
    (sqli_dir / "candidates.txt").write_text(
        "[SQLI-POC-VERIFIED] url=https://example.com/item?id=1\n",
        encoding="utf-8",
    )
    initial = finding_index.write_finding_index(findings_dir, target="example.com")
    finding_id = initial["findings"][0]["id"]

    payload = json.loads((findings_dir / "findings.json").read_text(encoding="utf-8"))
    payload["findings"][0]["validation_status"] = "validated"
    payload["findings"][0]["report_status"] = "generated"
    (findings_dir / "findings.json").write_text(json.dumps(payload), encoding="utf-8")
    assert finding_index.verify_finding_owner_provenance(
        findings_dir,
        payload["findings"][0],
        target="example.com",
    )["valid"] is False

    rebuilt = finding_index.write_finding_index(findings_dir, target="example.com")
    finding = next(item for item in rebuilt["findings"] if item["id"] == finding_id)

    assert finding["validation_status"] == "needs_owner_revalidation"
    assert finding["report_status"] == "not_generated"
    assert finding["claimed_validation_status"] == "validated"
    assert finding["claimed_report_status"] == "generated"
    assert finding_index.verify_finding_owner_provenance(
        findings_dir,
        finding,
        target="example.com",
    )["valid"] is True


def test_upsert_quarantines_direct_finality_before_merging_candidate(tmp_path):
    findings_dir = tmp_path / "findings" / "example.com"
    created = finding_index.upsert_finding(
        findings_dir,
        {
            "id": "sqli-direct-edit",
            "url": "https://example.com/item?id=1",
            "type": "sqli",
            "validation_status": "candidate",
        },
        target="example.com",
    )
    payload = created["payload"]
    payload["findings"][0]["validation_status"] = "validated"
    payload["findings"][0]["report_status"] = "generated"
    (findings_dir / "findings.json").write_text(json.dumps(payload), encoding="utf-8")

    finding_index.upsert_finding(
        findings_dir,
        {
            "id": "sqli-direct-edit",
            "url": "https://example.com/item?id=1",
            "type": "sqli",
            "severity": "high",
            "validation_status": "candidate",
        },
        target="example.com",
    )
    finding = finding_index.find_finding(findings_dir, "sqli-direct-edit")

    assert finding is not None
    assert finding["severity"] == "high"
    assert finding["validation_status"] == "needs_owner_revalidation"
    assert finding["report_status"] == "not_generated"
    assert finding["claimed_validation_status"] == "validated"
    assert finding["claimed_report_status"] == "generated"


def test_upsert_findings_without_endpoints_do_not_collapse_by_type(tmp_path):
    findings_dir = tmp_path / "findings" / "example.com"

    result = finding_index.upsert_findings(
        findings_dir,
        [
            {"id": "source-one", "type": "exposure", "raw": "first source artifact"},
            {"id": "source-two", "type": "exposure", "raw": "second source artifact"},
        ],
        target="example.com",
    )

    assert result["created"] == 2
    assert result["payload"]["total"] == 2
    assert {item["id"] for item in result["payload"]["findings"]} == {"source-one", "source-two"}


def test_build_finding_index_extracts_scanner_candidates(tmp_path):
    findings_dir = tmp_path / "findings" / "example.com"
    sqli_dir = findings_dir / "sqli"
    ssti_dir = findings_dir / "ssti"
    sqli_dir.mkdir(parents=True)
    ssti_dir.mkdir(parents=True)
    (sqli_dir / "timebased_candidates.txt").write_text(
        "[SQLI-POC-VERIFIED] dialect=mysql param=1 url=https://example.com/item?id=1\n",
        encoding="utf-8",
    )
    (ssti_dir / "ssti_candidates.txt").write_text(
        "[SSTI-CONFIRMED] engine=jinja2 url=https://example.com/render?name={{7*7}}\n",
        encoding="utf-8",
    )

    payload = finding_index.write_finding_index(findings_dir, target="example.com")

    assert payload["schema_version"] == 1
    assert payload["target"] == "example.com"
    assert payload["total"] == 2
    assert payload["counts"]["type"] == {"sqli": 1, "ssti": 1}
    assert payload["counts"]["confidence"] == {"confirmed": 2}
    assert (findings_dir / "findings.json").is_file()

    first = payload["findings"][0]
    assert first["id"].startswith("sqli_")
    assert first["url"] == "https://example.com/item?id=1"
    assert first["validation_status"] == "unvalidated"
    assert first["report_status"] == "not_generated"

    updated = finding_index.update_finding_status(
        findings_dir,
        first["id"],
        validation_status="validated",
        validation_summary="validated/validation-summary.json",
    )

    assert updated is not None
    assert updated["validation_status"] == "validated"
    reloaded = finding_index.load_finding_index(findings_dir)
    assert reloaded["findings"][0]["validation_summary"] == "validated/validation-summary.json"


def test_build_finding_index_skips_off_target_urls(tmp_path):
    findings_dir = tmp_path / "findings" / "target.com"
    idor_dir = findings_dir / "idor"
    idor_dir.mkdir(parents=True)
    (idor_dir / "idor_candidates.txt").write_text(
        "https://target.com/api/orders/123\n"
        "https://github.com/org/repo/issues/123\n",
        encoding="utf-8",
    )

    payload = finding_index.write_finding_index(findings_dir, target="target.com")

    assert payload["total"] == 1
    assert payload["findings"][0]["url"] == "https://target.com/api/orders/123"
    assert all("github.com" not in item["url"] for item in payload["findings"])


def test_root_json_claim_reconciles_only_as_incomplete_candidate(tmp_path):
    findings_dir = tmp_path / "findings" / "target.com"
    findings_dir.mkdir(parents=True)
    (findings_dir / "manual-sqli.json").write_text(
        json.dumps(
            {
                "title": "SQL injection claim",
                "severity": "critical",
                "endpoint": "/rest/products/search",
                "method": "GET",
                "vuln_class": "SQLi",
                "poc": "curl 'https://target.com/rest/products/search?q=...'",
                "evidence": ["response looked different"],
                "impact": "claimed database access",
            }
        ),
        encoding="utf-8",
    )

    before = finding_index.list_root_finding_claims(findings_dir, target="target.com")
    result = finding_index.reconcile_root_finding_claims(findings_dir, target="target.com")
    after = finding_index.list_root_finding_claims(findings_dir, target="target.com")
    payload = finding_index.load_finding_index(findings_dir)
    finding = payload["findings"][0]

    assert len(before) == 1
    assert result["status"] == "updated"
    assert result["created"] == 1
    assert after == []
    assert finding["id"] == before[0]["id"]
    assert finding["claim_source_file"] == "manual-sqli.json"
    assert finding["validation_status"] == "candidate"
    assert finding["report_status"] == "not_generated"
    assert finding["confidence"] == "needs_review"
    assert "evidence_rubric" not in finding


def test_root_json_claim_reconciliation_is_idempotent_and_ignores_summaries(tmp_path):
    findings_dir = tmp_path / "findings" / "target.com"
    findings_dir.mkdir(parents=True)
    (findings_dir / "manual-idor.json").write_text(
        json.dumps(
            {
                "title": "IDOR claim",
                "endpoint": "/api/orders/42",
                "vuln_class": "IDOR",
                "poc": "GET /api/orders/42",
                "impact": "claimed private order data",
            }
        ),
        encoding="utf-8",
    )
    (findings_dir / "validation-summary.json").write_text(
        json.dumps(
            {
                "target": "target.com",
                "endpoint": "/api/orders/42",
                "vuln_type": "IDOR",
                "impact": "not a root claim",
            }
        ),
        encoding="utf-8",
    )

    first = finding_index.reconcile_root_finding_claims(findings_dir, target="target.com")
    second = finding_index.reconcile_root_finding_claims(findings_dir, target="target.com")
    payload = finding_index.load_finding_index(findings_dir)

    assert first["created"] == 1
    assert second["status"] == "noop"
    assert second["created"] == 0
    assert payload["total"] == 1


def test_root_claim_reconciliation_ignores_per_finding_validation_summary(tmp_path):
    findings_dir = tmp_path / "findings" / "target.com"
    findings_dir.mkdir(parents=True)
    (findings_dir / "jwt-claim.json").write_text(
        json.dumps(
            {
                "kind": "finding_claim",
                "schema_version": 1,
                "title": "JWT verification claim",
                "endpoint": "/admin",
                "type": "authentication-bypass",
                "vuln_class": "JWT",
                "impact": "A forged token reaches an administrator-only action.",
            }
        ),
        encoding="utf-8",
    )

    finding_index.reconcile_root_finding_claims(findings_dir, target="target.com")
    original = finding_index.load_finding_index(findings_dir)["findings"][0]
    finding_index.update_finding_status(
        findings_dir,
        original["id"],
        validation_status="validated",
        report_status="not_generated",
    )
    before = finding_index.find_finding(findings_dir, original["id"])
    assert before is not None

    (findings_dir / f"{original['id']}-a1b2c3d4.validation-summary.json").write_text(
        json.dumps(
            {
                "target": "target.com",
                "endpoint": "/admin",
                "vuln_class": "authentication_bypass",
                "impact": "Validation evidence for the linked finding.",
                "finding_id": original["id"],
            }
        ),
        encoding="utf-8",
    )

    result = finding_index.reconcile_root_finding_claims(findings_dir, target="target.com")
    after = finding_index.find_finding(findings_dir, original["id"])

    assert finding_index.list_root_finding_claims(findings_dir, target="target.com") == []
    assert result["status"] == "noop"
    assert after is not None
    assert after["validation_status"] == "validated"
    assert after["vuln_class"] == before["vuln_class"] == "JWT"
    assert "evidence_rubric" not in after
    assert after["claim_sources"] == before["claim_sources"]


def test_incomplete_root_json_claim_is_recoverable_without_fabricating_endpoint(tmp_path):
    findings_dir = tmp_path / "findings" / "target.com"
    findings_dir.mkdir(parents=True)
    claim_path = findings_dir / "jwt-unverified-signature.json"
    claim_path.write_text(
        json.dumps(
            {
                "title": "JWT authentication bypass",
                "target": "target.com",
                "vulnerability_class": "Authentication Bypass",
                "severity": "critical",
                "state": "validated",
                "impact": "Forged token reaches the administrator view.",
                "evidence": {"artifact": "evidence/target.com/jwt/admin.response.txt"},
            }
        ),
        encoding="utf-8",
    )

    claims = finding_index.list_root_finding_claims(findings_dir, target="target.com")
    assert len(claims) == 1
    assert claims[0]["url"] == ""
    assert claims[0]["claim_status"] == "incomplete"
    assert "endpoint" in claims[0]["incomplete_fields"]
    assert claims[0]["claimed_validation_status"] == "validated"

    result = finding_index.reconcile_root_finding_claims(findings_dir, target="target.com")
    assert result["created"] == 1
    persisted = finding_index.load_finding_index(findings_dir)["findings"][0]
    assert persisted["url"] == ""
    assert persisted["claim_source_file"] == "jwt-unverified-signature.json"
    assert persisted["validation_status"] == "candidate"
    assert "evidence_rubric" not in persisted
    assert persisted["report_status"] == "not_generated"


def test_root_claim_classifier_rejects_status_json_and_unknown_kind(tmp_path):
    findings_dir = tmp_path / "findings" / "target.com"
    findings_dir.mkdir(parents=True)
    (findings_dir / "tool-status.json").write_text(
        json.dumps({"title": "Nightly probe summary", "status": "ok"}),
        encoding="utf-8",
    )
    (findings_dir / "foreign-kind.json").write_text(
        json.dumps(
            {
                "kind": "tool_run_summary",
                "title": "Potential SQL injection",
                "endpoint": "/item?id=1",
                "vuln_class": "sqli",
                "evidence": {"artifact": "raw.txt"},
            }
        ),
        encoding="utf-8",
    )
    (findings_dir / "future-schema.json").write_text(
        json.dumps(
            {
                "kind": "finding_claim",
                "schema_version": 2,
                "title": "Unsupported claim schema",
                "endpoint": "/item?id=1",
                "vuln_class": "sqli",
                "evidence": {"artifact": "raw.txt"},
            }
        ),
        encoding="utf-8",
    )

    assert finding_index.list_root_finding_claims(findings_dir, target="target.com") == []

    (findings_dir / "explicit-incomplete.json").write_text(
        json.dumps(
            {
                "kind": "finding_claim",
                "schema_version": 1,
                "title": "Interrupted validation claim",
                "status": "candidate",
            }
        ),
        encoding="utf-8",
    )
    claims = finding_index.list_root_finding_claims(findings_dir, target="target.com")
    assert len(claims) == 1
    assert claims[0]["claim_source_file"] == "explicit-incomplete.json"
    assert set(claims[0]["incomplete_fields"]) == {"endpoint", "vuln_class", "claim_detail"}


def test_root_claim_classifier_rejects_scheme_less_off_target_identity(tmp_path):
    findings_dir = tmp_path / "findings" / "target.com"
    findings_dir.mkdir(parents=True)
    (findings_dir / "off-target.json").write_text(
        json.dumps(
            {
                "kind": "finding_claim",
                "schema_version": 1,
                "title": "Copied claim",
                "target": "other.test",
                "endpoint": "other.test/api/private",
                "vuln_class": "idor",
                "evidence": {"artifact": "raw.txt"},
            }
        ),
        encoding="utf-8",
    )

    assert finding_index.list_root_finding_claims(findings_dir, target="target.com") == []


def test_root_claim_revision_replays_and_completes_missing_identity(tmp_path):
    findings_dir = tmp_path / "findings" / "target.com"
    findings_dir.mkdir(parents=True)
    claim_path = findings_dir / "manual-authz.json"
    payload = {
        "kind": "finding_claim",
        "schema_version": 1,
        "title": "Authorization claim",
        "vuln_class": "idor",
        "evidence": {"artifact": "evidence/target.com/raw.json"},
    }
    claim_path.write_text(json.dumps(payload), encoding="utf-8")

    first_claim = finding_index.list_root_finding_claims(findings_dir, target="target.com")[0]
    finding_index.reconcile_root_finding_claims(findings_dir, target="target.com")
    first_row = finding_index.find_finding(findings_dir, first_claim["id"])
    assert first_row is not None
    assert first_row["url"] == ""
    assert "endpoint" in first_row["incomplete_fields"]

    payload["endpoint"] = "/api/orders/42"
    claim_path.write_text(json.dumps(payload), encoding="utf-8")
    revised = finding_index.list_root_finding_claims(findings_dir, target="target.com")
    assert len(revised) == 1
    assert revised[0]["id"] == first_claim["id"]
    assert revised[0]["claim_revision"] != first_claim["claim_revision"]

    replay = finding_index.reconcile_root_finding_claims(findings_dir, target="target.com")
    row = finding_index.find_finding(findings_dir, first_claim["id"])
    assert replay["updated"] == 1
    assert row is not None
    assert row["url"] == "/api/orders/42"
    assert "endpoint" not in row["incomplete_fields"]
    assert len(row["claim_sources"]) == 2
    assert finding_index.reconcile_root_finding_claims(
        findings_dir,
        target="target.com",
    )["status"] == "noop"


def test_multi_source_claim_reconciliation_is_idempotent_and_lifecycle_monotonic(tmp_path):
    findings_dir = tmp_path / "findings" / "target.com"
    findings_dir.mkdir(parents=True)
    finding_index.upsert_finding(
        findings_dir,
        {
            "id": "validated-sqli",
            "url": "/item?id=1",
            "type": "sqli",
            "validation_status": "validated",
            "report_status": "generated",
        },
        target="target.com",
    )
    for name, title in (("a.json", "First claim"), ("b.json", "Second claim")):
        (findings_dir / name).write_text(
            json.dumps(
                {
                    "kind": "finding_claim",
                    "schema_version": 1,
                    "title": title,
                    "endpoint": "/item?id=1",
                    "vuln_class": "sqli",
                    "evidence": {"artifact": f"evidence/target.com/{name}"},
                }
            ),
            encoding="utf-8",
        )

    first = finding_index.reconcile_root_finding_claims(findings_dir, target="target.com")
    row = finding_index.find_finding(findings_dir, "validated-sqli")
    second = finding_index.reconcile_root_finding_claims(findings_dir, target="target.com")

    assert first["updated"] == 2
    assert second["status"] == "noop"
    assert row is not None
    assert row["validation_status"] == "validated"
    assert row["report_status"] == "generated"
    assert {item["source_file"] for item in row["claim_sources"]} == {"a.json", "b.json"}


def test_owner_mutation_keeps_legacy_state_aliases_in_sync(tmp_path):
    findings_dir = tmp_path / "findings" / "target.com"
    result = finding_index.upsert_finding(
        findings_dir,
        {
            "id": "legacy-status-row",
            "url": "/admin",
            "type": "auth_bypass",
            "state": "candidate",
            "status": "candidate",
            "validation_status": "candidate",
        },
        target="target.com",
    )
    updated = finding_index.update_finding_status(
        findings_dir,
        "legacy-status-row",
        validation_status="validated",
    )

    assert updated is not None
    assert updated["validation_status"] == "validated"
    assert updated["state"] == "validated"
    assert updated["status"] == "validated"


def test_write_finding_index_preserves_validation_and_report_state(tmp_path):
    findings_dir = tmp_path / "findings" / "example.com"
    sqli_dir = findings_dir / "sqli"
    sqli_dir.mkdir(parents=True)
    (sqli_dir / "timebased_candidates.txt").write_text(
        "[SQLI-POC-VERIFIED] dialect=mysql param=1 url=https://example.com/item?id=1\n",
        encoding="utf-8",
    )

    first = finding_index.write_finding_index(findings_dir, target="example.com")
    finding_id = first["findings"][0]["id"]
    finding_index.update_finding_status(
        findings_dir,
        finding_id,
        validation_status="validated",
        report_status="generated",
        validation_summary="evidence/example.com/validation/sqli/summary.json",
        report_file="reports/example.com/sqli_001.md",
    )

    rebuilt = finding_index.write_finding_index(findings_dir, target="example.com")
    finding = rebuilt["findings"][0]

    assert finding["id"] == finding_id
    assert finding["validation_status"] == "validated"
    assert finding["report_status"] == "generated"
    assert finding["validation_summary"] == "evidence/example.com/validation/sqli/summary.json"
    assert finding["report_file"] == "reports/example.com/sqli_001.md"


def test_write_finding_index_preserves_runner_backed_orphan_findings(tmp_path):
    findings_dir = tmp_path / "findings" / "example.com"
    sqli_dir = findings_dir / "sqli"
    sqli_dir.mkdir(parents=True)
    (sqli_dir / "timebased_candidates.txt").write_text(
        "[SQLI-POC-VERIFIED] dialect=mysql param=1 url=https://example.com/item?id=1\n",
        encoding="utf-8",
    )

    first = finding_index.write_finding_index(findings_dir, target="example.com")
    first["findings"].append(
        {
            "id": "authz-role-replay-api_users",
            "type": "auth_bypass",
            "category": "auth_bypass",
            "title": "Runner-backed role replay candidate",
            "summary": "authz:candidate-ready score=100 satisfied=4/4",
            "url": "https://example.com/api/Users",
            "severity": "high",
            "confidence": "confirmed",
            "source_file": "evidence/example.com/validation/authz-role-replay-api_users/summary.json",
            "line_number": 0,
            "template_id": "",
            "raw": "validation_runner:authz_role_replay:authz-role-replay-api_users",
            "validation_status": "partial",
            "report_status": "not_generated",
            "evidence_rubric": {"status": "candidate-ready"},
        }
    )
    first["total"] = len(first["findings"])
    (findings_dir / "findings.json").write_text(json.dumps(first), encoding="utf-8")

    rebuilt = finding_index.write_finding_index(findings_dir, target="example.com")
    by_id = {item["id"]: item for item in rebuilt["findings"]}

    assert rebuilt["total"] == 2
    assert "authz-role-replay-api_users" in by_id
    assert by_id["authz-role-replay-api_users"]["validation_status"] == "partial"
    assert by_id["authz-role-replay-api_users"]["source_file"].startswith("evidence/")
    assert rebuilt["counts"]["type"] == {"auth_bypass": 1, "sqli": 1}


def test_write_finding_index_drops_default_scanner_orphans(tmp_path):
    findings_dir = tmp_path / "findings" / "example.com"
    sqli_dir = findings_dir / "sqli"
    sqli_dir.mkdir(parents=True)
    (sqli_dir / "current.txt").write_text(
        "[SQLI-POC-VERIFIED] dialect=mysql param=1 url=https://example.com/item?id=1\n",
        encoding="utf-8",
    )

    first = finding_index.write_finding_index(findings_dir, target="example.com")
    first["findings"].append(
        {
            "id": "sqli_old_orphan",
            "type": "sqli",
            "category": "sqli",
            "title": "Old scanner-only candidate",
            "summary": "old scanner-only row",
            "url": "https://example.com/old?id=1",
            "severity": "high",
            "confidence": "medium",
            "source_file": "sqli/old.txt",
            "line_number": 1,
            "template_id": "",
            "raw": "[SQLI] https://example.com/old?id=1",
            "validation_status": "unvalidated",
            "report_status": "not_generated",
        }
    )
    first["total"] = len(first["findings"])
    (findings_dir / "findings.json").write_text(json.dumps(first), encoding="utf-8")

    rebuilt = finding_index.write_finding_index(findings_dir, target="example.com")

    assert rebuilt["total"] == 1
    assert all(item["id"] != "sqli_old_orphan" for item in rebuilt["findings"])


def test_report_generator_consumes_structured_findings(monkeypatch, tmp_path):
    findings_dir = tmp_path / "findings" / "example.com"
    findings_dir.mkdir(parents=True)
    (findings_dir / "findings.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "target": "example.com",
                "total": 1,
                "findings": [
                    {
                        "id": "sqli_abc123",
                        "type": "sqli",
                        "category": "sqli",
                        "title": "SQLi on item",
                        "summary": "verified SQLi",
                        "url": "https://example.com/item?id=1",
                        "severity": "high",
                        "confidence": "confirmed",
                        "validation_status": "validated",
                        "report_status": "not_generated",
                        "source_file": "sqli/timebased_candidates.txt",
                        "line_number": 1,
                        "template_id": "",
                        "raw": "[SQLI-POC-VERIFIED] dialect=mysql param=1 url=https://example.com/item?id=1",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    _record_owner_provenance(findings_dir, "sqli_abc123")
    monkeypatch.setattr(report_generator, "REPORTS_DIR", str(tmp_path / "reports"))

    total, index = report_generator.process_findings_dir(str(findings_dir))

    assert total == 1
    assert index[0]["finding_id"] == "sqli_abc123"
    assert index[0]["type"] == "sqli"
    report_path = Path(index[0]["file"])
    assert report_path.is_file()
    report_text = report_path.read_text(encoding="utf-8")
    assert "SQL Injection" in report_text
    assert "**Finding Reference:**" in report_text
    assert "- **Finding ID:** sqli_abc123" in report_text
    assert "- **Source artifact:** sqli/timebased_candidates.txt" in report_text
    assert "- **Confidence:** confirmed" in report_text
    updated_index = json.loads((findings_dir / "findings.json").read_text(encoding="utf-8"))
    assert updated_index["findings"][0]["report_status"] == "generated"
    assert updated_index["findings"][0]["report_id"] == "sqli_001"
    assert updated_index["findings"][0]["report_file"] == str(report_path)


def _primary_report_fixture(tmp_path: Path, *, delivery_status: str = "eligible"):
    target = "example.com"
    url = "https://example.com/items?id=1"
    store = TargetStore(tmp_path, target)
    store.initialize()
    store.create_finding(
        command_id="create:f1",
        finding_id="f1",
        endpoint=url,
        method="GET",
        family="sqli",
        title="SQL injection on item",
        claim="The item query crosses the expected input boundary",
        actor="operator",
    )
    response = tmp_path / "evidence" / target / "validation" / "f1" / "response.txt"
    response.parent.mkdir(parents=True)
    response.write_text("HTTP/1.1 200 OK\n\nfixture", encoding="utf-8")
    store.start_attempt(attempt_id="try1", source="native", started_at="2026-09-21T00:00:00Z", actor="operator")
    receipt = store.record_execution(
        attempt_id="try1",
        outcome="complete",
        observations=[{
            "endpoint": url,
            "method": "GET",
            "family": "sqli",
            "observed_at": "2026-09-21T00:00:00Z",
            "description": "Recorded fixture response",
            "artifacts": {"response": response.relative_to(tmp_path).as_posix()},
            "actor": "operator",
            "object_scope": "fixture",
            "variant": "baseline",
            "error": "",
            "truncated": False,
            "state_changing": False,
            "redline_checked": False,
            "result": "tested_finding",
            "identity_dimensions": {},
        }],
        candidate={
            "id": "f1",
            "endpoint": url,
            "method": "GET",
            "family": "sqli",
            "title": "SQL injection on item",
            "claim": "The item query crosses the expected input boundary",
        },
        actor="operator",
    )
    evidence = store.finding("f1")["evidence"]
    store.assess(
        command_id="assess:f1",
        finding_id="f1",
        verdict="confirmed",
        reason="The fixture records the claimed boundary crossing",
        boundary="The item query must remain within the expected input boundary",
        impact="A peer can influence the item query",
        evidence=evidence,
        actor="operator",
        expected_assessment=None,
    )
    store.decide_delivery(
        command_id="delivery:f1",
        finding_id="f1",
        assessment_id="assess:f1",
        destination="internal-review",
        status=delivery_status,
        reason="Fixture delivery decision",
        actor="operator",
        expected_decision=None,
    )
    findings_dir = tmp_path / "findings" / target
    findings_dir.mkdir(parents=True)
    payload = {
        "schema_version": 1,
        "target": target,
        "total": 1,
        "findings": [{
            "id": "f1",
            "type": "sqli",
            "category": "sqli",
            "title": "SQL injection on item",
            "summary": "Primary-store report fixture",
            "url": url,
            "severity": "high",
            "confidence": "confirmed",
            "validation_status": "validated",
            "report_status": "not_generated",
            "source_file": "fixture.txt",
            "raw": "fixture finding",
        }],
    }
    findings_path = findings_dir / "findings.json"
    findings_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return store, findings_dir, findings_path


def test_primary_report_generator_registers_store_report_without_legacy_writes(monkeypatch, tmp_path):
    store, findings_dir, findings_path = _primary_report_fixture(tmp_path)
    before = findings_path.read_bytes()
    monkeypatch.setattr(report_generator, "REPORTS_DIR", str(tmp_path / "reports"))

    total, index = report_generator.process_findings_dir(str(findings_dir))

    assert total == 1
    report_path = Path(index[0]["file"])
    assert report_path.parent == tmp_path / "reports" / "example.com"
    assert report_path.is_file()
    assert findings_path.read_bytes() == before
    assert json.loads((report_path.parent / "INDEX.json").read_text())["reports"] == index
    registered = store.finding("f1")["reports"]
    assert len(registered) == 1
    assert registered[0]["assessment_id"] == "assess:f1"
    assert registered[0]["delivery_id"] == "delivery:f1"
    assert store.finding("f1")["delivery_events"] == []
    published = json.loads((report_path.parent / "INDEX.json").read_text())
    assert published["source_binding"] == store.binding()
    assert published["as_of"] in (report_path.parent / "SUMMARY.md").read_text()


@pytest.mark.parametrize("bypass", ["target", "output", "symlink"])
def test_finding_writer_rejects_cross_target_destination(tmp_path, bypass):
    store, frozen_dir, frozen_path = _primary_report_fixture(tmp_path)
    before = frozen_path.read_bytes()
    legacy_dir = tmp_path / "findings" / "legacy.example"
    legacy_dir.mkdir()
    with pytest.raises(finding_index.StoreError):
        if bypass == "target":
            finding_index.upsert_finding(frozen_dir, {"id": "new", "type": "idor"}, target="other.example")
        elif bypass == "output":
            finding_index.write_finding_index(legacy_dir, output=frozen_path)
        else:
            (legacy_dir / "export").symlink_to(frozen_dir, target_is_directory=True)
            finding_index.write_finding_index(legacy_dir, output=legacy_dir / "export/findings.json")
    assert frozen_path.read_bytes() == before
    assert not (legacy_dir / "findings.json").exists()
    assert not (tmp_path / "state/other.example").exists()


def test_finding_writer_preserves_same_owner_custom_output(tmp_path):
    findings_dir = tmp_path / "findings" / "legacy.example"
    findings_dir.mkdir(parents=True)
    output = findings_dir / "custom-index.json"
    finding_index.write_finding_index(findings_dir, output=output, target="https://legacy.example")
    assert json.loads(output.read_text())["total"] == 0


@pytest.mark.parametrize("backend", ["preview", "frozen", "corrupt"])
def test_report_publication_refuses_nonlegacy_backend_before_artifacts(tmp_path, monkeypatch, backend):
    target = "example.com"
    store = TargetStore(tmp_path, target)
    store.initialize(allow_legacy=backend == "preview")
    if backend == "frozen":
        store.path.unlink()
    elif backend == "corrupt":
        store.path.write_bytes(b"broken database")
    findings_dir = tmp_path / "findings" / target
    findings_dir.mkdir(parents=True)
    (findings_dir / "findings.json").write_text(json.dumps({"target": target, "findings": [
        {"id": "draft", "type": "sqli", "url": "https://example.com/", "confidence": "confirmed"}
    ]}))
    monkeypatch.setattr(report_generator, "REPORTS_DIR", str(tmp_path / "reports"))
    with pytest.raises(ValueError):
        report_generator.process_findings_dir(findings_dir, allow_legacy_drafts=True)
    assert not (tmp_path / "reports").exists()


@pytest.mark.parametrize("rebind", ["target", "input_symlink", "output_symlink"])
def test_report_publication_rejects_owner_rebinding(tmp_path, monkeypatch, rebind):
    _, primary_dir, primary_path = _primary_report_fixture(tmp_path)
    before = primary_path.read_bytes()
    legacy_dir = tmp_path / "findings" / "legacy.example"
    legacy_dir.mkdir()
    findings_dir = legacy_dir
    if rebind == "target":
        (legacy_dir / "findings.json").write_text(json.dumps({"target": "example.com", "findings": []}))
    elif rebind == "input_symlink":
        findings_dir = tmp_path / "findings" / "alias.example"
        findings_dir.symlink_to(primary_dir, target_is_directory=True)
    else:
        (tmp_path / "reports").mkdir()
        (tmp_path / "reports/legacy.example").symlink_to(primary_dir, target_is_directory=True)
    monkeypatch.setattr(report_generator, "REPORTS_DIR", str(tmp_path / "reports"))
    with pytest.raises(ValueError):
        report_generator.process_findings_dir(findings_dir, allow_legacy_drafts=True)
    assert primary_path.read_bytes() == before
    assert not (primary_dir / "INDEX.json").exists()
    assert not (tmp_path / "reports/example.com").exists()


@pytest.mark.parametrize("interposition", ["read", "publish"])
def test_primary_report_index_rejects_delivery_drift(tmp_path, monkeypatch, interposition):
    store, findings_dir, _ = _primary_report_fixture(tmp_path)
    monkeypatch.setattr(report_generator, "REPORTS_DIR", str(tmp_path / "reports"))
    name = "_primary_findings" if interposition == "read" else "write_report_index"
    original = getattr(report_generator, name)
    reads = 0

    def revoke():
        store.decide_delivery(command_id="delivery:revoked", finding_id="f1", assessment_id="assess:f1",
                              destination="internal-review", status="ineligible", reason="Revoked",
                              actor="operator", expected_decision="delivery:f1")

    def drift(*args, **kwargs):
        nonlocal reads
        if interposition == "publish":
            revoke()
            return original(*args, **kwargs)
        result = original(*args, **kwargs)
        reads += 1
        if reads == 2:
            revoke()
        return result

    monkeypatch.setattr(report_generator, name, drift)
    with pytest.raises(report_generator.ConflictError, match="snapshot changed"):
        report_generator.process_findings_dir(findings_dir)
    assert store.finding("f1")["reports"][0]["stale"] is True
    assert not (tmp_path / "reports/example.com/INDEX.json").exists()
    assert not (tmp_path / "reports/example.com/SUMMARY.md").exists()


def test_primary_report_generator_reads_store_without_legacy_finding_index(monkeypatch, tmp_path):
    store, findings_dir, findings_path = _primary_report_fixture(tmp_path)
    findings_path.unlink()
    monkeypatch.setattr(report_generator, "REPORTS_DIR", str(tmp_path / "reports"))

    def forbidden(*args, **kwargs):
        raise AssertionError("primary report generation read findings.json")

    monkeypatch.setattr(report_generator, "load_finding_index", forbidden)

    total, index = report_generator.process_findings_dir(str(findings_dir))

    assert total == 1
    assert index[0]["finding_id"] == "f1"
    assert store.finding("f1")["reports"][0]["artifact_ref"].startswith("reports/example.com/")


@pytest.mark.parametrize("failure", ["registration", "index"])
def test_primary_report_retry_preserves_body_and_only_registers_once(monkeypatch, tmp_path, failure):
    store, findings_dir, findings_path = _primary_report_fixture(tmp_path)
    before = findings_path.read_bytes()
    monkeypatch.setattr(report_generator, "REPORTS_DIR", str(tmp_path / "reports"))
    owner = TargetStore if failure == "registration" else report_generator
    name = "register_report" if failure == "registration" else "write_report_index"
    original = getattr(owner, name)

    def interrupted(*args, **kwargs):
        raise OSError("injected publication failure")

    monkeypatch.setattr(owner, name, interrupted)
    with pytest.raises(OSError, match="injected publication failure"):
        report_generator.process_findings_dir(str(findings_dir))
    report_path = next((tmp_path / "reports" / "example.com").glob("report_*.md"))
    body = report_path.read_bytes()
    registered = store.finding("f1")["reports"]
    assert len(registered) == (0 if failure == "registration" else 1)
    monkeypatch.setattr(owner, name, original)
    total, index = report_generator.process_findings_dir(str(findings_dir))
    revision = store.binding()["revision"]
    assert total == 1
    assert report_generator.process_findings_dir(str(findings_dir)) == (total, index)
    assert store.binding()["revision"] == revision
    assert report_path.read_bytes() == body
    assert len(store.finding("f1")["reports"]) == 1
    assert store.finding("f1")["delivery_events"] == []
    assert findings_path.read_bytes() == before


def test_primary_report_index_preserves_all_registered_reports(monkeypatch, tmp_path):
    store, findings_dir, _ = _primary_report_fixture(tmp_path)
    monkeypatch.setattr(report_generator, "REPORTS_DIR", str(tmp_path / "reports"))

    def forbidden(*args, **kwargs):
        raise AssertionError("primary must not call a legacy owner")

    for name in ("load_finding_index", "update_finding_status", "_reconcile_report_action"):
        monkeypatch.setattr(report_generator, name, forbidden)
    _, first = report_generator.process_findings_dir(str(findings_dir))
    report_file = Path(first[0]["file"])
    second = report_file.with_name("operator-report.md")
    second.write_text("Independent registered report")
    store.register_report(command_id="operator:report", report_id="operator-report", finding_id="f1",
                          assessment_id="assess:f1", delivery_id="delivery:f1", artifact=str(second),
                          actor="operator")
    revision = store.binding()["revision"]
    total, index = report_generator.process_findings_dir(str(findings_dir))
    assert total == 2
    assert {row["id"] for row in index} == {first[0]["id"], "operator-report"}
    assert store.binding()["revision"] == revision
    assert json.loads((report_file.parent / "INDEX.json").read_text())["reports"] == index


@pytest.mark.parametrize("damaged", ["report", "evidence"])
def test_primary_report_rerun_removes_stale_index_without_rewriting_artifacts(monkeypatch, tmp_path, damaged):
    store, findings_dir, _ = _primary_report_fixture(tmp_path)
    monkeypatch.setattr(report_generator, "REPORTS_DIR", str(tmp_path / "reports"))
    _, index = report_generator.process_findings_dir(str(findings_dir))
    report = Path(index[0]["file"])
    artifact = report if damaged == "report" else tmp_path / "evidence/example.com/validation/f1/response.txt"
    artifact.write_text("damaged")
    body = report.read_bytes()
    revision = store.binding()["revision"]
    assert report_generator.process_findings_dir(str(findings_dir)) == (0, [])
    assert report.read_bytes() == body
    assert store.binding()["revision"] == revision
    assert json.loads((report.parent / "INDEX.json").read_text())["reports"] == []
    assert "Total findings: 0" in (report.parent / "SUMMARY.md").read_text()


def test_primary_new_assessment_gets_new_report_without_rebinding_old_body(monkeypatch, tmp_path):
    store, findings_dir, _ = _primary_report_fixture(tmp_path)
    monkeypatch.setattr(report_generator, "REPORTS_DIR", str(tmp_path / "reports"))
    _, first = report_generator.process_findings_dir(str(findings_dir))
    old_path = Path(first[0]["file"])
    body = old_path.read_bytes()
    store.assess(command_id="assess:f1:2", finding_id="f1", verdict="confirmed", reason="Rechecked",
                 boundary="Input isolation", impact="Peer query influence", evidence=store.finding("f1")["evidence"],
                 actor="operator", expected_assessment="assess:f1")
    store.decide_delivery(command_id="delivery:f1:2", finding_id="f1", assessment_id="assess:f1:2",
                          destination="internal-review", status="eligible", reason="Rechecked",
                          actor="operator", expected_decision="delivery:f1")
    total, current = report_generator.process_findings_dir(str(findings_dir))
    assert total == 1
    assert current[0]["id"] != first[0]["id"]
    assert current[0]["assessment_id"] == "assess:f1:2"
    assert old_path.read_bytes() == body
    assert len(store.finding("f1")["reports"]) == 2


def test_report_generator_preserves_jwt_structured_finding_type(monkeypatch, tmp_path):
    findings_dir = tmp_path / "findings" / "example.com"
    findings_dir.mkdir(parents=True)
    (findings_dir / "findings.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "target": "example.com",
                "total": 1,
                "findings": [
                    {
                        "id": "jwt_alg_none_abc123",
                        "type": "jwt",
                        "category": "jwt",
                        "title": "JWT alg none role escalation",
                        "summary": "validated JWT alg=none role escalation",
                        "url": "https://example.com/rest/order-history/orders",
                        "severity": "high",
                        "confidence": "confirmed",
                        "validation_status": "validated",
                        "report_status": "not_generated",
                        "source_file": "evidence/example.com/jwt/validation-summary.json",
                        "raw": "validate:confirmed:evidence/example.com/jwt/validation-summary.json",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    _record_owner_provenance(findings_dir, "jwt_alg_none_abc123")
    monkeypatch.setattr(report_generator, "REPORTS_DIR", str(tmp_path / "reports"))

    total, index = report_generator.process_findings_dir(str(findings_dir))

    assert total == 1
    assert index[0]["finding_id"] == "jwt_alg_none_abc123"
    assert index[0]["type"] == "jwt"
    report_path = Path(index[0]["file"])
    assert report_path.name == "jwt_001.md"
    report_text = report_path.read_text(encoding="utf-8")
    assert "JWT Validation Weakness" in report_text
    updated_index = json.loads((findings_dir / "findings.json").read_text(encoding="utf-8"))
    assert updated_index["findings"][0]["report_id"] == "jwt_001"


def test_report_generator_maps_canonical_authentication_bypass_type(monkeypatch, tmp_path):
    findings_dir = tmp_path / "findings" / "example.com"
    findings_dir.mkdir(parents=True)
    (findings_dir / "findings.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "target": "example.com",
                "total": 1,
                "findings": [
                    {
                        "id": "auth_bypass_canonical_abc123",
                        "type": "authentication_bypass",
                        "category": "authentication_bypass",
                        "title": "JWT subject claim accepted without verification",
                        "summary": "A regular session reaches an administrator-only action.",
                        "url": "https://example.com/admin",
                        "severity": "high",
                        "confidence": "confirmed",
                        "validation_status": "validated",
                        "report_status": "not_generated",
                        "source_file": "evidence/example.com/validation/browser-proof.json",
                        "raw": "validated browser baseline and variant",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    _record_owner_provenance(findings_dir, "auth_bypass_canonical_abc123")
    monkeypatch.setattr(report_generator, "REPORTS_DIR", str(tmp_path / "reports"))

    total, index = report_generator.process_findings_dir(str(findings_dir))

    assert total == 1
    assert index[0]["type"] == "auth_bypass"
    report_path = Path(index[0]["file"])
    assert report_path.name == "auth_bypass_001.md"
    assert "Authentication/Authorization Bypass" in report_path.read_text(encoding="utf-8")
    updated_index = json.loads((findings_dir / "findings.json").read_text(encoding="utf-8"))
    assert updated_index["findings"][0]["report_id"] == "auth_bypass_001"


def test_report_generator_keeps_existing_generated_reports_in_index(monkeypatch, tmp_path):
    findings_dir = tmp_path / "findings" / "example.com"
    findings_dir.mkdir(parents=True)
    report_dir = tmp_path / "reports" / "example.com"
    report_dir.mkdir(parents=True)
    existing_report = report_dir / "sqli_001.md"
    existing_report.write_text("# Existing SQLi report\n", encoding="utf-8")
    validation_dir = tmp_path / "evidence" / "example.com" / "validation" / "xss-1"
    validation_dir.mkdir(parents=True)
    validation_summary = validation_dir / "validation-summary.json"
    validation_summary.write_text(
        json.dumps(
            {
                "all_gates_passed": True,
                "four_validation_gates_passed": True,
                "seven_question_gate_passed": True,
                "seven_question_gate_decision": "pass",
                "evidence_rubric": {"summary": "xss browser marker evidence"},
            }
        ),
        encoding="utf-8",
    )
    (findings_dir / "findings.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "target": "example.com",
                "total": 2,
                "findings": [
                    {
                        "id": "sqli_done",
                        "type": "sqli",
                        "category": "sqli",
                        "title": "SQLi on item",
                        "summary": "verified SQLi",
                        "url": "https://example.com/item?id=1",
                        "severity": "high",
                        "confidence": "confirmed",
                        "validation_status": "validated",
                        "report_status": "generated",
                        "report_id": "sqli_001",
                        "report_file": str(existing_report),
                        "source_file": "sqli/timebased_candidates.txt",
                        "raw": "[SQLI-POC-VERIFIED] https://example.com/item?id=1",
                    },
                    {
                        "id": "xss_new",
                        "type": "xss",
                        "category": "xss",
                        "title": "DOM XSS on search",
                        "summary": "browser marker XSS",
                        "url": "https://example.com/#/search?q=<img>",
                        "severity": "medium",
                        "confidence": "confirmed",
                        "validation_status": "validated",
                        "validation_summary": str(validation_summary),
                        "report_status": "not_generated",
                        "source_file": "xss/manual_ai_candidates.txt",
                        "raw": "[DOM-XSS-MARKER] https://example.com/#/search?q=<img>",
                    },
                ],
            }
        ),
        encoding="utf-8",
    )
    _record_owner_provenance(findings_dir, "sqli_done")
    _record_owner_provenance(findings_dir, "xss_new")
    monkeypatch.setattr(report_generator, "REPORTS_DIR", str(tmp_path / "reports"))

    total, index = report_generator.process_findings_dir(str(findings_dir))

    assert total == 2
    assert {item["finding_id"] for item in index} == {"sqli_done", "xss_new"}
    saved = json.loads((report_dir / "INDEX.json").read_text(encoding="utf-8"))
    assert saved["total_reports"] == 2
    assert {item["finding_id"] for item in saved["reports"]} == {"sqli_done", "xss_new"}


def test_report_generator_incremental_same_type_uses_next_id_without_overwrite(monkeypatch, tmp_path):
    findings_dir = tmp_path / "findings" / "example.com"
    findings_dir.mkdir(parents=True)
    finding_index.upsert_finding(
        findings_dir,
        {
            "id": "sqli-first",
            "type": "sqli",
            "category": "sqli",
            "title": "First SQLi",
            "summary": "first validated SQLi",
            "url": "https://example.com/items?id=1",
            "severity": "high",
            "confidence": "confirmed",
            "validation_status": "validated",
            "report_status": "not_generated",
            "raw": "[SQLI-POC-VERIFIED] first",
        },
        target="example.com",
    )
    _record_owner_provenance(findings_dir, "sqli-first")
    monkeypatch.setattr(report_generator, "REPORTS_DIR", str(tmp_path / "reports"))

    first_total, first_index = report_generator.process_findings_dir(str(findings_dir))
    first_report = Path(first_index[0]["file"])
    first_content = first_report.read_text(encoding="utf-8")
    assert first_total == 1
    assert first_report.name == "sqli_001.md"

    finding_index.upsert_finding(
        findings_dir,
        {
            "id": "sqli-second",
            "type": "sqli",
            "category": "sqli",
            "title": "Second SQLi",
            "summary": "second validated SQLi",
            "url": "https://example.com/search?q=test",
            "severity": "high",
            "confidence": "confirmed",
            "validation_status": "validated",
            "report_status": "not_generated",
            "raw": "[SQLI-POC-VERIFIED] second",
        },
        target="example.com",
    )
    _record_owner_provenance(findings_dir, "sqli-second")
    second_total, second_index = report_generator.process_findings_dir(str(findings_dir))
    payload = finding_index.load_finding_index(findings_dir)
    by_id = {item["id"]: item for item in payload["findings"]}

    assert second_total == 2
    assert {item["id"] for item in second_index} == {"sqli_001", "sqli_002"}
    assert by_id["sqli-first"]["report_id"] == "sqli_001"
    assert by_id["sqli-second"]["report_id"] == "sqli_002"
    assert first_report.read_text(encoding="utf-8") == first_content
    assert (first_report.parent / "sqli_002.md").is_file()


def test_report_generator_does_not_overwrite_unowned_report_file(monkeypatch, tmp_path):
    findings_dir = tmp_path / "findings" / "example.com"
    findings_dir.mkdir(parents=True)
    report_dir = tmp_path / "reports" / "example.com"
    report_dir.mkdir(parents=True)
    occupied = report_dir / "sqli_001.md"
    occupied.write_text("# Existing unrelated report\n", encoding="utf-8")
    finding_index.upsert_finding(
        findings_dir,
        {
            "id": "sqli-new",
            "type": "sqli",
            "url": "https://example.com/items?id=2",
            "severity": "high",
            "confidence": "confirmed",
            "validation_status": "validated",
            "report_status": "not_generated",
            "raw": "[SQLI-POC-VERIFIED] new",
        },
        target="example.com",
    )
    _record_owner_provenance(findings_dir, "sqli-new")
    monkeypatch.setattr(report_generator, "REPORTS_DIR", str(tmp_path / "reports"))

    total, index = report_generator.process_findings_dir(str(findings_dir))

    assert total == 1
    assert index[0]["id"] == "sqli_002"
    assert occupied.read_text(encoding="utf-8") == "# Existing unrelated report\n"
    assert (report_dir / "sqli_002.md").is_file()


def test_report_generator_reuses_same_finding_crash_artifact(monkeypatch, tmp_path):
    findings_dir = tmp_path / "findings" / "example.com"
    findings_dir.mkdir(parents=True)
    finding = {
        "id": "sqli-crash-recovery",
        "type": "sqli",
        "url": "https://example.com/items?id=3",
        "severity": "high",
        "confidence": "confirmed",
        "validation_status": "validated",
        "report_status": "not_generated",
        "raw": "[SQLI-POC-VERIFIED] crash recovery",
    }
    finding_index.upsert_finding(findings_dir, finding, target="example.com")
    _record_owner_provenance(findings_dir, "sqli-crash-recovery")
    report_dir = tmp_path / "reports" / "example.com"
    report_dir.mkdir(parents=True)
    report_content, _ = report_generator.generate_report(finding, "sqli", "example.com")
    crash_file = report_dir / "sqli_004.md"
    crash_file.write_text(report_content, encoding="utf-8")
    before = crash_file.read_bytes()
    monkeypatch.setattr(report_generator, "REPORTS_DIR", str(tmp_path / "reports"))

    total, index = report_generator.process_findings_dir(str(findings_dir))
    persisted = finding_index.find_finding(findings_dir, "sqli-crash-recovery")

    assert total == 1
    assert index[0]["id"] == "sqli_004"
    assert crash_file.read_bytes() == before
    assert persisted is not None
    assert persisted["report_status"] == "generated"
    assert persisted["report_id"] == "sqli_004"


def test_report_generator_uses_canonical_report_dir_for_url_target(monkeypatch, tmp_path):
    findings_dir = tmp_path / "findings" / "127.0.0.1:3002"
    findings_dir.mkdir(parents=True)
    validation_dir = tmp_path / "evidence" / "127.0.0.1:3002" / "validation" / "xss"
    validation_dir.mkdir(parents=True)
    validation_summary = validation_dir / "validation-summary.json"
    validation_summary.write_text(
        json.dumps(
            {
                "all_gates_passed": True,
                "four_validation_gates_passed": True,
                "seven_question_gate_passed": True,
                "seven_question_gate_decision": "pass",
            }
        ),
        encoding="utf-8",
    )
    (findings_dir / "findings.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "target": "http://127.0.0.1:3002",
                "total": 1,
                "findings": [
                    {
                        "id": "xss_url_target",
                        "type": "xss",
                        "category": "xss",
                        "title": "DOM XSS",
                        "summary": "DOM XSS marker",
                        "url": "http://127.0.0.1:3002/#/search?q=<img>",
                        "severity": "medium",
                        "confidence": "confirmed",
                        "validation_status": "validated",
                        "validation_summary": str(validation_summary),
                        "report_status": "not_generated",
                        "source_file": "xss/manual.txt",
                        "raw": "[DOM-XSS] http://127.0.0.1:3002/#/search?q=<img>",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    _record_owner_provenance(findings_dir, "xss_url_target")
    monkeypatch.setattr(report_generator, "REPORTS_DIR", str(tmp_path / "reports"))

    total, index = report_generator.process_findings_dir(str(findings_dir))

    assert total == 1
    report_path = Path(index[0]["file"])
    assert report_path.parent == tmp_path / "reports" / "127.0.0.1:3002"
    assert (tmp_path / "reports" / "127.0.0.1:3002" / "INDEX.json").is_file()
    assert not (tmp_path / "reports" / "http:" / "127.0.0.1:3002").exists()


def _report_queue_fixture(monkeypatch, tmp_path):
    findings_dir = tmp_path / "findings" / "example.com"
    findings_dir.mkdir(parents=True)
    (findings_dir / "findings.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "target": "example.com",
                "total": 1,
                "findings": [
                    {
                        "id": "sqli_report_sync",
                        "type": "sqli",
                        "category": "sqli",
                        "title": "SQLi on item",
                        "summary": "verified SQLi",
                        "url": "https://example.com/item?id=1",
                        "severity": "high",
                        "confidence": "confirmed",
                        "validation_status": "validated",
                        "report_status": "not_generated",
                        "source_file": "sqli/timebased_candidates.txt",
                        "raw": "[SQLI-POC-VERIFIED] dialect=mysql param=1 url=https://example.com/item?id=1",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    _record_owner_provenance(findings_dir, "sqli_report_sync")
    queue_dir = tmp_path / "state" / "example.com"
    queue_dir.mkdir(parents=True, exist_ok=True)
    (queue_dir / "action_queue.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "target": "example.com",
                "actions": [
                    {
                        "id": "AQ-0001",
                        "status": "queued",
                        "type": "report",
                        "priority": 95,
                        "evidence": "Draft report for validated finding sqli_report_sync; do not submit without human review.",
                        "next_question": "Generate the report draft.",
                        "action": "Draft report for validated finding sqli_report_sync.",
                        "command_hint": "/report",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(report_generator, "BASE_DIR", str(tmp_path))
    monkeypatch.setattr(report_generator, "REPORTS_DIR", str(tmp_path / "reports"))
    return findings_dir, queue_dir


def test_report_generator_syncs_report_action_queue(monkeypatch, tmp_path):
    findings_dir, queue_dir = _report_queue_fixture(monkeypatch, tmp_path)

    total, index = report_generator.process_findings_dir(str(findings_dir))
    queue = json.loads((queue_dir / "action_queue.json").read_text(encoding="utf-8"))
    finding = finding_index.find_finding(findings_dir, "sqli_report_sync")

    assert total == 1
    assert index[0]["queue_sync"]["status"] == "updated"
    assert finding is not None
    assert finding["queue_sync"] == index[0]["queue_sync"]
    assert queue["actions"][0]["status"] == "reported"
    assert "report_file=" in queue["actions"][0]["result"]


@pytest.mark.parametrize(
    "failure_point",
    ["report_file", "finding", "queue_witness", "index"],
)
def test_report_generator_retry_reconciles_interrupted_cross_owner_flow(
    monkeypatch,
    tmp_path,
    failure_point,
):
    findings_dir, queue_dir = _report_queue_fixture(monkeypatch, tmp_path)
    failed = False
    original_update = report_generator.update_finding_status
    original_sync = report_generator.sync_report_action_queue
    original_write_index = report_generator.write_report_index

    def fail_update_once(*args, **updates):
        nonlocal failed
        should_fail = (
            failure_point == "report_file" and updates.get("report_status") == "generated"
        ) or (
            failure_point == "queue_witness" and "queue_sync" in updates
        )
        if should_fail and not failed:
            failed = True
            raise OSError(f"interrupted after {failure_point}")
        return original_update(*args, **updates)

    def fail_sync_once(*args, **kwargs):
        nonlocal failed
        if failure_point == "finding" and not failed:
            failed = True
            raise OSError(f"interrupted after {failure_point}")
        return original_sync(*args, **kwargs)

    def fail_index_once(*args, **kwargs):
        nonlocal failed
        if failure_point == "index" and not failed:
            failed = True
            raise OSError(f"interrupted after {failure_point}")
        return original_write_index(*args, **kwargs)

    monkeypatch.setattr(report_generator, "update_finding_status", fail_update_once)
    monkeypatch.setattr(report_generator, "sync_report_action_queue", fail_sync_once)
    monkeypatch.setattr(report_generator, "write_report_index", fail_index_once)

    with pytest.raises(OSError, match=f"interrupted after {failure_point}"):
        report_generator.process_findings_dir(str(findings_dir))

    total, index = report_generator.process_findings_dir(str(findings_dir))
    finding = finding_index.find_finding(findings_dir, "sqli_report_sync")
    queue = json.loads((queue_dir / "action_queue.json").read_text(encoding="utf-8"))
    report_dir = tmp_path / "reports" / "example.com"

    assert failed is True
    assert total == 1
    assert len(index) == 1
    assert finding is not None
    assert finding["report_status"] == "generated"
    assert finding["report_id"] == "sqli_001"
    assert finding["queue_sync"]["status"] in {"updated", "unchanged"}
    assert index[0]["queue_sync"] == finding["queue_sync"]
    assert queue["actions"][0]["status"] == "reported"
    assert len(queue["actions"]) == 1
    assert [path.name for path in report_dir.glob("sqli_*.md")] == ["sqli_001.md"]
    assert (report_dir / "INDEX.json").is_file()


def test_report_generator_uses_validation_summary_for_auth_bypass_narrative(monkeypatch, tmp_path):
    findings_dir = tmp_path / "findings" / "example.com"
    findings_dir.mkdir(parents=True)
    validation_dir = tmp_path / "evidence" / "example.com" / "validation" / "authz-1"
    validation_dir.mkdir(parents=True)
    validation_summary = validation_dir / "summary.json"
    validation_summary.write_text(
        json.dumps(
            {
                "summary_path": "evidence/example.com/validation/authz-1/summary.json",
                "markers": ["secret-like"],
                "artifacts": {
                    "baseline_request": "evidence/example.com/validation/authz-1/baseline.request.txt",
                    "baseline_response": "evidence/example.com/validation/authz-1/baseline.response.txt",
                },
                "baseline": {"status": 200},
                "evidence_rubric": {"summary": "authz:candidate-ready score=100 satisfied=4/4"},
                "all_gates_passed": True,
                "seven_question_gate_passed": True,
                "seven_question_gate_decision": "pass",
                "four_validation_gates_passed": True,
            }
        ),
        encoding="utf-8",
    )
    (findings_dir / "findings.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "target": "example.com",
                "total": 1,
                "findings": [
                    {
                        "id": "authz_abc123",
                        "type": "auth_bypass",
                        "category": "auth_bypass",
                        "title": "AUTH_BYPASS on feedbacks",
                        "summary": "200 1734 https://example.com/api/Feedbacks",
                        "url": "https://example.com/api/Feedbacks",
                        "severity": "high",
                        "confidence": "confirmed",
                        "validation_status": "validated",
                        "validation_summary": str(validation_summary),
                        "report_status": "not_generated",
                        "source_file": "auth_bypass/unauth_api_access.txt",
                        "line_number": 1,
                        "template_id": "",
                        "raw": "200 1734 https://example.com/api/Feedbacks",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    _record_owner_provenance(findings_dir, "authz_abc123")
    monkeypatch.setattr(report_generator, "REPORTS_DIR", str(tmp_path / "reports"))
    monkeypatch.setattr(report_generator, "BASE_DIR", str(tmp_path))

    total, index = report_generator.process_findings_dir(str(findings_dir))

    assert total == 1
    report_path = Path(index[0]["file"])
    report_text = report_path.read_text(encoding="utf-8")
    assert "Unauthenticated Sensitive Data Exposure" in report_text
    assert "secret-like" in report_text
    assert "Validation Summary" in report_text
    assert "Baseline Response" in report_text
    assert "(CVSS:" not in report_text


def test_report_generator_preserves_legacy_cvss_without_regrading(monkeypatch, tmp_path):
    findings_dir = tmp_path / "findings" / "example.com"
    findings_dir.mkdir(parents=True)
    validation_dir = tmp_path / "evidence" / "example.com" / "validation" / "cvss-critical"
    validation_dir.mkdir(parents=True)
    validation_summary = validation_dir / "summary.json"
    validation_summary.write_text(
        json.dumps(
            {
                "all_gates_passed": True,
                "seven_question_gate_passed": True,
                "four_validation_gates_passed": True,
                "cvss_score": 9.8,
                "cvss_version": "3.1",
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "severity": "medium",
            }
        ),
        encoding="utf-8",
    )
    (findings_dir / "findings.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "target": "example.com",
                "total": 1,
                "findings": [
                    {
                        "id": "cvss-critical",
                        "type": "sqli",
                        "category": "sqli",
                        "title": "SQL injection",
                        "url": "https://example.com/search?q=x",
                        "severity": "medium",
                        "confidence": "confirmed",
                        "validation_status": "validated",
                        "validation_summary": str(validation_summary),
                        "report_status": "not_generated",
                        "source_file": "sqli/findings.txt",
                        "raw": "SQLI-POC-VERIFIED",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    _record_owner_provenance(findings_dir, "cvss-critical")
    original_summary = validation_summary.read_bytes()
    original_digest = finding_index.find_finding(findings_dir, "cvss-critical").get("validation_summary_sha256")
    monkeypatch.setattr(report_generator, "REPORTS_DIR", str(tmp_path / "reports"))
    monkeypatch.setattr(report_generator, "BASE_DIR", str(tmp_path))

    total, index = report_generator.process_findings_dir(str(findings_dir))

    assert total == 1
    assert index[0]["severity"] == "medium"
    report_text = Path(index[0]["file"]).read_text(encoding="utf-8")
    assert "**MEDIUM** (CVSS: 9.8)" in report_text
    assert "CVSS Version: `3.1`" in report_text
    assert "CVSS Vector: `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`" in report_text
    assert finding_index.find_finding(findings_dir, "cvss-critical")["severity"] == "medium"
    assert validation_summary.read_bytes() == original_summary
    assert finding_index.find_finding(findings_dir, "cvss-critical").get("validation_summary_sha256") == original_digest


def test_report_generator_uses_write_sink_auth_bypass_narrative(monkeypatch, tmp_path):
    findings_dir = tmp_path / "findings" / "example.com"
    findings_dir.mkdir(parents=True)
    validation_dir = tmp_path / "evidence" / "example.com" / "validation" / "forged-review"
    validation_dir.mkdir(parents=True)
    validation_summary = validation_dir / "summary.json"
    validation_summary.write_text(
        json.dumps(
            {
                "summary_path": "evidence/example.com/validation/forged-review/summary.json",
                "method": "PUT",
                "endpoint": "/rest/products/1/reviews",
                "markers": ["anonymous_state_change", "author_spoof", "public_ui_visibility"],
                "ai_assessment": (
                    "Anonymous requests can create public reviews whose author field is taken "
                    "from the request body."
                ),
                "artifacts": {
                    "anonymous_request": "evidence/example.com/validation/forged-review/request.txt",
                    "anonymous_response_body": "evidence/example.com/validation/forged-review/response.body",
                },
                "evidence_rubric": {
                    "summary": "authz/business-logic:validated via anonymous state change"
                },
                "all_gates_passed": True,
                "seven_question_gate_passed": True,
                "seven_question_gate_decision": "report",
                "four_validation_gates_passed": True,
            }
        ),
        encoding="utf-8",
    )
    (findings_dir / "findings.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "target": "example.com",
                "total": 1,
                "findings": [
                    {
                        "id": "authz_forged_review",
                        "type": "auth_bypass",
                        "category": "auth_bypass",
                        "title": "Forged review author",
                        "summary": (
                            "Anonymous PUT accepts author from request body and renders the "
                            "review as admin@example.com."
                        ),
                        "url": "https://example.com/rest/products/1/reviews",
                        "method": "PUT",
                        "severity": "medium",
                        "confidence": "confirmed",
                        "validation_status": "validated",
                        "validation_summary": str(validation_summary),
                        "report_status": "not_generated",
                        "source_file": "evidence/example.com/validation/forged-review/summary.json",
                        "line_number": 0,
                        "template_id": "",
                        "raw": "manual-ai-validated:forged-review",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    _record_owner_provenance(findings_dir, "authz_forged_review")
    monkeypatch.setattr(report_generator, "REPORTS_DIR", str(tmp_path / "reports"))
    monkeypatch.setattr(report_generator, "BASE_DIR", str(tmp_path))

    total, index = report_generator.process_findings_dir(str(findings_dir))

    assert total == 1
    report_text = Path(index[0]["file"]).read_text(encoding="utf-8")
    assert "Unauthenticated Content Impersonation" in report_text
    assert "unauthenticated `PUT` request" in report_text
    assert "Send a `PUT` request" in report_text
    assert "request.txt" in report_text
    assert "author field" in report_text
    assert "Navigate to the following URL" not in report_text
    assert "returned HTTP 200" not in report_text


def test_report_generator_keeps_validated_lower_severity_and_skips_unvalidated_findings(
    monkeypatch,
    tmp_path,
):
    findings_dir = tmp_path / "findings" / "example.com"
    findings_dir.mkdir(parents=True)
    (findings_dir / "findings.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "target": "example.com",
                "total": 3,
                "findings": [
                    {
                        "id": "unvalidated_one",
                        "type": "sqli",
                        "url": "https://example.com/item?id=1",
                        "severity": "high",
                        "validation_status": "unvalidated",
                        "report_status": "not_generated",
                        "raw": "candidate",
                    },
                    {
                        "id": "validated_pending",
                        "type": "idor",
                        "url": "https://example.com/api/users/2",
                        "severity": "low",
                        "validation_status": "validated",
                        "report_status": "not_generated",
                        "raw": "validated candidate",
                    },
                    {
                        "id": "validated_done",
                        "type": "mfa",
                        "url": "https://example.com/mfa/verify",
                        "severity": "medium",
                        "validation_status": "validated",
                        "report_status": "generated",
                        "report_id": "mfa_001",
                        "report_file": "reports/example.com/mfa_001.md",
                        "raw": "already reported",
                    },
                ],
            }
        ),
        encoding="utf-8",
    )
    _record_owner_provenance(findings_dir, "validated_pending")
    _record_owner_provenance(findings_dir, "validated_done")
    monkeypatch.setattr(report_generator, "REPORTS_DIR", str(tmp_path / "reports"))

    total, index = report_generator.process_findings_dir(str(findings_dir))

    assert total == 2
    assert len(index) == 2
    assert {item["finding_id"] for item in index} == {"validated_pending", "validated_done"}
    updated_index = json.loads((findings_dir / "findings.json").read_text(encoding="utf-8"))
    statuses = {item["id"]: item["report_status"] for item in updated_index["findings"]}
    assert statuses == {
        "unvalidated_one": "not_generated",
        "validated_pending": "generated",
        "validated_done": "generated",
    }


def test_report_generator_requires_explicit_compat_for_statusless_structured_findings(
    monkeypatch,
    tmp_path,
):
    findings_dir = tmp_path / "findings" / "example.com"
    findings_dir.mkdir(parents=True)
    (findings_dir / "findings.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "target": "example.com",
                "total": 1,
                "findings": [
                    {
                        "id": "legacy_no_status",
                        "type": "sqli",
                        "url": "https://example.com/legacy?id=1",
                        "severity": "high",
                        "raw": "legacy candidate",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(report_generator, "REPORTS_DIR", str(tmp_path / "reports"))

    total, index = report_generator.process_findings_dir(str(findings_dir))

    assert total == 0
    assert index == []

    total, index = report_generator.process_findings_dir(
        str(findings_dir),
        allow_legacy_drafts=True,
    )

    assert total == 1
    assert index[0]["finding_id"] == "legacy_no_status"
    assert index[0]["canonical_lifecycle"] is False
    persisted = json.loads((findings_dir / "findings.json").read_text(encoding="utf-8"))
    assert "report_status" not in persisted["findings"][0]


def test_validate_prefill_loads_finding_candidate(tmp_path):
    findings_dir = tmp_path / "findings" / "example.com"
    findings_dir.mkdir(parents=True)
    (findings_dir / "findings.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "target": "example.com",
                "findings": [
                    {
                        "id": "mfa_abc123",
                        "type": "mfa",
                        "url": "https://example.com/mfa/verify",
                        "summary": "[MFA-NO-RATE-LIMIT] https://example.com/mfa/verify",
                        "source_file": "mfa/findings.txt",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    prefill = validate.load_finding_prefill(str(findings_dir), "mfa_abc123")

    assert prefill["target"] == "example.com"
    assert prefill["vuln_type"] == "MFA"
    assert prefill["endpoint"] == "https://example.com/mfa/verify"
    assert prefill["finding_id"] == "mfa_abc123"
    assert prefill["source_file"] == "mfa/findings.txt"
    assert prefill["summary"] == "[MFA-NO-RATE-LIMIT] https://example.com/mfa/verify"
    assert "rubric" not in prefill


def test_validate_prefill_keeps_source_and_ignores_legacy_rubric(tmp_path, monkeypatch):
    monkeypatch.setattr(validate, "BASE_DIR", tmp_path)
    summary_path = tmp_path / "evidence" / "target.com" / "validation" / "sqli-search" / "summary.json"
    summary_path.parent.mkdir(parents=True)
    summary_path.write_text(
        json.dumps(
            {
                "evidence_rubric": {
                    "rubric_id": "sqli",
                    "status": "candidate-ready",
                    "score": 100,
                    "missing_labels": [],
                    "summary": "sqli:candidate-ready score=100 satisfied=4/4",
                }
            }
        ),
        encoding="utf-8",
    )
    findings_dir = tmp_path / "findings" / "target.com"
    findings_dir.mkdir(parents=True)
    (findings_dir / "findings.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "target": "target.com",
                "findings": [
                    {
                        "id": "sqli-search",
                        "type": "sqli",
                        "url": "https://target.com/rest/products/search?q=apple",
                        "summary": "sqli:candidate-ready score=100 satisfied=4/4",
                        "source_file": "evidence/target.com/validation/sqli-search/summary.json",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    prefill = validate.load_finding_prefill(str(findings_dir), "sqli-search")

    assert "rubric" not in prefill
    assert prefill["source_file"] == "evidence/target.com/validation/sqli-search/summary.json"


def _seed_source_rejection(tmp_path: Path) -> tuple[Path, Path, Path]:
    source_path = tmp_path / "target-source" / "handlers.py"
    source_path.parent.mkdir(parents=True)
    source_path.write_text(
        "def read_order(actor, owner_id):\n"
        "    if actor.id != owner_id:\n"
        "        raise PermissionError('forbidden')\n",
        encoding="utf-8",
    )
    findings_dir = tmp_path / "findings" / "target.com"
    finding_index.upsert_finding(
        findings_dir,
        {
            "id": "source-idor-order",
            "type": "idor",
            "url": "https://target.com/api/orders/1",
            "source_file": str(source_path),
            "line_number": 1,
            "validation_status": "candidate",
        },
        target="target.com",
    )
    summary_path = tmp_path / "evidence" / "target.com" / "source-refutation.json"
    summary_path.parent.mkdir(parents=True)
    return findings_dir, source_path, summary_path


def test_source_finding_rejection_requires_a_real_guard_reference(tmp_path):
    findings_dir, source_path, summary_path = _seed_source_rejection(tmp_path)
    summary_path.write_text(
        json.dumps(
            {
                "result": "rejected",
                "source_guard": {
                    "source_file": str(source_path),
                    "line_number": 2,
                    "quote": "if actor.id != owner_id:",
                },
            }
        ),
        encoding="utf-8",
    )

    updated = finding_index.update_finding_status(
        findings_dir,
        "source-idor-order",
        validation_status="rejected",
        validation_summary=str(summary_path),
    )

    assert updated is not None
    assert updated["validation_status"] == "rejected"
    assert updated["validation_summary"] == str(summary_path)
    assert updated["validation_summary_sha256"]
    assert finding_index.verify_finding_owner_provenance(
        findings_dir,
        updated,
        target="target.com",
    )["valid"] is True


@pytest.mark.parametrize(
    ("guard", "message"),
    [
        (
            {"source_file": "missing.py", "line_number": 2, "quote": "if actor.id != owner_id:"},
            "guard file is not readable",
        ),
        (
            {"line_number": 99, "quote": "if actor.id != owner_id:"},
            "outside the source file",
        ),
        (
            {"line_number": 2, "quote": "if actor.is_admin:"},
            "does not match the cited source line",
        ),
        (
            {"line_number": 2, "quote": "actor.id"},
            "does not have guard shape",
        ),
    ],
)
def test_source_finding_rejection_fails_before_owner_write(tmp_path, guard, message):
    findings_dir, source_path, summary_path = _seed_source_rejection(tmp_path)
    guard = dict(guard)
    guard.setdefault("source_file", str(source_path))
    summary_path.write_text(
        json.dumps({"result": "rejected", "source_guard": guard}),
        encoding="utf-8",
    )
    finding_before = (findings_dir / "findings.json").read_bytes()
    events_before = (findings_dir / "mutation-events.jsonl").read_bytes()

    with pytest.raises(ValueError, match=message):
        finding_index.update_finding_status(
            findings_dir,
            "source-idor-order",
            validation_status="rejected",
            validation_summary=str(summary_path),
        )

    assert (findings_dir / "findings.json").read_bytes() == finding_before
    assert (findings_dir / "mutation-events.jsonl").read_bytes() == events_before


def test_source_finding_rejection_requires_a_new_validation_summary(tmp_path):
    findings_dir, _, _ = _seed_source_rejection(tmp_path)

    with pytest.raises(ValueError, match="requires a new validation_summary"):
        finding_index.update_finding_status(
            findings_dir,
            "source-idor-order",
            validation_status="rejected",
        )

    persisted = finding_index.find_finding(findings_dir, "source-idor-order")
    assert persisted is not None
    assert persisted["validation_status"] == "candidate"


@pytest.mark.parametrize(
    ("source_line", "message"),
    [
        ("# if actor.id != owner_id:\n", "points to a comment"),
        ('message = "if actor.id != owner_id:"\n', "does not match the cited source line"),
    ],
)
def test_source_finding_rejection_does_not_accept_comment_or_string(tmp_path, source_line, message):
    findings_dir, source_path, summary_path = _seed_source_rejection(tmp_path)
    source_path.write_text(source_line, encoding="utf-8")
    summary_path.write_text(
        json.dumps(
            {
                "result": "rejected",
                "source_guard": {
                    "source_file": str(source_path),
                    "line_number": 1,
                    "quote": "if actor.id != owner_id:",
                },
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match=message):
        finding_index.update_finding_status(
            findings_dir,
            "source-idor-order",
            validation_status="rejected",
            validation_summary=str(summary_path),
        )


def test_non_source_finding_rejection_remains_compatible(tmp_path):
    findings_dir = tmp_path / "findings" / "target.com"
    finding_index.upsert_finding(
        findings_dir,
        {
            "id": "http-candidate",
            "type": "sqli",
            "url": "https://target.com/search?q=x",
            "source_file": "evidence/target.com/raw-pair.json",
            "validation_status": "candidate",
        },
        target="target.com",
    )

    updated = finding_index.update_finding_status(
        findings_dir,
        "http-candidate",
        validation_status="rejected",
    )

    assert updated is not None
    assert updated["validation_status"] == "rejected"


def _f3_fixture(monkeypatch, tmp_path):
    """审计 F3 夹具：一个 validated+generated 的 finding + 真实 owner provenance。"""
    findings_dir = tmp_path / "findings" / "example.com"
    findings_dir.mkdir(parents=True, exist_ok=True)
    validation_dir = tmp_path / "evidence" / "example.com" / "validation" / "f3-1"
    validation_dir.mkdir(parents=True, exist_ok=True)
    validation_summary = validation_dir / "validation-summary.json"
    validation_summary.write_text(
        json.dumps(
            {
                "all_gates_passed": True,
                "four_validation_gates_passed": True,
                "seven_question_gate_passed": True,
                "seven_question_gate_decision": "pass",
                "evidence_rubric": {"summary": "f3 evidence"},
            }
        ),
        encoding="utf-8",
    )
    (findings_dir / "findings.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "target": "example.com",
                "total": 1,
                "findings": [
                    {
                        "id": "f3_finding",
                        "type": "sqli",
                        "category": "sqli",
                        "title": "SQLi on item",
                        "summary": "verified sqli",
                        "url": "https://example.com/item?id=1",
                        "severity": "high",
                        "confidence": "confirmed",
                        "validation_status": "validated",
                        "validation_summary": str(validation_summary),
                        "report_status": "not_generated",
                        "source_file": "sqli/manual_ai_candidates.txt",
                        "raw": "[SQLI-POC-VERIFIED] https://example.com/item?id=1",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    _record_owner_provenance(findings_dir, "f3_finding")
    monkeypatch.setattr(report_generator, "REPORTS_DIR", str(tmp_path / "reports"))
    return findings_dir, tmp_path / "reports" / "example.com"


def test_report_generator_regenerates_missing_report_file(monkeypatch, tmp_path):
    """审计 F3-1：已登记 generated 但文件被删 -> 重跑必须恢复，而不是空计 1 份。"""
    findings_dir, report_dir = _f3_fixture(monkeypatch, tmp_path)
    total, _ = report_generator.process_findings_dir(str(findings_dir))
    assert total == 1
    report_file = Path(
        json.loads((findings_dir / "findings.json").read_text(encoding="utf-8"))
        ["findings"][0]["report_file"]
    )
    assert report_file.is_file()
    # 模拟产物丢失（如误删/崩溃后清理）
    report_file.unlink()

    total2, index2 = report_generator.process_findings_dir(str(findings_dir))

    assert total2 == 1
    assert report_file.is_file(), "missing report file must be regenerated"
    assert any(item["finding_id"] == "f3_finding" for item in index2)
    findings_row = json.loads((findings_dir / "findings.json").read_text(encoding="utf-8"))["findings"][0]
    assert findings_row["report_status"] == "generated"


def test_report_generator_recovers_partial_crash_artifact(monkeypatch, tmp_path):
    """审计 F3-2：崩溃残片（只写到 Finding ID 行）-> 重跑原子替换为完整报告。"""
    findings_dir, report_dir = _f3_fixture(monkeypatch, tmp_path)
    total, _ = report_generator.process_findings_dir(str(findings_dir))
    findings_row = json.loads((findings_dir / "findings.json").read_text(encoding="utf-8"))["findings"][0]
    report_file = Path(findings_row["report_file"])
    # 模拟 open('x') 写到一半崩溃：保留 Finding ID 行但缺少终结标记
    truncated = f"# Broken report\n\n- **Finding ID:** f3_finding\n"
    report_file.write_text(truncated, encoding="utf-8")

    total2, _ = report_generator.process_findings_dir(str(findings_dir))

    assert total2 == 1
    recovered = report_file.read_text(encoding="utf-8")
    assert recovered != truncated, "partial artifact must be replaced"
    assert report_generator._REPORT_TERMINATOR in recovered, "recovered report must be complete"


def test_report_generator_idempotent_rerun_keeps_complete_report(monkeypatch, tmp_path):
    """审计 F3-3：完整报告重复运行不重建、不产生重复索引行。"""
    findings_dir, report_dir = _f3_fixture(monkeypatch, tmp_path)
    total, _ = report_generator.process_findings_dir(str(findings_dir))
    report_file = Path(
        json.loads((findings_dir / "findings.json").read_text(encoding="utf-8"))
        ["findings"][0]["report_file"]
    )
    before = report_file.read_text(encoding="utf-8")
    mtime_before = report_file.stat().st_mtime_ns

    total2, index2 = report_generator.process_findings_dir(str(findings_dir))

    assert total2 == total
    assert len(index2) == total2
    assert report_file.read_text(encoding="utf-8") == before
    assert report_file.stat().st_mtime_ns == mtime_before, "complete report must not be rewritten"


def test_runner_endpoint_slots_collect_pair_sides():
    """request-diff 记录了两个 URL；槽位收集必须含 request_pair 的 baseline/variant。"""
    from tools.runner_witness import _runner_endpoint_slots

    runner = {
        "url": "https://target.example/api/own/7",
        "request_pair": {
            "baseline": {"url": "https://target.example/api/own/7"},
            "variant": {"url": "https://target.example/api/admin/3"},
        },
    }
    slots = _runner_endpoint_slots(runner)
    assert "https://target.example/api/admin/3" in slots
    assert "https://target.example/api/own/7" in slots
    # 缺失/畸形 request_pair 时安全回退到顶层槽位
    assert _runner_endpoint_slots({"url": "https://target.example/x"}) == [
        "https://target.example/x"
    ]
    assert _runner_endpoint_slots({"request_pair": "not-a-dict"}) == []


def test_report_runner_witness_accepts_variant_side_endpoint(tmp_path):
    """finding 绑定 variant 侧端点也算命中：run 确实逐字打到了该 URL。

    2026-09-15 实战：request-diff summary 顶层 url 只记 baseline，导致绑定
    variant 实例的 claim 无法通过 witness，即使证据完整记录在 request_pair。
    """
    findings_dir = tmp_path / "findings" / "example.com"
    created = finding_index.upsert_finding(
        findings_dir,
        {
            "id": "variant-bound-finding",
            "type": "idor",
            "url": "https://example.com/api/Addresss/3",
            "method": "PUT",
            "validation_status": "validated",
            "report_status": "not_generated",
        },
        target="example.com",
    )
    _bind_report_runner_witness(findings_dir, created["finding"])
    finding = finding_index.find_finding(findings_dir, "variant-bound-finding")
    assert finding is not None
    summary_path = tmp_path / finding["runner_summary"]
    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    summary["request_pair"] = {
        "baseline": {"url": "https://example.com/api/Addresss/7"},
        "variant": {"url": "https://example.com/api/Addresss/3"},
    }
    summary_path.write_text(json.dumps(summary), encoding="utf-8")

    witness = report_generator._canonical_runner_witness(
        finding,
        findings_dir=findings_dir,
        target="example.com",
    )
    assert witness["valid"] is True, witness.get("reason")

    # 未记录的端点仍然拒绝：匹配面只是"run 打过的槽位"，不引入模板匹配
    summary["url"] = "https://example.com/api/Addresss/7"
    summary["request_pair"] = {
        "baseline": {"url": "https://example.com/api/Addresss/7"},
        "variant": {"url": "https://example.com/api/Addresss/8"},
    }
    summary_path.write_text(json.dumps(summary), encoding="utf-8")
    witness = report_generator._canonical_runner_witness(
        finding,
        findings_dir=findings_dir,
        target="example.com",
    )
    assert witness["valid"] is False
    assert "runner endpoint mismatch" in witness["reason"]
