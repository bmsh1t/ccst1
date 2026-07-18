"""Tests for structured scanner finding index."""

import json
from pathlib import Path

import finding_index
import report_generator
import validate


def _record_owner_provenance(findings_dir: Path, finding_id: str) -> None:
    """Make a fixture's lifecycle assertion originate from the canonical owner."""
    payload = json.loads((findings_dir / "findings.json").read_text(encoding="utf-8"))
    finding = next(item for item in payload["findings"] if item.get("id") == finding_id)
    updated = finding_index.update_finding_status(
        findings_dir,
        finding_id,
        validation_status=finding.get("validation_status", "unvalidated"),
        report_status=finding.get("report_status", "not_generated"),
    )
    assert updated is not None


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
    assert finding["evidence_rubric"]["ready"] is False
    assert finding["evidence_rubric"]["status"] == "needs-evidence"


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
    assert after["evidence_rubric"] == before["evidence_rubric"]
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
    assert persisted["evidence_rubric"]["ready"] is False


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


def test_report_generator_syncs_report_action_queue(monkeypatch, tmp_path):
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
    queue_dir.mkdir(parents=True)
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

    total, index = report_generator.process_findings_dir(str(findings_dir))
    queue = json.loads((queue_dir / "action_queue.json").read_text(encoding="utf-8"))

    assert total == 1
    assert index[0]["queue_sync"]["status"] == "updated"
    assert queue["actions"][0]["status"] == "reported"
    assert "report_file=" in queue["actions"][0]["result"]


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


def test_report_generator_skips_unvalidated_and_already_reported_structured_findings(
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
                        "severity": "high",
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


def test_report_generator_keeps_statusless_structured_findings_reportable_for_compat(
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

    assert total == 1
    assert index[0]["finding_id"] == "legacy_no_status"


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
    assert prefill["rubric"]["rubric_id"] == "authz"
    assert prefill["rubric"]["status"] in {"needs-evidence", "candidate-ready", "signal-only"}


def test_validate_prefill_uses_runner_evidence_rubric(tmp_path, monkeypatch):
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

    assert prefill["rubric"]["rubric_id"] == "sqli"
    assert prefill["rubric"]["status"] == "candidate-ready"
    assert prefill["rubric"]["score"] == 100
