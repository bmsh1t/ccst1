"""Finding material/history and Store-backed report consumer contracts."""

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

import finding_index
import pytest
import report_generator
import validate
from target_paths import target_storage_key
from target_store import ConflictError, StoreError, TargetStore


def _register_finding(store, finding_id="f1", *, family="sqli", method="GET", endpoint=None,
                      verdict="confirmed", delivery_status="eligible"):
    candidate = {"id": finding_id, "endpoint": endpoint or f"https://{store.target}/items?id=1",
                 "method": method, "family": family, "title": f"Claim {finding_id}",
                 "claim": "The recorded response crosses the expected input boundary"}
    raw = store.root / "evidence" / store.key / "validation" / finding_id / "response.txt"
    raw.parent.mkdir(parents=True, exist_ok=True)
    raw.write_text("HTTP/1.1 200 OK\n\nRecorded comparison", encoding="utf-8")
    store.start_attempt(attempt_id=f"try:{finding_id}", source="native",
                        started_at="2026-09-24T00:00:00Z", actor="operator")
    receipt = store.record_execution(attempt_id=f"try:{finding_id}", outcome="complete", actor="operator",
        candidate=candidate, observations=[{
            "endpoint": candidate["endpoint"], "method": method, "family": family,
            "observed_at": "2026-09-24T00:00:00Z", "description": "Recorded comparison",
            "artifacts": {"response": raw.relative_to(store.root).as_posix()}, "state_changing": False,
        }])
    if verdict is not None:
        store.assess(command_id=f"assess:{finding_id}", finding_id=finding_id, verdict=verdict,
                     reason="Reviewed recorded comparison", boundary="Owner/peer boundary",
                     impact="Peer data disclosure" if verdict == "confirmed" else "",
                     evidence=[{"operation_id": receipt["entity_id"], "step": 0}],
                     actor="operator", expected_assessment=None)
        if delivery_status is not None:
            store.decide_delivery(command_id=f"delivery:{finding_id}", finding_id=finding_id,
                                  assessment_id=f"assess:{finding_id}", destination="internal-review",
                                  status=delivery_status, reason="Reviewed destination policy",
                                  actor="operator", expected_decision=None)
    return candidate, receipt


def test_explicit_history_read_preserves_legacy_list_without_trusting_finality(tmp_path):
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

    payload = finding_index.load_legacy_finding_index(findings_dir)
    persisted = json.loads(path.read_text(encoding="utf-8"))

    assert persisted == legacy
    persisted = payload
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
    assert not (findings_dir / "mutation-events.jsonl").exists()
    assert not (tmp_path / "state").exists()


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
        finding_index.load_legacy_finding_index(findings_dir, target="example.com")


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
        finding_index.load_legacy_finding_index(findings_dir, target="example.com")


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

    projected = finding_index.load_legacy_finding_index(
        findings_dir,
        target="example.com",
        allow_legacy=True,
    )

    assert projected["target"] == "example.com"
    assert projected["findings"][0]["id"]
    assert projected["findings"][0]["validation_status"] == "needs_owner_revalidation"
    assert path.read_bytes() == original


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

    payload = finding_index.build_finding_index(findings_dir, target="example.com")

    assert payload["schema_version"] == 1
    assert payload["target"] == "example.com"
    assert payload["total"] == 2
    assert payload["counts"]["type"] == {"sqli": 1, "ssti": 1}
    assert payload["counts"]["confidence"] == {"confirmed": 2}
    assert not (findings_dir / "findings.json").exists()

    first = payload["findings"][0]
    assert first["id"].startswith("sqli_")
    assert first["url"] == "https://example.com/item?id=1"
    assert first["validation_status"] == "unvalidated"
    assert first["report_status"] == "not_generated"


def test_build_finding_index_skips_off_target_urls(tmp_path):
    findings_dir = tmp_path / "findings" / "target.com"
    idor_dir = findings_dir / "idor"
    idor_dir.mkdir(parents=True)
    (idor_dir / "idor_candidates.txt").write_text(
        "https://target.com/api/orders/123\n"
        "https://github.com/org/repo/issues/123\n",
        encoding="utf-8",
    )

    payload = finding_index.build_finding_index(findings_dir, target="target.com")

    assert payload["total"] == 1
    assert payload["findings"][0]["url"] == "https://target.com/api/orders/123"
    assert all("github.com" not in item["url"] for item in payload["findings"])


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


def _authored_body(finding):
    refs = "\n".join(f"{ref['operation_id']}:{ref['step']}" for ref in finding["evidence"])
    return (f"# Authored {finding['id']}\n\nSeverity: unknown\n\n"
            f"- **Finding ID:** {finding['id']}\n- **Claim family:** {finding['family']}\n"
            f"\n## Evidence\n{refs}\n\nBoundary: {finding['assessment']['boundary']}\n")


def _publish_all_authored_reports(findings_dir):
    """Fixture author explicitly submits a distinct body for each eligible binding."""
    root, target = finding_index._finding_backend_context(findings_dir)
    store = report_generator.runtime_store(root, target)
    for finding in store.finding_page(limit=1000)["items"]:
        assessment = finding.get("assessment") or {}
        if assessment.get("verdict") != "confirmed":
            continue
        pairs = {(r["assessment_id"], r["delivery_id"]) for r in finding["reports"]}
        for delivery in finding["deliveries"]:
            if (delivery["status"] != "eligible" or delivery["stale"]
                    or (assessment["id"], delivery["id"]) in pairs):
                continue
            draft = root / "authored-report.md"
            draft.write_text(_authored_body(finding) + f"\nDestination: {delivery['destination']}\n")
            report_generator.process_findings_dir(findings_dir, finding_id=finding["id"],
                assessment_id=assessment["id"], delivery_id=delivery["id"], body_file=draft)
    return report_generator.process_findings_dir(findings_dir)


def _primary_report_fixture(tmp_path: Path, *, delivery_status: str = "eligible"):
    store = TargetStore(tmp_path, "example.com")
    store.initialize()
    _register_finding(store, delivery_status=delivery_status)
    findings_dir = tmp_path / "findings" / store.key
    findings_dir.mkdir(parents=True)
    findings_path = findings_dir / "findings.json"
    findings_path.write_text(json.dumps({"target": store.target, "findings": [{
        "id": "retired", "url": "https://example.com/retired", "validation_status": "validated",
        "report_status": "generated", "report_file": "reports/example.com/retired.md",
    }]}), encoding="utf-8")
    return store, findings_dir, findings_path


def test_explicit_report_publication_registers_store_report_without_legacy_writes(monkeypatch, tmp_path):
    store, findings_dir, findings_path = _primary_report_fixture(tmp_path)
    before = findings_path.read_bytes()
    monkeypatch.setattr(report_generator, "REPORTS_DIR", str(tmp_path / "reports"))

    total, index = _publish_all_authored_reports(str(findings_dir))

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


@pytest.mark.parametrize("existing_report", [False, True])
def test_primary_report_generator_creates_all_current_eligible_destinations(monkeypatch, tmp_path, existing_report):
    store, findings_dir, _ = _primary_report_fixture(tmp_path)
    monkeypatch.setattr(report_generator, "REPORTS_DIR", str(tmp_path / "reports"))
    if existing_report:
        total, initial = _publish_all_authored_reports(findings_dir)
        assert total == 1
        original_path = Path(initial[0]["file"])
        original = original_path.read_bytes()
    store.decide_delivery(command_id="delivery:secondary", finding_id="f1", assessment_id="assess:f1",
                          destination="secondary-review", status="eligible", reason="Second destination",
                          actor="operator", expected_decision=None)

    total, first = _publish_all_authored_reports(findings_dir)
    assert total == 2
    assert {row["destination"] for row in first} == {"internal-review", "secondary-review"}
    assert len({row["file"] for row in first}) == 2
    if existing_report:
        assert original_path.read_bytes() == original

    revision = store.binding()["revision"]
    total, second = _publish_all_authored_reports(findings_dir)
    assert total == 2
    assert {row["destination"] for row in second} == {"internal-review", "secondary-review"}
    assert store.binding()["revision"] == revision


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
        _publish_all_authored_reports(findings_dir)
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
        _publish_all_authored_reports(findings_dir)
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
        if reads == 1:
            revoke()
        return result

    monkeypatch.setattr(report_generator, name, drift)
    with pytest.raises(report_generator.ConflictError, match="snapshot changed"):
        _publish_all_authored_reports(findings_dir)
    assert store.finding("f1")["reports"][0]["stale"] is True
    assert not (tmp_path / "reports/example.com/INDEX.json").exists()
    assert not (tmp_path / "reports/example.com/SUMMARY.md").exists()


def test_primary_report_generator_reads_store_without_legacy_finding_index(monkeypatch, tmp_path):
    store, findings_dir, findings_path = _primary_report_fixture(tmp_path)
    findings_path.unlink()
    findings_path.mkdir()
    monkeypatch.setattr(report_generator, "REPORTS_DIR", str(tmp_path / "reports"))

    def forbidden(*args, **kwargs):
        raise AssertionError("primary report generation read findings.json")

    monkeypatch.setattr(finding_index, "load_legacy_finding_index", forbidden)

    total, index = _publish_all_authored_reports(str(findings_dir))

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
        _publish_all_authored_reports(str(findings_dir))
    report_path = next((tmp_path / "reports" / "example.com").glob("report_*.md"))
    body = report_path.read_bytes()
    registered = store.finding("f1")["reports"]
    assert len(registered) == (0 if failure == "registration" else 1)
    monkeypatch.setattr(owner, name, original)
    total, index = _publish_all_authored_reports(str(findings_dir))
    revision = store.binding()["revision"]
    assert total == 1
    assert _publish_all_authored_reports(str(findings_dir)) == (total, index)
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

    monkeypatch.setattr(finding_index, "load_legacy_finding_index", forbidden)
    _, first = _publish_all_authored_reports(str(findings_dir))
    report_file = Path(first[0]["file"])
    second = report_file.with_name("operator-report.md")
    second.write_text("Independent registered report")
    store.register_report(command_id="operator:report", report_id="operator-report", finding_id="f1",
                          assessment_id="assess:f1", delivery_id="delivery:f1", artifact=str(second),
                          actor="operator")
    revision = store.binding()["revision"]
    total, index = _publish_all_authored_reports(str(findings_dir))
    assert total == 2
    assert {row["id"] for row in index} == {first[0]["id"], "operator-report"}
    assert store.binding()["revision"] == revision
    assert json.loads((report_file.parent / "INDEX.json").read_text())["reports"] == index


@pytest.mark.parametrize("damaged", ["report", "evidence"])
def test_primary_report_rerun_removes_stale_index_without_rewriting_artifacts(monkeypatch, tmp_path, damaged):
    store, findings_dir, _ = _primary_report_fixture(tmp_path)
    monkeypatch.setattr(report_generator, "REPORTS_DIR", str(tmp_path / "reports"))
    _, index = _publish_all_authored_reports(str(findings_dir))
    report = Path(index[0]["file"])
    artifact = report if damaged == "report" else tmp_path / "evidence/example.com/validation/f1/response.txt"
    artifact.write_text("damaged")
    body = report.read_bytes()
    revision = store.binding()["revision"]
    assert _publish_all_authored_reports(str(findings_dir)) == (0, [])
    assert report.read_bytes() == body
    assert store.binding()["revision"] == revision
    assert json.loads((report.parent / "INDEX.json").read_text())["reports"] == []
    assert "Total findings: 0" in (report.parent / "SUMMARY.md").read_text()


def test_primary_new_assessment_gets_new_report_without_rebinding_old_body(monkeypatch, tmp_path):
    store, findings_dir, _ = _primary_report_fixture(tmp_path)
    monkeypatch.setattr(report_generator, "REPORTS_DIR", str(tmp_path / "reports"))
    _, first = _publish_all_authored_reports(str(findings_dir))
    old_path = Path(first[0]["file"])
    body = old_path.read_bytes()
    store.assess(command_id="assess:f1:2", finding_id="f1", verdict="confirmed", reason="Rechecked",
                 boundary="Input isolation", impact="Peer query influence", evidence=store.finding("f1")["evidence"],
                 actor="operator", expected_assessment="assess:f1")
    store.decide_delivery(command_id="delivery:f1:2", finding_id="f1", assessment_id="assess:f1:2",
                          destination="internal-review", status="eligible", reason="Rechecked",
                          actor="operator", expected_decision="delivery:f1")
    total, current = _publish_all_authored_reports(str(findings_dir))
    assert total == 1
    assert current[0]["id"] != first[0]["id"]
    assert current[0]["assessment_id"] == "assess:f1:2"
    assert old_path.read_bytes() == body
    assert len(store.finding("f1")["reports"]) == 2



def test_claim_command_replays_without_merging_distinct_findings_or_rewinding_verdict(tmp_path):
    store = TargetStore(tmp_path, "example.com")
    store.initialize()
    candidate, _ = _register_finding(store)
    before = store.finding("f1")
    args = {key: value for key, value in candidate.items() if key != "id"}
    receipt = store.create_finding(command_id="create:f1", finding_id="f1", actor="operator", **args)
    assert store.create_finding(command_id="create:f1", finding_id="f1", actor="operator", **args)["replayed"]
    assert {key: value for key, value in store.finding("f1").items() if key != "revision"} == {
        key: value for key, value in before.items() if key != "revision"}
    store.create_finding(command_id="create:f2", finding_id="f2", actor="operator", **args)
    assert store.page("findings")["total"] == 2
    assert store.finding("f2")["assessment"] is None
    revision = store.binding()["revision"]
    with pytest.raises(ConflictError):
        store.create_finding(command_id="conflict", finding_id="f1", actor="operator", **{**args, "method": "POST"})
    assert store.binding()["revision"] == revision > receipt["revision"]
    assert store.finding("f1")["assessment"]["verdict"] == "confirmed"


def test_concurrent_finding_commands_do_not_lose_updates(tmp_path):
    store = TargetStore(tmp_path, "target.com")
    store.initialize()
    code = """
import sys
from tools.target_store import runtime_store
root, finding_id = sys.argv[1:]
store = runtime_store(root, "target.com")
store.create_finding(command_id=finding_id, finding_id=finding_id,
                     endpoint=f"https://target.com/{finding_id}", method="GET", family="custom",
                     title=finding_id, claim="Unassessed claim", actor="operator")
"""
    processes = [subprocess.Popen([sys.executable, "-B", "-c", code, str(tmp_path), finding_id],
                                  cwd=Path(__file__).resolve().parents[1], text=True,
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                 for finding_id in ("F-ONE", "F-TWO")]
    for process in processes:
        stdout, stderr = process.communicate(timeout=10)
        assert process.returncode == 0, stdout + stderr
    assert {row["id"] for row in store.finding_page()["items"]} == {"F-ONE", "F-TWO"}
    assert store.page("operations")["total"] == 0
    assert not (tmp_path / "findings" / "target.com" / "findings.json").exists()


@pytest.mark.parametrize("backend", ["primary", "preview", "missing"])
def test_explicit_history_read_is_read_only_beside_any_store(tmp_path, backend):
    store = TargetStore(tmp_path, "example.com")
    store.initialize(allow_legacy=backend == "preview")
    if backend == "missing":
        store.path.unlink()
    root = tmp_path / "findings" / "example.com"
    root.mkdir(parents=True)
    history = root / "findings.json"
    history.write_text(json.dumps([{"id": "old", "type": "idor", "url": "/orders/1",
                                    "validation_status": "validated", "report_status": "generated"}]))
    before = history.read_bytes()
    payload = finding_index.load_legacy_finding_index(root)
    assert payload["findings"][0]["id"] == "old"
    assert payload["findings"][0]["validation_status"] == "needs_owner_revalidation"
    assert history.read_bytes() == before
    assert not (root / "mutation-events.jsonl").exists()
    assert not (root / ".locks").exists()


@pytest.mark.parametrize("missing_endpoint", [False, True])
def test_material_index_preserves_claims_and_replays_without_inventing_facts(tmp_path, missing_endpoint):
    store = TargetStore(tmp_path, "target.com")
    store.initialize()
    root = tmp_path / "findings" / "target.com"
    root.mkdir(parents=True)
    source = root / "claim.json"
    claim = {"kind": "finding_claim", "schema_version": 1, "title": "JWT boundary claim",
             "vuln_class": "JWT", "impact": "Claimed administrator access", "state": "validated"}
    if not missing_endpoint:
        claim["endpoint"] = "/admin"
    source.write_text(json.dumps(claim))
    for name in ("validation-summary.json", "f1-a1b2c3d4.validation-summary.json"):
        (root / name).write_text(json.dumps({**claim, "finding_id": "f1"}))
    before = store.binding()
    listed = finding_index.list_root_finding_claims(root, target=store.target)
    assert len(listed) == 1
    assert ("endpoint" in listed[0]["incomplete_fields"]) == missing_endpoint
    assert listed[0]["validation_status"] == "candidate"
    assert listed[0]["claimed_validation_status"] == "validated"
    assert store.binding() == before
    first = finding_index.index_scanner_material(root, target=store.target)
    revision = store.binding()["revision"]
    second = finding_index.index_scanner_material(root, target=store.target)
    assert first["review_action_ids"] == second["review_action_ids"]
    assert store.binding()["revision"] == revision
    assert store.page("findings")["total"] == 0
    assert store.page("operations")["total"] == 0
    assert store.page("actions")["total"] == 1
    action = store.action(first["review_action_ids"][0])
    snapshot = tmp_path / action["subject_artifact"]["ref"]
    old_bytes = snapshot.read_bytes()
    claim["endpoint"] = "/admin/changed"
    source.write_text(json.dumps(claim))
    third = finding_index.index_scanner_material(root, target=store.target)
    assert third["review_action_ids"] != first["review_action_ids"]
    assert snapshot.read_bytes() == old_bytes
    assert store.page("actions")["total"] == 2
    assert not (root / "findings.json").exists()


def test_multiple_material_sources_do_not_merge_or_rewrite_assessed_claim(tmp_path):
    store, root, _ = _primary_report_fixture(tmp_path)
    finding_before = store.finding("f1")
    for name in ("a.json", "b.json"):
        (root / name).write_text(json.dumps({"kind": "finding_claim", "schema_version": 1,
            "title": name, "endpoint": "/items?id=1", "vuln_class": "sqli", "impact": "Claimed query influence"}))
    indexed = finding_index.index_scanner_material(root, target=store.target)
    assert len(indexed["review_action_ids"]) == 2
    assert {key: value for key, value in store.finding("f1").items() if key != "revision"} == {
        key: value for key, value in finding_before.items() if key != "revision"}
    assert store.page("findings")["total"] == 1
    revision = store.binding()["revision"]
    assert finding_index.index_scanner_material(root, target=store.target)["review_action_ids"] == indexed["review_action_ids"]
    assert store.binding()["revision"] == revision


@pytest.mark.parametrize("bypass", ["target", "output", "symlink"])
def test_material_writer_rejects_cross_target_destination(tmp_path, bypass):
    store, root, history = _primary_report_fixture(tmp_path)
    other = tmp_path / "findings" / "other.example"
    other.mkdir()
    before = history.read_bytes()
    revision = store.binding()["revision"]
    with pytest.raises(finding_index.StoreError):
        if bypass == "target":
            finding_index.index_scanner_material(root, target="other.example")
        elif bypass == "output":
            finding_index.index_scanner_material(root, output=other / "scanner_candidates.json")
        else:
            (other / "alias").symlink_to(root, target_is_directory=True)
            finding_index.index_scanner_material(other / "alias", target="other.example")
    assert history.read_bytes() == before
    assert store.binding()["revision"] == revision
    assert not (other / "scanner_candidates.json").exists()


@pytest.mark.parametrize("family, report_type", [
    ("sqli", "sqli"),
    ("JWT", "jwt"),
    ("authentication_bypass", "auth_bypass"),
    ("unmapped-protocol-boundary", "unmapped_protocol_boundary"),
])
def test_report_publication_preserves_authored_family_and_evidence_refs(tmp_path, family, report_type):
    store = TargetStore(tmp_path, "example.com")
    store.initialize()
    _, operation = _register_finding(store, family=family)
    findings_dir = tmp_path / "findings" / store.key
    findings_dir.mkdir(parents=True)
    total, index = _publish_all_authored_reports(findings_dir)
    assert total == 1
    assert index[0]["type"] == report_type
    assert index[0]["family"] == store.finding("f1")["family"]
    text = Path(index[0]["file"]).read_text()
    assert "# Authored f1" in text
    assert "**Finding ID:** f1" in text
    assert f"**Claim family:** {store.finding('f1')['family']}" in text
    assert operation["entity_id"] in text
    assert "Owner/peer boundary" in text
    assert store.finding("f1")["delivery_events"] == []


@pytest.mark.parametrize("delivery_status", ["ineligible", "deferred"])
def test_report_eligibility_does_not_change_technical_fact(tmp_path, delivery_status):
    store, root, _ = _primary_report_fixture(tmp_path, delivery_status=delivery_status)
    before = store.binding()
    assert _publish_all_authored_reports(root) == (0, [])
    assert store.finding("f1")["assessment"]["verdict"] == "confirmed"
    assert store.binding() == before


def test_report_incremental_generation_preserves_existing_report_and_skips_unassessed_claim(tmp_path):
    store, root, _ = _primary_report_fixture(tmp_path)
    _, first = _publish_all_authored_reports(root)
    first_path = Path(first[0]["file"])
    before = first_path.read_bytes(), first_path.stat().st_mtime_ns
    _register_finding(store, "f2")
    store.create_finding(command_id="unassessed", finding_id="f3", endpoint="https://example.com/untested",
                         method="GET", family="sqli", title="Unassessed", claim="Review needed", actor="operator")
    total, second = _publish_all_authored_reports(root)
    assert total == 2
    assert {row["finding_id"] for row in second} == {"f1", "f2"}
    assert len({row["id"] for row in second}) == 2
    assert (first_path.read_bytes(), first_path.stat().st_mtime_ns) == before
    assert store.finding("f3")["reports"] == []
    assert store.finding("f3")["assessment"] is None


def test_report_generation_requires_explicit_action_completion(tmp_path):
    store, root, _ = _primary_report_fixture(tmp_path)
    store.create_action(command_id="report-work", action_id="REPORT", kind="work",
                        subject={"finding_id": "f1"}, intent="Draft report", execution_key="report:f1", actor="operator")
    claim = store.transition_action(command_id="claim", action_id="REPORT", expected_version=1,
                                    status="claimed", actor="operator")
    _, index = _publish_all_authored_reports(root)
    assert store.action("REPORT")["status"] == "claimed"
    store.transition_action(command_id="done", action_id="REPORT", expected_version=2,
                            status="completed", claim_token=claim["command_id"], actor="operator",
                            reason="Report registered", completion={"artifact": index[0]["file"]})
    assert store.action("REPORT")["status"] == "completed"
    assert store.finding("f1")["delivery_events"] == []


@pytest.mark.parametrize("content", ["unrelated", "partial", "complete"])
def test_report_retry_handles_unregistered_publication_without_overwriting_other_work(tmp_path, monkeypatch, content):
    store, root, _ = _primary_report_fixture(tmp_path)
    original = TargetStore.register_report
    def interrupted(*args, **kwargs):
        raise OSError("registration interrupted")
    monkeypatch.setattr(TargetStore, "register_report", interrupted)
    with pytest.raises(OSError, match="registration interrupted"):
        _publish_all_authored_reports(root)
    path = next((tmp_path / "reports" / store.key).glob("report_*.md"))
    full = path.read_bytes()
    if content == "unrelated":
        path.write_text("# Other operator's report\n")
    elif content == "partial":
        path.write_text("# Interrupted report\n\n- **Finding ID:** f1\n")
    before = path.read_bytes(), path.stat().st_mtime_ns
    monkeypatch.setattr(TargetStore, "register_report", original)
    if content in {"unrelated", "partial"}:
        with pytest.raises(FileExistsError):
            _publish_all_authored_reports(root)
        assert (path.read_bytes(), path.stat().st_mtime_ns) == before
        assert store.finding("f1")["reports"] == []
    else:
        total, index = _publish_all_authored_reports(root)
        assert total == 1 and index[0]["finding_id"] == "f1"
        assert path.read_bytes() == full
        if content == "complete":
            assert (path.read_bytes(), path.stat().st_mtime_ns) == before
            assert path.read_bytes() == full
        else:
            assert path.read_bytes() != before[0]


def test_report_missing_registered_artifact_stays_explicitly_stale(tmp_path):
    store, root, _ = _primary_report_fixture(tmp_path)
    _, index = _publish_all_authored_reports(root)
    path = Path(index[0]["file"])
    path.unlink()
    before = store.binding()
    assert _publish_all_authored_reports(root) == (0, [])
    report = store.finding("f1")["reports"][0]
    assert report["stale"] is True
    assert report["artifact_available"] is False
    assert not path.exists()
    assert store.binding() == before


@pytest.mark.parametrize("damage", ["missing", "changed", "revoked"])
def test_explicit_report_retry_does_not_repair_registered_artifact(tmp_path, damage):
    store, root, _ = _primary_report_fixture(tmp_path)
    draft = tmp_path / "draft.md"
    draft.write_text("# Authored report\n")
    args = dict(finding_id="f1", assessment_id="assess:f1", delivery_id="delivery:f1", body_file=draft)
    _, index = report_generator.process_findings_dir(root, **args)
    path = Path(index[0]["file"])
    if damage == "missing":
        path.unlink()
    elif damage == "changed":
        path.write_text("other operator's bytes")
    else:
        report = store.finding("f1")["reports"][0]
        store.record_artifact_event(command_id="revoke-report", artifact_id=report["artifact_id"],
                                    dimension="provenance", state="revoked", reason="withdrawn", actor="operator")
    before = store.binding(), path.read_bytes() if path.exists() else None
    with pytest.raises(StoreError, match="registered report"):
        report_generator.process_findings_dir(root, **args)
    assert (store.binding(), path.read_bytes() if path.exists() else None) == before
    assert store.finding("f1")["reports"][0]["stale"] is True


def test_report_uses_canonical_url_target_directory(tmp_path):
    target = "http://127.0.0.1:3002"
    store = TargetStore(tmp_path, target)
    store.initialize()
    _register_finding(store, family="XSS", endpoint=target + "/#/search?q=marker")
    root = tmp_path / "findings" / store.key
    root.mkdir(parents=True)
    total, index = _publish_all_authored_reports(root)
    assert total == 1
    assert Path(index[0]["file"]).parent == tmp_path / "reports" / store.key
    assert not (tmp_path / "reports" / "http:").exists()


def test_legacy_report_path_has_no_normal_runtime_fallback(tmp_path):
    root = tmp_path / "findings" / "example.com"
    root.mkdir(parents=True)
    source = root / "findings.json"
    source.write_text(json.dumps([{"id": "old", "type": "sqli", "url": "https://example.com/",
                                  "validation_status": "validated"}]))
    before = source.read_bytes()
    with pytest.raises(StoreError, match="import"):
        _publish_all_authored_reports(root)
    assert source.read_bytes() == before
    assert not (tmp_path / "reports").exists()
    assert not (tmp_path / "state" / "example.com" / "metadata.sqlite3").exists()


def test_validate_prefill_reads_store_claim_and_bound_evidence_without_legacy_fields(tmp_path):
    store, root, legacy = _primary_report_fixture(tmp_path)
    before = store.binding(), legacy.read_bytes()
    prefill = validate.load_finding_prefill(str(root), "f1", include_canonical=True)
    assert prefill["target"] == store.target
    assert prefill["vuln_type"] == "SQLi"
    assert prefill["endpoint"] == "https://example.com/items?id=1"
    assert prefill["finding_id"] == "f1"
    assert prefill["summary"] == store.finding("f1")["claim"]
    assert prefill["_canonical_finding"]["evidence"] == store.finding("f1")["evidence"]
    assert "rubric" not in prefill
    assert "source_file" not in prefill
    assert (store.binding(), legacy.read_bytes()) == before


@pytest.mark.parametrize("damage", ["missing", "changed", "none"])
def test_refutation_requires_linked_unchanged_evidence(tmp_path, damage):
    store = TargetStore(tmp_path, "example.com")
    store.initialize()
    _, operation = _register_finding(store, verdict=None)
    raw = tmp_path / "evidence" / store.key / "validation/f1/response.txt"
    if damage == "missing":
        raw.unlink()
    elif damage == "changed":
        raw.write_text("Edited response")
    before = store.binding()
    args = dict(command_id="refute", finding_id="f1", verdict="refuted", reason="Recorded response enforces ownership",
                boundary="Owner/peer boundary", impact="", evidence=[{"operation_id": operation["entity_id"], "step": 0}],
                actor="operator", expected_assessment=None)
    if damage == "none":
        store.assess(**args)
        assert store.finding("f1")["assessment"]["verdict"] == "refuted"
    else:
        with pytest.raises(StoreError):
            store.assess(**args)
        assert store.finding("f1")["assessment"] is None
        assert store.binding() == before


def test_report_without_body_exposes_pending_destinations_without_writes(tmp_path):
    store, root, _ = _primary_report_fixture(tmp_path)
    store.decide_delivery(command_id="delivery:second", finding_id="f1", assessment_id="assess:f1",
                          destination="second", status="eligible", reason="Separate policy",
                          actor="operator", expected_decision=None)
    before = store.binding()
    assert report_generator.process_findings_dir(root) == (0, [])
    index = json.loads((tmp_path / "reports/example.com/INDEX.json").read_text())
    assert {row["delivery_id"] for row in index["pending_drafts"]} == {"delivery:f1", "delivery:second"}
    assert all(row["status"] == "needs_draft" for row in index["pending_drafts"])
    assert store.binding() == before and store.finding("f1")["reports"] == []
    assert list((tmp_path / "reports/example.com").glob("report_*.md")) == []


def test_report_explicit_body_bytes_destinations_and_pending_index(tmp_path):
    store, root, _ = _primary_report_fixture(tmp_path)
    draft = tmp_path / "draft.md"
    body = b"# Authored\r\n\r\nSeverity: low\r\nCVSS: 8.7 (destination metadata)\r\n"
    draft.write_bytes(body)
    store.decide_delivery(command_id="delivery:second", finding_id="f1", assessment_id="assess:f1",
                          destination="second", status="eligible", reason="Separate policy",
                          actor="operator", expected_decision=None)
    args = dict(finding_id="f1", assessment_id="assess:f1", delivery_id="delivery:f1", body_file=draft)
    total, index = report_generator.process_findings_dir(root, **args)
    path = Path(index[0]["file"])
    assert total == 1 and path.read_bytes() == body and index[0]["severity"] == "low"
    before = store.binding(), path.stat().st_ino
    assert report_generator.process_findings_dir(root, **args) == (total, index)
    assert (store.binding(), path.stat().st_ino) == before
    pending = json.loads((path.parent / "INDEX.json").read_text())["pending_drafts"]
    assert [row["delivery_id"] for row in pending] == ["delivery:second"]
    other = b"# Destination-specific report\nSeverity: info\n"
    draft.write_bytes(other)
    total, index = report_generator.process_findings_dir(root, **{**args, "delivery_id": "delivery:second"})
    assert total == 2 and path.read_bytes() == body
    assert {Path(row["file"]).read_bytes() for row in index} == {body, other}
    assert not json.loads((path.parent / "INDEX.json").read_text())["pending_drafts"]
    assert store.finding("f1")["delivery_events"] == []
    with pytest.raises(FileExistsError):
        report_generator.process_findings_dir(root, **args)
    assert path.read_bytes() == body


@pytest.mark.parametrize("fault", ["empty", "whitespace", "missing", "binary", "fifo", "assessment", "delivery", "evidence", "partial-args"])
def test_report_explicit_publication_rejects_invalid_input_before_metadata(tmp_path, fault):
    store, root, _ = _primary_report_fixture(tmp_path)
    body = tmp_path / "draft.md"
    body.write_text("# Reviewed body\n")
    args = dict(finding_id="f1", assessment_id="assess:f1", delivery_id="delivery:f1", body_file=body)
    if fault in {"empty", "whitespace", "binary"}:
        body.write_bytes({"empty": b"", "whitespace": b" \n\t", "binary": b"\xff"}[fault])
    elif fault == "missing":
        body.unlink()
    elif fault == "fifo":
        body.unlink()
        os.mkfifo(body)
    elif fault == "assessment":
        args["assessment_id"] = "other-assessment"
    elif fault == "delivery":
        args["delivery_id"] = "other-delivery"
    elif fault == "partial-args":
        args.pop("delivery_id")
    else:
        (tmp_path / "evidence/example.com/validation/f1/response.txt").write_text("changed")
    before = store.binding()
    with pytest.raises((OSError, ValueError, StoreError)):
        report_generator.process_findings_dir(root, **args)
    assert store.binding() == before and store.finding("f1")["reports"] == []
    assert list((tmp_path / "reports/example.com").glob("report_*.md")) == []


def test_report_missing_draft_does_not_block_existing_valid_report(tmp_path):
    store, root, _ = _primary_report_fixture(tmp_path)
    _, first = _publish_all_authored_reports(root)
    original = Path(first[0]["file"]).read_bytes()
    _register_finding(store, "waiting")
    before = store.binding()
    total, index = report_generator.process_findings_dir(root)
    assert total == 1 and index == first and Path(index[0]["file"]).read_bytes() == original
    pending = json.loads((Path(index[0]["file"]).parent / "INDEX.json").read_text())["pending_drafts"]
    assert [row["finding_id"] for row in pending] == ["waiting"]
    assert store.binding() == before


def test_manual_draft_keeps_inputs_without_category_narratives(tmp_path, monkeypatch):
    monkeypatch.setattr(report_generator, "REPORTS_DIR", str(tmp_path / "reports"))
    path = Path(report_generator.create_manual_report("auth_bypass", "https://example.com/api", "id", "Observed HTTP 200"))
    text = path.read_text()
    assert path.parent.name == "drafts" and "not assessed, registered, or submitted" in text
    assert "Observed HTTP 200" in text and "Parameter: id" in text
    assert "CRITICAL" not in text and "attacker can" not in text and "Remediation" not in text
    image = tmp_path / "sample.png"
    image.write_bytes(b"fixture image")
    report_generator.attach_poc_images(str(path), [str(image)])
    saved = next((path.parent / "poc_screenshots").glob("*.png"))
    assert f"poc_screenshots/{saved.name}" in path.read_text()
    assert saved.read_bytes() == image.read_bytes()
    assert not (tmp_path / "state").exists()


def test_authored_manual_body_preserves_cvss_and_has_no_category_rewrite(tmp_path, monkeypatch):
    monkeypatch.setattr(report_generator, "REPORTS_DIR", str(tmp_path / "reports"))
    body = tmp_path / "input.md"
    raw = "# Observed boundary\nSeverity: medium\nCVSS: 9.8\nExplicit limitations.\n"
    body.write_text(raw)
    output = Path(report_generator.create_manual_report("sqli", "https://example.com/", body_file=body))
    assert output.read_text().endswith(raw)
    assert "SQL Injection" not in output.read_text()
    assert not (tmp_path / "state").exists()


def test_report_cli_submits_explicit_body_and_rejects_partial_binding(tmp_path):
    store, root, _ = _primary_report_fixture(tmp_path)
    body = tmp_path / "input.md"
    body.write_text("# Authored\nSeverity: medium\nExact supplied bytes.\n")
    cmd = [sys.executable, str(Path(report_generator.__file__).resolve()), str(root), "--body-file", str(body)]
    rejected = subprocess.run(cmd, text=True, capture_output=True, timeout=30)
    assert rejected.returncode == 2 and store.finding("f1")["reports"] == []
    submitted = subprocess.run([*cmd, "--finding-id", "f1", "--assessment-id", "assess:f1", "--delivery-id", "delivery:f1"],
                               text=True, capture_output=True, timeout=30)
    assert submitted.returncode == 0, submitted.stderr
    report = store.finding("f1")["reports"][0]
    assert (tmp_path / report["artifact_ref"]).read_bytes() == body.read_bytes()


def test_manual_screenshots_survive_publication_without_mutating_registered_body(tmp_path, monkeypatch):
    store, root, _ = _primary_report_fixture(tmp_path)
    monkeypatch.setattr(report_generator, "REPORTS_DIR", str(tmp_path / "reports"))
    draft = Path(report_generator.create_manual_report("sqli", "https://example.com/", evidence="Supplied observation"))
    image = tmp_path / "shot.png"
    image.write_bytes(b"image fixture")
    report_generator.attach_poc_images(str(draft), [str(image)])
    raw = draft.read_bytes()
    total, index = report_generator.process_findings_dir(root, finding_id="f1", assessment_id="assess:f1",
                                                        delivery_id="delivery:f1", body_file=draft)
    report = Path(index[0]["file"])
    assert total == 1 and report.read_bytes() == raw
    name = next((draft.parent / "poc_screenshots").glob("*.png")).name
    assert (report.parent / "poc_screenshots" / name).read_bytes() == image.read_bytes()
    with pytest.raises(ValueError, match="manual draft"):
        report_generator.attach_poc_images(str(report), [str(image)])
    assert report.read_bytes() == raw


@pytest.mark.parametrize("stale", [False, True])
def test_attach_images_rejects_draft_registered_directly_in_store(tmp_path, monkeypatch, stale):
    store, _, _ = _primary_report_fixture(tmp_path)
    monkeypatch.setattr(report_generator, "REPORTS_DIR", str(tmp_path / "reports"))
    draft = Path(report_generator.create_manual_report("sqli", "https://example.com/"))
    store.register_report(command_id="direct-report", report_id="direct-report", finding_id="f1",
                          assessment_id="assess:f1", delivery_id="delivery:f1", artifact=str(draft), actor="operator")
    if stale:
        store.decide_delivery(command_id="revoke", finding_id="f1", assessment_id="assess:f1",
                              destination="internal-review", status="ineligible", reason="withdrawn",
                              actor="operator", expected_decision="delivery:f1")
    image = tmp_path / "shot.png"
    image.write_bytes(b"screenshot")
    before = draft.read_bytes(), store.binding()
    with pytest.raises(StoreError, match="registered report"):
        report_generator.attach_poc_images(draft, [image])
    assert (draft.read_bytes(), store.binding()) == before
    assert not (draft.parent / "poc_screenshots").exists()


@pytest.mark.parametrize("kind", ["symlink", "directory-symlink", "hardlink", "outside", "fifo"])
def test_attach_images_rejects_unsafe_draft_paths(tmp_path, monkeypatch, kind):
    reports = tmp_path / "reports"
    monkeypatch.setattr(report_generator, "REPORTS_DIR", str(reports))
    draft = Path(report_generator.create_manual_report("sqli", "https://example.com/"))
    before = draft.read_bytes()
    candidate = draft.parent / "alias.md"
    if kind == "symlink":
        candidate.symlink_to(draft)
    elif kind == "directory-symlink":
        alias = reports / "other.example"
        alias.symlink_to(draft.parent.parent, target_is_directory=True)
        candidate = alias / "drafts" / draft.name
    elif kind == "hardlink":
        os.link(draft, candidate)
    elif kind == "outside":
        candidate = tmp_path / "outside" / "drafts" / "note.md"
        candidate.parent.mkdir(parents=True)
        candidate.write_bytes(before)
    else:
        os.mkfifo(candidate)
    image = tmp_path / "shot.png"
    image.write_bytes(b"screenshot")
    with pytest.raises((ValueError, StoreError)):
        report_generator.attach_poc_images(candidate, [image])
    assert draft.read_bytes() == before
    assert not (draft.parent / "poc_screenshots").exists()
    assert not (tmp_path / "state").exists()


@pytest.mark.parametrize("damage", ["missing-db", "missing-fence", "corrupt-db"])
def test_attach_images_does_not_fall_back_from_damaged_store(tmp_path, monkeypatch, damage):
    store, _, _ = _primary_report_fixture(tmp_path)
    monkeypatch.setattr(report_generator, "REPORTS_DIR", str(tmp_path / "reports"))
    draft = Path(report_generator.create_manual_report("sqli", "https://example.com/"))
    if damage == "missing-db":
        store.path.unlink()
    elif damage == "missing-fence":
        store.fence_path.unlink()
    else:
        store.path.write_bytes(b"broken")
    image = tmp_path / "shot.png"
    image.write_bytes(b"screenshot")
    before = draft.read_bytes()
    with pytest.raises((StoreError, finding_index.StoreError)):
        report_generator.attach_poc_images(draft, [image])
    assert draft.read_bytes() == before
    assert not (draft.parent / "poc_screenshots").exists()


@pytest.mark.parametrize("existing", [False, True])
def test_report_cli_always_displays_pending_count_and_canonical_index_paths(tmp_path, existing):
    store, root, _ = _primary_report_fixture(tmp_path)
    if existing:
        body = root / "validate-authored-report.md"
        body.write_text("# Existing validation report\nSeverity: low\n")
        store.register_report(command_id="direct-report", report_id="direct-report", finding_id="f1",
                              assessment_id="assess:f1", delivery_id="delivery:f1", artifact=str(body), actor="operator")
        _register_finding(store, "waiting")
    before = store.binding()
    result = subprocess.run([sys.executable, str(Path(report_generator.__file__).resolve()), str(root)],
                            text=True, capture_output=True, timeout=30)
    assert result.returncode == 0, result.stderr
    assert f"Indexed {int(existing)} current reports" in result.stdout
    assert "Awaiting authored drafts: 1" in result.stdout
    assert f"Index: {tmp_path}/reports/example.com/INDEX.json" in result.stdout
    assert f"Summary: {tmp_path}/reports/example.com/SUMMARY.md" in result.stdout
    assert store.binding() == before


@pytest.mark.parametrize("success, output, expected", [
    (True, "[+] Indexed 0 current reports", 0),
    (True, "[+] Indexed 2 current reports", 2),
    (True, "[+] Generated 3 reports", 3),
    (False, "[+] Indexed 2 current reports", 0),
    (True, "unknown result", 0),
])
def test_hunt_report_count_uses_current_index_not_stale_files(tmp_path, monkeypatch, success, output, expected):
    import hunt
    root = tmp_path / "findings"
    root.mkdir()
    stale = tmp_path / "reports"
    stale.mkdir()
    (stale / "old.md").write_text("stale historical report")
    monkeypatch.setattr(hunt, "_resolve_findings_dir", lambda target: str(root))
    monkeypatch.setattr(hunt, "_resolve_reports_dir", lambda target: str(stale))
    monkeypatch.setattr(hunt, "run_argv", lambda *a, **kw: (success, output))
    assert hunt.generate_reports("example.com") == expected


def test_report_publication_rejects_dangling_screenshot_directory(tmp_path):
    store, root, _ = _primary_report_fixture(tmp_path)
    draft = tmp_path / "draft.md"
    draft.write_text("# Authored report\n")
    (tmp_path / "poc_screenshots").symlink_to(tmp_path / "missing", target_is_directory=True)
    before = store.binding()
    with pytest.raises(StoreError, match="real directory"):
        report_generator.process_findings_dir(root, finding_id="f1", assessment_id="assess:f1",
                                               delivery_id="delivery:f1", body_file=draft)
    assert store.binding() == before and store.finding("f1")["reports"] == []
