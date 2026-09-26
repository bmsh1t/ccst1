"""Finding material/history and Store-backed report consumer contracts."""

import hashlib
import json
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
        report_generator.process_findings_dir(findings_dir)
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
        report_generator.process_findings_dir(findings_dir)
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
    findings_path.mkdir()
    monkeypatch.setattr(report_generator, "REPORTS_DIR", str(tmp_path / "reports"))

    def forbidden(*args, **kwargs):
        raise AssertionError("primary report generation read findings.json")

    monkeypatch.setattr(finding_index, "load_legacy_finding_index", forbidden)

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

    monkeypatch.setattr(finding_index, "load_legacy_finding_index", forbidden)
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


@pytest.mark.parametrize("family, report_type, title", [
    ("sqli", "sqli", "SQL Injection"),
    ("JWT", "jwt", "JWT Validation Weakness"),
    ("authentication_bypass", "auth_bypass", "Authentication/Authorization Bypass"),
    ("unmapped-protocol-boundary", "misconfig", "Security Misconfiguration"),
])
def test_report_generation_preserves_family_and_evidence_refs(tmp_path, family, report_type, title):
    store = TargetStore(tmp_path, "example.com")
    store.initialize()
    _, operation = _register_finding(store, family=family)
    findings_dir = tmp_path / "findings" / store.key
    findings_dir.mkdir(parents=True)
    total, index = report_generator.process_findings_dir(findings_dir)
    assert total == 1
    assert index[0]["type"] == report_type
    assert index[0]["family"] == store.finding("f1")["family"]
    text = Path(index[0]["file"]).read_text()
    assert title in text
    assert "**Finding ID:** f1" in text
    assert f"**Claim family:** {store.finding('f1')['family']}" in text
    assert operation["entity_id"] in text
    assert "Owner/peer boundary" in text
    assert store.finding("f1")["delivery_events"] == []


@pytest.mark.parametrize("delivery_status", ["ineligible", "deferred"])
def test_report_eligibility_does_not_change_technical_fact(tmp_path, delivery_status):
    store, root, _ = _primary_report_fixture(tmp_path, delivery_status=delivery_status)
    before = store.binding()
    assert report_generator.process_findings_dir(root) == (0, [])
    assert store.finding("f1")["assessment"]["verdict"] == "confirmed"
    assert store.binding() == before


def test_report_incremental_generation_preserves_existing_report_and_skips_unassessed_claim(tmp_path):
    store, root, _ = _primary_report_fixture(tmp_path)
    _, first = report_generator.process_findings_dir(root)
    first_path = Path(first[0]["file"])
    before = first_path.read_bytes(), first_path.stat().st_mtime_ns
    _register_finding(store, "f2")
    store.create_finding(command_id="unassessed", finding_id="f3", endpoint="https://example.com/untested",
                         method="GET", family="sqli", title="Unassessed", claim="Review needed", actor="operator")
    total, second = report_generator.process_findings_dir(root)
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
    _, index = report_generator.process_findings_dir(root)
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
        report_generator.process_findings_dir(root)
    path = next((tmp_path / "reports" / store.key).glob("report_*.md"))
    full = path.read_bytes()
    if content == "unrelated":
        path.write_text("# Other operator's report\n")
    elif content == "partial":
        path.write_text("# Interrupted report\n\n- **Finding ID:** f1\n")
    before = path.read_bytes(), path.stat().st_mtime_ns
    monkeypatch.setattr(TargetStore, "register_report", original)
    if content == "unrelated":
        with pytest.raises(FileExistsError):
            report_generator.process_findings_dir(root)
        assert (path.read_bytes(), path.stat().st_mtime_ns) == before
        assert store.finding("f1")["reports"] == []
    else:
        total, index = report_generator.process_findings_dir(root)
        assert total == 1 and index[0]["finding_id"] == "f1"
        assert report_generator._REPORT_TERMINATOR in path.read_text()
        if content == "complete":
            assert (path.read_bytes(), path.stat().st_mtime_ns) == before
            assert path.read_bytes() == full
        else:
            assert path.read_bytes() != before[0]


def test_report_missing_registered_artifact_stays_explicitly_stale(tmp_path):
    store, root, _ = _primary_report_fixture(tmp_path)
    _, index = report_generator.process_findings_dir(root)
    path = Path(index[0]["file"])
    path.unlink()
    before = store.binding()
    assert report_generator.process_findings_dir(root) == (0, [])
    report = store.finding("f1")["reports"][0]
    assert report["stale"] is True
    assert report["artifact_available"] is False
    assert not path.exists()
    assert store.binding() == before


def test_report_uses_canonical_url_target_directory(tmp_path):
    target = "http://127.0.0.1:3002"
    store = TargetStore(tmp_path, target)
    store.initialize()
    _register_finding(store, family="XSS", endpoint=target + "/#/search?q=marker")
    root = tmp_path / "findings" / store.key
    root.mkdir(parents=True)
    total, index = report_generator.process_findings_dir(root)
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
        report_generator.process_findings_dir(root)
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



def test_manual_report_renderer_uses_validation_summary_for_auth_bypass_narrative(monkeypatch, tmp_path):
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
    finding = json.loads((findings_dir / "findings.json").read_text())["findings"][0]
    before = validation_summary.read_bytes()
    report_text, _ = report_generator.generate_report(
        finding, report_generator._report_vuln_type(finding), "example.com", repo_root=tmp_path,
    )
    assert "Unauthenticated Sensitive Data Exposure" in report_text
    assert "secret-like" in report_text
    assert "Validation Summary" in report_text
    assert "Baseline Response" in report_text
    assert "(CVSS:" not in report_text
    assert validation_summary.read_bytes() == before
    assert not (tmp_path / "reports").exists()



def test_manual_report_renderer_preserves_legacy_cvss_without_regrading(monkeypatch, tmp_path):
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
    finding = json.loads((findings_dir / "findings.json").read_text())["findings"][0]
    before = validation_summary.read_bytes()
    report_text, _ = report_generator.generate_report(
        finding, report_generator._report_vuln_type(finding), "example.com", repo_root=tmp_path,
    )
    assert "**MEDIUM** (CVSS: 9.8)" in report_text
    assert "CVSS Version: `3.1`" in report_text
    assert "CVSS Vector: `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`" in report_text
    assert validation_summary.read_bytes() == before
    assert not (tmp_path / "reports").exists()



def test_manual_report_renderer_uses_write_sink_auth_bypass_narrative(monkeypatch, tmp_path):
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
    finding = json.loads((findings_dir / "findings.json").read_text())["findings"][0]
    before = validation_summary.read_bytes()
    report_text, _ = report_generator.generate_report(
        finding, report_generator._report_vuln_type(finding), "example.com", repo_root=tmp_path,
    )
    assert "Unauthenticated Content Impersonation" in report_text
    assert "unauthenticated `PUT` request" in report_text
    assert "Send a `PUT` request" in report_text
    assert "request.txt" in report_text
    assert "author field" in report_text
    assert "Navigate to the following URL" not in report_text
    assert "returned HTTP 200" not in report_text
    assert validation_summary.read_bytes() == before
    assert not (tmp_path / "reports").exists()
