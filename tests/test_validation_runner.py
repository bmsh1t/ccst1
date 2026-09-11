"""Tests for deterministic validation runner v1 lanes."""

from __future__ import annotations

import hashlib
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

import pytest

import finding_index
import target_case_state
import validation_runner
from action_queue import ingest_checkpoint, load_queue, save_queue
from evidence_ledger import ledger_path
from identity_contract import build_closure_cell
from request_diff import RequestPairError, request_pair_digest, validate_request_pair
from tools.auth_session import AuthSession


def _target_key(target: str) -> str:
    return validation_runner.target_storage_key(validation_runner.canonical_target_value(target))


@pytest.mark.parametrize(
    ("classifier", "explicit", "expected"),
    [
        ("nosqli", "", "NoSQLi"),
        ("generic", "prototype-pollution", "PrototypePollution"),
        ("generic", "open-redirect", "OpenRedirect"),
        ("generic", "business-logic", "BusinessLogic"),
        ("ssti", "", "RCE"),
        ("generic", "command-injection", "RCE"),
        ("generic", "lfi", "Path"),
        ("unknown", "", ""),
    ],
)
def test_request_diff_uses_canonical_vuln_taxonomy(classifier, explicit, expected):
    actual = validation_runner._classifier_vuln_class(classifier, explicit)
    assert actual == expected
    assert not actual or actual in validation_runner.CLOSURE_FAMILIES


def _expect_auth_pair_spec() -> dict:
    return {
        "schema_version": 1,
        "baseline_request": {"method": "GET", "url": "https://target.test/api/users"},
        "variant_request": {
            "method": "GET",
            "url": "https://target.test/api/users",
            "headers": {"Authorization": "Bearer denied"},
        },
        "active_dimension": "header:Authorization",
        "classifier": "authz",
    }


def test_request_diff_distinct_bodies_promotes_sub_threshold_cross_user_read(monkeypatch, tmp_path):
    """V-2: a cross-user read whose body delta is below the 20-byte material
    threshold is still a different object. distinct_bodies has no threshold,
    so the Users/24-vs-Users/1 shape (delta ~15 bytes) promotes."""

    def fake_request_once(**kwargs):
        url = kwargs["url"]
        if url.endswith("/24"):
            return _fake_response(url, body='{"data":{"id":24,"email":"me@target.test"}}')
        return _fake_response(url, body='{"data":{"id":1,"email":"admin@juice-sh.op"}}')

    monkeypatch.setattr(validation_runner, "request_once", fake_request_once)
    spec = {
        "schema_version": 1,
        "baseline_request": {"method": "GET", "url": "https://target.test/api/Users/24"},
        "variant_request": {"method": "GET", "url": "https://target.test/api/Users/1"},
        "active_dimension": "path:/api/Users/24",
        "classifier": "authz_access",
        "vuln_class": "Authz",
        "expected": ["distinct_bodies"],
        "expected_note": "reading another user's record should not return their row",
        "repeat": 1,
    }
    summary = validation_runner.run_request_diff(
        repo_root=tmp_path,
        target="https://target.test",
        request_spec=spec,
    )
    assert summary["result"] == "tested_finding"
    assert summary["candidate_ready"] is True
    assert summary["expected_check"]["unmet"] == []
    # The diff-relative threshold fact must NOT hold for this pair.
    assert summary["expected_check"]["observed"]["distinct_bodies"] is True


def test_request_diff_needle_facts_promote_structurally_identical_cross_user_read(monkeypatch, tmp_path):
    """V-3: a cross-user read whose responses are structurally identical
    (same JSON shape, same size, different owner) cannot be expressed by any
    diff-relative fact. The AI declares a needle — the owner identifier — and
    the runner verifies the substring mechanically."""

    def fake_request_once(**kwargs):
        url = kwargs["url"]
        if url.endswith("/7"):
            return _fake_response(url, body='{"id":7,"UserId":25,"coupon":null}')
        return _fake_response(url, body='{"id":6,"UserId":24,"coupon":null}')

    monkeypatch.setattr(validation_runner, "request_once", fake_request_once)
    spec = {
        "schema_version": 1,
        "baseline_request": {"method": "GET", "url": "https://target.test/rest/basket/7"},
        "variant_request": {"method": "GET", "url": "https://target.test/rest/basket/6"},
        "active_dimension": "path:/rest/basket/7",
        "classifier": "authz_access",
        "vuln_class": "Authz",
        "expected": [
            'variant_body_contains::"UserId":24',
            'baseline_body_lacks::"UserId":24',
        ],
        "expected_note": "the non-owner basket read must return the other owner's id",
        "repeat": 2,
    }
    summary = validation_runner.run_request_diff(
        repo_root=tmp_path,
        target="https://target.test",
        request_spec=spec,
    )
    assert summary["result"] == "tested_finding"
    assert summary["candidate_ready"] is True
    assert summary["expected_check"]["unmet"] == []
    assert summary["expected_check"]["observed"] == {
        'variant_body_contains::"UserId":24': True,
        'baseline_body_lacks::"UserId":24': True,
    }


def test_request_diff_needle_fact_contradicted_falls_to_candidate(monkeypatch, tmp_path):
    """Anti-forgery for needles: declaring a needle that the wire disproves
    rejects to candidate with the entry named in unmet."""

    def fake_request_once(**kwargs):
        url = kwargs["url"]
        if url.endswith("/7"):
            return _fake_response(url, body='{"id":7,"UserId":25}')
        return _fake_response(url, body='{"id":6,"UserId":24}')

    monkeypatch.setattr(validation_runner, "request_once", fake_request_once)
    spec = {
        "schema_version": 1,
        "baseline_request": {"method": "GET", "url": "https://target.test/rest/basket/7"},
        "variant_request": {"method": "GET", "url": "https://target.test/rest/basket/6"},
        "active_dimension": "path:/rest/basket/7",
        "classifier": "authz_access",
        "vuln_class": "Authz",
        # Both needles are false here: the variant lacks UserId 99 and the
        # baseline DOES contain the string the declaration says it lacks.
        "expected": [
            'variant_body_contains::"UserId":99',
            'baseline_body_lacks::"UserId":25',
        ],
        "repeat": 1,
    }
    summary = validation_runner.run_request_diff(
        repo_root=tmp_path,
        target="https://target.test",
        request_spec=spec,
    )
    assert summary["result"] == "candidate"
    assert summary["candidate_ready"] is False
    assert summary["expected_check"]["unmet"] == [
        'variant_body_contains::"UserId":99',
        'baseline_body_lacks::"UserId":25',
    ]


def test_request_pair_needle_fact_validation(tmp_path):
    """Needle parsing: unknown needle-fact name and out-of-bounds needle
    length are hard input errors; a valid entry rides the digest."""

    base = {
        "schema_version": 1,
        "baseline_request": {"method": "GET", "url": "https://target.test/a"},
        "variant_request": {"method": "GET", "url": "https://target.test/b"},
        "active_dimension": "path:/a",
        "classifier": "generic",
    }
    base["baseline_request"]["url"] = "https://target.test/users/1"
    base["variant_request"]["url"] = "https://target.test/users/2"
    base["active_dimension"] = "path:/users/1"

    valid = dict(base, expected=['variant_body_contains::"UserId":24'])
    normalized = validate_request_pair(valid)
    assert normalized["expected"] == ['variant_body_contains::"UserId":24']

    with pytest.raises(RequestPairError, match="unknown fact name"):
        validate_request_pair(dict(base, expected=['variant_body_has::"UserId":24']))
    # Short needles are valid: the AI judges what string is discriminative
    # ('49' for a 7*7 render, '7*7' for an unevaluated template).
    assert validate_request_pair(dict(base, expected=['variant_body_contains::49']))["expected"] == [
        'variant_body_contains::49'
    ]
    assert validate_request_pair(dict(base, expected=['variant_body_contains::7*7']))["expected"] == [
        'variant_body_contains::7*7'
    ]
    with pytest.raises(RequestPairError, match="unknown fact name"):
        validate_request_pair(dict(base, expected=['variant_body_contains::']))
    with pytest.raises(RequestPairError, match="needle"):
        validate_request_pair(dict(base, expected=[f'variant_body_contains::{"x" * 201}']))
    assert request_pair_digest(valid) != request_pair_digest(dict(base, expected=['variant_body_contains::"UserId":25']))


def test_request_pair_declaration_intent_parse_and_digest(tmp_path):
    base = {
        "schema_version": 1,
        "baseline_request": {"method": "GET", "url": "https://target.test/users/1"},
        "variant_request": {"method": "GET", "url": "https://target.test/users/2"},
        "active_dimension": "path:/users/1",
        "classifier": "generic",
        "expected": ["distinct_bodies"],
    }
    # Absent defaults to hazard (today's behavior for every existing spec).
    assert validate_request_pair(base)["declaration_intent"] == "hazard"
    assert validate_request_pair(dict(base, declaration_intent="clean"))["declaration_intent"] == "clean"
    assert validate_request_pair(dict(base, declaration_intent="HAZARD"))["declaration_intent"] == "hazard"
    with pytest.raises(RequestPairError, match="declaration_intent"):
        validate_request_pair(dict(base, declaration_intent="maybe"))
    # Intent rides the digest: a clean declaration is a different operation.
    assert request_pair_digest(dict(base, declaration_intent="clean")) != request_pair_digest(base)


def test_request_diff_clean_intent_confirmed_lands_tested_clean(monkeypatch, tmp_path):
    """O-1: declaring the CLEAN direction and confirming it yields a
    mechanically-backed tested_clean (expected_check archived), not a
    finding-shaped artifact. The runner routes on the declared intent; it
    never infers direction from the fact names."""

    def fake_request_once(**kwargs):
        # Redirect-allowlist shape: both sides rejected identically apart from
        # echoing the input; the boundary holds.
        return _fake_response(kwargs["url"], status=406, body="refused")

    monkeypatch.setattr(validation_runner, "request_once", fake_request_once)
    spec = {
        "schema_version": 1,
        "baseline_request": {"method": "GET", "url": "https://target.test/redirect?to=ok"},
        "variant_request": {"method": "GET", "url": "https://target.test/redirect?to=bad"},
        "active_dimension": "query:to",
        "evidence_shape": "request_diff",
        "classifier": "open_redirect",
        "vuln_class": "OpenRedirect",
        "expected": ["both_sides_rejected"],
        "declaration_intent": "clean",
        "expected_note": "the allowlist should refuse both a valid-but-foreign and an offsite target",
        "repeat": 2,
    }
    summary = validation_runner.run_request_diff(
        repo_root=tmp_path,
        target="https://target.test",
        request_spec=spec,
    )
    assert summary["result"] == "tested_clean"
    assert summary["candidate_ready"] is True
    assert summary["expected_check"]["unmet"] == []
    assert summary["declaration_intent"] == "clean"

    # Same pair without intent: hazard default promotes as today (regression).
    spec.pop("declaration_intent")
    hazard = validation_runner.run_request_diff(
        repo_root=tmp_path,
        target="https://target.test",
        request_spec=spec,
    )
    assert hazard["result"] == "tested_finding"

    # Clean declaration NOT holding: kill-condition failure is signal —
    # candidate, reaching review.
    spec["declaration_intent"] = "clean"
    spec["expected"] = ["distinct_bodies"]
    unmet = validation_runner.run_request_diff(
        repo_root=tmp_path,
        target="https://target.test",
        request_spec=spec,
    )
    assert unmet["result"] == "candidate"
    assert unmet["expected_check"]["unmet"] == ["distinct_bodies"]


def test_request_pair_expect_auth_parse_and_digest():
    """expect_auth is an AI-declared boolean judgment: the parser carries it
    unchanged (never infers it), and it participates in the operation digest
    because declaring it makes the replay a different operation."""

    base = _expect_auth_pair_spec()
    normalized = validate_request_pair(base)
    assert normalized["expect_auth"] is False

    declared = dict(base, expect_auth=True)
    assert validate_request_pair(declared)["expect_auth"] is True

    # Absent, null, and empty all mean "no assertion" (legacy behavior).
    assert validate_request_pair(dict(base, expect_auth=None))["expect_auth"] is False
    assert validate_request_pair(dict(base, expect_auth=""))["expect_auth"] is False

    # A spec with and without the declaration are different operations.
    assert request_pair_digest(declared) != request_pair_digest(base)

    # Non-boolean truthy values are hard input errors, not silently coerced.
    with pytest.raises(RequestPairError):
        validate_request_pair(dict(base, expect_auth="yes"))


def _fake_response(url: str, *, status: int = 200, body: str = "{}") -> dict:
    return {
        "url": url,
        "method": "GET",
        "request_text": f"GET {urlparse(url).path or '/'} HTTP/1.1\nHost: {urlparse(url).netloc}\n",
        "status": status,
        "reason": "OK",
        "headers": {"Content-Type": "application/json"},
        "body": body,
        "response_text": f"HTTP/1.1 {status} OK\nContent-Type: application/json\n\n{body}",
    }


def _runner_reconciliation_fixture(monkeypatch, tmp_path):
    target = "https://target.test"
    url = "https://target.test/rest/admin/application-configuration"
    finding_id = "AUTHZ-RECONCILE"
    key = _target_key(target)
    queue_dir = tmp_path / "state" / key
    queue_dir.mkdir(parents=True)
    (queue_dir / "action_queue.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "target": target,
                "actions": [
                    {
                        "id": "AQ-RECONCILE",
                        "status": "queued",
                        "type": "validation",
                        "metadata": {"finding_id": finding_id, "url": url},
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(
        validation_runner,
        "request_once",
        lambda **kwargs: _fake_response(
            kwargs["url"],
            body=json.dumps({"config": {"googleOauth": {"clientId": "client.apps.test"}}}),
        ),
    )
    summary = validation_runner.run_marker_replay(
        repo_root=tmp_path,
        target=target,
        url=url,
        expect_marker="googleOauth",
        finding_id=finding_id,
    )
    return summary, queue_dir / "action_queue.json", key


def _build_case_state_for_authz_role(tmp_path):
    target = "https://target.test"
    target_case_state.add_actor(tmp_path, target, actor="user_a", role="user")
    target_case_state.add_actor(tmp_path, target, actor="user_b", role="user")
    target_case_state.add_session(
        tmp_path,
        target,
        session="sess_user_a",
        actor="user_a",
        kind="bearer",
        header_value="Bearer owner",
        validity="valid",
    )
    target_case_state.add_session(
        tmp_path,
        target,
        session="sess_user_b",
        actor="user_b",
        kind="bearer",
        header_value="Bearer peer",
        validity="valid",
    )
    return target


def test_candidate_followup_reingest_is_idempotent_across_runner_and_checkpoint(tmp_path):
    target = "https://target.test"
    url = "https://target.test/rest/admin/application-configuration"
    original = {
        "id": "A1",
        "priority": 70,
        "type": "surface-review",
        "status": "ready",
        "action": f"Review surface candidate {url}: validate exposure evidence.",
        "command_hint": "capture baseline",
        "source": "checkpoint",
        "source_id": "A1",
        "metadata": {
            "url": url,
            "endpoint": "/rest/admin/application-configuration",
        },
    }
    ingest_checkpoint(tmp_path, target, checkpoint={"next_action_queue": [original]})
    queue = load_queue(tmp_path, target)
    queue["actions"][0]["status"] = "candidate"

    summary = {
        "finding_id": "exposure_f0731e9e75",
        "url": url,
        "summary_path": "evidence/target.test/summary.json",
        "lane": "authz_public_exposure",
        "evidence_rubric": {
            "status": "candidate",
            "missing_labels": ["policy/role expectation"],
        },
    }
    patched = validation_runner._patch_candidate_queue_followup_in_queue(
        queue,
        action_id="AQ-0001",
        summary=summary,
    )
    assert patched["patched"] is True
    duplicate = {
        **queue["actions"][0],
        "id": "AQ-LEGACY-DUP",
        "dedupe_key": "legacy-candidate-gap",
        "metadata": dict(queue["actions"][0]["metadata"]),
    }
    queue["actions"].append(duplicate)
    save_queue(tmp_path, target, queue)

    candidate = validation_runner._candidate_queue_followup(summary)
    candidate.update(
        {
            "id": "A9",
            "priority": 70,
            "status": "ready",
            "source": "checkpoint",
            "source_id": "A9",
        }
    )
    validation = {
        "id": "A10",
        "priority": 100,
        "type": "validation",
        "status": "ready",
        "action": f"Run /validate for finding {summary['finding_id']} on {url}.",
        "command_hint": "/validate",
        "source": "checkpoint",
        "source_id": "A10",
        "metadata": {"finding_id": summary["finding_id"]},
    }

    first = ingest_checkpoint(
        tmp_path,
        target,
        checkpoint={"next_action_queue": [candidate, validation]},
    )
    second = ingest_checkpoint(
        tmp_path,
        target,
        checkpoint={"next_action_queue": [candidate, validation]},
    )
    actions = load_queue(tmp_path, target)["actions"]
    active_candidates = [
        item
        for item in actions
        if item.get("type") == "candidate-evidence-gap"
        and item.get("status") in {"queued", "candidate", "running"}
    ]
    active_validations = [
        item
        for item in actions
        if item.get("type") == "validation"
        and item.get("status") in {"queued", "candidate", "running"}
    ]

    assert first["stats"]["added"] == 1
    assert second["stats"]["added"] == 0
    assert len(active_candidates) == 1
    assert active_candidates[0]["id"] == "AQ-0001"
    assert [item for item in actions if item.get("id") == "AQ-LEGACY-DUP"][0]["status"] == "n/a"
    assert len(active_validations) == 1


def test_runner_queue_sync_prefers_exact_finding_id_over_legacy_url(tmp_path):
    target = "https://target.test"
    url = "https://target.test/api/Users"
    key = _target_key(target)
    queue_dir = tmp_path / "state" / key
    queue_dir.mkdir(parents=True)
    (queue_dir / "action_queue.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "target": target,
                "actions": [
                    {
                        "id": "AQ-EXACT",
                        "status": "queued",
                        "type": "ranked-surface",
                        "metadata": {"finding_id": "F-EXACT", "url": "https://target.test/other"},
                    },
                    {
                        "id": "AQ-LEGACY",
                        "status": "queued",
                        "type": "ranked-surface",
                        "action": f"Replay {url} and classify it.",
                    },
                ],
            },
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )

    synced = validation_runner._sync_action_queue(
        {"target": target, "finding_id": "F-EXACT", "url": url, "result": "tested_clean"},
        repo_root=tmp_path,
    )
    queue = json.loads((queue_dir / "action_queue.json").read_text(encoding="utf-8"))
    statuses = {item["id"]: item["status"] for item in queue["actions"]}

    assert synced["status"] == "updated"
    assert synced["id"] == "AQ-EXACT"
    assert synced["match_kind"] == "finding_id"
    assert statuses == {"AQ-EXACT": "tested", "AQ-LEGACY": "queued"}


def test_runner_queue_sync_refuses_ambiguous_legacy_marker(tmp_path):
    target = "https://target.test"
    url = "https://target.test/api/Users"
    key = _target_key(target)
    queue_dir = tmp_path / "state" / key
    queue_dir.mkdir(parents=True)
    actions = [
        {"id": "AQ-ONE", "status": "queued", "type": "ranked-surface", "action": f"Replay {url}."},
        {"id": "AQ-TWO", "status": "queued", "type": "coverage-gap", "evidence": f"Observed {url}."},
    ]
    (queue_dir / "action_queue.json").write_text(
        json.dumps({"schema_version": 1, "target": target, "actions": actions}),
        encoding="utf-8",
    )

    synced = validation_runner._sync_action_queue(
        {"target": target, "url": url, "result": "tested_clean"},
        repo_root=tmp_path,
    )
    queue = json.loads((queue_dir / "action_queue.json").read_text(encoding="utf-8"))

    assert synced == {
        "status": "ambiguous",
        "reason": "multiple legacy_marker queue actions match runner output",
        "ids": ["AQ-ONE", "AQ-TWO"],
    }
    assert [item["status"] for item in queue["actions"]] == ["queued", "queued"]


def test_queue_endpoint_match_normalizes_trailing_slash_without_path_suffix_match():
    exact = {
        "id": "AQ-EXACT",
        "status": "queued",
        "type": "validation",
        "metadata": {"endpoint": "/api/Users"},
    }
    legacy_suffix = {
        "id": "AQ-SUFFIX",
        "status": "queued",
        "type": "validation",
        "action": "Replay /v1/api/Users and classify it.",
    }
    matches, match_kind = validation_runner._select_queue_actions_for_summary(
        {"actions": [exact, legacy_suffix]},
        {"url": "https://target.test/api/Users/"},
        "tested",
    )

    assert [item["id"] for item in matches] == ["AQ-EXACT"]
    assert match_kind == "endpoint"
    assert validation_runner._action_matches_legacy_marker(
        legacy_suffix,
        ["/api/Users"],
    ) is False


def test_queue_endpoint_match_prefers_running_versioned_hypothesis_over_advisory_review():
    endpoint = "https://target.test/rest/admin"
    versioned = {
        "id": "AQ-VERSIONED",
        "status": "running",
        "type": "coverage-gap",
        "metadata": {
            "endpoint": "/rest/admin",
            "depth_contract_version": 1,
        },
    }
    advisory = {
        "id": "AQ-ADVISORY",
        "status": "queued",
        "type": "surface-review",
        "metadata": {"endpoint": "/rest/admin"},
    }

    matches, match_kind = validation_runner._select_queue_actions_for_summary(
        {"actions": [advisory, versioned]},
        {"url": endpoint},
        "tested",
    )

    assert [item["id"] for item in matches] == ["AQ-VERSIONED"]
    assert match_kind == "versioned_endpoint"


def test_runner_sync_does_not_downgrade_validated_finding(monkeypatch, tmp_path, capsys):
    target = "https://target.test"
    url = "https://target.test/rest/admin/application-configuration"
    key = _target_key(target)
    findings_dir = tmp_path / "findings" / key
    findings_dir.mkdir(parents=True)
    (findings_dir / "findings.json").write_text(
        json.dumps(
            {
                "target": target,
                "total": 1,
                "findings": [
                    {
                        "id": "AUTHZ-VALIDATED",
                        "type": "auth_bypass",
                        "severity": "high",
                        "confidence": "confirmed",
                        "url": url,
                        "validation_status": "validated",
                        "validation_summary": "validated/validation-summary.json",
                        "report_status": "not_generated",
                    }
                ],
            },
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )
    validation_runner.update_finding_status(
        findings_dir,
        "AUTHZ-VALIDATED",
        validation_status="validated",
        report_status="not_generated",
    )

    monkeypatch.setattr(
        validation_runner,
        "request_once",
        lambda **kwargs: _fake_response(
            kwargs["url"],
            body=json.dumps({"config": {"application": {"name": "Shop"}, "googleOauth": {"clientId": "x"}}}),
        ),
    )

    rc = validation_runner.main(
        [
            "marker-replay",
            "--repo-root",
            str(tmp_path),
            "--target",
            target,
            "--url",
            url,
            "--expect-marker",
            "googleOauth",
            "--finding-id",
            "AUTHZ-VALIDATED",
        ]
    )
    summary = json.loads(capsys.readouterr().out)
    findings = json.loads((findings_dir / "findings.json").read_text(encoding="utf-8"))

    assert rc == 0
    assert summary["sync"]["finding"]["validation_status"] == "validated"
    assert findings["findings"][0]["validation_status"] == "validated"
    assert findings["findings"][0]["validation_summary"] == "validated/validation-summary.json"
    assert findings["findings"][0]["evidence_rubric"]["status"] == "candidate-ready"


def test_runner_replay_does_not_reopen_finalized_queue_action(monkeypatch, tmp_path):
    summary, queue_path, key = _runner_reconciliation_fixture(monkeypatch, tmp_path)
    first = validation_runner.sync_runner_artifacts(summary, repo_root=tmp_path)
    assert first["status"] == "updated"

    findings_dir = tmp_path / "findings" / key
    finding_index.update_finding_status(
        findings_dir,
        "AUTHZ-RECONCILE",
        validation_status="validated",
        report_status="not_generated",
    )
    queue = json.loads(queue_path.read_text(encoding="utf-8"))
    queue["actions"][0]["status"] = "dead-end"
    queue_path.write_text(json.dumps(queue), encoding="utf-8")

    replay = validation_runner.sync_runner_artifacts(summary, repo_root=tmp_path)
    persisted_queue = json.loads(queue_path.read_text(encoding="utf-8"))

    assert replay["status"] == "deduplicated"
    assert replay["action_queue"]["status"] == "deduplicated"
    assert persisted_queue["actions"][0]["status"] == "dead-end"


def test_runner_replay_ignores_report_and_sibling_followups(monkeypatch, tmp_path):
    summary, queue_path, _ = _runner_reconciliation_fixture(monkeypatch, tmp_path)
    assert validation_runner.sync_runner_artifacts(summary, repo_root=tmp_path)["status"] == "updated"

    queue = json.loads(queue_path.read_text(encoding="utf-8"))
    queue["actions"][0]["status"] = "n/a"
    finding_id = summary["finding_id"]
    queue["actions"].extend(
        [
            {"id": "AQ-REPORT", "status": "queued", "type": "report", "metadata": {"finding_id": finding_id}},
            {
                "id": "AQ-SIBLING",
                "status": "queued",
                "type": "sibling-chain-review",
                "metadata": {"finding_id": finding_id},
            },
        ]
    )
    queue_path.write_text(json.dumps(queue), encoding="utf-8")

    replay = validation_runner.sync_runner_artifacts(summary, repo_root=tmp_path)
    persisted = json.loads(queue_path.read_text(encoding="utf-8"))

    assert replay["status"] == "deduplicated"
    assert replay["action_queue"]["status"] == "deduplicated"
    assert {item["status"] for item in persisted["actions"][1:]} == {"queued"}


def test_runner_sync_completes_missing_claim_identity_without_creating_second_finding(tmp_path):
    import finding_index

    target = "target.test"
    findings_dir = tmp_path / "findings" / target
    findings_dir.mkdir(parents=True)
    claim_path = findings_dir / "manual-authz.json"
    claim_path.write_text(
        json.dumps(
            {
                "kind": "finding_claim",
                "schema_version": 1,
                "title": "Interrupted authorization validation",
                "vuln_class": "authz",
                "evidence": {"artifact": "evidence/target.test/raw.json"},
            }
        ),
        encoding="utf-8",
    )
    claim = finding_index.list_root_finding_claims(findings_dir, target=target)[0]
    finding_index.reconcile_root_finding_claims(findings_dir, target=target)
    summary_path = tmp_path / "evidence" / target / "validation" / claim["id"] / "summary.json"
    summary_path.parent.mkdir(parents=True)
    summary_path.write_text("{}\n", encoding="utf-8")

    sync = validation_runner._sync_finding_status(
        {
            "target": target,
            "finding_id": claim["id"],
            "result": "tested_finding",
            "url": "https://target.test/api/orders/42",
            "vuln_class": "authz",
            "lane": "authz_public_exposure",
            "summary_path": str(summary_path),
            "evidence_rubric": {"status": "candidate-ready", "ready": True},
        },
        repo_root=tmp_path,
    )
    payload = finding_index.load_finding_index(findings_dir)
    row = payload["findings"][0]

    assert sync["status"] == "updated"
    assert payload["total"] == 1
    assert row["id"] == claim["id"]
    assert row["url"] == "https://target.test/api/orders/42"
    assert "endpoint" not in row["incomplete_fields"]
    assert row["claim_status"] == "complete"


def test_runner_sync_rejects_off_target_completion_for_missing_endpoint(tmp_path):
    import finding_index

    target = "target.test"
    findings_dir = tmp_path / "findings" / target
    findings_dir.mkdir(parents=True)
    (findings_dir / "manual-authz.json").write_text(
        json.dumps(
            {
                "kind": "finding_claim",
                "schema_version": 1,
                "title": "Interrupted authorization validation",
                "vuln_class": "authz",
                "evidence": {"artifact": "evidence/target.test/raw.json"},
            }
        ),
        encoding="utf-8",
    )
    claim = finding_index.list_root_finding_claims(findings_dir, target=target)[0]
    finding_index.reconcile_root_finding_claims(findings_dir, target=target)

    sync = validation_runner._sync_finding_status(
        {
            "target": target,
            "finding_id": claim["id"],
            "result": "tested_finding",
            "url": "other.test/api/orders/42",
            "vuln_class": "authz",
            "lane": "authz_public_exposure",
        },
        repo_root=tmp_path,
    )
    row = finding_index.find_finding(findings_dir, claim["id"])

    assert sync["status"] == "skipped"
    assert "off target" in sync["reason"]
    assert row is not None
    assert row["url"] == ""
    assert "endpoint" in row["incomplete_fields"]


@pytest.mark.parametrize(
    ("runner_url", "runner_class", "reason"),
    [
        (
            "https://target.test/api/orders/99",
            "authz",
            "runner endpoint conflicts with non-empty canonical finding identity",
        ),
        (
            "https://target.test/api/orders/42",
            "sqli",
            "runner vulnerability class conflicts with non-empty canonical finding identity",
        ),
    ],
)
def test_runner_sync_rejects_non_empty_canonical_identity_conflicts(
    tmp_path,
    runner_url,
    runner_class,
    reason,
):
    import finding_index

    target = "target.test"
    findings_dir = tmp_path / "findings" / target
    findings_dir.mkdir(parents=True)
    (findings_dir / "manual-authz.json").write_text(
        json.dumps(
            {
                "kind": "finding_claim",
                "schema_version": 1,
                "title": "Authorization validation",
                "endpoint": "/api/orders/42",
                "vuln_class": "authz",
                "evidence": {"artifact": "evidence/target.test/raw.json"},
            }
        ),
        encoding="utf-8",
    )
    claim = finding_index.list_root_finding_claims(findings_dir, target=target)[0]
    finding_index.reconcile_root_finding_claims(findings_dir, target=target)
    index_path = findings_dir / "findings.json"
    events_path = findings_dir / "mutation-events.jsonl"
    index_before = index_path.read_bytes()
    events_before = events_path.read_bytes()

    sync = validation_runner._sync_finding_status(
        {
            "target": target,
            "finding_id": claim["id"],
            "result": "tested_finding",
            "url": runner_url,
            "vuln_class": runner_class,
            "lane": "authz_public_exposure",
        },
        repo_root=tmp_path,
    )

    assert sync["status"] == "skipped"
    assert sync["reason"] == reason
    assert index_path.read_bytes() == index_before
    assert events_path.read_bytes() == events_before


def test_request_diff_replays_post_json_with_sql_classifier(monkeypatch, tmp_path):
    def fake_request_once(**kwargs):
        body = kwargs["body"]
        name = body["filter"]["name"] if isinstance(body, dict) else ""
        count = 3 if "select" in name.lower() or "or" in name.lower() else 1
        return _fake_response(kwargs["url"], body=json.dumps({"data": [{"id": index} for index in range(count)]}))

    monkeypatch.setattr(validation_runner, "request_once", fake_request_once)
    summary = validation_runner.run_request_diff(
        repo_root=tmp_path,
        target="https://target.test",
        request_spec={
            "schema_version": 1,
            "baseline_request": {
                "method": "POST",
                "url": "https://target.test/api/search",
                "headers": {"Content-Type": "application/json"},
                "body": {"filter": {"name": "SAMPLE"}},
            },
            "variant_request": {
                "method": "POST",
                "url": "https://target.test/api/search",
                "headers": {"Content-Type": "application/json"},
                "body": {"filter": {"name": "' OR 1=1 --"}},
            },
            "active_dimension": "body:/filter/name",
            "evidence_shape": "request_diff",
            "classifier": "sqli",
            "vuln_class": "SQLi",
            "expected": ["count_delta_positive"],
            "repeat": 2,
        },
        finding_id="SQLI-POST-JSON",
        repeat=2,
    )

    assert summary["method"] == "POST"
    assert summary["active_dimension"] == "body:/filter/name"
    assert summary["evidence_shape"] == "request_diff"
    assert summary["classifier"] == "sqli"
    assert summary["result"] == "tested_finding"
    assert summary["candidate_ready"] is True
    assert summary["expected_check"]["unmet"] == []
    assert summary["ledger_record"]["write_status"] in {"written", "deduplicated", "updated"}
    assert validation_runner.sync_runner_artifacts(summary, repo_root=tmp_path)["ledger"]["status"] in {
        "written",
        "deduplicated",
        "updated",
    }
    assert all(run["method"] if "method" in run else True for run in summary["runs"])


def test_request_diff_without_canonical_ledger_family_keeps_sync_skipped(monkeypatch, tmp_path):
    def fake_request_once(**kwargs):
        query = parse_qs(urlparse(kwargs["url"]).query).get("q", [""])[0]
        count = 2 if query == "banana" else 1
        return _fake_response(kwargs["url"], body=json.dumps({"data": list(range(count))}))

    monkeypatch.setattr(validation_runner, "request_once", fake_request_once)
    summary = validation_runner.run_request_diff(
        repo_root=tmp_path,
        target="https://target.test",
        request_spec={
            "baseline_request": {"method": "GET", "url": "https://target.test/search?q=apple"},
            "variant_request": {"method": "GET", "url": "https://target.test/search?q=banana"},
            "active_dimension": "query:q",
            "classifier": "generic",
        },
        finding_id="GENERIC-REQUEST-DIFF",
    )

    sync = validation_runner.sync_runner_artifacts(summary, repo_root=tmp_path)

    assert summary["ledger_record"]["write_status"] == "skipped"
    assert sync["status"] == "skipped"
    assert sync["ledger"]["status"] == "skipped"
    assert "error" not in sync["ledger"]


def test_request_diff_marks_multipart_manual_required_without_request(monkeypatch, tmp_path):
    def fail_request(**kwargs):
        raise AssertionError("unsupported wire body must not be sent")

    monkeypatch.setattr(validation_runner, "request_once", fail_request)
    summary = validation_runner.run_request_diff(
        repo_root=tmp_path,
        target="https://target.test",
        request_spec={
            "baseline_request": {
                "method": "POST",
                "url": "https://target.test/upload",
                "headers": {"Content-Type": "multipart/form-data"},
                "body": "binary",
            },
            "variant_request": {
                "method": "POST",
                "url": "https://target.test/upload",
                "headers": {"Content-Type": "multipart/form-data"},
                "body": "other",
            },
            "active_dimension": "body:/file",
        },
        finding_id="UPLOAD-MANUAL",
    )

    assert summary["result"] == "manual_required"
    assert "multipart" in summary["manual_required"]


def test_request_diff_replay_keeps_operation_id_and_one_ledger_event(monkeypatch, tmp_path):
    monkeypatch.setattr(
        validation_runner,
        "request_once",
        lambda **kwargs: _fake_response(kwargs["url"], body='{"data":[{"id":1},{"id":2}]}'),
    )
    spec = {
        "baseline_request": {"method": "POST", "url": "https://target.test/api/search", "body": {"q": "SAMPLE"}},
        "variant_request": {"method": "POST", "url": "https://target.test/api/search", "body": {"q": "PAYLOAD"}},
        "active_dimension": "body:/q",
        "classifier": "sqli",
    }
    first = validation_runner.run_request_diff(repo_root=tmp_path, target="https://target.test", request_spec=spec, finding_id="PAIR-IDEMPOTENT")
    second = validation_runner.run_request_diff(repo_root=tmp_path, target="https://target.test", request_spec=spec, finding_id="PAIR-IDEMPOTENT")
    ledger = tmp_path / "memory" / "evidence" / _target_key("https://target.test") / "ledger.jsonl"
    assert first["operation_id"] == second["operation_id"]
    assert len(ledger.read_text(encoding="utf-8").splitlines()) == 1


def test_marker_replay_creates_bundle_and_ledger(monkeypatch, tmp_path):
    monkeypatch.setattr(
        validation_runner,
        "request_once",
        lambda **kwargs: _fake_response(kwargs["url"], body="rendered value: CCST_MARKER_42"),
    )

    summary = validation_runner.run_marker_replay(
        repo_root=tmp_path,
        target="https://target.test",
        url="https://target.test/render?name={{safe_calc}}",
        expect_marker="CCST_MARKER_42",
        finding_id="RCE-MARKER-1",
        vuln_class="SSTI",
        repeat=2,
        browser_observed=True,
    )

    key = _target_key("https://target.test")
    bundle = (tmp_path / summary["summary_path"]).parent
    ledger = tmp_path / "memory" / "evidence" / key / "ledger.jsonl"
    assert summary["lane"] == "marker_replay"
    assert summary["result"] == "tested_finding"
    assert summary["candidate_ready"] is True
    assert all(run["marker_found"] for run in summary["runs"])
    assert (tmp_path / summary["runs"][0]["artifacts"]["request"]).is_file()
    assert (tmp_path / summary["runs"][1]["artifacts"]["response"]).is_file()
    assert (bundle / "summary.json").is_file()
    entry = json.loads(ledger.read_text(encoding="utf-8").splitlines()[-1])
    assert entry["vuln_class"] == "RCE"
    assert entry["result"] == "tested_finding"
    assert entry["browser_observed"] is True


def test_marker_replay_without_marker_is_clean(monkeypatch, tmp_path):
    monkeypatch.setattr(
        validation_runner,
        "request_once",
        lambda **kwargs: _fake_response(kwargs["url"], body="ordinary render output"),
    )

    summary = validation_runner.run_marker_replay(
        repo_root=tmp_path,
        target="https://target.test",
        url="https://target.test/render?name=test",
        expect_marker="CCST_MARKER_42",
        finding_id="RCE-MARKER-CLEAN",
        vuln_class="RCE",
    )

    assert summary["result"] == "tested_clean"
    assert summary["candidate_ready"] is False
    assert summary["runs"][0]["marker_found"] is False


def test_marker_replay_ignores_stderr_marker(monkeypatch, tmp_path):
    marker = "CCST_STDERR_MARKER_42"

    def fake_request_once(**kwargs):
        response = _fake_response(kwargs["url"], body="ordinary output")
        response["stderr"] = f"diagnostic: {marker}"
        return response

    monkeypatch.setattr(validation_runner, "request_once", fake_request_once)
    summary = validation_runner.run_marker_replay(
        repo_root=tmp_path,
        target="https://target.test",
        url="https://target.test/render",
        expect_marker=marker,
        finding_id="MARKER-STDERR-ONLY",
        no_ledger=True,
    )

    assert summary["result"] == "tested_clean"
    assert summary["candidate_ready"] is False
    assert summary["runs"][0]["marker_found"] is False
    assert summary["runs"][0]["marker_occurrences"] == 0


def test_marker_replay_control_proves_baseline_absence(monkeypatch, tmp_path):
    marker = "CCST_UNIQUE_MARKER_42"

    def fake_request_once(**kwargs):
        return _fake_response(
            kwargs["url"],
            body="ordinary output" if "neutral" in kwargs["url"] else f"rendered {marker}",
        )

    monkeypatch.setattr(validation_runner, "request_once", fake_request_once)
    summary = validation_runner.run_marker_replay(
        repo_root=tmp_path,
        target="https://target.test",
        url=f"https://target.test/render?q={marker}",
        baseline_url="https://target.test/render?q=neutral",
        expect_marker=marker,
        finding_id="MARKER-ORACLE-PASS",
        vuln_class="SSTI",
        no_ledger=True,
    )

    assert summary["result"] == "tested_finding"
    assert summary["marker_oracle"]["status"] == "passed"
    assert summary["marker_oracle"]["baseline_absent"] is True
    assert summary["runs"][0]["baseline_marker_found"] is False


def test_marker_replay_valid_control_without_marker_is_clean(monkeypatch, tmp_path):
    monkeypatch.setattr(
        validation_runner,
        "request_once",
        lambda **kwargs: _fake_response(kwargs["url"], body="ordinary output"),
    )

    summary = validation_runner.run_marker_replay(
        repo_root=tmp_path,
        target="https://target.test",
        url="https://target.test/render?q=neutral",
        baseline_url="https://target.test/render?q=control",
        expect_marker="CCST_UNIQUE_MARKER_42",
        finding_id="MARKER-ORACLE-CLEAN",
        no_ledger=True,
    )

    assert summary["result"] == "tested_clean"
    assert summary["marker_oracle"]["status"] == "rejected"
    assert summary["marker_oracle"]["baseline_valid"] is True


def test_marker_replay_control_rejects_natural_marker_and_weak_token(monkeypatch, tmp_path):
    monkeypatch.setattr(
        validation_runner,
        "request_once",
        lambda **kwargs: _fake_response(kwargs["url"], body="already contains MARKER"),
    )

    summary = validation_runner.run_marker_replay(
        repo_root=tmp_path,
        target="https://target.test",
        url="https://target.test/render?q=MARKER",
        baseline_url="https://target.test/render?q=neutral",
        expect_marker="MARKER",
        finding_id="MARKER-ORACLE-REJECT",
        no_ledger=True,
    )

    assert summary["result"] == "candidate"
    assert summary["candidate_ready"] is False
    assert summary["marker_oracle"]["status"] == "rejected"
    assert summary["marker_oracle"]["baseline_absent"] is False
    assert summary["marker_oracle"]["marker_quality"]["sufficient"] is False


@pytest.mark.parametrize("invalid_kind", ["status", "truncated"])
def test_marker_replay_invalid_control_never_returns_tested_terminal(
    monkeypatch, tmp_path, invalid_kind
):
    marker = "CCST_UNIQUE_MARKER_42"

    def fake_request_once(**kwargs):
        if "neutral" in kwargs["url"]:
            response = _fake_response(
                kwargs["url"],
                status=500 if invalid_kind == "status" else 200,
                body="ordinary output",
            )
            if invalid_kind == "truncated":
                response["body_truncated"] = True
            return response
        return _fake_response(kwargs["url"], body=f"rendered {marker}")

    monkeypatch.setattr(validation_runner, "request_once", fake_request_once)
    summary = validation_runner.run_marker_replay(
        repo_root=tmp_path,
        target="https://target.test",
        url=f"https://target.test/render?q={marker}",
        baseline_url="https://target.test/render?q=neutral",
        expect_marker=marker,
        finding_id=f"MARKER-INVALID-{invalid_kind}",
        no_ledger=True,
    )

    assert summary["result"] == "candidate"
    assert summary["candidate_ready"] is False
    assert summary["marker_oracle"]["status"] == "invalid_control"
    assert summary["marker_oracle"]["baseline_valid"] is False


def test_xss_marker_reflection_stays_open_signal_until_browser_context(monkeypatch, tmp_path):
    monkeypatch.setattr(
        validation_runner,
        "request_once",
        lambda **kwargs: _fake_response(kwargs["url"], body="reflected CCST_XSS_MARKER"),
    )

    summary = validation_runner.run_marker_replay(
        repo_root=tmp_path,
        target="https://target.test",
        url="https://target.test/reflected?q=CCST_XSS_MARKER",
        expect_marker="CCST_XSS_MARKER",
        finding_id="XSS-MARKER-SIGNAL",
        vuln_class="XSS",
        repeat=2,
    )

    ledger = tmp_path / "memory" / "evidence" / _target_key("https://target.test") / "ledger.jsonl"
    entry = json.loads(ledger.read_text(encoding="utf-8").splitlines()[-1])

    assert summary["result"] == "tested_finding"
    # The oracle is the single promotion authority: the advisory rubric may
    # still score the reflection evidence low, but the ledger row must never
    # disagree with the runner result the witness compares.
    assert summary["evidence_rubric"]["ready"] is False
    assert entry["result"] == "tested_finding"
    assert "reflected" in summary["ai_next"]["hypothesis"]
    assert "browser execution context" in summary["ai_next"]["next_action"]


def test_request_once_rejects_off_target_before_open(monkeypatch):
    called = False

    def fail_if_called(*args, **kwargs):
        nonlocal called
        called = True
        raise AssertionError("network opener must not be built")

    monkeypatch.setattr(validation_runner.urllib.request, "build_opener", fail_if_called)
    with pytest.raises(ValueError, match="outside target scope"):
        validation_runner.request_once(
            target="target.test",
            url="https://other.test/api",
        )
    assert called is False


def test_redirect_handler_rejects_off_target_redirect():
    handler = validation_runner._TargetRedirectHandler("target.test")
    with pytest.raises(ValueError, match="redirect left target scope"):
        handler.redirect_request(None, None, 302, "Found", {}, "https://other.test/callback?token=secret")


def test_request_once_records_same_target_redirect_identity():
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802 - BaseHTTPRequestHandler API
            if self.path == "/start":
                self.send_response(302)
                self.send_header("Location", "/final")
                self.end_headers()
                return
            self.send_response(200)
            self.send_header("Content-Length", "5")
            self.end_headers()
            self.wfile.write(b"final")

        def log_message(self, *_args):
            return

    try:
        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    except OSError as exc:  # pragma: no cover - restricted sandboxes
        pytest.skip(f"localhost listener unavailable: {exc}")
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    requested_url = f"http://127.0.0.1:{server.server_port}/start"
    final_url = f"http://127.0.0.1:{server.server_port}/final"
    try:
        response = validation_runner.request_once(
            target=f"127.0.0.1:{server.server_port}",
            url=requested_url,
        )
    finally:
        server.shutdown()
        thread.join(timeout=2)
        server.server_close()

    assert response["url"] == requested_url
    assert response["requested_url"] == requested_url
    assert response["final_url"] == final_url
    assert response["redirect_chain"] == [{
        "status": 302,
        "from_url": requested_url,
        "to_url": final_url,
    }]


def test_cross_origin_redirect_replays_only_explicitly_authorized_session_headers():
    sink_headers: list[dict[str, str]] = []
    source_headers: list[dict[str, str]] = []

    class SinkHandler(BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802 - BaseHTTPRequestHandler API
            sink_headers.append(dict(self.headers.items()))
            self.send_response(200)
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"ok")

        def log_message(self, *_args):
            return

    try:
        sink = ThreadingHTTPServer(("127.0.0.1", 0), SinkHandler)
    except OSError as exc:  # pragma: no cover - restricted sandboxes
        pytest.skip(f"localhost listener unavailable: {exc}")
    sink_thread = threading.Thread(target=sink.serve_forever, daemon=True)
    sink_thread.start()
    sink_url = f"http://127.0.0.1:{sink.server_port}/final"

    class SourceHandler(BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802 - BaseHTTPRequestHandler API
            source_headers.append(dict(self.headers.items()))
            self.send_response(302)
            self.send_header("Location", sink_url)
            self.end_headers()

        def log_message(self, *_args):
            return

    try:
        source = ThreadingHTTPServer(("127.0.0.1", 0), SourceHandler)
    except OSError as exc:  # pragma: no cover - restricted sandboxes
        sink.shutdown()
        sink_thread.join(timeout=2)
        sink.server_close()
        pytest.skip(f"localhost listener unavailable: {exc}")
    source_thread = threading.Thread(target=source.serve_forever, daemon=True)
    source_thread.start()
    source_url = f"http://127.0.0.1:{source.server_port}/start"
    try:
        untrusted = AuthSession(
            ["Authorization: Bearer session", "Cookie: sid=session"],
            target="127.0.0.1",
        )
        validation_runner.request_once(
            target="127.0.0.1",
            url=source_url,
            headers={"Authorization": "Bearer raw", "X-Raw-Auth": "raw"},
            session=untrusted,
        )

        trusted = AuthSession(
            ["Authorization: Bearer session", "Cookie: sid=session"],
            target="127.0.0.1",
            allowed_origins=[sink_url],
        )
        validation_runner.request_once(
            target="127.0.0.1",
            url=source_url,
            headers={"Authorization": "Bearer raw", "X-Raw-Auth": "raw"},
            session=trusted,
        )
    finally:
        source.shutdown()
        source_thread.join(timeout=2)
        source.server_close()
        sink.shutdown()
        sink_thread.join(timeout=2)
        sink.server_close()

    assert source_headers[0]["Authorization"] == "Bearer raw"
    assert "Authorization" not in sink_headers[0]
    assert "Cookie" not in sink_headers[0]
    assert "X-Raw-Auth" not in sink_headers[0]
    assert sink_headers[1]["Authorization"] == "Bearer session"
    assert sink_headers[1]["Cookie"] == "sid=session"
    assert "X-Raw-Auth" not in sink_headers[1]


def test_cli_auth_file_builds_session_and_raw_header_keeps_precedence(monkeypatch, tmp_path, capsys):
    auth = tmp_path / "auth.json"
    auth.write_text(
        json.dumps({"target": "target.test", "bearer": "session-token"}),
        encoding="utf-8",
    )
    captured = {}

    def fake_run(**kwargs):
        captured.update(kwargs)
        return {"result": "tested_clean"}

    monkeypatch.setattr(validation_runner, "run_marker_replay", fake_run)
    assert validation_runner.main([
        "marker-replay",
        "--target",
        "target.test",
        "--url",
        "https://target.test/check",
        "--expect-marker",
        "SAFE",
        "--auth-file",
        str(auth),
        "--header",
        "Authorization: Bearer raw-token",
        "--no-ledger",
        "--no-sync",
    ]) == 0
    capsys.readouterr()

    assert validation_runner._request_headers(
        captured["session"],
        "https://target.test/check",
        captured["headers"],
    )["Authorization"] == "Bearer raw-token"


@pytest.mark.parametrize("failed_owner", ["ledger", "finding", "action_queue"])
def test_runner_reconciliation_replay_repairs_each_owner_without_duplicates(
    monkeypatch,
    tmp_path,
    failed_owner,
):
    summary, queue_path, key = _runner_reconciliation_fixture(monkeypatch, tmp_path)
    owner_functions = {
        "ledger": "_sync_evidence_ledger",
        "finding": "_sync_finding_status",
        "action_queue": "_sync_action_queue",
    }
    owner_name = owner_functions[failed_owner]
    original = getattr(validation_runner, owner_name)
    if failed_owner == "ledger":
        ledger_path(tmp_path, summary["target"]).unlink()

    monkeypatch.setattr(
        validation_runner,
        owner_name,
        lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError(f"{failed_owner} fault")),
    )
    partial = validation_runner.sync_runner_artifacts(summary, repo_root=tmp_path)
    assert partial["status"] == "partial"
    assert partial[failed_owner]["status"] == "error"

    findings_dir = tmp_path / "findings" / key
    assert (findings_dir / "findings.json").is_file() is (failed_owner != "finding")
    assert ledger_path(tmp_path, summary["target"]).is_file() is (failed_owner != "ledger")
    interrupted_queue = json.loads(queue_path.read_text(encoding="utf-8"))["actions"][0]
    assert interrupted_queue["status"] == ("queued" if failed_owner == "action_queue" else "candidate")

    monkeypatch.setattr(validation_runner, owner_name, original)
    recovered = validation_runner.sync_runner_artifacts(summary, repo_root=tmp_path)
    replay = validation_runner.sync_runner_artifacts(summary, repo_root=tmp_path)

    finding = json.loads((findings_dir / "findings.json").read_text(encoding="utf-8"))["findings"][0]
    events = (findings_dir / "mutation-events.jsonl").read_text(encoding="utf-8").splitlines()
    queue = json.loads(queue_path.read_text(encoding="utf-8"))["actions"][0]
    rows = ledger_path(tmp_path, summary["target"]).read_text(encoding="utf-8").splitlines()

    assert recovered["status"] == "updated"
    assert replay["status"] == "deduplicated"
    assert len(rows) == 1
    assert len(events) == 1
    assert finding["runner_operation_id"] == summary["operation_id"]
    assert queue["metadata"]["runner_operation_id"] == summary["operation_id"]
    assert queue["attempts"] == 1


def test_runner_replay_repairs_finding_event_missing_after_canonical_write(monkeypatch, tmp_path):
    original_append = finding_index._append_mutation_events
    failed = {"value": False}

    def fail_once(path, events):
        if not failed["value"]:
            failed["value"] = True
            raise OSError("mutation event fault")
        return original_append(path, events)

    monkeypatch.setattr(finding_index, "_append_mutation_events", fail_once)
    summary, queue_path, key = _runner_reconciliation_fixture(monkeypatch, tmp_path)
    monkeypatch.setattr(finding_index, "_append_mutation_events", original_append)

    recovered = validation_runner.sync_runner_artifacts(summary, repo_root=tmp_path)
    replay = validation_runner.sync_runner_artifacts(summary, repo_root=tmp_path)
    findings_dir = tmp_path / "findings" / key
    finding = json.loads((findings_dir / "findings.json").read_text(encoding="utf-8"))["findings"][0]
    events = (findings_dir / "mutation-events.jsonl").read_text(encoding="utf-8").splitlines()
    queue = json.loads(queue_path.read_text(encoding="utf-8"))["actions"][0]

    assert recovered["status"] == "updated"
    assert replay["status"] == "deduplicated"
    assert len(events) == 1
    assert finding_index.verify_finding_owner_provenance(
        findings_dir,
        finding,
        target=summary["target"],
    )["valid"] is True
    assert queue["metadata"]["runner_operation_id"] == summary["operation_id"]


def test_request_once_bounds_response_and_records_hash(monkeypatch):
    class FakeResponse:
        status = 200
        reason = "OK"
        headers = {"Content-Type": "text/plain", "Content-Length": "6"}

        def geturl(self):
            return "https://target.test/api"

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def read(self, amount):
            assert amount == 5
            return b"abcde"

    class FakeOpener:
        def open(self, request, timeout):
            return FakeResponse()

    monkeypatch.setattr(validation_runner.urllib.request, "build_opener", lambda *args: FakeOpener())
    response = validation_runner.request_once(
        target="target.test",
        url="https://target.test/api",
        max_body_bytes=4,
    )
    snapshot = validation_runner._response_snapshot(response)

    assert response["body"] == "abcd"
    assert response["body_retained_bytes"] == 4
    assert response["body_observed_bytes"] == 6
    assert response["body_truncated"] is True
    assert snapshot["body_truncated"] is True
    assert snapshot["body_sha256"] == validation_runner.hashlib.sha256(b"abcd").hexdigest()
    assert "body_preview" not in snapshot


def test_state_changing_without_redline_fails_before_request(monkeypatch, tmp_path):
    called = False

    def fake_request_once(**kwargs):
        nonlocal called
        called = True
        return _fake_response(kwargs["url"], body="MARKER")

    monkeypatch.setattr(validation_runner, "request_once", fake_request_once)
    with pytest.raises(ValueError, match="requires --redline-checked"):
        validation_runner.run_marker_replay(
            repo_root=tmp_path,
            target="target.test",
            url="https://target.test/submit",
            expect_marker="MARKER",
            method="POST",
            state_changing=True,
            redline_checked=False,
        )
    assert called is False


@pytest.mark.parametrize("state_changing", [None, False])
def test_patch_without_explicit_state_fact_is_not_redline_blocked(
    monkeypatch, tmp_path, state_changing
):
    called = False

    def fake_request_once(**kwargs):
        nonlocal called
        called = True
        return _fake_response(kwargs["url"], body="MARKER")

    monkeypatch.setattr(validation_runner, "request_once", fake_request_once)
    summary = validation_runner.run_marker_replay(
        repo_root=tmp_path,
        target="target.test",
        url="https://target.test/submit",
        expect_marker="MARKER",
        method="PATCH",
        state_changing=state_changing,
        no_ledger=True,
    )
    assert called is True
    assert summary["state_changing"] is state_changing
    assert summary["redline_checked"] is False


def test_post_defaults_to_unknown_state_and_private_unique_runs(monkeypatch, tmp_path):
    secret = "SECRET_VALIDATION_FIXTURE"
    monkeypatch.setattr(
        validation_runner,
        "request_once",
        lambda **kwargs: _fake_response(kwargs["url"], body=f"result={secret}"),
    )

    summaries = [
        validation_runner.run_marker_replay(
            repo_root=tmp_path,
            target="target.test",
            url=f"https://target.test/submit?token={secret}",
            expect_marker=secret,
            method="POST",
            headers={"Authorization": f"Bearer {secret}"},
            body=secret,
            finding_id="MARKER-PRIVATE",
            no_ledger=True,
        )
        for _ in range(2)
    ]

    assert summaries[0]["summary_path"] != summaries[1]["summary_path"]
    assert summaries[0]["operation_id"] == summaries[1]["operation_id"]
    assert all(item["state_changing"] is None for item in summaries)
    assert all(item["redline_checked"] is False for item in summaries)
    public_text = "\n".join(
        path.read_text(encoding="utf-8", errors="ignore")
        for path in (tmp_path / "evidence").rglob("*")
        if path.is_file()
    )
    private_files = [path for path in (tmp_path / ".private").rglob("*") if path.is_file()]
    private_bytes = b"\n".join(path.read_bytes() for path in private_files)

    assert secret not in public_text
    assert secret.encode() in private_bytes
    assert private_files
    assert all(path.stat().st_mode & 0o777 == 0o600 for path in private_files)
    assert all(
        path.stat().st_mode & 0o777 == 0o700
        for path in (tmp_path / ".private").rglob("*")
        if path.is_dir()
    )


def _boundary_pair_spec(active: str, baseline_header: dict, variant_header: dict) -> dict:
    return {
        "schema_version": 1,
        "baseline_request": {
            "method": "GET",
            "url": "https://target.test/api/Users",
            "headers": baseline_header,
        },
        "variant_request": {
            "method": "GET",
            "url": "https://target.test/api/Users",
            "headers": variant_header,
        },
        "active_dimension": active,
        "evidence_shape": "request_diff",
        "classifier": "authz",
        "repeat": 2,
    }


def test_request_diff_credential_boundary_dimension_promotes_without_shape_detector(monkeypatch, tmp_path):
    def fake_request_once(**kwargs):
        headers = kwargs.get("headers") or {}
        if "Bearer admin" in str(headers.get("Authorization", "")):
            return _fake_response(kwargs["url"], body='{"users": ["a", "b"]}')
        return _fake_response(kwargs["url"], status=401, body="unauthorized")

    monkeypatch.setattr(validation_runner, "request_once", fake_request_once)
    spec = _boundary_pair_spec(
        "header:authorization",
        {},
        {"Authorization": "Bearer admin"},
    )
    # Declared expectation: the credential dimension differentiates the
    # requesters (status delta observed). Reconciliation, not a vocabulary.
    spec["expected"] = ["status_delta"]
    summary = validation_runner.run_request_diff(
        repo_root=tmp_path,
        target="https://target.test",
        request_spec=spec,
    )

    assert summary["result"] == "tested_finding"
    assert summary["candidate_ready"] is True
    assert summary["expected_check"]["unmet"] == []
    led = summary.get("ledger_record") or {}
    assert led.get("result") == "tested_finding"

    # Undeclared, the same pair keeps the legacy conservative outcome.
    spec.pop("expected")
    undeclared = validation_runner.run_request_diff(
        repo_root=tmp_path,
        target="https://target.test",
        request_spec=spec,
    )
    assert undeclared["result"] == "candidate"


def test_request_diff_declared_boundary_without_actual_difference_stays_candidate(monkeypatch, tmp_path):
    def fake_request_once(**kwargs):
        headers = kwargs.get("headers") or {}
        # Both requests carry the same declared credential, but the response
        # differs for an unrelated reason (still material).
        marker = "Bearer same"
        body = (
            '{"users": ["a"], "note": "one short body"}'
            if str(headers.get("Authorization", "")).endswith(marker)
            else '{"users": ["a"], "note": "a materially longer unrelated response body"}'
        )
        return _fake_response(kwargs["url"], body=body)

    monkeypatch.setattr(validation_runner, "request_once", fake_request_once)
    spec = {
        "schema_version": 1,
        "baseline_request": {
            "method": "GET",
            "url": "https://target.test/api/Users",
            "headers": {"Authorization": "Bearer same", "X-Tag": "one"},
        },
        "variant_request": {
            "method": "GET",
            "url": "https://target.test/api/Users",
            "headers": {"Authorization": "Bearer same", "X-Tag": "two"},
        },
        "active_dimension": "header:authorization",
        "evidence_shape": "request_diff",
        "classifier": "authz",
        "repeat": 2,
    }
    # The spec validator enforces that the declared active dimension is the
    # one that actually changed; a mismatched declaration is a hard input
    # error and is rejected before any replay rather than silently re-labeled.
    with pytest.raises(validation_runner.RequestPairError):
        validation_runner.run_request_diff(
            repo_root=tmp_path,
            target="https://target.test",
            request_spec=spec,
        )


def test_request_diff_non_boundary_material_diff_stays_candidate(monkeypatch, tmp_path):
    def fake_request_once(**kwargs):
        body = '{"page": 1, "items": []}' if "page=1" in kwargs["url"] else '{"page": 2, "items": ["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]}'
        return _fake_response(kwargs["url"], body=body)

    monkeypatch.setattr(validation_runner, "request_once", fake_request_once)
    spec = {
        "schema_version": 1,
        "baseline_request": {"method": "GET", "url": "https://target.test/search?page=1"},
        "variant_request": {"method": "GET", "url": "https://target.test/search?page=2"},
        "active_dimension": "query:page",
        "evidence_shape": "request_diff",
        "classifier": "authz",
        "repeat": 2,
    }
    summary = validation_runner.run_request_diff(
        repo_root=tmp_path,
        target="https://target.test",
        request_spec=spec,
    )

    assert summary["result"] == "candidate"
    assert summary["candidate_ready"] is False


def test_request_diff_sqli_material_diff_without_strong_shape_is_candidate_not_clean(monkeypatch, tmp_path):
    """A material diff must never fall to tested_clean just because the
    classifier label is sqli but the shape detector did not confirm."""

    def fake_request_once(**kwargs):
        # Material length delta but no DB-error/count-expansion/field-added
        # shape: the SQLi detector stays quiet, so a bare material diff must
        # not be promoted and must not fall to tested_clean either.
        body = '{"result": "no rows for this very ordinary baseline query response"}' if "zzz" not in kwargs["url"] else '{"result": "still no rows but a materially much longer ordinary response body padding padding padding"}'
        return _fake_response(kwargs["url"], body=body)

    monkeypatch.setattr(validation_runner, "request_once", fake_request_once)
    spec = {
        "schema_version": 1,
        "baseline_request": {"method": "GET", "url": "https://target.test/search?q=apple"},
        "variant_request": {"method": "GET", "url": "https://target.test/search?q=zzz"},
        "active_dimension": "query:q",
        "evidence_shape": "request_diff",
        "classifier": "sqli",
        "repeat": 2,
    }
    summary = validation_runner.run_request_diff(
        repo_root=tmp_path,
        target="https://target.test",
        request_spec=spec,
    )

    assert summary["result"] == "candidate"
    assert summary["candidate_ready"] is False


def test_request_diff_credential_pair_both_sides_succeed_stays_candidate_not_clean(monkeypatch, tmp_path):
    """Anonymous 200 + denied-credential 200 with identical bodies means the
    endpoint performs no identity check. That pair must stay a reviewable
    candidate; recording tested_clean would invert the meaning."""

    def fake_request_once(**kwargs):
        body = '{"config": {"chatbot": "shared"}}'
        return _fake_response(kwargs["url"], body=body)

    monkeypatch.setattr(validation_runner, "request_once", fake_request_once)
    spec = {
        "schema_version": 1,
        "baseline_request": {"method": "GET", "url": "https://target.test/rest/admin/application-configuration"},
        "variant_request": {
            "method": "GET",
            "url": "https://target.test/rest/admin/application-configuration",
            "headers": {"Authorization": "Bearer denied"},
        },
        "active_dimension": "header:Authorization",
        "evidence_shape": "auth_boundary",
        "classifier": "authz_access",
        "vuln_class": "Authz",
        "repeat": 1,
    }
    summary = validation_runner.run_request_diff(
        repo_root=tmp_path,
        target="https://target.test",
        request_spec=spec,
    )

    assert summary["result"] == "candidate", (
        "identical 200 responses across a credential boundary are the evidence "
        "of a missing identity check, not a clean auth boundary"
    )


def test_request_diff_missing_auth_expect_auth_pair_promotes_to_tested_finding(monkeypatch, tmp_path):
    """Identical 200s across a credential boundary plus an explicit
    expect_auth declaration promote through the missing-auth route: the
    runner asserts the fact (the endpoint does not differentiate requesters)
    and leaves the intent judgment to review."""

    def fake_request_once(**kwargs):
        body = '{"config": {"chatbot": "shared"}}'
        return _fake_response(kwargs["url"], body=body)

    monkeypatch.setattr(validation_runner, "request_once", fake_request_once)
    spec = {
        "schema_version": 1,
        "baseline_request": {"method": "GET", "url": "https://target.test/rest/admin/application-configuration"},
        "variant_request": {
            "method": "GET",
            "url": "https://target.test/rest/admin/application-configuration",
            "headers": {"Authorization": "Bearer denied"},
        },
        "active_dimension": "header:Authorization",
        "evidence_shape": "auth_boundary",
        "classifier": "authz_access",
        "vuln_class": "Authz",
        "expect_auth": True,
        "repeat": 1,
    }
    summary = validation_runner.run_request_diff(
        repo_root=tmp_path,
        target="https://target.test",
        request_spec=spec,
    )

    assert summary["result"] == "tested_finding"
    assert summary["candidate_ready"] is True
    assert summary["vuln_class"] == "Authz"
    rubric = summary.get("evidence_rubric") or {}
    assert rubric.get("status") == "candidate-ready"
    ai_next = summary.get("ai_next") or {}
    assert "remaining judgment" in str(ai_next.get("hypothesis", ""))
    spec_view = summary.get("request_pair") or {}
    assert spec_view.get("expect_auth") is True
    assert summary["expected_check"]["declared"] == ["identical_success_pair"]
    assert summary["expected_check"]["unmet"] == []
    led = summary.get("ledger_record") or {}
    assert led.get("result") == "tested_finding"


def test_request_diff_expect_auth_trusts_arbitrary_declared_dimension(monkeypatch, tmp_path):
    """When the AI declares expect_auth, the declared active dimension IS the
    credential boundary. The runner must not second-guess the header name
    against a fixed well-known vocabulary: custom auth headers
    (X-Internal-Auth, X-Company-Token, ...) promote exactly like
    Authorization. The vocabulary only serves the undeclared default path."""

    def fake_request_once(**kwargs):
        body = '{"internal": {"config": "shared"}}'
        return _fake_response(kwargs["url"], body=body)

    monkeypatch.setattr(validation_runner, "request_once", fake_request_once)
    spec = {
        "schema_version": 1,
        "baseline_request": {"method": "GET", "url": "https://target.test/internal/config"},
        "variant_request": {
            "method": "GET",
            "url": "https://target.test/internal/config",
            "headers": {"X-Internal-Auth": "Bearer denied"},
        },
        "active_dimension": "header:X-Internal-Auth",
        "evidence_shape": "auth_boundary",
        "classifier": "authz_access",
        "vuln_class": "Authz",
        "expect_auth": True,
        "repeat": 1,
    }
    summary = validation_runner.run_request_diff(
        repo_root=tmp_path,
        target="https://target.test",
        request_spec=spec,
    )

    assert summary["result"] == "tested_finding"
    assert summary["candidate_ready"] is True

    # Without the declaration the same custom-header pair has no
    # AI-asserted boundary meaning: an ordinary header value that does not
    # change the response is clean for that dimension (same semantics as an
    # ineffective probe). The well-known vocabulary (Authorization & co.)
    # keeps its extra undeclared-candidate conservatism.
    spec.pop("expect_auth")
    summary_undeclared = validation_runner.run_request_diff(
        repo_root=tmp_path,
        target="https://target.test",
        request_spec=spec,
    )
    assert summary_undeclared["result"] == "tested_clean"
    assert summary_undeclared["candidate_ready"] is False


def test_request_diff_expected_declaration_is_category_agnostic(monkeypatch, tmp_path):
    """The same error-marker declaration promotes a NoSQLi pair and a
    SQLi pair through the identical channel — and would promote an SSTI or
    command-injection pair the same way. classifier is metadata only."""

    def fake_request_once(**kwargs):
        body = kwargs["body"]
        query = body.get("q", "") if isinstance(body, dict) else ""
        if query != "apple":
            return _fake_response(
                kwargs["url"], status=500, body='{"error": "MongoError: CastError in query"}'
            )
        return _fake_response(kwargs["url"], body='{"data": []}')

    monkeypatch.setattr(validation_runner, "request_once", fake_request_once)
    for classifier, vuln_class, variant_query in (
        ("nosqli", "NoSQLi", '{"$ne": null}'),
        ("sqli", "SQLi", "' || true || '"),
        ("ssti", "RCE", "{{7*7}}"),
    ):
        spec = {
            "schema_version": 1,
            "baseline_request": {
                "method": "POST",
                "url": "https://target.test/api/search",
                "headers": {"Content-Type": "application/json"},
                "body": {"q": "apple"},
            },
            "variant_request": {
                "method": "POST",
                "url": "https://target.test/api/search",
                "headers": {"Content-Type": "application/json"},
                "body": {"q": variant_query},
            },
            "active_dimension": "body:/q",
            "evidence_shape": "request_diff",
            "classifier": classifier,
            "vuln_class": vuln_class,
            "expected": ["error_marker_variant_only"],
            "repeat": 1,
        }
        summary = validation_runner.run_request_diff(
            repo_root=tmp_path,
            target="https://target.test",
            request_spec=spec,
            finding_id=f"EXPECTED-AGNOSTIC-{classifier}",
        )
        assert summary["result"] == "tested_finding", classifier
        assert summary["candidate_ready"] is True
        assert summary["expected_check"]["unmet"] == []


def test_request_diff_declared_expectation_contradicted_falls_to_candidate(monkeypatch, tmp_path):
    """Anti-forgery: the AI declares a count expansion, the wire shows none —
    the declaration is rejected, the unmet fact is archived, and the result
    never becomes tested_finding on an unconfirmed declaration."""

    def fake_request_once(**kwargs):
        return _fake_response(kwargs["url"], body='{"data": [{"id": 1}]}')

    monkeypatch.setattr(validation_runner, "request_once", fake_request_once)
    spec = {
        "schema_version": 1,
        "baseline_request": {"method": "GET", "url": "https://target.test/search?q=apple"},
        "variant_request": {"method": "GET", "url": "https://target.test/search?q=zzz"},
        "active_dimension": "query:q",
        "evidence_shape": "request_diff",
        "classifier": "sqli",
        "expected": ["count_delta_positive", "fields_added"],
        "repeat": 1,
    }
    summary = validation_runner.run_request_diff(
        repo_root=tmp_path,
        target="https://target.test",
        request_spec=spec,
    )

    assert summary["result"] == "candidate"
    assert summary["candidate_ready"] is False
    assert summary["expected_check"]["unmet"] == ["count_delta_positive", "fields_added"]
    assert summary["expected_check"]["observed"] == {
        "count_delta_positive": False,
        "fields_added": False,
    }


def test_request_diff_unknown_expected_fact_name_is_rejected(tmp_path):
    """A typo in a declared fact name is a hard input error, never silently
    ignored — a silently-dropped declaration would silently demote the pair."""

    spec = {
        "schema_version": 1,
        "baseline_request": {"method": "GET", "url": "https://target.test/search?q=apple"},
        "variant_request": {"method": "GET", "url": "https://target.test/search?q=zzz"},
        "active_dimension": "query:q",
        "classifier": "sqli",
        "expected": ["count_delta_postive"],  # typo
        "repeat": 1,
    }
    with pytest.raises(validation_runner.RequestPairError, match="unknown fact name"):
        validation_runner.run_request_diff(
            repo_root=tmp_path,
            target="https://target.test",
            request_spec=spec,
        )


def test_request_diff_expected_note_and_digest_distinction(tmp_path):
    """expected/expected_note ride the normalized spec: declaring an
    expectation makes the replay a distinct operation, and the note is
    archived verbatim without being interpreted."""

    base = {
        "schema_version": 1,
        "baseline_request": {"method": "GET", "url": "https://target.test/a"},
        "variant_request": {"method": "GET", "url": "https://target.test/b"},
        "active_dimension": "path:",
        "classifier": "generic",
    }
    # path: dimension needs different paths
    base["baseline_request"]["url"] = "https://target.test/users/1"
    base["variant_request"]["url"] = "https://target.test/users/2"
    base["active_dimension"] = "path:/users/1"
    normalized = validate_request_pair(base)
    assert normalized["expected"] == []
    assert normalized["expected_note"] == ""

    declared = dict(base, expected=["material_diff_any"], expected_note="owner swap should change the row")
    normalized_declared = validate_request_pair(declared)
    assert normalized_declared["expected"] == ["material_diff_any"]
    assert normalized_declared["expected_note"] == "owner swap should change the row"

    assert request_pair_digest(declared) != request_pair_digest(base)


def test_request_diff_missing_auth_pair_with_3xx_both_sides_promotes(monkeypatch, tmp_path):
    """The success class is 2xx/3xx: redirects on both sides still count as
    'the endpoint answered both requesters' for the missing-auth route."""

    def fake_request_once(**kwargs):
        return _fake_response(kwargs["url"], status=302, body="")

    monkeypatch.setattr(validation_runner, "request_once", fake_request_once)
    spec = {
        "schema_version": 1,
        "baseline_request": {"method": "GET", "url": "https://target.test/api/users"},
        "variant_request": {
            "method": "GET",
            "url": "https://target.test/api/users",
            "headers": {"Cookie": "session=denied"},
        },
        "active_dimension": "cookie:session",
        "evidence_shape": "auth_boundary",
        "classifier": "authz_access",
        "vuln_class": "Authz",
        "expect_auth": True,
        "repeat": 1,
    }
    summary = validation_runner.run_request_diff(
        repo_root=tmp_path,
        target="https://target.test",
        request_spec=spec,
    )

    assert summary["result"] == "tested_finding"
    assert summary["candidate_ready"] is True


def test_request_diff_missing_auth_declaration_alone_does_not_override_held_boundary(monkeypatch, tmp_path):
    """expect_auth is a declaration, not a verdict: when the boundary held
    (both sides rejected identically) the declared identical-success fact is
    CONTRADICTED on the wire, so the pair falls to candidate with the unmet
    fact archived — the declaration never manufactures a finding, and the
    contradiction is surfaced instead of silently cleaned."""

    def fake_request_once(**kwargs):
        return _fake_response(kwargs["url"], status=401, body='{"error": "unauthorized"}')

    monkeypatch.setattr(validation_runner, "request_once", fake_request_once)
    spec = {
        "schema_version": 1,
        "baseline_request": {"method": "GET", "url": "https://target.test/api/users"},
        "variant_request": {
            "method": "GET",
            "url": "https://target.test/api/users",
            "headers": {"Cookie": "session=denied"},
        },
        "active_dimension": "cookie:session",
        "evidence_shape": "auth_boundary",
        "classifier": "authz_access",
        "vuln_class": "Authz",
        "expect_auth": True,
        "repeat": 1,
    }
    summary = validation_runner.run_request_diff(
        repo_root=tmp_path,
        target="https://target.test",
        request_spec=spec,
    )

    assert summary["result"] == "candidate"
    assert summary["candidate_ready"] is False
    assert summary["expected_check"]["declared"] == ["identical_success_pair"]
    assert summary["expected_check"]["unmet"] == ["identical_success_pair"]


def test_request_diff_credential_pair_both_sides_rejected_is_clean(monkeypatch, tmp_path):
    """Anonymous 401 + invalid-credential 401 with identical bodies means the
    auth boundary held; that pair is a genuine tested_clean."""

    def fake_request_once(**kwargs):
        return _fake_response(kwargs["url"], status=401, body='{"error": "unauthorized"}')

    monkeypatch.setattr(validation_runner, "request_once", fake_request_once)
    spec = {
        "schema_version": 1,
        "baseline_request": {"method": "GET", "url": "https://target.test/api/users"},
        "variant_request": {
            "method": "GET",
            "url": "https://target.test/api/users",
            "headers": {"Authorization": "Bearer denied"},
        },
        "active_dimension": "header:Authorization",
        "evidence_shape": "auth_boundary",
        "classifier": "authz_access",
        "vuln_class": "Authz",
        "repeat": 1,
    }
    summary = validation_runner.run_request_diff(
        repo_root=tmp_path,
        target="https://target.test",
        request_spec=spec,
    )

    assert summary["result"] == "tested_clean"
