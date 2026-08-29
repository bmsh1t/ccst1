from __future__ import annotations

import json

import pytest

from tools.action_queue import (
    add_manual_action,
    claim_next_action,
    ingest_checkpoint,
    load_queue,
    resolve_action,
    save_queue,
)
from tools.autopilot_state import load_closure_projection
from tools.checkpoint import _attach_activation_context, _capability_chain_review_item
from tools.coverage_matrix import save_matrix
from tools.validation_runner import _runner_observed_difference, _sync_action_queue


TARGET = "target.test"
ENDPOINT = "https://target.test/api/export?order_id=42"
ROUTE = {
    "skill_id": "web2-vuln-classes",
    "skill_path": "skills/web2-vuln-classes/SKILL.md",
    "reason": "authorization and workflow evidence converge on one input",
    "required_dimensions": ["parameter", "sibling", "workflow", "chain"],
}
ALT_ROUTE = {
    "skill_id": "triage-validation",
    "skill_path": "skills/triage-validation/SKILL.md",
    "reason": "stored validation route",
    "required_dimensions": ["baseline", "variant", "impact", "replay"],
}
CARD = "knowledge/cards/api-idor.md"


def _write_json(path, payload: dict) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload), encoding="utf-8")
    return str(path)


def _activation_context(evidence_ref: str) -> dict:
    return {
        "activation_required": True,
        "skill_route": ROUTE,
        "route_required": True,
        "knowledge_refs": [CARD],
        "evidence_ref": evidence_ref,
        "baseline_ref": evidence_ref,
        "hypothesis_seed": "order export may cross an object boundary",
        "max_hypothesis_actions_cap": 3,
        "endpoint": ENDPOINT,
        "method": "POST",
        "input_boundary": "order_id",
    }


def _activation() -> dict:
    return {
        "depth_contract_version": 1,
        "hypothesis_id": "H-export-boundary",
        "family": "target-specific composite authorization",
        "technique": "cross-workflow object substitution",
        "active_dimension": "parameter",
        "expected_learning": "whether the object selector reaches another tenant",
        "kill_condition": "two controlled identities and the sibling workflow show no boundary change",
        "risk_tier": "high",
        "max_hypothesis_actions": 3,
        "selected_knowledge_refs": [CARD],
        "decision_reason": "browser and source evidence expose the same privileged export input",
    }


def _runner_summary(tmp_path, operation: str, observed: str) -> dict:
    relative = f"evidence/{TARGET}/validation/{operation}/summary.json"
    _write_json(tmp_path / relative, {"operation_id": operation, "observed": observed})
    return {
        "target": TARGET,
        "url": ENDPOINT,
        "lane": "marker_replay",
        "result": "tested_clean",
        "summary_path": relative,
        "operation_id": operation,
        "generated_at": f"2026-08-11T00:00:0{operation[-1]}Z",
        "observed_difference": observed,
    }


def _queued_depth_action(tmp_path, *, context: dict | None = None):
    baseline = f"evidence/{TARGET}/correlation/baseline.json"
    _write_json(tmp_path / baseline, {"status": 200})
    added = add_manual_action(
        tmp_path,
        target=TARGET,
        action_type="validation",
        evidence="Target-owned export evidence",
        next_question="Does the object selector cross the boundary?",
        action="Replay one controlled object substitution.",
        metadata=context if context is not None else _activation_context(baseline),
    )
    return added["queue"]["actions"][0]["id"], tmp_path / "state" / TARGET / "action_queue.json"


def _observed_depth_action(tmp_path) -> str:
    action_id, _queue_path = _queued_depth_action(tmp_path)
    claim_next_action(tmp_path, TARGET, action_id=action_id, metadata=_activation())
    synced = _sync_action_queue(
        _runner_summary(tmp_path, "operation-1", "one stable controlled comparison"),
        repo_root=tmp_path,
    )
    assert synced["status"] == "updated"
    return action_id


@pytest.mark.parametrize(
    ("field", "value"),
    [
        (
            "last_outcome",
            {
                "status": "tested_clean",
                "summary_ref": f"evidence/{TARGET}/correlation/baseline.json",
                "evidence_ref": f"evidence/{TARGET}/correlation/baseline.json",
                "observed_difference": "fabricated controlled difference",
                "operation_id": "fabricated-operation",
                "at": "2026-08-11T00:00:01Z",
            },
        ),
        ("tested_dimensions", ["parameter"]),
        ("runner_operation_id", "fabricated-operation"),
    ],
)
def test_versioned_claim_rejects_runner_observation_fields_without_writing(tmp_path, field, value):
    action_id, queue_path = _queued_depth_action(tmp_path)
    before = queue_path.read_bytes()
    activation = {**_activation(), field: value}

    with pytest.raises(ValueError, match="Runner-owned observation fields"):
        claim_next_action(tmp_path, TARGET, action_id=action_id, metadata=activation)

    assert queue_path.read_bytes() == before
    queued = load_queue(tmp_path, TARGET)["actions"][0]
    assert queued["status"] == "queued"
    assert field not in queued["metadata"]


def test_versioned_claim_cannot_disable_required_activation(tmp_path):
    action_id, queue_path = _queued_depth_action(tmp_path)
    before = queue_path.read_bytes()

    with pytest.raises(ValueError, match="cannot override activation_required"):
        claim_next_action(
            tmp_path,
            TARGET,
            action_id=action_id,
            metadata={"activation_required": False},
        )

    assert queue_path.read_bytes() == before
    assert load_queue(tmp_path, TARGET)["actions"][0]["status"] == "queued"


def test_versioned_claim_reports_missing_stored_cap_without_writing(tmp_path):
    baseline = f"evidence/{TARGET}/correlation/baseline.json"
    context = _activation_context(baseline)
    context.pop("max_hypothesis_actions_cap")
    action_id, queue_path = _queued_depth_action(tmp_path, context=context)
    before = queue_path.read_bytes()

    with pytest.raises(ValueError, match="AQ-0001 lacks max_hypothesis_actions_cap"):
        claim_next_action(tmp_path, TARGET, action_id=action_id, metadata=_activation())

    assert queue_path.read_bytes() == before
    assert load_queue(tmp_path, TARGET)["actions"][0]["status"] == "queued"


def test_versioned_claim_reports_all_missing_activation_fields_without_writing(tmp_path):
    baseline = f"evidence/{TARGET}/correlation/baseline.json"
    context = _activation_context(baseline)
    context.pop("input_boundary")
    action_id, queue_path = _queued_depth_action(tmp_path, context=context)
    before = queue_path.read_bytes()
    activation = _activation()
    activation.pop("decision_reason")

    with pytest.raises(ValueError, match="decision_reason, input_boundary"):
        claim_next_action(tmp_path, TARGET, action_id=action_id, metadata=activation)

    assert queue_path.read_bytes() == before
    assert load_queue(tmp_path, TARGET)["actions"][0]["status"] == "queued"


def test_versioned_claim_cannot_override_queue_owned_cap(tmp_path):
    action_id, queue_path = _queued_depth_action(tmp_path)
    before = queue_path.read_bytes()

    with pytest.raises(ValueError, match="cannot override Queue-owned max_hypothesis_actions_cap"):
        claim_next_action(
            tmp_path,
            TARGET,
            action_id=action_id,
            metadata={**_activation(), "max_hypothesis_actions_cap": 100},
        )

    assert queue_path.read_bytes() == before
    assert load_queue(tmp_path, TARGET)["actions"][0]["metadata"]["max_hypothesis_actions_cap"] == 3


def test_versioned_claim_accepts_redundant_matching_stored_cap(tmp_path):
    action_id, _queue_path = _queued_depth_action(tmp_path)

    claimed = claim_next_action(
        tmp_path,
        TARGET,
        action_id=action_id,
        metadata={**_activation(), "max_hypothesis_actions_cap": 3},
    )

    assert claimed["status"] == "running"
    assert claimed["metadata"]["max_hypothesis_actions_cap"] == 3


def test_versioned_claim_reports_invalid_stored_cap_without_writing(tmp_path):
    baseline = f"evidence/{TARGET}/correlation/baseline.json"
    context = {**_activation_context(baseline), "max_hypothesis_actions_cap": "three"}
    action_id, queue_path = _queued_depth_action(tmp_path, context=context)
    before = queue_path.read_bytes()

    with pytest.raises(ValueError, match="AQ-0001 has invalid max_hypothesis_actions_cap"):
        claim_next_action(tmp_path, TARGET, action_id=action_id, metadata=_activation())

    assert queue_path.read_bytes() == before
    assert load_queue(tmp_path, TARGET)["actions"][0]["status"] == "queued"


def test_versioned_claim_reports_requested_cap_above_stored_cap_without_writing(tmp_path):
    action_id, queue_path = _queued_depth_action(tmp_path)
    before = queue_path.read_bytes()

    with pytest.raises(ValueError, match="exceeds the stored hypothesis action cap"):
        claim_next_action(
            tmp_path,
            TARGET,
            action_id=action_id,
            metadata={**_activation(), "max_hypothesis_actions": 4},
        )

    assert queue_path.read_bytes() == before
    assert load_queue(tmp_path, TARGET)["actions"][0]["status"] == "queued"


def test_versioned_candidate_is_reclaimed_for_runner_replay(tmp_path):
    action_id, _queue_path = _queued_depth_action(tmp_path)
    claim_next_action(tmp_path, TARGET, action_id=action_id, metadata=_activation())
    queue = load_queue(tmp_path, TARGET)
    queue["actions"][0]["status"] = "candidate"
    save_queue(tmp_path, TARGET, queue)

    reclaimed = claim_next_action(tmp_path, TARGET, action_id=action_id, metadata=_activation())

    assert reclaimed["previous_status"] == "candidate"
    assert reclaimed["claim_status"] == "reclaimed"
    assert reclaimed["status"] == "running"
    assert load_queue(tmp_path, TARGET)["actions"][0]["attempts"] == 2


def test_special_candidate_is_not_promoted_to_runner(tmp_path):
    added = add_manual_action(
        tmp_path,
        target=TARGET,
        action_type="oast-callback",
        evidence="callback candidate",
        next_question="Can the callback be correlated?",
        action="Poll the callback artifact.",
        source="oast_listen",
    )
    action_id = added["queue"]["actions"][0]["id"]
    queue = load_queue(tmp_path, TARGET)
    queue["actions"][0]["status"] = "candidate"
    save_queue(tmp_path, TARGET, queue)

    selected = claim_next_action(tmp_path, TARGET, action_id=action_id)

    assert selected["previous_status"] == "candidate"
    assert selected["claim_status"] == "selected"
    assert selected["status"] == "candidate"


def test_claimed_first_skill_route_does_not_require_override_reason(tmp_path):
    baseline = f"evidence/{TARGET}/correlation/baseline.json"
    context = _activation_context(baseline)
    context.pop("skill_route")
    context.pop("route_required")
    action_id, _queue_path = _queued_depth_action(tmp_path, context=context)
    activation = {**_activation(), "skill_route": ROUTE}

    claimed = claim_next_action(tmp_path, TARGET, action_id=action_id, metadata=activation)

    assert claimed["metadata"]["skill_route"] == ROUTE


def test_active_dimension_outside_route_requires_explicit_override_reason(tmp_path):
    action_id, _queue_path = _queued_depth_action(tmp_path)

    with pytest.raises(ValueError, match="dimension_override_reason"):
        claim_next_action(
            tmp_path,
            TARGET,
            action_id=action_id,
            metadata={**_activation(), "active_dimension": "parser"},
        )

    claimed = claim_next_action(
        tmp_path,
        TARGET,
        action_id=action_id,
        metadata={
            **_activation(),
            "active_dimension": "parser",
            "dimension_override_reason": "the response parser is the evidence-linked boundary",
        },
    )
    assert claimed["metadata"]["active_dimension"] == "parser"
    assert "skill_override_reason" not in claimed["metadata"]


def test_claimed_skill_route_override_requires_reason(tmp_path):
    baseline = f"evidence/{TARGET}/correlation/baseline.json"
    context = {**_activation_context(baseline), "skill_route": ALT_ROUTE}
    action_id, queue_path = _queued_depth_action(tmp_path, context=context)
    activation = {**_activation(), "skill_route": ROUTE}
    before = queue_path.read_bytes()

    with pytest.raises(ValueError, match="skill_override_reason"):
        claim_next_action(tmp_path, TARGET, action_id=action_id, metadata=activation)

    assert queue_path.read_bytes() == before
    activation["skill_override_reason"] = "current target evidence supports the authorization route"
    claimed = claim_next_action(tmp_path, TARGET, action_id=action_id, metadata=activation)
    assert claimed["metadata"]["skill_route"] == ROUTE


@pytest.mark.parametrize("selection", ["missing", "empty"])
def test_versioned_claim_accepts_optional_knowledge_refs(tmp_path, selection):
    baseline = f"evidence/{TARGET}/correlation/baseline.json"
    context = {**_activation_context(baseline), "knowledge_refs": []}
    action_id, _queue_path = _queued_depth_action(tmp_path, context=context)
    activation = _activation()
    if selection == "missing":
        activation.pop("selected_knowledge_refs")
    else:
        activation["selected_knowledge_refs"] = []

    claimed = claim_next_action(
        tmp_path,
        TARGET,
        action_id=action_id,
        metadata=activation,
    )

    assert claimed["metadata"]["selected_knowledge_refs"] == []


@pytest.mark.parametrize("selected_refs", [None, CARD, [""]])
def test_versioned_claim_rejects_malformed_optional_knowledge_refs(
    tmp_path,
    selected_refs,
):
    action_id, queue_path = _queued_depth_action(tmp_path)
    activation = {**_activation(), "selected_knowledge_refs": selected_refs}
    before = queue_path.read_bytes()

    with pytest.raises(ValueError, match="list of non-empty references"):
        claim_next_action(tmp_path, TARGET, action_id=action_id, metadata=activation)

    assert queue_path.read_bytes() == before


def test_versioned_claim_requires_reason_for_unrecommended_knowledge_refs(tmp_path):
    action_id, queue_path = _queued_depth_action(tmp_path)
    other_card = "knowledge/cards/auth-access.md"
    activation = {**_activation(), "selected_knowledge_refs": [other_card, other_card]}
    before = queue_path.read_bytes()

    with pytest.raises(ValueError, match="knowledge_override_reason"):
        claim_next_action(tmp_path, TARGET, action_id=action_id, metadata=activation)

    assert queue_path.read_bytes() == before
    activation["knowledge_override_reason"] = "current evidence requires the auth boundary card"
    claimed = claim_next_action(
        tmp_path,
        TARGET,
        action_id=action_id,
        metadata=activation,
    )
    assert claimed["metadata"]["selected_knowledge_refs"] == [other_card]


def test_versioned_runner_requires_operation_id_without_writing(tmp_path):
    action_id, queue_path = _queued_depth_action(tmp_path)
    claim_next_action(tmp_path, TARGET, action_id=action_id, metadata=_activation())
    summary_ref = f"evidence/{TARGET}/validation/missing-operation/summary.json"
    _write_json(tmp_path / summary_ref, {"result": "tested_clean"})
    before = queue_path.read_bytes()

    synced = _sync_action_queue(
        {
            "target": TARGET,
            "url": ENDPOINT,
            "result": "tested_clean",
            "summary_path": summary_ref,
            "generated_at": "2026-08-11T00:00:01Z",
            "observed_difference": "no controlled body or status difference",
        },
        repo_root=tmp_path,
    )

    assert synced["status"] == "blocked"
    assert "operation_id" in synced["reason"]
    assert queue_path.read_bytes() == before


@pytest.mark.parametrize(
    "observation",
    [
        {"observed_difference": "Authorization: Bearer SECRET"},
        {"difference_summary": "Cookie: sid=SECRET"},
        {"runs": [{"summary": "Set-Cookie: sid=SECRET"}]},
        {"runs": [{"diff": {"summary": "Bearer SECRET"}}]},
        {"runs": [{"diff": {"changed": {"token": "SECRET"}}}]},
        {"observed_difference": "password=SECRET"},
        {"difference_summary": "api-key: SECRET"},
    ],
    ids=["authorization", "cookie", "set-cookie", "bearer", "token", "password", "api-key"],
)
def test_versioned_runner_rejects_credential_values_without_writing(tmp_path, observation):
    action_id, queue_path = _queued_depth_action(tmp_path)
    claim_next_action(tmp_path, TARGET, action_id=action_id, metadata=_activation())
    summary_ref = f"evidence/{TARGET}/validation/credential-value/summary.json"
    _write_json(tmp_path / summary_ref, {"operation_id": "operation-secret"})
    before = queue_path.read_bytes()
    summary = {
        "target": TARGET,
        "url": ENDPOINT,
        "result": "tested_clean",
        "summary_path": summary_ref,
        "operation_id": "operation-secret",
        "generated_at": "2026-08-11T00:00:01Z",
        **observation,
    }

    synced = _sync_action_queue(summary, repo_root=tmp_path)

    assert synced["status"] == "blocked"
    assert "credential or header values" in synced["reason"]
    assert queue_path.read_bytes() == before
    assert load_queue(tmp_path, TARGET)["actions"][0]["status"] == "running"


def test_versioned_runner_accepts_authorization_prose_and_resume_reads_observation(tmp_path):
    action_id, _queue_path = _queued_depth_action(tmp_path)
    claim_next_action(tmp_path, TARGET, action_id=action_id, metadata=_activation())

    synced = _sync_action_queue(
        _runner_summary(tmp_path, "operation-1", "no authorization difference"),
        repo_root=tmp_path,
    )
    resumed = claim_next_action(tmp_path, TARGET, action_id=action_id)

    assert synced["status"] == "updated"
    assert resumed["claim_status"] == "resumed"
    assert resumed["metadata"]["last_outcome"]["observed_difference"] == "no authorization difference"


def test_versioned_resolve_cannot_fabricate_runner_observation_fields(tmp_path):
    action_id, queue_path = _queued_depth_action(tmp_path)
    claim_next_action(tmp_path, TARGET, action_id=action_id, metadata=_activation())
    before = queue_path.read_bytes()

    with pytest.raises(ValueError, match="Runner-owned observation fields"):
        resolve_action(
            tmp_path,
            target=TARGET,
            action_id=action_id,
            status="running",
            metadata={"tested_dimensions": ["parameter"]},
        )

    assert queue_path.read_bytes() == before
    assert "tested_dimensions" not in load_queue(tmp_path, TARGET)["actions"][0]["metadata"]


def test_hidden_surface_requires_correlated_local_evidence_before_activation(tmp_path):
    browser = tmp_path / "recon" / TARGET / "browser" / "xhr.json"
    source = tmp_path / "findings" / TARGET / "source_intel" / "routes.json"
    _write_json(browser, {"url": ENDPOINT})
    context = {
        "skill_route": ROUTE,
        "knowledge_cards": [CARD],
        "hypothesis_seeds": ["export route crosses an object boundary"],
        "must_read": [
            f"recon/{TARGET}/browser/xhr.json",
            f"findings/{TARGET}/source_intel/routes.json",
        ],
    }

    one_source = [{
        "type": "evidence-convergence",
        "action": f"Cross-evidence high-value surface {ENDPOINT}: POST route",
        "command_hint": "focused replay with browser/JS/source evidence",
        "metadata": {"skill_route": ROUTE, "route_required": True},
    }]
    _attach_activation_context(one_source, repo=tmp_path, target=TARGET, context=context)
    assert "activation_required" not in one_source[0]

    _write_json(source, {"method": "POST", "route": "/api/export"})
    correlated = json.loads(json.dumps(one_source))
    _attach_activation_context(correlated, repo=tmp_path, target=TARGET, context=context)

    assert correlated[0]["activation_required"] is True
    assert len(correlated[0]["metadata"]["evidence_refs"]) == 2
    assert correlated[0]["metadata"]["method"] == "POST"


def test_activation_context_does_not_require_recommended_route_or_cards(tmp_path):
    browser = tmp_path / "recon" / TARGET / "browser" / "xhr.json"
    source = tmp_path / "findings" / TARGET / "source_intel" / "routes.json"
    _write_json(browser, {"url": ENDPOINT})
    _write_json(source, {"method": "POST", "route": "/api/export"})
    actions = [{
        "type": "evidence-convergence",
        "action": f"Cross-evidence high-value surface {ENDPOINT}: POST route",
        "command_hint": "focused replay with browser/JS/source evidence",
    }]

    _attach_activation_context(
        actions,
        repo=tmp_path,
        target=TARGET,
        context={
            "knowledge_cards": [],
            "hypothesis_seeds": ["export route crosses an object boundary"],
            "must_read": [
                f"recon/{TARGET}/browser/xhr.json",
                f"findings/{TARGET}/source_intel/routes.json",
            ],
        },
    )

    metadata = actions[0]["metadata"]
    assert actions[0]["activation_required"] is True
    assert metadata["knowledge_refs"] == []
    assert metadata["max_hypothesis_actions_cap"] == 4
    assert metadata["baseline_ref"] == f"recon/{TARGET}/browser/xhr.json"
    assert "hypothesis_seed" not in metadata
    assert "skill_route" not in metadata
    assert "route_required" not in metadata


def test_surface_review_remains_versionless_even_with_replay_draft(tmp_path):
    browser = tmp_path / "recon" / TARGET / "browser" / "xhr.json"
    source = tmp_path / "findings" / TARGET / "source_intel" / "routes.json"
    _write_json(browser, {"url": ENDPOINT})
    _write_json(source, {"method": "POST", "route": "/api/export"})
    action = [{
        "type": "surface-review",
        "action": f"Review surface candidate {ENDPOINT}",
        "command_hint": "AI reviews the exact replay draft",
        "metadata": {"endpoint": ENDPOINT, "replay_draft": "POST one controlled replay"},
    }]
    _attach_activation_context(
        action,
        repo=tmp_path,
        target=TARGET,
        context={
            "skill_route": ROUTE,
            "knowledge_cards": [CARD],
            "hypothesis_seeds": ["export route crosses an object boundary"],
            "must_read": [
                f"recon/{TARGET}/browser/xhr.json",
                f"findings/{TARGET}/source_intel/routes.json",
            ],
        },
    )
    assert "activation_required" not in action[0]


def test_versioned_terminal_requires_claim_and_real_observation(tmp_path):
    baseline = f"evidence/{TARGET}/correlation/baseline.json"
    _write_json(tmp_path / baseline, {"status": 200})
    added = add_manual_action(
        tmp_path,
        target=TARGET,
        action_type="validation",
        evidence="Target-owned export evidence",
        next_question="Does the object selector cross the boundary?",
        action="Replay one controlled object substitution.",
        metadata=_activation_context(baseline),
    )
    action_id = added["queue"]["actions"][0]["id"]
    before = (tmp_path / "state" / TARGET / "action_queue.json").read_bytes()
    with pytest.raises(ValueError, match="running claimed action"):
        resolve_action(
            tmp_path,
            target=TARGET,
            action_id=action_id,
            status="tested",
            result="premature terminal result",
            metadata=_activation(),
        )
    assert (tmp_path / "state" / TARGET / "action_queue.json").read_bytes() == before

    claim_next_action(tmp_path, TARGET, action_id=action_id, metadata=_activation())
    summary_ref = f"evidence/{TARGET}/validation/operation-1/summary.json"
    _write_json(tmp_path / summary_ref, {"operation_id": "operation-1"})
    synced = _sync_action_queue(
        {
            "target": TARGET,
            "url": ENDPOINT,
            "result": "tested_clean",
            "summary_path": summary_ref,
            "operation_id": "operation-1",
            "generated_at": "2026-08-11T00:00:01Z",
            "observed_difference": "no controlled body or status difference",
        },
        repo_root=tmp_path,
    )
    assert synced["action_status"] == "running"
    before = (tmp_path / "state" / TARGET / "action_queue.json").read_bytes()
    with pytest.raises(ValueError, match="exactly one continuation"):
        resolve_action(
            tmp_path,
            target=TARGET,
            action_id=action_id,
            status="tested",
            result="no difference was recorded",
        )
    assert (tmp_path / "state" / TARGET / "action_queue.json").read_bytes() == before


def test_runner_observation_rejects_non_target_summary_ref(tmp_path):
    baseline = f"evidence/{TARGET}/correlation/baseline.json"
    _write_json(tmp_path / baseline, {"status": 200})
    added = add_manual_action(
        tmp_path,
        target=TARGET,
        action_type="validation",
        evidence="Target-owned export evidence",
        next_question="Does the object selector cross the boundary?",
        action="Replay one controlled object substitution.",
        metadata=_activation_context(baseline),
    )
    action_id = added["queue"]["actions"][0]["id"]
    claim_next_action(tmp_path, TARGET, action_id=action_id, metadata=_activation())
    foreign_ref = "evidence/other-target/validation/summary.json"
    _write_json(tmp_path / foreign_ref, {"operation_id": "operation-1"})
    synced = _sync_action_queue(
        {
            "target": TARGET,
            "url": ENDPOINT,
            "result": "tested_clean",
            "summary_path": foreign_ref,
            "operation_id": "operation-1",
            "generated_at": "2026-08-11T00:00:01Z",
        },
        repo_root=tmp_path,
    )
    assert synced["status"] == "blocked"
    assert load_queue(tmp_path, TARGET)["actions"][0]["status"] == "running"


def test_runner_observation_rejects_baseline_without_controlled_difference(tmp_path):
    baseline = f"evidence/{TARGET}/correlation/baseline.json"
    _write_json(tmp_path / baseline, {"status": 200})
    added = add_manual_action(
        tmp_path,
        target=TARGET,
        action_type="validation",
        evidence="Target-owned export evidence",
        next_question="Does the object selector cross the boundary?",
        action="Replay one controlled object substitution.",
        metadata=_activation_context(baseline),
    )
    action_id = added["queue"]["actions"][0]["id"]
    claim_next_action(tmp_path, TARGET, action_id=action_id, metadata=_activation())
    summary_ref = f"evidence/{TARGET}/validation/operation-1/summary.json"
    _write_json(tmp_path / summary_ref, {"operation_id": "operation-1"})
    synced = _sync_action_queue(
        {
            "target": TARGET,
            "url": ENDPOINT,
            "result": "tested_clean",
            "summary_path": summary_ref,
            "operation_id": "operation-1",
            "generated_at": "2026-08-11T00:00:01Z",
            "baseline": {"status": 200, "body_length": 42},
        },
        repo_root=tmp_path,
    )
    assert synced["status"] == "blocked"
    action = load_queue(tmp_path, TARGET)["actions"][0]
    assert action["status"] == "running"
    assert "last_outcome" not in action["metadata"]


def test_runner_observation_prefers_replay_diff_over_status_only(tmp_path):
    assert "count changed" in _runner_observed_difference({
        "result": "tested_clean",
        "runs": [{"diff": {"summary": "count changed from 1 to 2"}}],
    })


def test_evidence_skill_hypothesis_result_continuation_and_kill_replay(tmp_path):
    baseline = f"evidence/{TARGET}/correlation/baseline.json"
    _write_json(tmp_path / baseline, {"status": 200, "shape": "owner-export"})
    added = add_manual_action(
        tmp_path,
        target=TARGET,
        action_type="validation",
        evidence="Browser and source evidence identify POST order_id export.",
        next_question="Does another object selector cross the tenant boundary?",
        action="Replay one controlled object substitution.",
        metadata=_activation_context(baseline),
    )
    action_id = added["queue"]["actions"][0]["id"]
    before = (tmp_path / "state" / TARGET / "action_queue.json").read_bytes()

    with pytest.raises(ValueError, match="depth_contract_version=1"):
        claim_next_action(tmp_path, TARGET, action_id=action_id)
    assert (tmp_path / "state" / TARGET / "action_queue.json").read_bytes() == before

    preclaim = _runner_summary(tmp_path, "operation-0", "runner must not activate a queued hypothesis")
    assert _sync_action_queue(preclaim, repo_root=tmp_path)["status"] == "blocked"
    assert load_queue(tmp_path, TARGET)["actions"][0]["status"] == "queued"

    claimed = claim_next_action(
        tmp_path,
        TARGET,
        action_id=action_id,
        metadata=_activation(),
    )
    assert claimed["status"] == "running"
    assert claimed["metadata"]["execution_key"].startswith("depth-v1:")
    assert claimed["metadata"]["selected_knowledge_refs"] == [CARD]

    first = _runner_summary(tmp_path, "operation-1", "no controlled body or status difference")
    synced = _sync_action_queue(first, repo_root=tmp_path)
    observed = load_queue(tmp_path, TARGET)["actions"][0]
    assert synced["action_status"] == "running"
    assert observed["status"] == "running"
    assert observed["metadata"]["tested_dimensions"] == ["parameter"]
    assert observed["metadata"]["last_outcome"]["operation_id"] == "operation-1"

    unresolved_bytes = (tmp_path / "state" / TARGET / "action_queue.json").read_bytes()
    with pytest.raises(ValueError, match="exactly one continuation"):
        resolve_action(
            tmp_path,
            target=TARGET,
            action_id=action_id,
            status="tested",
            result="one negative parameter comparison",
        )
    assert (tmp_path / "state" / TARGET / "action_queue.json").read_bytes() == unresolved_bytes

    resolve_action(
        tmp_path,
        target=TARGET,
        action_id=action_id,
        status="tested",
        result="parameter comparison was negative; test the evidence-linked sibling",
        metadata={
            "continuation": {
                "kind": "sibling",
                "dimension": "sibling",
                "question": "Does the download sibling enforce the same object boundary?",
                "expected_learning": "whether the sibling uses a different authorization path",
                "reason": "source evidence links export and download handlers",
            }
        },
    )
    queue = load_queue(tmp_path, TARGET)
    child = next(item for item in queue["actions"] if item["id"] != action_id)
    assert child["metadata"]["parent_action_id"] == action_id
    assert child["metadata"]["hypothesis_id"] == "H-export-boundary"
    assert child["metadata"]["active_dimension"] == "sibling"
    assert child["metadata"]["depth_contract_version"] == 1
    assert child["metadata"]["activation_required"] is True
    assert "tested_dimensions" not in child["metadata"]

    open_closure = load_closure_projection(
        str(tmp_path),
        {"target": TARGET, "resolved_target": TARGET, "next_action": "resume_action_queue"},
        max_lanes_reached=False,
        apply_round_guard=False,
    )
    assert open_closure["verdict"] == "handoff"

    claim_next_action(tmp_path, TARGET, action_id=child["id"])
    second = _runner_summary(tmp_path, "operation-2", "sibling preserves the same authorization boundary")
    _sync_action_queue(second, repo_root=tmp_path)
    resolve_action(
        tmp_path,
        target=TARGET,
        action_id=child["id"],
        status="tested",
        result="the bounded sibling dimension satisfies the target-specific stop condition",
        metadata={
            "kill_condition_met": True,
            "kill_reason": "controlled parameter and sibling comparisons both preserve the boundary",
        },
    )

    save_matrix(
        TARGET,
        {
            "target": TARGET,
            "vuln_classes": ["IDOR"],
            "endpoints": [{
                "endpoint": "/api/export",
                "weight": 3.0,
                "cells": {"IDOR": {"status": "tested_clean"}},
            }],
        },
        repo_root=tmp_path,
    )
    closed = load_closure_projection(
        str(tmp_path),
        {"target": TARGET, "resolved_target": TARGET, "next_action": "handoff"},
        max_lanes_reached=False,
        apply_round_guard=False,
    )
    assert closed["verdict"] == "finish"
    assert closed["can_claim_exhausted"] is True


def test_explicit_baseline_observation_is_recoverable_but_cannot_kill(tmp_path):
    baseline = f"evidence/{TARGET}/correlation/baseline.json"
    _write_json(tmp_path / baseline, {"status": 500})
    added = add_manual_action(
        tmp_path,
        target=TARGET,
        action_type="validation",
        evidence="Target-owned admin route evidence",
        next_question="Does a browser-linked child handler expose the same data?",
        action="Replay one anonymous admin baseline.",
        metadata=_activation_context(baseline),
    )
    action_id = added["queue"]["actions"][0]["id"]
    claim_next_action(tmp_path, TARGET, action_id=action_id, metadata=_activation())

    summary_ref = f"evidence/{TARGET}/validation/operation-baseline/summary.json"
    evidence_ref = f"evidence/{TARGET}/validation/operation-baseline/response.txt"
    _write_json(tmp_path / summary_ref, {"operation_id": "operation-baseline"})
    _write_json(tmp_path / evidence_ref, {"status": 500})
    synced = _sync_action_queue(
        {
            "target": TARGET,
            "url": ENDPOINT,
            "result": "tested_clean",
            "summary_path": summary_ref,
            "operation_id": "operation-baseline",
            "generated_at": "2026-08-11T00:00:01Z",
            "observation_kind": "baseline_only",
            "baseline": {
                "status": 500,
                "body_length": 2422,
                "content_type": "text/html",
                "body_sha256": "abc123",
            },
            "marker_sources": {"body": []},
            "ledger_record": {"evidence_ref": evidence_ref},
        },
        repo_root=tmp_path,
    )
    assert synced["status"] == "updated"
    action = load_queue(tmp_path, TARGET)["actions"][0]
    assert action["status"] == "running"
    assert action["metadata"]["last_outcome"]["observation_kind"] == "baseline_only"
    before = (tmp_path / "state" / TARGET / "action_queue.json").read_bytes()
    with pytest.raises(ValueError, match="baseline-only observation"):
        resolve_action(
            tmp_path,
            target=TARGET,
            action_id=action_id,
            status="tested",
            result="baseline denied",
            metadata={"kill_condition_met": True, "kill_reason": "baseline denied"},
        )
    assert (tmp_path / "state" / TARGET / "action_queue.json").read_bytes() == before


@pytest.mark.parametrize(
    "kind",
    [
        "sibling",
        "bypass",
        "identity",
        "object",
        "parser",
        "transport",
        "workflow",
        "chain",
        "blocked",
        "rotation",
    ],
)
def test_supported_continuation_kinds_materialize_at_most_one_child(tmp_path, kind):
    action_id = _observed_depth_action(tmp_path)

    resolve_action(
        tmp_path,
        target=TARGET,
        action_id=action_id,
        status="tested",
        result=f"The {kind} decision follows the persisted comparison.",
        metadata={
            "continuation": {
                "kind": kind,
                "dimension": kind,
                "question": f"Does the bounded {kind} comparison change the result?",
                "expected_learning": f"whether {kind} exposes a distinct boundary",
                "reason": f"the persisted evidence supports one {kind} comparison",
            }
        },
    )

    queue = load_queue(tmp_path, TARGET)
    children = [
        item for item in queue["actions"]
        if item.get("metadata", {}).get("parent_action_id") == action_id
    ]
    assert len(children) == (0 if kind == "rotation" else 1)
    if children:
        assert children[0]["metadata"]["hypothesis_id"] == "H-export-boundary"
        assert children[0]["metadata"]["continuation_kind"] == kind


def test_execution_repeat_requires_new_evidence_and_reason(tmp_path):
    evidence_a = f"evidence/{TARGET}/repeat/a.json"
    evidence_b = f"evidence/{TARGET}/repeat/b.json"
    _write_json(tmp_path / evidence_a, {"revision": "a"})
    _write_json(tmp_path / evidence_b, {"revision": "b"})

    def add_repeat(label: str, evidence_ref: str) -> str:
        before = {item["id"] for item in load_queue(tmp_path, TARGET)["actions"]}
        add_manual_action(
            tmp_path,
            target=TARGET,
            action_type="validation",
            evidence=f"Repeat fixture {label}",
            next_question="Does the same semantic comparison need another execution?",
            action=f"Execute repeat fixture {label}.",
            metadata=_activation_context(evidence_ref),
        )
        after = load_queue(tmp_path, TARGET)["actions"]
        return next(item["id"] for item in after if item["id"] not in before)

    first = add_repeat("first", evidence_a)
    same = add_repeat("same", evidence_a)
    changed = add_repeat("changed", evidence_b)
    claim_next_action(tmp_path, TARGET, action_id=first, metadata=_activation())

    with pytest.raises(ValueError, match="duplicate execution with the same evidence"):
        claim_next_action(tmp_path, TARGET, action_id=same, metadata=_activation())
    with pytest.raises(ValueError, match="requires repeat_reason for changed evidence"):
        claim_next_action(tmp_path, TARGET, action_id=changed, metadata=_activation())

    repeated = claim_next_action(
        tmp_path,
        TARGET,
        action_id=changed,
        metadata={**_activation(), "repeat_reason": "new source revision changes the evidence basis"},
    )
    assert repeated["status"] == "running"
    assert repeated["metadata"]["repeat_reason"] == "new source revision changes the evidence basis"


def test_hypothesis_action_budget_rejects_continuation_without_mutating_queue(tmp_path):
    baseline = f"evidence/{TARGET}/correlation/budget-baseline.json"
    _write_json(tmp_path / baseline, {"status": 200})
    context = {**_activation_context(baseline), "max_hypothesis_actions_cap": 1}
    action_id, queue_path = _queued_depth_action(tmp_path, context=context)
    claim_next_action(
        tmp_path,
        TARGET,
        action_id=action_id,
        metadata={**_activation(), "max_hypothesis_actions": 1},
    )
    assert _sync_action_queue(
        _runner_summary(tmp_path, "operation-1", "one stable controlled comparison"),
        repo_root=tmp_path,
    )["status"] == "updated"
    before = queue_path.read_bytes()

    with pytest.raises(ValueError, match="hypothesis action budget is exhausted"):
        resolve_action(
            tmp_path,
            target=TARGET,
            action_id=action_id,
            status="tested",
            result="A second action would exceed the bounded hypothesis budget.",
            metadata={
                "continuation": {
                    "kind": "sibling",
                    "dimension": "sibling",
                    "question": "Does one sibling expose a different boundary?",
                    "expected_learning": "whether the sibling changes the controlled result",
                    "reason": "the evidence suggests one sibling but the cap is exhausted",
                }
            },
        )

    assert queue_path.read_bytes() == before


@pytest.mark.parametrize(
    ("risk_tier", "family", "technique"),
    [
        ("low", "target-specific response boundary", "controlled sibling comparison"),
        ("medium", "novel parser ownership boundary", "alternate representation replay"),
        ("high", "custom workflow authority boundary", "cross-state object substitution"),
        ("critical", "unlisted capability composition", "bounded primitive composition"),
    ],
)
def test_open_family_technique_and_all_risk_tiers_use_generic_activation(
    tmp_path, risk_tier, family, technique
):
    action_id, _queue_path = _queued_depth_action(tmp_path)
    claimed = claim_next_action(
        tmp_path,
        TARGET,
        action_id=action_id,
        metadata={
            **_activation(),
            "risk_tier": risk_tier,
            "family": family,
            "technique": technique,
        },
    )

    assert claimed["metadata"]["risk_tier"] == risk_tier
    assert claimed["metadata"]["family"] == family
    assert claimed["metadata"]["technique"] == technique


def test_legacy_action_without_depth_metadata_keeps_versionless_lifecycle(tmp_path):
    added = add_manual_action(
        tmp_path,
        target=TARGET,
        action_type="legacy-review",
        evidence="Legacy target-owned review remains readable.",
        next_question="Can the legacy review be classified?",
        action="Classify the legacy review.",
        metadata={"hypothesis_id": "legacy-H", "pivot_hints": []},
    )
    action_id = added["queue"]["actions"][0]["id"]

    claimed = claim_next_action(tmp_path, TARGET, action_id=action_id)
    resolved = resolve_action(
        tmp_path,
        target=TARGET,
        action_id=action_id,
        status="tested",
        result="Legacy review completed without the depth contract.",
    )

    assert claimed["status"] == "running"
    assert resolved["status"] == "tested"
    assert len(load_queue(tmp_path, TARGET)["actions"]) == 1


def test_capability_review_blocks_closure_until_dead_end_then_allows_finish(tmp_path):
    action_id = _observed_depth_action(tmp_path)
    primitive_ref = f"evidence/{TARGET}/validation/operation-1/summary.json"
    resolve_action(
        tmp_path,
        target=TARGET,
        action_id=action_id,
        status="tested",
        result="Standalone impact stopped, but one reusable capability remains.",
        metadata={
            "kill_condition_met": True,
            "kill_reason": "the standalone comparison reached its bounded stop condition",
            "capability_primitives": [{
                "capability": "cross-workflow object selector",
                "evidence_ref": primitive_ref,
                "continuation_hint": "compare the linked download workflow",
            }],
        },
    )
    review = _capability_chain_review_item(tmp_path, TARGET)
    ingest_checkpoint(tmp_path, TARGET, checkpoint={"next_action_queue": [review]})
    durable_review = next(
        item for item in load_queue(tmp_path, TARGET)["actions"]
        if item["type"] == "capability-chain-review"
    )
    save_matrix(
        TARGET,
        {
            "target": TARGET,
            "vuln_classes": ["IDOR"],
            "endpoints": [{
                "endpoint": "/api/export",
                "weight": 3.0,
                "cells": {"IDOR": {"status": "tested_clean"}},
            }],
        },
        repo_root=tmp_path,
    )

    active = load_closure_projection(
        str(tmp_path),
        {"target": TARGET, "resolved_target": TARGET, "next_action": "resume_action_queue"},
        max_lanes_reached=False,
        apply_round_guard=False,
    )
    assert active["verdict"] == "handoff"

    resolve_action(
        tmp_path,
        target=TARGET,
        action_id=durable_review["id"],
        status="dead-end",
        result="No executable in-scope chain remained.",
    )
    assert _capability_chain_review_item(tmp_path, TARGET) == {}
    closed = load_closure_projection(
        str(tmp_path),
        {"target": TARGET, "resolved_target": TARGET, "next_action": "handoff"},
        max_lanes_reached=False,
        apply_round_guard=False,
    )
    assert closed["verdict"] == "finish"


def test_unsupported_primitive_speculation_does_not_block_closure(tmp_path):
    action_id = _observed_depth_action(tmp_path)
    primitive_ref = f"evidence/{TARGET}/validation/operation-1/summary.json"
    resolve_action(
        tmp_path,
        target=TARGET,
        action_id=action_id,
        status="tested",
        result="The bounded action stopped without an executable chain continuation.",
        metadata={
            "kill_condition_met": True,
            "kill_reason": "the controlled comparison reached its bounded stop condition",
            "capability_primitives": [{
                "capability": "possible parser relationship",
                "evidence_ref": primitive_ref,
            }],
        },
    )
    assert _capability_chain_review_item(tmp_path, TARGET) == {}
    save_matrix(
        TARGET,
        {
            "target": TARGET,
            "vuln_classes": ["IDOR"],
            "endpoints": [{
                "endpoint": "/api/export",
                "weight": 3.0,
                "cells": {"IDOR": {"status": "tested_clean"}},
            }],
        },
        repo_root=tmp_path,
    )

    closed = load_closure_projection(
        str(tmp_path),
        {"target": TARGET, "resolved_target": TARGET, "next_action": "handoff"},
        max_lanes_reached=False,
        apply_round_guard=False,
    )
    assert closed["verdict"] == "finish"
    assert closed["can_claim_exhausted"] is True
