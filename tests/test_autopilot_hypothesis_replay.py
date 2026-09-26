"""Explicit hypothesis work retains context without automatic continuation or verdicts."""
from __future__ import annotations

import json
import subprocess

import pytest

from tools.action_queue import add_manual_action, claim_next_action, load_queue, resolve_action
from tools.checkpoint import build_checkpoint
from tools.target_store import TargetStore

TARGET = "target.test"
ENDPOINT = "https://target.test/api/export?order_id=42"
CARD = "knowledge/cards/api-idor.md"
ROUTE = {"skill_id": "web2-vuln-classes", "required_dimensions": ["parameter"]}
ALT_ROUTE = {"skill_id": "triage-validation"}


@pytest.fixture
def store(tmp_path):
    result = TargetStore(tmp_path, TARGET)
    result.initialize()
    return result


def _queued_depth_action(tmp_path, *, context=None):
    store = TargetStore(tmp_path, TARGET)
    baseline = f"evidence/{TARGET}/correlation/baseline.json"
    path = tmp_path / baseline
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"status": 200}), encoding="utf-8")
    for name in ("api-idor.md", "auth-access.md"):
        card = tmp_path / "knowledge/cards" / name
        card.parent.mkdir(parents=True, exist_ok=True)
        card.write_text("Recorded knowledge card", encoding="utf-8")
    action_id = f"A-{store.page('actions')['total']}"
    added = add_manual_action(
        tmp_path, target=TARGET, action_id=action_id, action_type="validation",
        evidence="Target-owned export evidence", next_question="Does the object selector cross the boundary?",
        action="Replay one controlled object substitution.",
        metadata=context if context is not None else _activation_context(baseline),
    )
    return added["action"]["id"], store


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
def test_versioned_claim_rejects_runner_observation_fields_without_writing(tmp_path, field, value, store):
    action_id, action_store = _queued_depth_action(tmp_path)
    before = action_store.binding()
    activation = {**_activation(), field: value}

    with pytest.raises(ValueError, match="Runner-owned"):
        claim_next_action(tmp_path, TARGET, action_id=action_id, metadata=activation)

    assert action_store.binding() == before
    queued = load_queue(tmp_path, TARGET)["actions"][0]
    assert queued["status"] == "queued"
    assert field not in queued["metadata"]


def test_versioned_claim_reports_all_missing_activation_fields_without_writing(tmp_path, store):
    """The 16-field required gate is retired (2026-09-14 dumb-queue refactor):
    a claim missing judgment fields succeeds and stores exactly what the AI
    supplied — nothing is fabricated, nothing is demanded."""
    baseline = f"evidence/{TARGET}/correlation/baseline.json"
    context = _activation_context(baseline)
    context.pop("input_boundary")
    action_id, action_store = _queued_depth_action(tmp_path, context=context)
    activation = _activation()
    activation.pop("decision_reason")

    claimed = claim_next_action(tmp_path, TARGET, action_id=action_id, metadata=activation)

    assert claimed["metadata"]["hypothesis_id"] == activation["hypothesis_id"]
    assert "decision_reason" not in claimed["metadata"]
    assert "input_boundary" not in claimed["metadata"]


def test_versioned_claim_cannot_override_queue_owned_cap(tmp_path, store):
    action_id, action_store = _queued_depth_action(tmp_path)
    before = action_store.binding()

    with pytest.raises(ValueError, match="immutable after creation"):
        claim_next_action(
            tmp_path,
            TARGET,
            action_id=action_id,
            metadata={**_activation(), "max_hypothesis_actions_cap": 100},
        )

    assert action_store.binding() == before
    assert load_queue(tmp_path, TARGET)["actions"][0]["metadata"]["max_hypothesis_actions_cap"] == 3


def test_versioned_claim_accepts_redundant_matching_stored_cap(tmp_path, store):
    action_id, _queue_path = _queued_depth_action(tmp_path)

    claimed = claim_next_action(
        tmp_path,
        TARGET,
        action_id=action_id,
        metadata={**_activation(), "max_hypothesis_actions_cap": 3},
    )

    assert claimed["status"] == "claimed"
    assert claimed["metadata"]["max_hypothesis_actions_cap"] == 3


def test_versioned_claim_reports_requested_cap_above_stored_cap_without_writing(tmp_path, store):
    action_id, action_store = _queued_depth_action(tmp_path)
    before = action_store.binding()

    with pytest.raises(ValueError, match="exceeds the stored action cap"):
        claim_next_action(
            tmp_path,
            TARGET,
            action_id=action_id,
            metadata={**_activation(), "max_hypothesis_actions": 4},
        )

    assert action_store.binding() == before
    assert load_queue(tmp_path, TARGET)["actions"][0]["status"] == "queued"


def test_selected_knowledge_refs_missing_card_is_rejected_when_cards_root_exists(tmp_path, store):
    """Anti-forgery for card selection: when a real knowledge/cards tree is
    present, a ref naming a non-existent card is a typo or forgery and the
    claim is rejected naming the card. Judgment about WHICH card is never
    questioned."""
    baseline = f"evidence/{TARGET}/correlation/baseline.json"
    context = _activation_context(baseline)
    action_id, _queue_path = _queued_depth_action(tmp_path, context=context)
    cards_root = tmp_path / "knowledge" / "cards"
    cards_root.mkdir(parents=True, exist_ok=True)
    (cards_root / "auth-access.md").write_text("card\n", encoding="utf-8")

    with pytest.raises(ValueError, match="not a target-owned card"):
        claim_next_action(
            tmp_path,
            TARGET,
            action_id=action_id,
            metadata={**_activation(), "selected_knowledge_refs": ["knowledge/cards/typo-card.md"]},
        )

    claimed = claim_next_action(
        tmp_path,
        TARGET,
        action_id=action_id,
        metadata={**_activation(), "selected_knowledge_refs": ["knowledge/cards/auth-access.md"]},
    )
    assert claimed["metadata"]["selected_knowledge_refs"] == ["knowledge/cards/auth-access.md"]


def test_claimed_first_skill_route_does_not_require_override_reason(tmp_path, store):
    baseline = f"evidence/{TARGET}/correlation/baseline.json"
    context = _activation_context(baseline)
    context.pop("skill_route")
    context.pop("route_required")
    action_id, _queue_path = _queued_depth_action(tmp_path, context=context)
    activation = {**_activation(), "skill_route": ROUTE}

    claimed = claim_next_action(tmp_path, TARGET, action_id=action_id, metadata=activation)

    assert claimed["metadata"]["skill_route"] == ROUTE


def test_active_dimension_outside_route_needs_no_override_reason(tmp_path, store):
    """K-4: route dimensions name reasoning steps; active_dimension names the
    replay variable. Membership between the two is a category error, not a
    gate — any well-formed single-dimension label claims without a reason."""
    action_id, _queue_path = _queued_depth_action(tmp_path)

    claimed = claim_next_action(
        tmp_path,
        TARGET,
        action_id=action_id,
        metadata={**_activation(), "active_dimension": "parser"},
    )
    assert claimed["metadata"]["active_dimension"] == "parser"
    assert "dimension_override_reason" not in claimed["metadata"]

    # Form validation stays: a multi-word label is malformed, not judgment.
    action_id2, _q2 = _queued_depth_action(tmp_path)
    with pytest.raises(ValueError, match="single-dimension label"):
        claim_next_action(
            tmp_path,
            TARGET,
            action_id=action_id2,
            metadata={**_activation(), "active_dimension": "two words here"},
        )


def test_claimed_skill_route_override_requires_reason(tmp_path, store):
    """Skill-route override justification is AI judgment now, not a write-time
    gate: a different route on an identified action replaces it wholesale."""
    baseline = f"evidence/{TARGET}/correlation/baseline.json"
    context = {**_activation_context(baseline), "skill_route": ALT_ROUTE}
    action_id, action_store = _queued_depth_action(tmp_path, context=context)
    activation = {**_activation(), "skill_route": ROUTE}
    before = action_store.binding()

    claimed = claim_next_action(tmp_path, TARGET, action_id=action_id, metadata=activation)
    assert claimed["metadata"]["skill_route"] == ROUTE
    assert action_store.binding() != before


@pytest.mark.parametrize("selection", ["missing", "empty"])
def test_versioned_claim_accepts_optional_knowledge_refs(tmp_path, selection, store):
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

    if selection == "missing":
        assert "selected_knowledge_refs" not in claimed["metadata"]
    else:
        assert claimed["metadata"]["selected_knowledge_refs"] == []


@pytest.mark.parametrize("selected_refs", [None, CARD, [""]])
def test_versioned_claim_rejects_malformed_optional_knowledge_refs(
    tmp_path,
    selected_refs, store):
    action_id, action_store = _queued_depth_action(tmp_path)
    activation = {**_activation(), "selected_knowledge_refs": selected_refs}
    before = action_store.binding()

    with pytest.raises(ValueError, match="list of non-empty references"):
        claim_next_action(tmp_path, TARGET, action_id=action_id, metadata=activation)

    assert action_store.binding() == before



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
    tmp_path, risk_tier, family, technique, store):
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



@pytest.mark.parametrize("metadata", [{}, {"selected_knowledge_refs": []}])
def test_absent_or_empty_card_selection_needs_no_card_tree(tmp_path, store, metadata):
    store.create_action(command_id="work", action_id="work", intent="Inspect material",
                        execution_key="work", kind="work", subject={"target": TARGET}, actor="operator")
    claimed = claim_next_action(tmp_path, TARGET, action_id="work", metadata=metadata)
    assert claimed["status"] == "claimed"
    assert not (tmp_path / "knowledge").exists()


def test_explicit_hypothesis_replay_recovers_conditions_without_automatic_work(tmp_path, store):
    store.create_action(
        command_id="create-first", action_id="first", kind="execution",
        endpoint=ENDPOINT, family="ObjectBoundary", intent="Compare controlled object responses",
        execution_key="object-comparison", actor="action-queue",
        metadata={"hypothesis_id": "H-object", "active_dimension": "object"},
    )
    claim = claim_next_action(tmp_path, TARGET, action_id="first")
    proof = tmp_path / f"evidence/{TARGET}/response.txt"
    proof.parent.mkdir(parents=True)
    proof.write_text("Owner and peer responses preserve the object boundary", encoding="utf-8")
    store.start_attempt(attempt_id="first-attempt", source="native", started_at="2026-09-24T00:00:00Z",
                        action_id="first", claim_token=claim["claim_token"], actor="action-queue")
    observed = dict(
        attempt_id="first-attempt", outcome="complete", actor="action-queue",
        observations=[{
            "endpoint": ENDPOINT, "method": "POST", "family": "ObjectBoundary",
            "observed_at": "2026-09-24T00:00:00Z", "description": "Controlled object comparison",
            "artifacts": {"response": proof.relative_to(tmp_path).as_posix()}, "result": "tested_clean",
            "actor": "peer", "state_changing": False,
            "detail": {"tested_dimensions": ["object"], "observed_difference": "No object data crossed tenants"},
        }],
    )
    operation = store.record_execution(**observed)
    revision = store.binding()["revision"]
    assert store.record_execution(**observed)["replayed"] is True
    assert store.binding()["revision"] == revision
    assert store.action("first")["status"] == "claimed"
    assert "last_outcome" not in store.action("first")["metadata"]
    evidence = [{"operation_id": operation["entity_id"], "step": 0}]
    for entry_id, kind, statement in (
        ("negative", "negative", "Object boundary held under the recorded sessions"),
        ("primitive", "primitive", "Controlled object identifiers can be compared across the workflow"),
    ):
        store.remember(command_id=entry_id, kind=kind, statement=statement,
                       conditions="Two controlled sessions in separate tenants",
                       reopen_when="Session role or workflow implementation changes",
                       next_intent="", evidence=evidence, actor="operator")
    resolved = resolve_action(
        tmp_path, target=TARGET, action_id="first", status="tested",
        result=f"operation_id={operation['entity_id']}",
        metadata={"continuation": {"kind": "sibling", "question": "Inspect a linked workflow"}},
    )
    assert resolved["status"] == "completed"
    assert store.page("actions")["total"] == 1
    assert store.page("findings")["total"] == 0
    # A real repeat is a separately identified intent and attempt.
    store.create_action(
        command_id="create-second", action_id="second", kind="execution", endpoint=ENDPOINT,
        family="ObjectBoundary", intent="Compare after a session role change", execution_key="object-comparison",
        repeat_of="first", repeat_reason="Session role changed", actor="action-queue",
    )
    claim = claim_next_action(tmp_path, TARGET, action_id="second")
    store.start_attempt(attempt_id="second-attempt", source="native", started_at="2026-09-24T00:01:00Z",
                        action_id="second", claim_token=claim["claim_token"], actor="action-queue")
    second = store.record_execution(**{
        **observed, "attempt_id": "second-attempt",
        "observations": [{**observed["observations"][0], "observed_at": "2026-09-24T00:01:00Z"}],
    })
    assert second["entity_id"] != operation["entity_id"]
    # Old owners are poisoned; fresh processes and repeated views must ignore them.
    for relative in (f"state/{TARGET}/action_queue.json", f"memory/evidence/{TARGET}/ledger.jsonl",
                     f"memory/goals/targets/{TARGET}.json", f"findings/{TARGET}/findings.json"):
        path = tmp_path / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("corrupt historical owner", encoding="utf-8")
    before = store.binding()
    for _ in range(3):
        checkpoint = build_checkpoint(tmp_path, target=TARGET)
        assert {item["id"] for item in checkpoint["next_action_queue"]} == {"second"}
        entries = checkpoint["context_pack"]["target_experiences"]["items"]
        assert {item["entry_id"] for item in entries} == {"negative", "primitive"}
    cli = subprocess.run(
        ["python3", "tools/resume.py", "--repo-root", str(tmp_path), "--target", TARGET,
         "--memory-dir", str(tmp_path / "hunt-memory"), "--json"],
        capture_output=True, text=True, check=True,
    )
    recovered = json.loads(cli.stdout)
    serialized = json.dumps(recovered)
    assert "Two controlled sessions in separate tenants" in serialized
    assert "Session role or workflow implementation changes" in serialized
    assert "second" in serialized
    assert store.binding() == before
    assert store.page("actions")["total"] == 2
    assert store.action("first")["status"] == "completed"
    assert store.action("second")["status"] == "claimed"
