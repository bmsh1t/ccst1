"""Explicit Action commands backed by the target Store; no automatic proposal writes."""

from __future__ import annotations

import json
import multiprocessing
import subprocess
import sys
from pathlib import Path

import pytest

import action_queue as action_queue_module
from action_queue import (
    add_manual_action, build_action, claim_next_action, format_action, load_queue, load_legacy_queue,
    main, resolve_action, active_action_ids, summarize_queue,
)
from runtime_state import runtime_phase_lock, update_runtime_state
from tools.target_store import StoreError, TargetStore, initialize_target_store


@pytest.fixture
def store(tmp_path):
    initialize_target_store(tmp_path, "target.com")
    return TargetStore(tmp_path, "target.com")


def add_work(store, action_id="A1", **kwargs):
    return add_manual_action(
        store.root, target=store.target, action_id=action_id, action_type="source-review",
        evidence="Recorded material", next_question="What does it establish?",
        action=f"Review material {action_id}", **kwargs,
    )["action"]


def _claim_action_worker(repo_root, target, barrier, output):
    try:
        barrier.wait(timeout=10)
        claimed = claim_next_action(repo_root, target, action_id="A1")
        output.put((claimed["claim_status"], ""))
    except Exception as exc:
        output.put(("error", str(exc)))


def test_primary_action_commands_use_store_without_legacy_queue_file(tmp_path):
    target = "primary-actions.test"
    store = TargetStore(tmp_path, target)
    store.initialize()

    created = add_manual_action(
        tmp_path,
        target=target,
        action_type="source-review",
        evidence="Review the target-owned source material.",
        next_question="What concrete boundary does the material establish?",
        action="Review the target-owned source material.",
        action_id="WORK-1",
    )
    assert created["backend"] == "primary"
    assert created["action"]["kind"] == "work"
    assert store.action("WORK-1")["status"] == "ready"

    claimed = claim_next_action(tmp_path, target, action_id="WORK-1")
    assert claimed["claim_status"] == "claimed"
    resumed = claim_next_action(tmp_path, target, action_id="WORK-1")
    assert resumed["claim_status"] == "resumed"

    result = tmp_path / "evidence" / target / "source-review.txt"
    result.parent.mkdir(parents=True)
    result.write_text("reviewed", encoding="utf-8")
    resolved = resolve_action(
        tmp_path,
        target=target,
        action_id="WORK-1",
        status="tested",
        result=f"artifact={result.relative_to(tmp_path)}",
    )
    assert resolved["status"] == "completed"
    assert store.action("WORK-1")["completion"]["artifact_id"].startswith("artifact:")
    replayed = resolve_action(
        tmp_path,
        target=target,
        action_id="WORK-1",
        status="tested",
        result=f"artifact={result.relative_to(tmp_path)}",
    )
    assert replayed["replayed"] is True
    assert not (tmp_path / "state" / target / "action_queue.json").exists()


def test_explicit_action_kind_validates_identity_and_cannot_be_spoofed(tmp_path):
    target = "kind-contract.test"
    store = TargetStore(tmp_path, target)
    store.initialize()
    created = add_manual_action(
        tmp_path, target=target, action_id="EXEC-1", kind="execution",
        action_type="request-diff", evidence="Recorded pair", next_question="What does it establish?",
        action="Review the pair", metadata={"endpoint": "https://kind-contract.test/api", "family": "Authz"},
    )
    assert created["action"]["kind"] == "execution"
    row = store.action("EXEC-1")
    assert row["kind"] == "execution"
    assert row["endpoint"] == "https://kind-contract.test/api"
    assert row["family"] == "Authz"

    before = store.binding()
    with pytest.raises(StoreError, match="require endpoint and family"):
        add_manual_action(
            tmp_path, target=target, action_id="EXEC-MISSING", kind="execution",
            action_type="request-diff", evidence="Recorded pair", next_question="Review?",
            action="Review the pair", metadata={"endpoint": "https://kind-contract.test/api"},
        )
    assert store.binding() == before

    work = add_manual_action(
        tmp_path, target=target, action_id="WORK-SPOOF", kind="work",
        action_type="review", evidence="Recorded material", next_question="Review?",
        action="Review material", metadata={"kind": "execution", "action_context": {"kind": "execution"}},
    )
    assert work["action"]["kind"] == "work"
    assert store.action("WORK-SPOOF")["kind"] == "work"
    assert load_queue(tmp_path, target)["actions"][-1]["kind"] == "work"


def test_primary_action_claim_persists_bounded_metadata(tmp_path):
    target = "primary-claim.test"
    store = TargetStore(tmp_path, target)
    store.initialize()
    add_manual_action(
        tmp_path,
        target=target,
        action_type="review",
        evidence="Review target context.",
        next_question="What is known?",
        action="Review target context.",
        action_id="WORK-2",
        metadata={"hypothesis_id": "h1", "expected_learning": "role boundary"},
    )
    claimed = claim_next_action(
        tmp_path, target, action_id="WORK-2", metadata={"active_dimension": "role"}
    )
    assert claimed["claim_status"] == "claimed"
    assert claimed["metadata"]["hypothesis_id"] == "h1"
    assert claimed["metadata"]["active_dimension"] == "role"


def test_concurrent_manual_actions_do_not_lose_updates(tmp_path):
    initialize_target_store(tmp_path, "target.com")
    code = """
import sys
from tools.action_queue import add_manual_action

root, evidence = sys.argv[1:]
add_manual_action(
    root,
    target="target.com",
    action_type="manual-check",
    evidence=evidence,
    next_question=f"review {evidence}",
    action=f"run {evidence}",
)
"""
    repo_root = Path(__file__).resolve().parents[1]
    processes = [
        subprocess.Popen(
            [sys.executable, "-c", code, str(tmp_path), evidence],
            cwd=repo_root,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        for evidence in ("first", "second")
    ]
    for process in processes:
        stdout, stderr = process.communicate(timeout=10)
        assert process.returncode == 0, stdout + stderr

    queue = load_queue(tmp_path, "target.com")
    assert {item["evidence"] for item in queue["actions"]} == {"first", "second"}


@pytest.mark.parametrize(
    ("other_type", "other_status"),
    [
        ("runtime-recovery", "running"),
        ("validation", "queued"),
        ("candidate-evidence-gap", "candidate"),
        ("report", "queued"),
    ],
)
def test_capability_chain_review_never_preempts_existing_owner_work(other_type, other_status):
    """Advisory preemption semantics retired: chain review and owner work
    coexist in the active list; selection is the AI's judgment."""
    review = build_action(
        target="target.com",
        action_type="capability-chain-review",
        evidence="A persisted capability primitive needs bounded chain review.",
        next_question="Does one evidence-backed chain remain?",
        action="Review one primitive.",
        priority=999,
    )
    review["id"] = "AQ-REVIEW"
    other = build_action(
        target="target.com",
        action_type=other_type,
        evidence="Existing owner work remains open.",
        next_question="Can the existing work be completed?",
        action="Complete the existing owner work.",
        priority=1,
    )
    other.update({"id": "AQ-OWNER", "status": other_status})

    assert set(active_action_ids({"actions": [review, other]})) == {"AQ-REVIEW", "AQ-OWNER"}


def test_manual_action_cli_accepts_stop_condition_for_high_risk_lane(tmp_path):
    initialize_target_store(tmp_path, "api.target.com")
    code = main([
        "--repo-root", str(tmp_path),
        "add",
        "--target", "api.target.com",
        "--type", "ssrf-parser-boundary",
        "--evidence", "URL fetch path accepts user-controlled callback URL.",
        "--next-question", "Does parser normalization change internal host handling?",
        "--action", "python3 tools/context_pack.py --target api.target.com --focus ssrf",
        "--command-hint", "python3 tools/context_pack.py --target api.target.com --focus ssrf",
        "--stop-condition", "Stop after a read-only parser-boundary probe is recorded as tested, blocked, dead-end, signal, or candidate.",
        "--json",
    ])

    assert code == 0
    queue = load_queue(tmp_path, "api.target.com")
    action = queue["actions"][0]
    assert action["type"] == "ssrf-parser-boundary"
    assert action["stop_condition"].startswith("Stop after a read-only parser-boundary probe")
    assert action["stop_condition"] != "record tested, dead-end, blocked, lead, signal, candidate, or validated before moving to the next queued action"


def test_manual_action_cli_writes_metadata_and_preserves_duplicate_queue_behavior(tmp_path):
    initialize_target_store(tmp_path, "api.target.com")
    metadata = {
        "hypothesis_id": "H-42",
        "family": "custom-template-chain",
        "chain": ["template", "sandbox", "execution"],
        "expected_learning": "A role difference should reveal object scoping.",
        "kill_condition": "Responses remain identical across both actors.",
        "next_question": "Does the sibling endpoint enforce the same object check?",
        "attempts": 2,
    }
    argv = [
        "--repo-root", str(tmp_path),
        "add",
        "--target", "api.target.com",
        "--type", "browser-api",
        "--evidence", "Observed an object endpoint in the browser trace.",
        "--next-question", "Can a low-role actor replay the object request?",
        "--action", "Replay the request with the low-role actor.",
        "--metadata-json", json.dumps(metadata),
        "--json",
    ]

    assert main(argv) == 0
    assert main(argv) == 0
    queue = load_queue(tmp_path, "api.target.com")

    assert len(queue["actions"]) == 1
    assert all(queue["actions"][0]["metadata"][key] == value for key, value in metadata.items())


def test_target_owned_evidence_ref_rejects_resolver_path_outside_repo(tmp_path, monkeypatch):
    from tools import target_paths

    monkeypatch.setattr(
        target_paths,
        "_locatable_evidence_ref",
        lambda *_args: "/tmp/foreign/evidence.json",
    )
    assert target_paths._target_owned_evidence_ref(tmp_path, "api.target.com", "foreign") == ""


@pytest.mark.parametrize("metadata", [{}, {"route_required": True}, {
    "skill_route": {"skill_id": "../retired-skill", "required_dimensions": []},
}])
def test_action_queue_does_not_consume_retired_skill_routes(metadata):
    action = build_action(
        target="api.target.com", action_type="hypothesis",
        evidence="Observed an API object path.", next_question="Can a peer actor read it?",
        action="Replay the object path with a peer actor.", metadata=metadata,
    )
    # Historical fields are opaque input; no file is loaded or path synthesized.
    assert action.get("metadata", {}) == metadata


@pytest.mark.parametrize("metadata_json", ["not-json", "[]", "null", '"text"'])
def test_manual_action_cli_rejects_non_object_metadata_json(tmp_path, capsys, metadata_json):
    code = main([
        "--repo-root", str(tmp_path),
        "add",
        "--target", "api.target.com",
        "--evidence", "Observed an endpoint.",
        "--next-question", "Can it be replayed?",
        "--action", "Replay the endpoint.",
        "--metadata-json", metadata_json,
    ])

    assert code == 2
    assert "--metadata-json" in capsys.readouterr().err
    assert not (tmp_path / "state" / "api.target.com" / "action_queue.json").exists()


@pytest.mark.parametrize("field", ["authorization", "cookie", "access_token", "private_marker"])
def test_manual_action_cli_rejects_sensitive_metadata_without_writing(tmp_path, capsys, field):
    code = main([
        "--repo-root", str(tmp_path),
        "add",
        "--target", "api.target.com",
        "--evidence", "Observed an endpoint.",
        "--next-question", "Can it be replayed?",
        "--action", "Replay the endpoint.",
        "--metadata-json", json.dumps({field: "secret-value"}),
    ])

    assert code == 2
    assert "sensitive field" in capsys.readouterr().err
    assert not (tmp_path / "state" / "api.target.com" / "action_queue.json").exists()


def test_action_identities_keep_vulnerability_and_auth_context_lanes_distinct():
    endpoint = "https://target.com/api/orders/42"
    idor = {
        "metadata": {
            "endpoint": endpoint,
            "vuln_class": "IDOR",
            "method": "GET",
            "semantic_shape_id": "shape-orders-id",
            "auth_context": "authenticated",
            "actor": "user-a",
            "object_scope": "tenant-a",
        }
    }
    authz = {
        "metadata": {
            "endpoint": endpoint,
            "vuln_class": "Authz",
            "method": "GET",
            "semantic_shape_id": "shape-orders-id",
            "auth_context": "authenticated",
            "actor": "user-a",
            "object_scope": "tenant-a",
        }
    }

    assert action_queue_module._action_identities(idor).isdisjoint(
        action_queue_module._action_identities(authz)
    )


def test_legacy_action_identity_keeps_endpoint_compatibility():
    action = {"metadata": {"endpoint": "https://target.com/api/orders/42"}}

    assert action_queue_module._action_identities(action) == {"endpoint:/api/orders/42"}


def test_queue_fingerprint_ignores_container_timestamps():
    first = {
        "schema_version": 1,
        "target": "target.com",
        "created_at": "2026-01-01T00:00:00Z",
        "updated_at": "2026-01-01T00:00:00Z",
        "actions": [],
    }
    second = {
        **first,
        "created_at": "2026-01-02T00:00:00Z",
        "updated_at": "2026-01-02T00:00:00Z",
    }

    assert action_queue_module.queue_fingerprint(first) == action_queue_module.queue_fingerprint(second)


def test_action_summary_preserves_window_running_selection_and_generation(store, monkeypatch):
    from tools.checkpoint import build_checkpoint, _evidence_vuln_classes
    from tools.autopilot_state import _load_action_queue_next

    assert action_queue_module.load_queue_summary(store.root, store.target)["total"] == 0
    for index in range(20):
        action_id = f"A-{index:02}"
        add_work(store, action_id, metadata={"family": "Authz" if index == 18 else "custom"})
        if index < 10:
            resolve_action(store.root, target=store.target, action_id=action_id, status="n/a", result="Cancelled")
    claim_next_action(store.root, store.target, action_id="A-19")
    full = load_queue(store.root, store.target)
    snapshot = action_queue_module.load_queue_summary(store.root, store.target)
    assert (snapshot["total"], snapshot["pending_total"]) == (20, 10)
    assert snapshot["actions"] == full["actions"][10:15]
    assert snapshot["running_action"] == snapshot["next_action"] == full["actions"][19]
    assert _load_action_queue_next(str(store.root), store.target, queue_snapshot=snapshot)["id"] == "A-19"
    assert _evidence_vuln_classes([], snapshot) == _evidence_vuln_classes([], full)
    assert action_queue_module.queue_fingerprint(snapshot) == action_queue_module.queue_fingerprint(full)
    before = store.binding()
    monkeypatch.setattr(TargetStore, "action_page", lambda *args, **kwargs: pytest.fail("unneeded history read"))
    # No intel material means the default checkpoint has no terminal review history to read.
    checkpoint = build_checkpoint(store.root, target=store.target)
    assert checkpoint["default_candidate"]["id"] == "A-19"
    assert checkpoint["action_queue_window"]["total"] == 10
    assert checkpoint["action_queue_window"]["remaining"] == 5
    assert store.binding() == before
    resolve_action(store.root, target=store.target, action_id="A-19", status="blocked", result="Need context")
    fresh = action_queue_module.load_queue_summary(store.root, store.target)
    assert fresh["next_action"]["id"] == "A-10"
    assert action_queue_module.queue_fingerprint(fresh) != action_queue_module.queue_fingerprint(snapshot)


@pytest.mark.parametrize("damaged", ["{broken", "[]", "null"])
def test_action_summary_exposes_corrupt_terminal_metadata(store, damaged):
    import sqlite3

    add_work(store)
    resolve_action(store.root, target=store.target, action_id="A1", status="n/a", result="Cancelled")
    with sqlite3.connect(store.path) as conn:
        conn.execute("UPDATE actions SET metadata_json=?", (damaged,))
    with pytest.raises(StoreError, match="metadata"):
        action_queue_module.load_queue_summary(store.root, store.target)


def test_action_filtered_pages_bind_filters_and_keep_terminal_history(store):
    from tools.target_store import ConflictError

    for index in range(7):
        add_manual_action(store.root, target=store.target, action_id=f"A-{index}",
                          action_type="intel-advisory" if index % 2 else "source-review",
                          action="Review advisory", evidence="Recorded material", next_question="Review?")
    page = store.action_page(statuses=("ready",), action_type="intel-advisory", limit=2)
    assert [row["id"] for row in page["items"]] == ["A-1", "A-3"]
    assert page["total"] == 3 and page["remaining"] == 1
    tail = store.action_page(statuses=("ready",), action_type="intel-advisory", limit=2, cursor=page["next_cursor"])
    assert [row["id"] for row in tail["items"]] == ["A-5"]
    with pytest.raises(ConflictError, match="filter"):
        store.action_page(statuses=("blocked",), action_type="intel-advisory", cursor=page["next_cursor"])
    with pytest.raises(ConflictError, match="filter"):
        store.action_page(statuses=("ready",), action_type="source-review", cursor=page["next_cursor"])
    with pytest.raises(StoreError):
        store.action_page(statuses=("unknown",))
    resolve_action(store.root, target=store.target, action_id="A-1", status="n/a", result="Cancelled")
    assert len(load_queue(store.root, store.target)["actions"]) == 7
    assert [row["id"] for row in load_queue(store.root, store.target, statuses=("cancelled",), action_type="intel-advisory")["actions"]] == ["A-1"]


def test_intel_terminal_filter_uses_descriptive_type_not_storage_kind(store):
    from tools.intel_continuation import _final_queue_dispositions

    for action_id, action_type in (("intel", "intel-advisory"), ("source", "source-review")):
        add_manual_action(store.root, target=store.target, action_id=action_id, action_type=action_type,
                          action="Review advisory", evidence="Recorded material", next_question="Review?")
        resolve_action(store.root, target=store.target, action_id=action_id, status="n/a", result="Reviewed CVE-2026-12345")
    assert store.action("intel")["kind"] == "work"
    dispositions = _final_queue_dispositions(store.root, store.target)
    assert len(dispositions["CVE-2026-12345"]) == 1
    store.create_action(command_id="whitespace", action_id="whitespace", kind="work", subject={"target": store.target},
                        intent="Review advisory", execution_key="whitespace", actor="operator",
                        metadata={"action_context": {"type": "\tintel-advisory\u2003"}})
    assert [row["id"] for row in store.action_page(action_type="intel-advisory")["items"]] == ["intel", "whitespace"]


def test_action_summary_uses_one_revision_during_concurrent_write(store, monkeypatch):
    add_work(store, "B")
    before = store.binding()
    check = store._require_action_metadata

    def concurrent_write(conn):
        add_work(store, "A")
        check(conn)

    with monkeypatch.context() as patch:
        patch.setattr(store, "_require_action_metadata", concurrent_write)
        pinned = store.action_summary(limit=1)
    assert pinned["revision"] == before["revision"]
    assert pinned["counts"] == {"total": 1, "pending": 1}
    assert pinned["items"][0]["id"] == "B"
    assert store.action_summary(limit=1)["items"][0]["id"] == "A"


def test_action_summary_preserves_family_order_beyond_preview(store):
    from tools.checkpoint import _evidence_vuln_classes

    for index in range(8):
        add_work(store, f"A-{index}", metadata={"family": "custom" if index < 5 else ("GraphQL" if index == 5 else "Authz"),
                                              "vuln_class": "IDOR" if index == 7 else ""})
    full = load_queue(store.root, store.target)
    window = action_queue_module.load_queue_summary(store.root, store.target)
    assert _evidence_vuln_classes([], window) == _evidence_vuln_classes([], full)


def test_explicit_legacy_inspection_rejects_corrupt_or_invalid_state(tmp_path):
    path = tmp_path / "state" / "target.com" / "action_queue.json"
    path.parent.mkdir(parents=True)

    path.write_text('{"actions":', encoding="utf-8")
    with pytest.raises(ValueError, match="invalid action queue JSON"):
        load_legacy_queue(tmp_path, "target.com")

    path.write_text(json.dumps([{"id": "AQ-0001"}]), encoding="utf-8")
    with pytest.raises(ValueError, match="must contain one object"):
        load_legacy_queue(tmp_path, "target.com")

    path.write_text(json.dumps({"schema_version": 1, "actions": {}}), encoding="utf-8")
    with pytest.raises(ValueError, match="actions must be a list"):
        load_legacy_queue(tmp_path, "target.com")

    path.write_text(json.dumps({"schema_version": 2, "actions": []}), encoding="utf-8")
    with pytest.raises(ValueError, match="schema_version must be 1"):
        load_legacy_queue(tmp_path, "target.com")



def test_retired_queue_writers_and_selection_are_absent(store):
    for name in ("save_queue", "ingest_checkpoint", "select_next_action", "upsert_actions"):
        assert not hasattr(action_queue_module, name)
    with pytest.raises(SystemExit) as exc:
        main(["ingest-checkpoint", "--target", store.target])
    assert exc.value.code == 2
    assert not (store.path.parent / "action_queue.json").exists()


def test_concurrent_claim_grants_one_execution_permit(store):
    add_work(store)
    context = multiprocessing.get_context("fork")
    output = context.Queue()
    barrier = context.Barrier(6)
    processes = [context.Process(target=_claim_action_worker,
                                args=(str(store.root), store.target, barrier, output)) for _ in range(6)]
    for process in processes:
        process.start()
    results = [output.get(timeout=15) for _ in processes]
    for process in processes:
        process.join(timeout=15)
    assert all(process.exitcode == 0 for process in processes)
    assert all(not error for _, error in results), results
    assert [status for status, _ in results].count("claimed") == 1
    assert [status for status, _ in results].count("resumed") == 5
    assert store.action("A1")["version"] == 2


@pytest.mark.parametrize("phase", ["scan", "recon"])
def test_runtime_wait_keeps_all_explicit_work_visible(store, phase, capsys):
    add_work(store, "A1", priority=1)
    add_work(store, "A2", priority=99)
    before = store.binding()
    update_runtime_state(store.root, store.target, mode=f"{phase}_running", last_executed_workflow=f"run_{phase}_started")
    with runtime_phase_lock(store.root, store.target, phase):
        assert set(active_action_ids(load_queue(store.root, store.target))) == {"A1", "A2"}
        assert main(["--repo-root", str(store.root), "list", "--target", store.target, "--json"]) == 0
        assert {row["id"] for row in json.loads(capsys.readouterr().out)} == {"A1", "A2"}
    assert store.binding() == before


def test_claim_requires_explicit_id_and_never_reidentifies_work(store):
    add_work(store, metadata={"hypothesis_id": "H1", "family": "authz", "technique": "object-swap"})
    before = store.binding()
    with pytest.raises(ValueError, match="requires --id"):
        claim_next_action(store.root, store.target)
    with pytest.raises(StoreError, match="re-identify"):
        claim_next_action(store.root, store.target, action_id="A1", metadata={"hypothesis_id": "H2"})
    assert store.binding() == before
    claim_next_action(store.root, store.target, action_id="A1", metadata={"active_dimension": "role"})
    assert claim_next_action(store.root, store.target, action_id="A1", metadata={"active_dimension": "role"})["claim_status"] == "resumed"
    before = store.binding()
    with pytest.raises(StoreError, match="different content"):
        claim_next_action(store.root, store.target, action_id="A1", metadata={"active_dimension": "object"})
    with pytest.raises(StoreError, match="another operator"):
        claim_next_action(store.root, store.target, action_id="A1", actor="another")
    assert store.binding() == before


@pytest.mark.parametrize("entry", ["add", "claim", "resolve"])
@pytest.mark.parametrize("field", ["last_outcome", "tested_dimensions", "runner_operation_id"])
def test_all_action_commands_reject_runner_observation_forgery(store, entry, field):
    add_work(store)
    before = store.binding()
    metadata = {field: "forged"}
    with pytest.raises(ValueError, match="Runner-owned"):
        if entry == "add":
            add_work(store, "A2", metadata=metadata)
        elif entry == "claim":
            claim_next_action(store.root, store.target, action_id="A1", metadata=metadata)
        else:
            resolve_action(store.root, target=store.target, action_id="A1", status="blocked", result="review", metadata=metadata)
    assert store.binding() == before


@pytest.mark.parametrize("ref", ["evidence/target.com/missing.json", "evidence/foreign.test/foreign.json"])
def test_claim_rejects_missing_or_foreign_evidence_refs(store, ref):
    add_work(store)
    foreign = store.root / "evidence/foreign.test/foreign.json"
    foreign.parent.mkdir(parents=True)
    foreign.write_text("{}")
    before = store.binding()
    with pytest.raises((StoreError, OSError), match="artifact|target"):
        claim_next_action(store.root, store.target, action_id="A1", metadata={"evidence_ref": ref})
    assert store.binding() == before


def test_claim_accepts_explicit_evidence_without_inferring_judgment(store, capsys):
    add_work(store)
    raw = store.root / "evidence/target.com/probe.json"
    raw.parent.mkdir(parents=True)
    raw.write_text(json.dumps({"kind": "probe", "request": {"url": "https://target.com/other"}}))
    metadata = {"evidence_ref": raw.relative_to(store.root).as_posix()}
    assert main(["--repo-root", str(store.root), "claim", "--target", store.target, "--id", "A1",
                 "--metadata-json", json.dumps(metadata), "--json"]) == 0
    claimed = json.loads(capsys.readouterr().out)
    assert claimed["metadata"]["evidence_ref"] == metadata["evidence_ref"]
    for field in ("endpoint", "method", "baseline_ref", "hypothesis_id", "family", "kill_condition"):
        assert field not in claimed["metadata"]
    assert "--from-evidence" not in action_queue_module.build_parser().format_help()
    with pytest.raises(SystemExit) as exc:
        main(["claim", "--target", store.target, "--id", "A1", "--from-evidence", str(raw)])
    assert exc.value.code == 2


@pytest.mark.parametrize("status", ["tested", "tested_clean", "validated", "reported"])
def test_completion_aliases_require_claim_and_explicit_owned_proof(store, status):
    add_work(store)
    with pytest.raises(StoreError, match="explicit .*proof"):
        resolve_action(store.root, target=store.target, action_id="A1", status=status, result="looks complete")
    proof = store.root / "evidence/target.com/review.txt"
    proof.parent.mkdir(parents=True)
    proof.write_text("Reviewed source observation")
    arguments = dict(target=store.target, action_id="A1", status=status,
                     result=f"artifact={proof.relative_to(store.root)}")
    with pytest.raises(StoreError, match="explicit claim"):
        resolve_action(store.root, **arguments)
    claim_next_action(store.root, store.target, action_id="A1")
    assert resolve_action(store.root, **arguments)["status"] == "completed"
    before = store.binding()
    assert resolve_action(store.root, **arguments)["replayed"] is True
    assert store.binding() == before


@pytest.mark.parametrize("change", ["result", "notes", "metadata", "actor"])
def test_terminal_resolve_rejects_different_command_content(store, change):
    add_work(store)
    claim_next_action(store.root, store.target, action_id="A1")
    args = dict(target=store.target, action_id="A1", status="dead-end", result="No usable fixture material",
                metadata={"next_question": "Review another source"})
    resolve_action(store.root, **args)
    assert resolve_action(store.root, **args)["replayed"] is True
    before = store.binding()
    changed = {**args, change: {"next_question": "changed"} if change == "metadata" else "different"}
    with pytest.raises(StoreError, match="terminal"):
        resolve_action(store.root, **changed)
    assert store.binding() == before


def test_blocked_resolve_replays_without_rewriting_or_auto_continuation(store):
    add_work(store, metadata={"hypothesis_id": "H1", "pivot_hints": ["sibling", "encoding"]})
    args = dict(target=store.target, action_id="A1", status="blocked", result="Awaiting fixture material",
                metadata={"next_question": "Does another source help?"})
    assert resolve_action(store.root, **args)["status"] == "blocked"
    before = store.binding()
    assert resolve_action(store.root, **args)["replayed"] is True
    assert store.binding() == before
    assert store.page("actions")["total"] == 1
    assert not (store.path.parent / "unsafe_skipped_reviews.json").exists()
    assert not (store.root / "coverage/target.com/matrix.json").exists()


@pytest.mark.parametrize("status", ["candidate", "lead", "signal", "running"])
def test_resolve_does_not_forge_observation_or_reclaim(store, status):
    add_work(store)
    before = store.binding()
    with pytest.raises(StoreError, match="observation state|re-claim"):
        resolve_action(store.root, target=store.target, action_id="A1", status=status, result="AI judgment")
    assert store.binding() == before


def test_hypothesis_budget_uses_domain_status_and_releases_only_on_terminal(store):
    for action_id in ("A1", "A2", "A3"):
        add_work(store, action_id, metadata={"hypothesis_id": "H1", "max_hypothesis_actions": 2})
    for action_id in ("A1", "A2"):
        claim_next_action(store.root, store.target, action_id=action_id)
    with pytest.raises(StoreError, match="budget is exhausted"):
        claim_next_action(store.root, store.target, action_id="A3", metadata={"status": "queued"})
    resolve_action(store.root, target=store.target, action_id="A1", status="blocked", result="Pending context")
    with pytest.raises(StoreError, match="budget is exhausted"):
        claim_next_action(store.root, store.target, action_id="A3")
    resolve_action(store.root, target=store.target, action_id="A1", status="dead-end", result="Abandoned explicit intent")
    assert claim_next_action(store.root, store.target, action_id="A3")["claim_status"] == "claimed"
    assert store.action("A2")["status"] == "claimed"


@pytest.mark.parametrize("fault", ["uninitialized", "preview", "missing", "corrupt"])
def test_queue_cli_reports_store_fault_without_legacy_fallback(tmp_path, capsys, fault):
    store = TargetStore(tmp_path, "target.com", allow_preview=fault == "preview")
    if fault != "uninitialized":
        store.initialize(allow_legacy=fault == "preview")
    if fault == "missing":
        store.path.unlink()
    elif fault == "corrupt":
        store.path.write_bytes(b"broken database")
    path = tmp_path / "state/target.com/action_queue.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text('{"schema_version": 1, "actions": [{"id": "old"}]}')
    original = path.read_bytes()
    assert main(["--repo-root", str(tmp_path), "summary", "--target", store.target, "--json"]) == 2
    output = capsys.readouterr()
    assert not output.out and "Traceback" not in output.err
    assert path.read_bytes() == original
