"""Primary continuations preserve producer context without scanner-owned verdicts."""

import json

import pytest

from tools import action_queue, oast_listen, param_discovery, spray_contract
from tools.target_store import ConflictError, StoreError, TargetStore, initialize_target_store


def test_primary_action_context_survives_without_overriding_domain_state(tmp_path):
    store = TargetStore(tmp_path, "review.test")
    store.initialize()
    fields = dict(
        target=store.target, action_type="intel-advisory", source="intel",
        source_id="advisory-1", evidence="Recorded advisory material",
        action="Review the material", next_question="Does it apply?",
        command_hint="read the recorded material", evidence_type="advisory",
        generation="first", safety="read_only", stop_condition="record the review",
    )
    first = action_queue.add_manual_action(tmp_path, **fields)
    revision = store.page("actions")["revision"]
    replay = action_queue.add_manual_action(tmp_path, **fields)
    assert replay["receipt"]["replayed"]
    assert store.page("actions")["revision"] == revision
    projected = action_queue.load_queue(tmp_path, store.target)["actions"][0]
    for key in action_queue.ACTION_CONTEXT_FIELDS:
        assert projected[key] == fields["action_type" if key == "type" else key]
    assert projected["metadata"]["generation"] == "first"
    assert projected["status"] == "queued"
    assert first["action"]["kind"] == "work"
    claimed = action_queue.claim_next_action(tmp_path, store.target, action_id=projected["id"])
    assert claimed["status"] == "claimed"
    assert action_queue.load_queue(tmp_path, store.target)["actions"][0]["status"] == "running"
    assert not action_queue.queue_path(tmp_path, store.target).exists()


def test_action_write_uses_explicitly_initialized_primary_backend(tmp_path):
    target = "first-write.test"
    initialize_target_store(tmp_path, target)
    result = action_queue.add_manual_action(
        tmp_path, target=target, action_type="review", evidence="material",
        next_question="What is known?", action="Review material", action_id="first",
    )
    assert result["backend"] == "primary"
    assert TargetStore(tmp_path, target).action("first")["status"] == "ready"
    assert not action_queue.queue_path(tmp_path, target).exists()


def test_primary_context_cannot_project_a_second_lifecycle(tmp_path):
    store = TargetStore(tmp_path, "context.test")
    store.initialize()
    store.create_action(
        command_id="add", action_id="work", intent="Read", execution_key="read", actor="ai",
        kind="work", subject={"target": store.target},
        metadata={"action_context": {"type": "review", "status": "tested", "id": "forged"}},
    )
    row = action_queue.load_queue(tmp_path, store.target)["actions"][0]
    assert row["id"] == "work" and row["status"] == "queued" and row["type"] == "review"


@pytest.mark.parametrize("context", [None, {"evidence": []}])
def test_open_metadata_context_remains_readable(tmp_path, context):
    store = TargetStore(tmp_path, "opaque.test")
    store.initialize()
    store.create_action(command_id="add", action_id="work", intent="Read", execution_key="read", actor="ai",
                        kind="work", subject={"target": store.target}, metadata={"action_context": context})
    row = action_queue.load_queue(tmp_path, store.target)["actions"][0]
    assert row["id"] == "work" and row["status"] == "queued"
    assert row["metadata"]["action_context"] == context


def test_pre_context_primary_add_replays_without_rewriting_history(tmp_path, monkeypatch):
    store = TargetStore(tmp_path, "older.test")
    store.initialize()
    create = TargetStore.create_action

    def pre_context_create(self, **arguments):
        arguments["metadata"] = {key: value for key, value in arguments["metadata"].items()
                                 if key != "action_context"}
        return create(self, **arguments)

    fields = dict(target=store.target, action_type="review", evidence="material", action="Review",
                  next_question="What is known?", action_id="work", metadata={"generation": "g1"})
    with monkeypatch.context() as old:
        old.setattr(TargetStore, "create_action", pre_context_create)
        action_queue.add_manual_action(tmp_path, **fields)
    before = store.action("work")
    assert action_queue.add_manual_action(tmp_path, **fields)["receipt"]["replayed"]
    assert store.action("work") == before
    with pytest.raises(ConflictError):
        action_queue.add_manual_action(tmp_path, **{**fields, "metadata": {"generation": "different"}})


def test_primary_oast_start_poll_stop_preserve_work_and_material(tmp_path, monkeypatch):
    target = "oast.test"
    store = TargetStore(tmp_path, target)
    store.initialize()
    monkeypatch.setattr(oast_listen, "REPO_ROOT", tmp_path)
    monkeypatch.setattr(oast_listen, "FINDINGS_ROOT", tmp_path / "findings")
    paths = oast_listen._paths(target)
    paths["base"].mkdir(parents=True)
    start = dict(backend="fixture", url="listener.test", pid=1)
    oast_listen._sync_start_action(target, **start)
    action = oast_listen._latest_oast_action(target)
    assert action is not None
    revision = store.page("actions")["revision"]
    oast_listen._sync_start_action(target, **start)
    assert store.page("actions")["revision"] == revision

    raw = b'{"protocol":"dns","name":"marker.listener.test"}\n'
    paths["callbacks"].write_bytes(raw)
    oast_listen._sync_poll_action(target, paths=paths, callbacks=1)
    revision = store.page("actions")["revision"]
    oast_listen._sync_poll_action(target, paths=paths, callbacks=1)
    assert store.page("actions")["revision"] == revision
    oast_listen._sync_stop_action(target, paths=paths)
    oast_listen._sync_stop_action(target, paths=paths)
    notes = store.page("experiences")["items"]
    assert len(notes) == 2
    assert all(note["action_id"] == action["id"] and note["kind"] == "handoff" for note in notes)
    assert any("stopped=True" in note["statement"] for note in notes)
    assert store.action(action["id"])["status"] == "ready"
    assert store.page("findings")["total"] == store.page("operations")["total"] == 0
    assert paths["callbacks"].read_bytes() == raw
    assert not action_queue.queue_path(tmp_path, target).exists()

    action_queue.resolve_action(tmp_path, target=target, action_id=action["id"],
                                status="dead-end", result="explicit operator decision")
    paths["callbacks"].write_bytes(raw + raw)
    oast_listen._sync_poll_action(target, paths=paths, callbacks=2)
    oast_listen._sync_stop_action(target, paths=paths)
    assert store.page("experiences")["total"] == 4
    assert store.action(action["id"])["status"] == "cancelled"
    oast_listen._sync_start_action(target, **start)
    assert store.action(action["id"])["status"] == "cancelled"
    oast_listen._sync_start_action(target, **{**start, "pid": 2})
    assert store.page("actions")["total"] == 2
    assert oast_listen._latest_oast_action(target)["id"] != action["id"]


@pytest.mark.parametrize("target", ["empty.test", "Empty.test"])
def test_primary_oast_no_callback_is_not_a_negative_verdict(tmp_path, monkeypatch, target):
    store = TargetStore(tmp_path, "empty.test")
    store.initialize()
    monkeypatch.setattr(oast_listen, "REPO_ROOT", tmp_path)
    monkeypatch.setattr(oast_listen, "FINDINGS_ROOT", tmp_path / "findings")
    oast_listen._sync_start_action(target, backend="fixture", url="listener.test")
    paths = oast_listen._paths(target)
    with pytest.raises(ValueError, match="nonempty callback material"):
        oast_listen._sync_poll_action(store.target, paths=paths, callbacks=1)
    oast_listen._sync_stop_action(store.target, paths=paths)
    assert store.page("actions")["items"][0]["status"] == "ready"
    assert "sha256=absent" in store.page("experiences")["items"][0]["statement"]


def _parameter_summary(root, target):
    summary = {
        "target": target, "batch_id": 1, "session_id": "anonymous", "method": "GET",
        "status": "completed", "counts": {"discoveries": 0}, "runs": [],
        "artifacts": {"summary": f"recon/{target}/params/summary.json"},
    }
    path = root / summary["artifacts"]["summary"]
    path.parent.mkdir(parents=True)
    path.write_text(json.dumps(summary))
    return summary


def test_parameter_material_registration_is_idempotent_not_a_verdict(tmp_path):
    store = TargetStore(tmp_path, "params.test")
    store.initialize()
    summary = _parameter_summary(tmp_path, store.target)
    first = param_discovery._sync_action_queue(tmp_path, store.target, summary)
    revision = store.page("actions")["revision"]
    assert param_discovery._sync_action_queue(tmp_path, store.target, summary) == first
    assert store.page("actions")["revision"] == revision
    row = action_queue.load_queue(tmp_path, store.target)["actions"][0]
    assert row["type"] == "parameter-discovery" and row["source"] == "param_discovery"
    assert row["status"] == "queued" and first["queue_status"] == "ready"
    snapshot = tmp_path / row["metadata"]["summary_path"]
    snapshot_bytes = snapshot.read_bytes()
    changed = {**summary, "counts": {"discoveries": 1}}
    (tmp_path / summary["artifacts"]["summary"]).write_text(json.dumps(changed))
    assert param_discovery._sync_action_queue(tmp_path, store.target, changed)["action_id"] != first["action_id"]
    assert store.page("actions")["total"] == 2
    assert snapshot.read_bytes() == snapshot_bytes
    assert json.loads(snapshot_bytes)["material"]["counts"] == {"discoveries": 0}
    assert store.action(first["action_id"])["subject_artifact"]["ref"] == str(snapshot.relative_to(tmp_path))
    assert store.page("operations")["total"] == store.page("findings")["total"] == 0
    assert not action_queue.queue_path(tmp_path, store.target).exists()


def test_parameter_material_write_uses_explicitly_initialized_store(tmp_path):
    target = "new-params.test"
    initialize_target_store(tmp_path, target)
    summary = _parameter_summary(tmp_path, target)
    result = param_discovery._sync_action_queue(tmp_path, target, summary)

    assert result["backend"] == "primary"
    assert TargetStore(tmp_path, target).page("actions")["total"] == 1
    assert not action_queue.queue_path(tmp_path, target).exists()


def test_uninitialized_action_and_parameter_writes_do_not_create_store(tmp_path):
    action_target = "uninitialized-action.test"
    with pytest.raises(StoreError, match="not initialized"):
        action_queue.add_manual_action(
            tmp_path, target=action_target, action_type="review", evidence="material",
            next_question="What is known?", action="Review material", action_id="first",
        )
    assert not TargetStore(tmp_path, action_target).path.exists()

    parameter_target = "uninitialized-params.test"
    with pytest.raises(StoreError, match="not initialized"):
        param_discovery._sync_action_queue(
            tmp_path, parameter_target, _parameter_summary(tmp_path, parameter_target)
        )
    assert not TargetStore(tmp_path, parameter_target).path.exists()


def _spray_context(root, target):
    run_dir = root / "recon" / target / "spray" / "run-1"
    return spray_contract.RunContext(
        mode="fixture", target_url=target, target_key=target, run_id="run-1",
        users=[], passwords=[], delay=0, jitter=0, continue_on_hit=False,
        binding={}, shape={}, run_dir=run_dir, private_dir=root / ".private" / "spray" / target,
        attempts_path=run_dir / "attempts.jsonl", summary_path=run_dir / "summary.json",
    )


@pytest.mark.parametrize("counts", [{"valid_session": 1}, {"invalid_credentials": 1}, {"unknown": 1}])
def test_spray_finish_records_review_without_interpreting_results(tmp_path, counts):
    store = TargetStore(tmp_path, "spray.test")
    store.initialize()
    context = _spray_context(tmp_path, store.target)
    fields = dict(status="completed", stop_reason="completed", counters=counts, exit_code=0)
    first = spray_contract.finish_run(context, **fields)
    revision = store.page("actions")["revision"]
    second = spray_contract.finish_run(context, **fields)
    assert first["action_queue_sync"] == second["action_queue_sync"]
    assert store.page("actions")["revision"] == revision
    assert first["action_queue_sync"]["queue_status"] == "ready"
    row = action_queue.load_queue(tmp_path, store.target)["actions"][0]
    assert row["type"] == "credential-spray" and row["source"] == "spray_contract"
    assert row["metadata"]["source_summary_path"] == str(context.summary_path.relative_to(tmp_path))
    snapshot = tmp_path / row["metadata"]["summary_path"]
    assert json.loads(snapshot.read_text())["material"]["counts"] == counts
    assert json.loads(context.summary_path.read_text())["counts"] == counts
    assert store.page("findings")["total"] == store.page("operations")["total"] == 0
    assert not action_queue.queue_path(tmp_path, store.target).exists()

    changed = {"new_result": 1}
    spray_contract.finish_run(context, **{**fields, "counters": changed})
    assert json.loads(snapshot.read_text())["material"]["counts"] == counts
    assert store.page("actions")["total"] == 2


def test_changed_review_snapshot_is_not_overwritten(tmp_path):
    store = TargetStore(tmp_path, "tampered.test")
    store.initialize()
    summary = _parameter_summary(tmp_path, store.target)
    first = param_discovery._sync_action_queue(tmp_path, store.target, summary)
    snapshot = tmp_path / store.action(first["action_id"])["subject_artifact"]["ref"]
    snapshot.write_text("changed outside the writer")
    with pytest.raises(StoreError, match="review snapshot differs"):
        param_discovery._sync_action_queue(tmp_path, store.target, summary)
    assert snapshot.read_text() == "changed outside the writer"
    assert store.page("actions")["total"] == 1


def test_spray_registration_failure_retains_material_for_retry(tmp_path, monkeypatch):
    store = TargetStore(tmp_path, "retry.test")
    store.initialize()
    context = _spray_context(tmp_path, store.target)
    fields = dict(status="completed", stop_reason="completed", counters={"unknown": 1}, exit_code=0)

    def failed_registration(*args, **kwargs):
        raise StoreError("injected registration failure")

    with monkeypatch.context() as failure:
        failure.setattr(TargetStore, "create_action", failed_registration)
        result = spray_contract.finish_run(context, **fields)
    assert result["action_queue_sync"]["status"] == "error"
    assert context.summary_path.is_file() and result["warnings"]
    snapshots = list(context.run_dir.glob("summary.review-*.json"))
    assert len(snapshots) == 1 and store.page("actions")["total"] == 0
    raw = snapshots[0].read_bytes()
    assert spray_contract.finish_run(context, **fields)["action_queue_sync"]["queue_status"] == "ready"
    assert snapshots[0].read_bytes() == raw
    assert list(context.run_dir.glob("summary.review-*.json")) == snapshots
    assert store.page("actions")["total"] == 1


def test_preview_spray_keeps_material_and_reports_registration_failure(tmp_path):
    store = TargetStore(tmp_path, "preview.test", allow_preview=True)
    store.initialize(allow_legacy=True)
    context = _spray_context(tmp_path, store.target)
    result = spray_contract.finish_run(context, status="completed", stop_reason="completed",
                                       counters={"invalid_credentials": 1}, exit_code=0)
    assert result["action_queue_sync"]["status"] == "error" and result["warnings"]
    assert context.summary_path.is_file()
    assert store.page("actions")["total"] == 0
    assert not action_queue.queue_path(tmp_path, store.target).exists()


def test_parameter_writer_does_not_resume_legacy_queue(tmp_path):
    target = "legacy.test"
    summary = _parameter_summary(tmp_path, target)
    legacy_queue = action_queue.queue_path(tmp_path, target)
    legacy_queue.parent.mkdir(parents=True, exist_ok=True)
    legacy_queue.write_text(json.dumps({"target": target, "actions": []}))
    before = legacy_queue.read_bytes()
    with pytest.raises(StoreError, match="not initialized"):
        param_discovery._sync_action_queue(tmp_path, target, summary)
    assert legacy_queue.read_bytes() == before
    assert not TargetStore(tmp_path, target).path.exists()


@pytest.mark.parametrize("metadata", [{}, {"route_required": True}, {
    "skill_route": {"skill_id": "missing-skill", "required_dimensions": []},
}])
def test_primary_action_add_and_claim_need_no_skill_files(tmp_path, metadata):
    store = TargetStore(tmp_path, "native-skill.test")
    store.initialize()
    added = action_queue.add_manual_action(
        tmp_path, target=store.target, action_type="review", evidence="Local observation",
        next_question="What does the observation mean?", action="Review the observation",
        action_id="native-review", metadata=metadata,
    )
    assert added["action"]["status"] == "ready"
    claimed = action_queue.claim_next_action(tmp_path, store.target, action_id="native-review")
    assert claimed["status"] == "claimed"
    assert store.action("native-review")["status"] == "claimed"
    assert not (tmp_path / "skills").exists()
    assert not action_queue.queue_path(tmp_path, store.target).exists()


def test_blocked_store_action_remains_pending_in_runtime_view(tmp_path):
    from tools.runtime_state import derive_state_view

    store = TargetStore(tmp_path, "blocked-work.test")
    store.initialize()
    store.create_action(command_id="add", action_id="blocked", intent="Review evidence",
                        execution_key="blocked", actor="operator", kind="work",
                        subject={"target": store.target})
    store.transition_action(command_id="block", action_id="blocked", expected_version=1,
                            status="blocked", reason="Waiting for required material", actor="operator")
    view = derive_state_view(tmp_path, store.target)
    assert view["derived"]["status"] == "action_pending"
    assert view["derived"]["queue"]["active"] == 1
    assert view["derived"]["queue"]["final"] == 0
