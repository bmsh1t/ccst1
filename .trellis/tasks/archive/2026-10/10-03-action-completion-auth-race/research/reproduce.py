"""Reproduce F04 with a real temporary Store and a deterministic second writer."""

import json
from pathlib import Path
import runpy
import sqlite3
import sys
from tempfile import TemporaryDirectory
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT))

from tools.target_store import StoreError, TargetStore


def reproduce(root):
    fixture = runpy.run_path(str(ROOT / "tests/test_target_store.py"))
    store = fixture["make_store"](root)
    fixture["create_action"](store)
    store.transition_action(command_id="claim1", action_id="a1", expected_version=1,
                            status="claimed", actor="operator")
    obs = fixture["observation"](root)
    store.start_attempt(attempt_id="bound", source="native", started_at=fixture["AT"],
                        actor="operator", action_id="a1", claim_token="claim1")
    operation = store.record_execution(attempt_id="bound", outcome="complete",
                                       observations=[obs], actor="operator")["entity_id"]
    with sqlite3.connect(store.path) as conn:
        artifact = conn.execute(
            "SELECT artifact_id FROM observation_artifacts WHERE operation_id=? AND step=0 AND kind='response'",
            (operation,),
        ).fetchone()[0]
    verify = store.verify_operation
    other = TargetStore(root, store.target)
    revocation = {}

    def revoke_after_verify(operation_id):
        result = verify(operation_id)
        revocation.update(other.record_artifact_event(
            command_id="revoke-before-finish", artifact_id=artifact,
            dimension="provenance", state="revoked", reason="Fixture revocation", actor="operator"))
        return result

    finished, error = None, None
    with patch.object(store, "verify_operation", revoke_after_verify):
        try:
            finished = store.transition_action(
                command_id="finish", action_id="a1", expected_version=2,
                status="completed", actor="operator", claim_token="claim1",
                reason="Fixture completion", completion={"operation_id": operation})
        except StoreError as exc:
            error = str(exc)
    assert revocation, "the revocation must commit after real verification"
    action = store.action("a1")
    authorized = store.artifact_status(artifact)["authorized"]
    assert authorized is False
    if finished:
        assert revocation["revision"] < finished["revision"]
    return {
        "completion_accepted": finished is not None,
        "action_status": action["status"],
        "action_version": action["version"],
        "claim_token": action["claim_token"],
        "revoke_revision": revocation["revision"],
        "completion_revision": finished["revision"] if finished else None,
        "store_revision": store.binding()["revision"],
        "artifact_authorized": authorized,
        "error": error,
    }


if __name__ == "__main__":
    with TemporaryDirectory(prefix="ccst-f04-") as directory:
        print(json.dumps(reproduce(Path(directory)), indent=2))
