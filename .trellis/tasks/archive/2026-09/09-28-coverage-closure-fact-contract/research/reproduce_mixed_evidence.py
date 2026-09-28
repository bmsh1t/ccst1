"""Reproduce mismatched Coverage/Closure evidence without mutating the repo."""

import json
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from tools import autopilot_state
from tools.coverage_matrix import require_matching_truth
from tools.current_truth import current_cell_projection
from tools.target_store import StoreError, TargetStore


TARGET = "fact-contract.test"
AT = "2026-09-28T00:00:00Z"


def reproduce(initially_damaged):
    with TemporaryDirectory(prefix="closure-fact-contract-") as directory:
        root = Path(directory)
        store = TargetStore(root, TARGET)
        store.initialize()
        raw = root / ".private" / "validation" / TARGET / "response.txt"
        raw.parent.mkdir(parents=True)
        raw.write_text("registered response", encoding="utf-8")
        store.start_attempt(attempt_id="attempt", source="native", started_at=AT, actor="operator")
        store.record_execution(
            attempt_id="attempt", outcome="complete", actor="operator", observations=[{
                "endpoint": f"https://{TARGET}/object", "method": "GET", "family": "Authz",
                "observed_at": AT, "description": "Recorded local fixture response",
                "artifacts": {"response": str(raw.relative_to(root))},
                "state_changing": False, "result": "tested_clean",
            }],
        )
        if initially_damaged:
            raw.write_text("changed response", encoding="utf-8")
        state = autopilot_state.build_autopilot_state(str(root), TARGET, bounded=True)
        binding = store.binding()
        markers = autopilot_state._owner_source_markers(root, TARGET)
        acquired = {}
        read_matrix = autopilot_state.read_matrix

        def acquire_then_change(*args, **kwargs):
            matrix = read_matrix(*args, **kwargs)
            acquired["matrix"] = matrix
            raw.write_text(
                "registered response" if initially_damaged else "changed response", encoding="utf-8",
            )
            return matrix

        with patch.object(autopilot_state, "read_matrix", acquire_then_change):
            closure = autopilot_state.load_closure_projection(str(root), state)
        truth = current_cell_projection(root, TARGET)
        matrix = acquired["matrix"]
        try:
            require_matching_truth(matrix, truth)
        except StoreError as error:
            guard_error = str(error)
        else:
            raise AssertionError("The existing consistency guard must reject these inputs")
        result = {
            "direction": "restore" if initially_damaged else "damage",
            "coverage_health": matrix["evidence_health"]["status"],
            "closure_health": closure["ledger_health"]["status"],
            "truth_health": truth["health"]["status"],
            "store_unchanged": store.binding() == binding,
            "owner_markers_unchanged": autopilot_state._owner_source_markers(root, TARGET) == markers,
            "mixed_snapshot_returned": bool(closure.get("snapshot_digest")),
            "snapshot_stale": closure.get("snapshot_stale", False),
            "can_claim_exhausted": closure["can_claim_exhausted"],
            "reasons": closure["reasons"],
            "existing_guard_error": guard_error,
        }
        assert result["coverage_health"] != result["closure_health"] == result["truth_health"]
        assert result["store_unchanged"] and result["owner_markers_unchanged"]
        assert result["mixed_snapshot_returned"] and not result["snapshot_stale"]
        print(json.dumps(result, ensure_ascii=False, sort_keys=True))


if __name__ == "__main__":
    reproduce(False)
    reproduce(True)
