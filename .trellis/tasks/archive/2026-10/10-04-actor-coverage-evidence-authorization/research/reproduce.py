"""Reproduce F05 using temporary Store state and existing offline test fixtures."""

import json
from pathlib import Path
import runpy
import sys
from tempfile import TemporaryDirectory


ROOT = next(parent for parent in Path(__file__).resolve().parents if (parent / "tools/target_store.py").is_file())
sys.path[:0] = [str(ROOT), str(ROOT / "tools")]

from tools.target_store import TargetStore


def main():
    fixture = runpy.run_path(str(ROOT / "tests/test_evidence_ledger.py"))
    with TemporaryDirectory(prefix="f05-actor-evidence-") as directory:
        root = Path(directory)
        store = TargetStore(root, "target.com")
        store.initialize()
        _, raw = fixture["record_observation"](
            store, endpoint="https://target.com/api/accounts/42/export", family="IDOR",
            actor="peer", object_scope="other_object_same_org", variant="id_swap",
            identity_dimensions={},
        )
        kwargs = dict(target=store.target, focus_endpoints=["/api/accounts/42/export"], vuln_classes=["IDOR"])
        original = raw.read_bytes()
        binding = store.binding()
        before = fixture["build_summary"](root, **kwargs)
        raw.write_text("Changed fixture bytes", encoding="utf-8")
        damaged = fixture["build_summary"](root, **kwargs)
        raw.write_bytes(original)
        restored = fixture["build_summary"](root, **kwargs)

        def state(summary):
            peer = next(row for row in summary["actor_matrix"]["rows"] if row["actor"] == "peer")
            return {"peer": peer["status"], "latest_result": peer["latest_result"],
                    "ledger_status": summary["ledger_status"],
                    "invalid_count": summary["ledger_diagnostics"]["invalid_count"],
                    "gaps": summary["actor_matrix"]["gap_count"], "entries": summary["entry_count"]}

        result = {"before": state(before), "damaged": state(damaged), "restored": state(restored),
                  "revision_unchanged": store.binding() == binding,
                  "history_unchanged": before["recent_entries"] == damaged["recent_entries"]}
        assert result["before"]["peer"] == "covered"
        assert result["damaged"]["invalid_count"] == 1
        assert result["revision_unchanged"] and result["history_unchanged"]
        result["f05_reproduced"] = result["damaged"]["peer"] == "covered"
        print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
