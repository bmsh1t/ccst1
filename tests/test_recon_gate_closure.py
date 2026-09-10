"""Recon phase gates must not block Closure on normal pipeline timing.

Three regression anchors from the juice-shop blind run (2026-09-10):
1. A later phase legitimately rewriting a shared artifact (raw_archive
   appends urls/raw/all.txt; every record touches the manifest itself; a
   directory artifact tracks the whole tree) must stay an advisory
   artifact_changed_since_record gap, not force the earlier phase partial.
2. A phase without bounded metadata (skipped for an IP target) must not
   inherit closure_blocking=True from the torn-accounting default; only an
   invalid bounded dict forces blocking.
3. Zero-result API candidate validation must record a resolvable artifact
   reference instead of a wildcard that matches nothing.
"""

import json

from tools.autopilot_state import _blocking_recon_phase_gate, _recon_phase_residuals
from tools.recon_gate import gate_from_record


def _write_manifest(root, records):
    recon_dir = root / "recon" / "target.test"
    recon_dir.mkdir(parents=True, exist_ok=True)
    (recon_dir / "urls" / "raw").mkdir(parents=True, exist_ok=True)
    (recon_dir / "urls" / "raw" / "all.txt").write_text("http://target.test/a\n")
    with (recon_dir / "recon_manifest.jsonl").open("w", encoding="utf-8") as handle:
        for record in records:
            handle.write(json.dumps(record, sort_keys=True) + "\n")
    return root


def test_binding_drift_keeps_complete_status_with_advisory_gap(tmp_path):
    _write_manifest(tmp_path, [])
    gate = gate_from_record(
        tmp_path,
        {
            "record_type": "recon_phase",
            "phase": "url_collection",
            "status": "ok",
            "artifact": "",
        },
    )
    assert gate["status"] == "partial"  # no artifact at all still downgrades

    record = {
        "record_type": "recon_phase",
        "phase": "url_collection",
        "status": "ok",
        "artifact": "recon/target.test/urls/raw/all.txt",
        "note": "input_total=1; selected=1; remaining=0",
        "gate": {
            "status": "complete",
            # A binding from an older generation: later phases appended the file.
            "artifact_binding": {"st_dev": 2049, "st_ino": 999999, "size": 1, "mtime_ns": 1},
        },
    }
    gate = gate_from_record(tmp_path, record)
    assert gate["status"] == "complete"
    assert "artifact_changed_since_record" in gate["coverage_gaps"]
    assert "reconcile" in gate["next_focus"].lower()


def test_skipped_phase_without_bounded_metadata_is_not_closure_blocking(tmp_path):
    _write_manifest(
        tmp_path,
        [
            {
                "record_type": "recon_phase",
                "phase": "subdomain_enum",
                "status": "skipped",
                "artifact": "recon/target.test/live/discovery_hosts.txt",
                "note": "domain targets run passive enum; URL/IP targets seed directly",
            }
        ],
    )
    from tools.runtime_state import _phase_gate_state

    gates = _phase_gate_state(tmp_path / "recon" / "target.test")
    assert gates["latest"]["subdomain_enum"]["status"] == "blocked"

    state = {"recon_artifacts": {"phase_gates": gates}}
    assert _blocking_recon_phase_gate(state)[0] == ""
    residuals = _recon_phase_residuals(state, closure_blocking=True)
    assert residuals == []
