"""Regression tests for validation-time pattern calibration wiring."""

from __future__ import annotations

import json


class TestCalibrationWiring:
    def test_validate_module_exposes_record_validation_calibration(self):
        from tools import validate

        assert callable(validate.record_validation_calibration)

    def test_outcome_mapping(self):
        from tools.validate import _map_validate_result_to_calibration_outcome as mapfn

        assert mapfn("confirmed") == "helped"
        assert mapfn("rejected") == "false_positive"
        assert mapfn("partial") == "no_signal"
        assert mapfn("informational") == "no_signal"
        assert mapfn("") is None
        assert mapfn("???") is None
        assert mapfn(None) is None  # type: ignore[arg-type]

    def test_record_validation_calibration_writes_helped(self, tmp_path):
        from tools.validate import record_validation_calibration

        cal_path = tmp_path / "cal.jsonl"
        record = record_validation_calibration(
            {
                "target": "alpha.com",
                "vuln_class": "idor",
                "result": "confirmed",
                "technique": "swap-numeric",
            },
            path=cal_path,
        )

        assert record is not None
        assert record["outcome"] == "helped"
        assert record["pattern_id"] == "alpha.com|idor|swap-numeric"
        assert json.loads(cal_path.read_text().strip())["outcome"] == "helped"

    def test_record_validation_calibration_skips_invalid_summary(self, tmp_path):
        from tools.validate import record_validation_calibration

        cal_path = tmp_path / "cal.jsonl"
        for summary in (
            {"target": "", "vuln_class": "idor", "result": "confirmed"},
            {"target": "alpha.com", "vuln_class": "", "result": "confirmed"},
            {"target": "alpha.com", "vuln_class": "idor", "result": "wat"},
        ):
            assert record_validation_calibration(summary, path=cal_path) is None
        assert not cal_path.exists()

    def test_update_runtime_state_after_validate_calls_calibration(self, tmp_path, monkeypatch):
        from tools import validate as validate_module

        calls: list[dict] = []

        def fake_record(summary, *, session_id="", path=None):
            calls.append({"summary": summary, "session_id": session_id})
            return {"ok": True}

        monkeypatch.setattr(validate_module, "record_validation_calibration", fake_record)
        from tools import runtime_state

        monkeypatch.setattr(runtime_state, "update_runtime_state", lambda *a, **k: None, raising=False)
        monkeypatch.setattr(runtime_state, "inspect_recon_artifacts", lambda *a, **k: {}, raising=False)

        validate_module.update_runtime_state_after_validate(
            {
                "target": "gamma.com",
                "vuln_class": "ssrf",
                "result": "confirmed",
                "session_id": "sess-123",
            }
        )

        assert calls == [{
            "summary": {
                "target": "gamma.com",
                "vuln_class": "ssrf",
                "result": "confirmed",
                "session_id": "sess-123",
            },
            "session_id": "sess-123",
        }]
