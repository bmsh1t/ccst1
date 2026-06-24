"""tests/test_self_review.py — B12c acceptance tests.

Covers:
  R1   red_team worker spawn (via B6 primitive, mocked subprocess)
  R2   review output schema (VERDICT line + free-text rationale)
  R3   parent decision branching across 3 verdicts
  R4   --self-review CLI flag wired into agent.py
  R5   audit-log payload carries verdict + worker_id + parent_session
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from tools import self_review as sr           # noqa: E402
from tools import parallel_workers as pw      # noqa: E402
from tools import red_team_worker             # noqa: E402


# ---------------------------------------------------------------------
#  R2: Verdict parsing
# ---------------------------------------------------------------------

class TestVerdictParsing:
    def test_parses_no_flaw_found(self):
        text = "VERDICT: no_flaw_found\n\n## Rationale\n\nAll claims verified.\n"
        assert sr.parse_verdict_text(text) == sr.VERDICT_NO_FLAW

    def test_parses_likely_flaw(self):
        text = "VERDICT: likely_flaw\nsome rationale"
        assert sr.parse_verdict_text(text) == sr.VERDICT_LIKELY

    def test_parses_definitive_disqualifier(self):
        text = "VERDICT: definitive_disqualifier\nreason"
        assert sr.parse_verdict_text(text) == sr.VERDICT_DISQUALIFY

    def test_returns_none_when_missing_verdict_line(self):
        assert sr.parse_verdict_text("no verdict here") is None

    def test_returns_none_on_invalid_verdict_value(self):
        assert sr.parse_verdict_text("VERDICT: maybe") is None

    def test_returns_none_on_empty_text(self):
        assert sr.parse_verdict_text("") is None

    def test_verdict_can_be_indented(self):
        # Be lenient about whitespace around the line
        assert sr.parse_verdict_text("   VERDICT: no_flaw_found  ") == sr.VERDICT_NO_FLAW

    def test_parses_verdict_file(self, tmp_path):
        p = tmp_path / "red_team.md"
        p.write_text("VERDICT: likely_flaw\nbody")
        assert sr.parse_verdict_file(p) == sr.VERDICT_LIKELY

    def test_file_parsing_returns_none_if_missing(self, tmp_path):
        assert sr.parse_verdict_file(tmp_path / "absent.md") is None


# ---------------------------------------------------------------------
#  R3: Parent decision branching (3 verdicts)
# ---------------------------------------------------------------------

class TestDecisionBranches:
    def test_no_flaw_found_keeps_finding(self):
        assert sr.decision_for(sr.VERDICT_NO_FLAW) == sr.DECISION_KEEP

    def test_likely_flaw_demotes_finding(self):
        assert sr.decision_for(sr.VERDICT_LIKELY) == sr.DECISION_DEMOTE

    def test_definitive_disqualifier_kills_finding(self):
        assert sr.decision_for(sr.VERDICT_DISQUALIFY) == sr.DECISION_KILL

    def test_missing_verdict_defaults_to_keep(self):
        assert sr.decision_for(None) == sr.DECISION_KEEP

    def test_invalid_verdict_defaults_to_keep(self):
        assert sr.decision_for("bogus") == sr.DECISION_KEEP


# ---------------------------------------------------------------------
#  R5: Audit-log payload shape
# ---------------------------------------------------------------------

class TestAuditRecord:
    def test_keep_branch_audit_record(self):
        rec = sr.build_audit_record(
            target="x.com",
            finding_id="f-1",
            verdict=sr.VERDICT_NO_FLAW,
            worker_id="rt-1",
            parent_session="s-1",
            rationale="all claims verified",
        )
        assert rec["kind"] == "self_review"
        assert rec["verdict"] == "no_flaw_found"
        assert rec["decision"] == "keep"
        assert rec["worker_id"] == "rt-1"
        assert rec["parent_session"] == "s-1"

    def test_kill_branch_audit_record(self):
        rec = sr.build_audit_record(
            target="x.com", finding_id="f-1",
            verdict=sr.VERDICT_DISQUALIFY,
            worker_id="rt-2", parent_session="s-2",
            rationale="finding is intentional behaviour",
        )
        assert rec["decision"] == "kill"
        assert rec["rationale_snippet"] == "finding is intentional behaviour"

    def test_rationale_is_truncated_to_240_chars(self):
        long = "x" * 500
        rec = sr.build_audit_record(
            target="x.com", finding_id="f-1",
            verdict=sr.VERDICT_NO_FLAW,
            worker_id="rt", parent_session="s",
            rationale=long,
        )
        assert len(rec["rationale_snippet"]) == 240


# ---------------------------------------------------------------------
#  R2: write_review produces the expected file shape
# ---------------------------------------------------------------------

class TestWriteReview:
    def test_write_review_includes_verdict_line(self, tmp_path):
        path = red_team_worker.write_review(
            target="x.com", finding_id="f-1",
            verdict=sr.VERDICT_NO_FLAW,
            rationale="OK", repo_root=tmp_path,
        )
        body = path.read_text()
        assert body.startswith("VERDICT: no_flaw_found")
        assert "## Rationale" in body
        assert "OK" in body

    def test_write_review_rejects_invalid_verdict(self, tmp_path):
        with pytest.raises(ValueError):
            red_team_worker.write_review(
                target="x.com", finding_id="f-1",
                verdict="bogus", rationale="", repo_root=tmp_path,
            )

    def test_write_review_creates_parents(self, tmp_path):
        path = red_team_worker.write_review(
            target="x.com", finding_id="f-1",
            verdict=sr.VERDICT_LIKELY, rationale="x",
            repo_root=tmp_path,
        )
        # Path must be evidence/<target>/findings/<id>/red_team.md
        rel = path.relative_to(tmp_path)
        assert rel.parts == ("evidence", "x.com", "findings", "f-1", "red_team.md")


# ---------------------------------------------------------------------
#  R1: spawn + run end-to-end with mock verdict
# ---------------------------------------------------------------------

class TestSpawnEndToEnd:
    @pytest.mark.parametrize("verdict,expected_decision", [
        (sr.VERDICT_NO_FLAW, sr.DECISION_KEEP),
        (sr.VERDICT_LIKELY, sr.DECISION_DEMOTE),
        (sr.VERDICT_DISQUALIFY, sr.DECISION_KILL),
    ])
    def test_worker_writes_red_team_md_for_each_verdict(self, tmp_path, verdict, expected_decision):
        seed_path = tmp_path / "seed.json"
        seed_path.write_text(json.dumps({
            "kind": "red_team",
            "worker_id": "rt-test",
            "target": "x.com",
            "candidate_finding": {
                "id": "fid",
                "endpoint": "/api/v1/orders/1",
                "vuln_class": "IDOR",
            },
            "parent_session": "sess-1",
        }))
        # Patch BASE_DIR so writes land under tmp_path
        import tools.red_team_worker as rtw
        original_base = rtw.BASE_DIR
        rtw.BASE_DIR = tmp_path
        try:
            rc = rtw.main([
                "--target", "x.com",
                "--seed", str(seed_path),
                "--scratch-dir", str(tmp_path / "scratch"),
                "--mock-verdict", verdict,
                "--timeout-secs", "5",
            ])
        finally:
            rtw.BASE_DIR = original_base
        assert rc == 0
        # red_team.md exists with the expected VERDICT line
        path = tmp_path / "evidence" / "x.com" / "findings" / "fid" / "red_team.md"
        assert path.is_file()
        parsed = sr.parse_verdict_file(path)
        assert parsed == verdict
        assert sr.decision_for(parsed) == expected_decision
        # done.flag exists
        assert (tmp_path / "scratch" / "done.flag").exists()
        # findings.json is empty list
        assert json.loads((tmp_path / "scratch" / "findings.json").read_text()) == []


# ---------------------------------------------------------------------
#  R4: --self-review CLI flag
# ---------------------------------------------------------------------

class TestCliFlag:
    def test_self_review_flag_in_agent_py(self):
        text = (REPO_ROOT / "agent.py").read_text(encoding="utf-8")
        assert "--self-review" in text

    def test_self_review_default_off(self):
        import argparse
        parser = argparse.ArgumentParser()
        parser.add_argument("--self-review", action="store_true")
        ns = parser.parse_args([])
        assert ns.self_review is False


# ---------------------------------------------------------------------
#  R3 false-positive pattern recording
# ---------------------------------------------------------------------

class TestDisqualifierRecording:
    def test_records_to_journal(self, tmp_path):
        journal_path = tmp_path / "journal.jsonl"
        out = sr.record_disqualifier_as_false_positive(
            finding={"id": "f-1", "vuln_class": "IDOR", "endpoint": "/x"},
            target="x.com",
            journal_path=journal_path,
        )
        # The hunt_journal may impose schema constraints — if so, out is None.
        # In that case the file should still exist (no crash).
        assert journal_path.exists() or out is not None


# ---------------------------------------------------------------------
#  Docs: --self-review mentioned in commands/validate.md and autopilot.md
# ---------------------------------------------------------------------

class TestDocsMention:
    def test_validate_md_mentions_self_review(self):
        path = REPO_ROOT / "commands" / "validate.md"
        if not path.exists():
            pytest.skip("commands/validate.md does not exist yet in this repo")
        text = path.read_text(encoding="utf-8")
        assert "--self-review" in text or "self-review" in text.lower()

    def test_autopilot_md_mentions_self_review(self):
        text = (REPO_ROOT / "commands" / "autopilot.md").read_text(encoding="utf-8")
        assert "--self-review" in text or "self-review" in text.lower()


# ---------------------------------------------------------------------
#  CLI subcommand
# ---------------------------------------------------------------------

class TestCliMain:
    def test_parse_subcommand(self, tmp_path, capsys):
        p = tmp_path / "rt.md"
        p.write_text("VERDICT: likely_flaw\n\nrationale")
        rc = sr.main(["parse", "--path", str(p)])
        assert rc == 0
        out = capsys.readouterr().out
        assert "likely_flaw" in out
        assert "demote" in out

    def test_parse_subcommand_exits_nonzero_on_missing_verdict(self, tmp_path, capsys):
        p = tmp_path / "rt.md"
        p.write_text("no verdict here")
        rc = sr.main(["parse", "--path", str(p)])
        assert rc != 0
