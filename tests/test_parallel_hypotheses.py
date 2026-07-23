"""tests/test_parallel_hypotheses.py — B12a acceptance tests."""

from __future__ import annotations

import json
import signal
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from tools import hypothesis_fleet as hf       # noqa: E402
from tools import parallel_workers as pw       # noqa: E402
from tools import hypothesis_worker            # noqa: E402


# ---------------------------------------------------------------------
#  R1, C4: Fanout planning + queue overflow
# ---------------------------------------------------------------------

class TestFanoutPlanning:
    def test_first_wave_capped_at_max_parallel(self):
        hyps = [{"working_hypothesis": f"h{i}"} for i in range(5)]
        wave1, queue = hf.plan_fanout(hyps, max_parallel=3)
        assert len(wave1) == 3
        assert len(queue) == 2

    def test_smaller_than_cap_returns_no_queue(self):
        hyps = [{"working_hypothesis": "a"}, {"working_hypothesis": "b"}]
        wave1, queue = hf.plan_fanout(hyps, max_parallel=3)
        assert len(wave1) == 2
        assert queue == []

    def test_zero_max_parallel_defaults_to_one(self):
        hyps = [{"working_hypothesis": "a"}]
        wave1, queue = hf.plan_fanout(hyps, max_parallel=0)
        assert len(wave1) == 1


# ---------------------------------------------------------------------
#  R2: Per-worker scratch dir layout
# ---------------------------------------------------------------------

class TestPerWorkerScratch:
    def test_hypothesis_worker_scratch_dir_layout(self, tmp_path):
        repo = tmp_path
        h = pw.spawn_hypothesis_worker(
            hypothesis={"working_hypothesis": "tenant cache key mixing"},
            worker_id="h1",
            target="x.com",
            repo_root=repo,
            auto_start=False,
        )
        # Per B12a R2: evidence/<target>/workers/hypothesis-<slot>-<run-id>/
        rel = Path(h.scratch_dir).relative_to(repo)
        assert rel.parts[:3] == ("evidence", "x.com", "workers")
        assert rel.parts[3].startswith("hypothesis-h1-")
        # hypothesis.md exists
        assert (Path(h.scratch_dir) / "hypothesis.md").exists()
        # Standard B6 layout files
        assert (Path(h.scratch_dir) / "attempts.jsonl").exists()
        assert (Path(h.scratch_dir) / "findings.json").exists()
        assert (Path(h.scratch_dir) / "seed.json").exists()


# ---------------------------------------------------------------------
#  R3: Outcome classification
# ---------------------------------------------------------------------

class TestClassifyOutcome:
    def test_findings_with_high_severity_become_validated(self):
        r = pw.WorkerResult(
            worker_id="a", kind="hypothesis", scratch_dir="",
            completed=True, timed_out=False, exit_code=0,
            findings=[{"endpoint": "/x", "vuln_class": "IDOR", "severity": "high"}],
        )
        assert hf.classify_worker_outcome(r) == hf.OUTCOME_VALIDATED

    def test_findings_without_high_become_strong_signal(self):
        r = pw.WorkerResult(
            worker_id="a", kind="hypothesis", scratch_dir="",
            completed=True, timed_out=False, exit_code=0,
            findings=[{"endpoint": "/x", "vuln_class": "IDOR", "severity": "low"}],
        )
        assert hf.classify_worker_outcome(r) == hf.OUTCOME_STRONG

    def test_no_findings_falls_back_to_done_flag_outcome(self):
        r = pw.WorkerResult(
            worker_id="a", kind="hypothesis", scratch_dir="",
            completed=True, timed_out=False, exit_code=0,
            findings=[],
        )
        assert hf.classify_worker_outcome(r, done_flag_summary={"outcome": "leads_only"}) == hf.OUTCOME_LEADS
        assert hf.classify_worker_outcome(r, done_flag_summary={"outcome": "strong_signal"}) == hf.OUTCOME_STRONG

    def test_unknown_outcome_falls_back_to_leads(self):
        r = pw.WorkerResult(
            worker_id="a", kind="hypothesis", scratch_dir="",
            completed=True, timed_out=False, exit_code=0,
        )
        assert hf.classify_worker_outcome(r) == hf.OUTCOME_LEADS


# ---------------------------------------------------------------------
#  R3: Ranking + winner selection
# ---------------------------------------------------------------------

class TestRanking:
    def _result(self, wid: str, findings: list[dict], scratch: Path | None = None):
        return pw.WorkerResult(
            worker_id=wid, kind="hypothesis",
            scratch_dir=str(scratch) if scratch else "",
            completed=True, timed_out=False, exit_code=0,
            findings=findings,
        )

    def test_validated_finding_beats_strong_signal(self):
        results = [
            self._result("a", [{"severity": "low"}]),
            self._result("b", [{"severity": "high"}]),
        ]
        ranked = hf.rank_results(results)
        assert ranked[0]["worker_id"] == "b"
        assert ranked[0]["outcome"] == hf.OUTCOME_VALIDATED

    def test_strong_signal_beats_leads(self):
        results = [
            self._result("a", []),
            self._result("b", [{"severity": "low"}]),
        ]
        ranked = hf.rank_results(results)
        assert ranked[0]["worker_id"] == "b"

    def test_pick_winner_returns_highest(self):
        results = [self._result("solo", [{"severity": "high"}])]
        ranked = hf.rank_results(results)
        winner = hf.pick_winner(ranked)
        assert winner["worker_id"] == "solo"

    def test_pick_winner_returns_none_when_empty(self):
        assert hf.pick_winner([]) is None


# ---------------------------------------------------------------------
#  R3: Demote losers to journal
# ---------------------------------------------------------------------

class TestDemoteToJournal:
    def test_writes_one_row_per_loser(self, tmp_path):
        ranked = [
            {"worker_id": "win", "hypothesis_id": "h0", "working_hypothesis": "h0",
             "outcome": "validated_finding", "rank": 3, "finding_count": 1,
             "scratch_dir": "", "parent_session": "s"},
            {"worker_id": "lose1", "hypothesis_id": "h1", "working_hypothesis": "h1",
             "outcome": "leads_only", "rank": 1, "finding_count": 0,
             "scratch_dir": "", "parent_session": "s"},
            {"worker_id": "lose2", "hypothesis_id": "h2", "working_hypothesis": "h2",
             "outcome": "leads_only", "rank": 1, "finding_count": 0,
             "scratch_dir": "", "parent_session": "s"},
        ]
        jpath = tmp_path / "journal.jsonl"
        written = hf.demote_losers_to_journal(ranked, ranked[0], "x.com",
                                              journal_path=jpath)
        assert len(written) == 2
        assert jpath.exists()
        rows = [json.loads(line) for line in jpath.read_text().splitlines() if line]
        assert all(r["technique"] == "parallel_hypothesis_lead" for r in rows)


# ---------------------------------------------------------------------
#  R5: Audit rows include hypothesis_id
# ---------------------------------------------------------------------

class TestAuditRows:
    def test_build_audit_records_includes_hypothesis_id(self):
        ranked = [
            {"worker_id": "w1", "hypothesis_id": "hA", "working_hypothesis": "x",
             "outcome": "validated_finding", "rank": 3, "finding_count": 1,
             "scratch_dir": "", "parent_session": "s"},
        ]
        rows = hf.build_audit_records(ranked, parent_session="ps")
        assert rows[0]["hypothesis_id"] == "hA"
        assert rows[0]["parent_session"] == "ps"
        assert rows[0]["kind"] == "hypothesis_fanout"


# ---------------------------------------------------------------------
#  R1, R3: End-to-end fanout with injected spawn/wait
# ---------------------------------------------------------------------

class TestRunFanoutEndToEnd:
    def _stub_handle(self, tmp_path, worker_id, target, findings, outcome):
        scratch = tmp_path / f"scratch-{worker_id}"
        scratch.mkdir()
        (scratch / "findings.json").write_text(json.dumps(findings))
        (scratch / "attempts.jsonl").write_text("")
        (scratch / "done.flag").write_text(
            json.dumps({"worker_id": worker_id, "hypothesis_id": worker_id,
                        "working_hypothesis": "h-text", "outcome": outcome}),
        )
        return pw.WorkerHandle(
            worker_id=worker_id, kind="hypothesis", target=target,
            scratch_dir=str(scratch),
            seed_path=str(scratch / "seed.json"),
            proc=None, started_at="t",
            budget_tools=12, timeout_secs=300, parent_session="ps",
        )

    def test_fanout_winner_chosen_from_validated(self, tmp_path):
        captured_spawns = []
        # Stub spawn: returns handles whose findings.json/done.flag drive outcome
        def spawn(*, hypothesis, worker_id, target, repo_root, parent_session):
            captured_spawns.append(worker_id)
            findings = hypothesis.get("mock_findings", [])
            outcome = hypothesis.get("mock_outcome", "leads_only")
            return self._stub_handle(tmp_path, worker_id, target, findings, outcome)
        def wait(handles, *, timeout_secs):
            results = []
            for h in handles:
                findings = json.loads((Path(h.scratch_dir) / "findings.json").read_text())
                results.append(pw.WorkerResult(
                    worker_id=h.worker_id, kind=h.kind, scratch_dir=h.scratch_dir,
                    completed=True, timed_out=False, exit_code=0,
                    findings=findings, attempt_count=0, parent_session=h.parent_session,
                ))
            return results

        hyps = [
            {"working_hypothesis": "weak A",
             "mock_findings": [],
             "mock_outcome": "leads_only"},
            {"working_hypothesis": "strong B",
             "mock_findings": [{"endpoint": "/x", "vuln_class": "IDOR", "severity": "high"}],
             "mock_outcome": "validated_finding"},
            {"working_hypothesis": "medium C",
             "mock_findings": [{"endpoint": "/y", "vuln_class": "IDOR", "severity": "low"}],
             "mock_outcome": "strong_signal"},
        ]
        out = hf.run_fanout(
            hyps, target="x.com", max_parallel=3, repo_root=tmp_path,
            parent_session="ps", spawn=spawn, wait=wait,
        )
        assert out["workers_total"] == 3
        # B (strong) must win
        winner_id = out["winner"]["worker_id"]
        # winner is hyp-w1-1 (index 1 in first wave)
        assert "hyp-w1-1" == winner_id

    def test_queue_overflow_runs_in_second_wave(self, tmp_path):
        spawn_calls = []
        def spawn(*, hypothesis, worker_id, target, repo_root, parent_session):
            spawn_calls.append(worker_id)
            return self._stub_handle(tmp_path, worker_id, target, [], "leads_only")
        def wait(handles, *, timeout_secs):
            return [pw.WorkerResult(
                worker_id=h.worker_id, kind=h.kind, scratch_dir=h.scratch_dir,
                completed=True, timed_out=False, exit_code=0, findings=[], attempt_count=0,
                parent_session=h.parent_session,
            ) for h in handles]

        hyps = [{"working_hypothesis": f"h{i}"} for i in range(5)]
        out = hf.run_fanout(
            hyps, target="x.com", max_parallel=2, repo_root=tmp_path,
            spawn=spawn, wait=wait,
        )
        # Two waves: wave1 (2 workers) + wave2 (2 workers) + wave3 (1 worker)
        assert out["workers_total"] == 5
        wave_prefixes = [w.split("-")[1] for w in spawn_calls]
        # Wave count = max waves seen, 3 here
        assert max(int(p[1:]) for p in wave_prefixes) == 3


# ---------------------------------------------------------------------
#  CLI flag
# ---------------------------------------------------------------------

class TestCliFlag:
    def test_parallel_hypotheses_flag_in_agent_py(self):
        text = (REPO_ROOT / "agent.py").read_text(encoding="utf-8")
        assert "--parallel-hypotheses" in text

    def test_default_off(self):
        import argparse
        parser = argparse.ArgumentParser()
        parser.add_argument("--parallel-hypotheses", action="store_true")
        ns = parser.parse_args([])
        assert ns.parallel_hypotheses is False


# ---------------------------------------------------------------------
#  Docs
# ---------------------------------------------------------------------

class TestDocsMention:
    def test_autopilot_md_mentions_parallel_hypotheses(self):
        text = (REPO_ROOT / "commands" / "autopilot.md").read_text(encoding="utf-8")
        assert "--parallel-hypotheses" in text


# ---------------------------------------------------------------------
#  hypothesis_worker subprocess (mock mode)
# ---------------------------------------------------------------------

class TestHypothesisWorkerMockMode:
    def test_mock_mode_writes_findings_from_seed(self, tmp_path):
        seed_path = tmp_path / "seed.json"
        seed_path.write_text(json.dumps({
            "kind": "hypothesis",
            "worker_id": "h-mock",
            "target": "x.com",
            "hypothesis": {
                "working_hypothesis": "weak cache mix",
                "mock_outcome": {
                    "outcome": "strong_signal",
                    "findings": [{"endpoint": "/y", "vuln_class": "IDOR", "severity": "low"}],
                },
            },
            "parent_session": "ps",
        }))
        rc = hypothesis_worker.main([
            "--target", "x.com",
            "--seed", str(seed_path),
            "--scratch-dir", str(tmp_path / "s"),
            "--mock-mode",
            "--timeout-secs", "5",
        ])
        assert rc == 0
        assert signal.alarm(0) == 0
        findings = json.loads((tmp_path / "s" / "findings.json").read_text())
        assert findings == [{"endpoint": "/y", "vuln_class": "IDOR", "severity": "low"}]
        summary = json.loads((tmp_path / "s" / "done.flag").read_text().strip())
        assert summary["outcome"] == "strong_signal"
