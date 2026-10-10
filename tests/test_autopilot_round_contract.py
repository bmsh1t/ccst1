"""Contract tests for the native `/loop` Autopilot round wrapper."""

import json
from pathlib import Path

from tools import autopilot_bootstrap, autopilot_state
from tools.autopilot_args import parse_autopilot_args


REPO_ROOT = Path(__file__).resolve().parents[1]


def _read(relative_path: str) -> str:
    return (REPO_ROOT / relative_path).read_text(encoding="utf-8")


def test_round_defaults_are_bounded_and_explicit_arguments_win():
    default = parse_autopilot_args(["demo.test"], round_defaults=True)
    explicit = parse_autopilot_args(
        ["demo.test", "--paranoid", "--max-lanes", "7"],
        round_defaults=True,
    )

    assert default["action"] == "continue"
    assert default["cadence"] == "normal"
    assert default["deep"] is True
    assert default["max_lanes"] == 16
    assert default["invocation_batch"] == {
        "bounded": True,
        "max_lanes": 16,
        "handoff": "checkpoint_and_handoff_after_max_lanes",
    }
    assert explicit["cadence"] == "paranoid"
    assert explicit["max_lanes"] == 7


def test_round_bootstrap_cli_forwards_round_defaults(monkeypatch, capsys):
    captured = {}

    def fake_build(argv, *, round_defaults=False):
        captured.update(argv=list(argv), round_defaults=round_defaults)
        return {"action": "continue"}

    monkeypatch.setattr(autopilot_bootstrap, "build_autopilot_bootstrap", fake_build)

    assert (
        autopilot_bootstrap.main(
            ["--json", "--round-defaults", "--", "demo.test", "--quick"]
        )
        == 0
    )
    assert captured == {
        "argv": ["demo.test", "--quick"],
        "round_defaults": True,
    }
    assert json.loads(capsys.readouterr().out) == {"action": "continue"}


def test_round_reuses_the_bootstrap_and_canonical_controller_contract():
    command = _read("commands/autopilot-round.md")
    for tool in ("Bash", "Agent", "ToolSearch", "CronList", "CronDelete",
                 '"mcp__Playwright__*"', '"mcp__chrome-devtools__*"', '"mcp__fofamap__*"'):
        assert f"- {tool}" in command
    assert command.count("autopilot_bootstrap.py") == 1
    assert "--json --round-defaults --" in command
    assert "Read complete H2 `commands/autopilot.md#shared-automation`" in command
    assert "excluding main Bootstrap" in command
    assert "with this Bootstrap, excluding main Bootstrap" in command
    assert "Never invoke `/autopilot`" in command
    assert "run_recon" not in command and "validate_finding" not in command


def test_terminal_precheck_is_state_only_and_precedes_target_work():
    command = _read("commands/autopilot-round.md")
    precheck = command.split("## Prepare And Terminal Precheck", 1)[1].split("## Round Mechanics", 1)[0]
    assert "autopilot_round.py prepare --target <target_shell> --max-lanes <invocation_batch.max_lanes> --json" in precheck
    assert "autopilot_state.py" not in precheck
    assert "`terminal`: no target work" in precheck
    assert "Other results: Status, skipping lanes/settle" in precheck
    assert "Other/missing/malformed: `STATUS: ERROR" in command
    for active in ("tools/hunt.py", "tools/surface.py", "/validate", "/report"):
        assert active not in precheck


def test_round_command_execution_and_advisory_family_contract_is_explicit():
    command = _read("commands/autopilot-round.md")
    shared = _read("commands/autopilot.md").split("## Shared Automation", 1)[1].split("\n## ", 1)[0]
    assert "Use Shared Automation's selected action" in command
    assert "evidence-supported families/primitives/chains" in shared
    assert "rules/tool-ai-boundary.md" in shared
    assert "Unknown AI families" not in command


def test_round_end_uses_explicit_loop_guard_and_owner_settle():
    command = " ".join(_read("commands/autopilot-round.md").split())
    shared = " ".join(_read("commands/autopilot.md").split())
    assert "autopilot_state.py" not in command
    assert shared.count("--loop-check --projection-only --json") == 1
    assert shared.index("Round terminal heartbeat first") < shared.index("--loop-check")
    assert "Use fresh `control`; re-read only after owner writes" in shared
    assert command.index("After heartbeats and shared saving/cleanup") < command.index("autopilot_round.py settle")
    assert "`settled`/`already_settled` complete only this round" in command
    assert "no memory save, Queue sync or Surface refresh" in command
    assert "keeps the round active" not in command
    assert "never blocks settle or flips a settled round back to active" in command
    assert "budget alone never requires another round" in shared


def test_round_budget_is_checkpoint_owned_not_prompt_counted():
    command = " ".join(_read("commands/autopilot-round.md").split())
    shared = " ".join(_read("commands/autopilot.md").split())
    assert "Active checkpoint owns `max_lanes`" in command
    assert "--record-round-lane --lane <stable_lane_id> --max-lanes <invocation_batch.max_lanes> --json" in command
    assert "--record-round-lane-result --lane <stable_lane_id> --lane-status <completed_or_blocked>" in command
    assert "--decision <decision_shell> --evidence-ref <evidence_ref_shell> --next-action <next_action_shell> --json" in command
    assert "recover `started` heartbeats" in command
    assert "never replay other refusals" in command
    assert "Active checkpoint owns `max_lanes`" in command
    assert "`started` lanes forbid closure" in command
    assert "No raw responses/prompts/credentials" in command
    assert "`max_lanes` limits only new lanes, not evidence import/owner write-back/cleanup/Checkpoint/Closure" in shared


def test_round_routes_incomplete_review_forms_through_checkpoint():
    command = " ".join(_read("commands/autopilot-round.md").split())
    assert "Prepare/settle/replay `review_required`: shared Global Review + fresh Closure" in command
    assert "no new lane/round" in command
    assert "Review still required: `STATUS: CONTINUE next_action=global-review`" in command
    shared = _read("commands/autopilot.md").split("## Shared Automation", 1)[1]
    assert "commands/checkpoint.md" in shared and "Re-read Closure after writes" in shared
    checkpoint = _read("commands/checkpoint.md")
    assert "--record-global-review" in checkpoint
    assert "snapshot_digest" in checkpoint


def test_post_review_status_consumes_current_closure_not_stale_coordinator_fields():
    status = " ".join(_read("commands/autopilot-round.md").split("### Status", 1)[1].split())
    assert status.index("unknown/malformed means ERROR") < status.index("`closure.verdict=finish`")
    assert "After review discard old coordinator status; project current" in status
    fresh = autopilot_state.build_decision_projection({
        "target": "demo.test",
        "closure": {"verdict": "finish", "can_claim_exhausted": True, "round_progress": {}},
        "structured_findings": {"reported": 2},
    }, "closure")
    assert "status" not in fresh and "round_progress" not in fresh
    assert fresh["closure"]["verdict"] == "finish"
    assert fresh["closure"]["can_claim_exhausted"] is True
    assert fresh["structured_findings"]["reported"] == 2


def test_round_claims_only_ai_selected_owner_backed_substantive_work():
    command = " ".join(_read("commands/autopilot-round.md").split())
    shared = _read("commands/autopilot.md")
    assert "Use Shared Automation's selected action" in command
    assert command.index("None executable: handoff/closure") < command.index("--record-round-lane")
    assert "AI selects `owner_continuations`" in shared
    assert "select one runnable item from `state.priority_frontier`" not in command
    assert "Never replace selected work with passive" not in command


def test_status_projection_is_owner_driven_and_distinguishes_finish_outcomes():
    command = " ".join(_read("commands/autopilot-round.md").split())
    for field in ("status", "round_progress", "closure", "structured_findings.reported"):
        assert f"`{field}`" in command
    assert "`closure.verdict=finish` + `can_claim_exhausted=true`: reported > 0 → `STATUS: DONE`; reported == 0 → `STATUS: EXHAUSTED" in command
    assert "<closure.next_action>" in command and "<closure.reasons>" in command
    assert "`handoff`: `STATUS: CONTINUE next_action=" in command
    assert "`blocked`: `STATUS: BLOCKED reason=" in command
    assert "Other/missing/malformed: `STATUS: ERROR reason=" in command
    assert "no STATUS override" in command


def test_terminal_statuses_bound_residual_blind_spots_and_exhaustion_claims():
    command = " ".join(_read("commands/autopilot-round.md").split())
    assert "At most five Bootstrap/state-evidenced labels" in command
    assert "no STATUS override or blind-spot store" in command
    assert "none-recorded" in command
    assert "Evidence-bounded, not exhaustive" in command


def test_readme_documents_native_loop_cancellation_and_disk_resume():
    readme = " ".join(_read("README.md").split())

    assert "/loop 10m /autopilot-round target.com --normal --deep --max-lanes 16" in readme
    for status in ("CONTINUE", "DONE", "EXHAUSTED", "BLOCKED", "ERROR"):
        assert f"`{status}`" in readme
    assert "One loop owns one target" in readme
    assert "deletes its exact matching recurring job" in readme
    assert "If a turn is interrupted, the next round resumes from disk" in readme
    assert "does not resume the prior conversational turn" in readme
    assert "evidence-bounded, not proof that every payload" in readme


def test_round_keeps_existing_report_and_live_action_boundaries():
    command = _read("commands/autopilot-round.md")
    shared = _read("commands/autopilot.md")
    assert "commands/autopilot.md#shared-automation" in command
    assert "Scope/Auth" in shared
    assert "commands/report.md" in shared
    assert "no placeholder reports/auto-submission" in shared


def test_bootstrap_errors_stop_and_cancel_without_target_work():
    gate = " ".join(_read("commands/autopilot-round.md").split("## Bootstrap Gate", 1)[1].split("## Prepare And Terminal Precheck", 1)[0].split())
    assert "Only fresh Bootstrap `action=continue` proceeds" in gate
    assert "otherwise terminal cron cleanup" in gate
    assert "`STATUS: ERROR reason=<bounded-summary>`" in gate
    assert "stop before target work/sync" in gate


def test_fixed_interval_loop_cleanup_is_exact_and_terminal_only():
    command = _read("commands/autopilot-round.md")
    scheduler = " ".join(command.split("## Native Loop Ownership", 1)[1].split())
    assert "`/autopilot-round $ARGUMENTS`" in command
    assert "fixed-interval cron job" in scheduler
    assert "`STATUS: CONTINUE`: no CronList/CronDelete" in scheduler
    assert "Before DONE/EXHAUSTED/BLOCKED/ERROR, CronList once" in scheduler
    assert "whose `prompt` exactly equals the expanded fixed-loop prompt identity" in scheduler
    assert "never by substring/cadence/position" in scheduler
    assert "`STATUS: ERROR reason=loop-cancel-failed`" in scheduler
    assert "Never create or modify cron jobs" in scheduler


def test_shared_h2_contains_recovery_loop_and_finish_without_bootstrap():
    command = _read("commands/autopilot.md")
    shared = command.split("\n## Shared Automation\n", 1)[1].split("\n## ", 1)[0]
    assert "autopilot_bootstrap.py" not in shared
    assert "AUTOPILOT_CRITICAL_RUNTIME_MANIFEST" not in shared
    for heading in ("Startup And Recovery", "State Consumption Loop", "Execution Invariants", "Transition And Finish Contract"):
        assert f"### {heading}" in shared
    assert "read/apply complete" in shared
    assert "skills/runtime-protocol.md#shared-memory-continuity" in shared
    assert "resume/compaction" in shared and "--closure" in shared
    assert "SHARED_AUTOMATION_START" not in command and "SHARED_AUTOMATION_END" not in command


def test_round_claim_precedes_recon_without_changing_ordinary_defaults():
    shared = _read("commands/autopilot.md").split("### State Consumption Loop", 1)[1]
    assert shared.index("Round only: claim lane") < shared.index("`run_recon`: dispatch")
    assert shared.index("`run_recon`: dispatch") < shared.index("#state-and-queue")
    assert "never merely deep/bounded flags" in _read("commands/autopilot.md")
    ordinary = parse_autopilot_args(["demo.test"])
    assert ordinary["cadence"] == "paranoid"
    assert ordinary["deep"] is False
    assert ordinary["invocation_batch"]["bounded"] is False


def test_non_action_work_does_not_require_a_fabricated_queue_claim():
    shared = " ".join(_read("commands/autopilot.md").split("### State Consumption Loop", 1)[1].split())
    assert "Before Action-bound execution read" in shared
    assert "Register/resolve/kill as applicable" in shared
    assert "Independent native evidence may register unbound" in shared


def test_combined_entry_budget_and_pre_execution_claim_owner():
    # 11 KiB merged floor: restored do-not-reinterpret anchors, the settle
    # stale-Surface contract and full command descriptions sit above the
    # 10 KiB budget of the pre-merge draft.
    assert sum((REPO_ROOT / path).stat().st_size for path in (
        "commands/autopilot.md", "commands/autopilot-round.md"
    )) <= 11 * 1024
    shared = _read("commands/autopilot.md")
    before_result = shared.split("5. Register/resolve/kill", 1)[0]
    assert "Before Action-bound execution read" in before_result
    assert "docs/evidence-runners.md#绑定已认领行动" in before_result
    assert "same explicit `--actor OPERATOR`" in before_result
    binding = _read("docs/evidence-runners.md").split("### 绑定已认领行动", 1)[1].split("\n## ", 1)[0]
    assert "--action-id ACTION_ID --claim-token CLAIM_TOKEN --actor OPERATOR" in binding
    assert "登记不完成行动" in binding and "partial/unknown 不能完成" in binding
