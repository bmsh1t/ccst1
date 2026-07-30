"""Contract tests for the native `/loop` Autopilot round wrapper."""

import json
from pathlib import Path

from tools import autopilot_bootstrap
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
    assert default["max_lanes"] == 3
    assert default["invocation_batch"] == {
        "bounded": True,
        "max_lanes": 3,
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
    normalized = " ".join(command.split())

    for tool in (
        "Bash",
        "Agent",
        "ToolSearch",
        "CronList",
        "CronDelete",
        '"mcp__Playwright__*"',
        '"mcp__chrome-devtools__*"',
    ):
        assert f"- {tool}" in command
    assert command.count("autopilot_bootstrap.py") == 1
    assert "--json --round-defaults --" in command
    assert "read and obey `commands/autopilot.md` as the sole controller contract" in normalized
    assert "Do not execute its embedded bootstrap again" in normalized
    assert "run_recon" not in command
    assert "validate_finding" not in command


def test_terminal_precheck_is_state_only_and_precedes_target_work():
    command = _read("commands/autopilot-round.md")
    precheck = command.split("## Read-Only Terminal Precheck", 1)[1].split(
        "## One Canonical Round", 1
    )[0]
    normalized_precheck = " ".join(precheck.split())
    closure = (
        "python3 tools/autopilot_state.py --target <target_shell> "
        "--bounded --closure --json"
    )

    assert command.index("## Read-Only Terminal Precheck") < command.index(
        "## One Canonical Round"
    )
    assert closure in precheck
    assert f"{closure} --max-lanes-reached" not in precheck
    assert "`finish` or `blocked` is terminal" in normalized_precheck
    assert "apply terminal cron cleanup, emit, and stop" in normalized_precheck
    assert "For STATUS selection, read only `closure.verdict`" in normalized_precheck
    assert "For terminal residual blind spots only" in normalized_precheck
    assert "these advisory facts never select or override STATUS" in normalized_precheck
    assert "stop without any target action" in normalized_precheck
    for active_path in ("tools/hunt.py", "tools/surface.py", "/validate", "/report"):
        assert active_path not in precheck


def test_round_end_orders_checkpoint_coverage_and_lane_limited_closure():
    command = _read("commands/autopilot-round.md")
    normalized = " ".join(command.split())
    checkpoint = command.index("After the canonical checkpoint/write-back")
    rebuild = command.index("python3 tools/coverage_matrix.py rebuild", checkpoint)
    gaps = command.index("python3 tools/coverage_matrix.py find-gaps", rebuild)
    record = command.index("python3 tools/checkpoint.py --target <target_shell> --record-round-closure --json", gaps)
    closure = command.index(
        "python3 tools/autopilot_state.py --target <target_shell> --bounded --closure --json",
        record,
    )

    assert checkpoint < rebuild < gaps < record < closure
    assert "After every substantive lane" in command
    assert "canonical `--loop-check --json` guard" in command
    assert "at most bootstrap `invocation_batch.max_lanes`" in normalized
    assert "Include `--max-lanes-reached` only when this invocation actually executed its full substantive-lane budget" in normalized


def test_status_projection_is_owner_driven_and_distinguishes_finish_outcomes():
    command = " ".join(_read("commands/autopilot-round.md").split())

    assert "`structured_findings.reported > 0`: `STATUS: DONE" in command
    assert "`structured_findings.reported == 0`: `STATUS: EXHAUSTED" in command
    assert "`handoff`: `STATUS: CONTINUE next_action=" in command
    assert "`blocked`: `STATUS: BLOCKED reason=" in command
    assert "Any other shape: `STATUS: ERROR reason=" in command
    assert "After a successful bootstrap, closure owner fields alone select STATUS" in command
    assert "never override them" in command
    assert "`stop_runtime_error`" in command


def test_terminal_statuses_bound_residual_blind_spots_and_exhaustion_claims():
    command = " ".join(_read("commands/autopilot-round.md").split())

    assert "emit at most five labels already evidenced by bootstrap/state" in command
    assert "Do not create a new blind-spot store or speculate beyond state" in command
    assert "`none-recorded`" in command
    assert "not universal absence" in command
    assert "`EXHAUSTED` is evidence-bounded" in command
    assert "does not prove that every payload, identity, timing, business state, or vulnerability has been exhausted" in command


def test_readme_documents_native_loop_cancellation_and_disk_resume():
    readme = " ".join(_read("README.md").split())

    assert "/loop 10m /autopilot-round target.com --normal --deep --max-lanes 3" in readme
    for status in ("CONTINUE", "DONE", "EXHAUSTED", "BLOCKED", "ERROR"):
        assert f"`{status}`" in readme
    assert "One loop owns one target" in readme
    assert "deletes its exact matching recurring job" in readme
    assert "If a turn is interrupted, the next round resumes from disk" in readme
    assert "does not resume legacy `agent.py --agent` working memory" in readme
    assert "evidence-bounded, not proof that every payload" in readme


def test_round_keeps_existing_report_and_live_action_boundaries():
    command = " ".join(_read("commands/autopilot-round.md").split())

    assert "All `commands/autopilot.md` pause boundaries remain unchanged" in command
    assert "never auto-submit reports" in command
    assert "destructive, irreversible, target, credential, or current-turn confirmation boundaries" in command


def test_bootstrap_errors_stop_and_cancel_without_target_work():
    command = _read("commands/autopilot-round.md")
    gate = command.split("## Bootstrap Gate", 1)[1].split(
        "## Read-Only Terminal Precheck", 1
    )[0]
    normalized = " ".join(gate.split())

    for action in ("ask_target", "stop_invalid_arguments", "stop_runtime_drift"):
        assert f"`{action}`" in gate
    assert "apply the terminal cron cleanup" in normalized
    assert "`STATUS: ERROR reason=<bounded-summary>`" in normalized
    assert "do not perform a target action" in normalized


def test_fixed_interval_loop_cleanup_is_exact_and_terminal_only():
    command = _read("commands/autopilot-round.md")
    scheduler = command.split("## Native Loop Ownership", 1)[1]
    normalized = " ".join(scheduler.split())

    assert "Native fixed-loop prompt identity" in command
    assert "`/autopilot-round $ARGUMENTS`" in command
    assert "fixed-interval cron job" in normalized
    assert "For `STATUS: CONTINUE`, do not call CronList or CronDelete" in normalized
    assert "Before emitting DONE, EXHAUSTED, BLOCKED, or ERROR, call CronList once" in normalized
    assert "whose `prompt` exactly equals" in normalized
    assert "Never delete by target substring, cadence alone, or job position" in normalized
    assert "load exactly CronList and CronDelete through ToolSearch once" in normalized
    assert "No exact match means" in normalized
    assert "`STATUS: ERROR reason=loop-cancel-failed`" in normalized
    assert "Never create or modify a cron job from this wrapper" in normalized
