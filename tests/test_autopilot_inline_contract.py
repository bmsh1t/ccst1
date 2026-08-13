"""Claude CLI `/autopilot` inline 与 legacy agent 入口分离契约。"""

from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]


def _read(relative_path: str) -> str:
    return (REPO_ROOT / relative_path).read_text(encoding="utf-8")


def test_slash_command_runs_inline_with_one_controller_and_bounded_specialist():
    text = _read("commands/autopilot.md")
    normalized = " ".join(text.split())

    assert "runs inline in the current Claude session as the sole controller" in normalized
    assert "does not create/resume legacy `agent_session.json`" in normalized
    assert "specialists default to zero" in normalized
    assert "At most one bounded specialist" in normalized
    assert "The invoked specialist must not spawn nested agents, run full recon/scans, write final closure, or control finish" in normalized
    assert "--isolated" not in text


def test_slash_command_uses_authoritative_parser_and_rejects_legacy_flags():
    text = _read("commands/autopilot.md")
    normalized = " ".join(text.split())

    assert 'allowed-tools:' in text
    assert '- Bash' in text
    assert '- Agent' in text
    assert 'mcp__Playwright__*' in text
    assert 'mcp__chrome-devtools__*' in text
    assert 'mcp__fofamap__*' in text
    assert "through Claude Code's `Agent` tool" in normalized
    assert 'tools/autopilot_bootstrap.py" --json -- "$0" "$1" "$2" "$3" "$4" "$5" "$6" "$7" "$8" "$9"' in text
    assert "git rev-parse --show-toplevel" in text
    assert "Authoritative bootstrap contract (do not reinterpret)" in normalized
    assert "Only `continue` may act" in normalized
    assert "invalid inline" in normalized
    assert "python3 agent.py --target <target_shell>" in normalized
    assert "python3 tools/hunt.py --target <target_shell> --agent" in normalized
    assert "repo_root_shell" in normalized
    assert '"$ARGUMENTS"' not in text


def test_fofamap_is_evidence_triggered_and_scope_bound():
    command = " ".join(_read("docs/autopilot-lanes.md").split()).lower()

    assert "fofamap (`mcp__fofamap__*`) is one optional" in command
    assert "fofa/shodan adapter for a concrete coverage gap" in command
    assert "do not call it every round" in command
    assert "asset_relation_observations.jsonl" in command
    assert "python3 tools/recon_candidates.py --target <target_shell>" in command
    assert "external-chain-context" in command
    assert "never send active validation requests" in command


def test_generic_asset_relationship_lane_is_bounded_public_and_scope_preserving():
    paths = (
        "commands/autopilot.md",
        "docs/autopilot-lanes.md",
        "commands/recon.md",
        "skills/web2-recon/SKILL.md",
        "docs/tool-index.md",
    )
    combined = " ".join("\n".join(_read(path) for path in paths).split()).lower()

    for marker in (
        "generic asset-relationship expansion is optional and evidence-triggered",
        "quick requires explicit intent",
        "normal performs one pass with depth 1",
        "deep may recurse to depth 3",
        "full may recurse to depth 4",
        "ownership_pct > 50",
        "two consecutive levels add no domains",
        "without target-application credentials",
        "do not send the result through `tools/browser_mcp_import.py`",
        "asset_relation_summary.json",
        "scope-review",
        "external-chain-context",
        "candidate limits never truncate raw observations",
    ):
        assert marker in combined


def test_inline_auth_and_seed_contract_uses_formal_arguments_only():
    command = _read("commands/autopilot.md")
    readme = _read("README.md")
    product = _read("docs/PRODUCT.md")

    assert "[--auth-file PATH]" in command
    assert "arguments.seed_url" in command
    assert "arguments.hunt_auth_flags" in command
    assert "arguments.auth_file_shell" in command
    assert "cd -- <repo_root_shell> &&" in command
    assert "/autopilot target.com --normal --auth-file .private/auth.json" in readme
    assert "/autopilot target.com --normal, use" not in readme
    assert "URL 目标保留 canonical host state" in product


def test_bounded_deep_invocation_handoffs_instead_of_expanding_new_lanes():
    command = _read("commands/autopilot.md")
    agent = _read("agents/autopilot.md")

    assert "[--max-lanes N]" in command
    assert "invocation_batch.bounded" in command
    assert "browser/source discoveries become next-invocation work, not lane n+1" in " ".join(command.split()).lower()
    assert "after lane N do not execute a newly discovered queue item" in command
    assert "terminal handoff overrides target exhaustion" in command
    assert "checkpoint/sync durable queue" in agent


def test_browser_first_use_probe_retries_only_transient_session_failures():
    command = " ".join(
        (_read("commands/autopilot.md"), _read("docs/autopilot-lanes.md"))
    ).lower()

    assert "browser actions use only visible playwright/chrome mcp" in command
    assert "never run `agent-browser` or `playwright-cli` through bash" in command
    assert "first use" in command
    assert "harmless page-list/session probe" in command
    assert "retry once" in command
    assert "timeout, disconnect, or closed-context errors" in command
    assert "missing/configuration/permission/protocol errors do not retry" in command
    assert "checkpoint the blocker in the existing action queue" in command
    assert "pivot to js/source/api evidence" in command
    assert "next invocation, after repair, or on explicit operator retry" in command


def test_incomplete_durable_state_is_handoff_not_target_exhaustion():
    command = " ".join(_read("commands/autopilot.md").split()).lower()

    assert "active durable work, pending validation/report" in command
    assert "partial browser/source/intel, or untouched high-value work" in command
    assert "`handoff/partial`" in command
    assert "never `finish/complete/exhausted`" in command
    assert "passing `check_autopilot_run.py` proves state-chain integrity, not target exhaustion" in command


def test_finish_contract_rebuilds_coverage_then_reads_explicit_closure_verdict():
    command = _read("commands/autopilot.md")
    normalized = " ".join(command.split()).lower()

    rebuild = "python3 tools/coverage_matrix.py rebuild --target <target_shell>"
    gaps = "python3 tools/coverage_matrix.py find-gaps --target <target_shell>"
    closure = "python3 tools/autopilot_state.py --target <target_shell> --bounded --closure --projection-only --json"
    assert command.count(rebuild) == 1
    assert command.index(rebuild) < command.index(gaps) < command.index(closure)
    assert "only `verdict=finish` with `can_claim_exhausted=true`" in normalized
    assert "--max-lanes-reached" in command


def test_finish_contract_surfaces_high_value_memory_recommendations_without_auto_promotion():
    text = _read("commands/autopilot.md")
    command = " ".join(text.split()).lower()

    assert command.count("memory recommendations") == 1
    assert "only in the final handoff/finish response of each bounded `/autopilot` invocation" in command
    assert "perform exactly one compact, presentation-only promotion review" in command
    assert "round” means one bounded invocation, not an individual lane, replay, or checkpoint" in command
    assert "- promote:" in command
    assert "- target-only:" in command
    assert "- reject:" in command
    assert "locatable target-owned evidence reference" in command
    assert "why the lesson is high-value" in command
    assert "one next action" in command
    assert "one stop/validation condition" in command
    assert "not their write-back commands" in command
    assert "do not write target memory, edit knowledge/skills/rules" in command
    assert "create a pending candidate" in command
    assert "call `/remember`; any write-back or promotion remains a separate existing reviewed workflow" in command
    assert "must not change routing or lane selection, action budgets" in command
    assert "action queue state" in command
    assert "closure verdict, the next action, or any existing project capability" in command
    assert "no new reusable lesson was produced" in command
    assert "do not repeat the full review inside the loop" in command
    assert "do not summarize the recommendations elsewhere" in command


def test_versioned_hypothesis_contract_keeps_runner_observation_fields_tool_owned():
    command = " ".join(_read("commands/autopilot.md").split()).lower()

    assert "for `depth_contract_version=1`, runner owns `last_outcome`, `tested_dimensions`, and `runner_operation_id`" in command
    assert "ai claim/resolve metadata must not fabricate them" in command
    assert "when resolving a legacy/versionless action" in command


def test_versioned_claim_uses_the_stored_cap_without_guessing_retries():
    command = " ".join(_read("commands/autopilot.md").split()).lower()

    assert "read that stored cap from the selected action before claim" in command
    assert "never include `max_hypothesis_actions_cap` in claim metadata" in command
    assert "refresh and re-ingest the checkpoint action" in command
    assert "instead of guessing fields or retrying the same contract" in command


def test_durable_queue_work_is_claimed_before_replay():
    command = _read("docs/autopilot-lanes.md")

    assert "python3 tools/action_queue.py claim --target <target_shell>" in command
    assert "python3 tools/action_queue.py next --target <target_shell>" not in command


def test_case_state_continuation_has_an_explicit_controller_branch():
    command = _read("docs/autopilot-lanes.md")

    assert "`resume_case_state`" in command
    assert "state.case_state.top_next_action" in command


def test_substantive_lanes_obey_explicit_loop_guard_without_overriding_durable_work():
    command = " ".join(_read("commands/autopilot.md").split()).lower()

    assert "after every substantive lane" in command
    assert "autopilot_state.py --target <target_shell> --bounded --loop-check --projection-only --json" in command
    assert "obey `loop_guard.verdict`" in command
    assert "do not continue the reported `endpoint_family` × `vuln_class`" in command
    assert "bounded `rotation_target` when present" in command
    assert "never overrides runtime waits, candidate validation, report work, or durable action queue work" in command


def test_failed_sources_and_tools_are_suppressed_within_one_invocation():
    command = " ".join(_read("commands/autopilot.md").split()).lower()

    assert "within one invocation, do not rerun the same failed source/tool" in command
    assert "preserve cached/stale evidence as partial/blocked" in command
    assert "tools/external_arsenal.sh --versions" in command
    assert "diagnostics-only, never startup" in command


def test_inline_json_injection_uses_bounded_baseline_relative_waf_adaptation():
    command = " ".join(_read("docs/autopilot-lanes.md").split()).lower()

    assert "live/wafw00f_hits.txt" in command
    assert "sampled host-level context" in command
    assert "python3 -m tools.json_inject_probe" in command
    assert "--no-default-seeds" in command
    assert "--max-requests <budget>" in command
    assert "poc/json_inject/summary.json" in command
    assert "defaults to four evidence-linked semantic variants and permits at most eight" in command
    assert "`429`, transport failure, block pages" in command
    assert "never spray because parameters or a waf exist" in command


def test_optional_autopilot_agent_is_not_the_slash_command_backend():
    text = _read("agents/autopilot.md")
    normalized = " ".join(text.split())

    assert "explicitly invoked optional Claude subagent" in normalized
    assert "not the implicit backend of the `/autopilot` slash command" in normalized
    assert "its caller owns the target boundary, state write-back, and result collection" in normalized


def test_operator_docs_separate_inline_autopilot_from_legacy_agent_sessions():
    claude = " ".join(_read("CLAUDE.md").split())
    readme = " ".join(_read("README.md").split())
    product = " ".join(_read("docs/PRODUCT.md").split())

    for text in (claude, readme):
        assert "current Claude session" in text

    for text in (claude, readme, product):
        assert "tools/hunt.py" in text
        assert "--agent" in text

    assert "当前 Claude 会话" in product
    assert "Continue this target in the current Claude session" in readme
    assert "Explicit legacy local-agent runs" in readme
    assert "默认的 `/autopilot target.com` 或 agent 运行会创建新的本地 session" not in product
    assert "默认会创建新的本地 agent session" not in product
    assert "默认创建新的本地 agent session" not in product


def test_legacy_agent_resume_entrypoints_remain_documented():
    combined = "\n".join((_read("README.md"), _read("docs/PRODUCT.md")))

    assert "python3 tools/hunt.py --target target.com --agent --resume latest" in combined
    assert "python3 tools/hunt.py --target target.com --agent --resume <session_id>" in combined
