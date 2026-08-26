"""Claude CLI `/autopilot` inline 与 legacy agent 入口分离契约。"""

from pathlib import Path

from tools.action_queue import activation_contract_projection


REPO_ROOT = Path(__file__).resolve().parents[1]


def _read(relative_path: str) -> str:
    return (REPO_ROOT / relative_path).read_text(encoding="utf-8")


def test_slash_command_keeps_one_controller_and_ai_selected_bounded_specialists():
    text = _read("commands/autopilot.md")
    normalized = " ".join(text.split())

    assert "runs inline in the current AI session" in normalized
    assert "sole writer/closure controller" in normalized
    assert "Specialists default to zero" in normalized
    assert "current AI session may delegate distinct, bounded evidence questions" in normalized
    assert "platform's delegation tool" in normalized
    assert "bounded context/request cost" in normalized
    assert "expected information gain" in normalized
    assert "stop when no independent question remains" in normalized
    for forbidden in ("never nest", "run full recon/scans", "create lanes", "expand budgets", "write owner state", "decide closure/finish"):
        assert forbidden in normalized
    assert "controller collects results and writes back" in normalized
    assert "one read-only second opinion per frontier projection" in normalized
    assert "--isolated" not in text


def test_deep_mode_propagates_to_supported_inline_specialists_without_budget_expansion():
    command = " ".join(_read("commands/autopilot.md").split())
    lanes = " ".join(_read("docs/autopilot-lanes.md").split())

    for text in (command, lanes):
        assert "arguments.deep" in text
        assert "invocation_batch" in text
        assert "DEEP HUNT MODE" in text
        assert "value-first comprehensive-depth" in text
        assert "max_lanes" in text
        assert "reparse" in text

    assert "When `arguments.deep=true`" in command
    assert "without increasing `invocation_batch.max_lanes`" in command
    assert "When `arguments.deep=false`, do not upgrade the specialist to deep" in command
    assert "the inline controller alone claims lanes" in lanes


def test_slash_command_uses_authoritative_parser_and_rejects_legacy_flags():
    text = _read("commands/autopilot.md")
    normalized = " ".join(text.split())

    assert 'allowed-tools:' in text
    assert '- Bash' in text
    assert '- Agent' in text
    assert 'mcp__Playwright__*' in text
    assert 'mcp__chrome-devtools__*' in text
    assert 'mcp__fofamap__*' in text
    assert "`Agent` in Claude Code or the native equivalent" in normalized
    assert 'tools/autopilot_bootstrap.py" --json -- "$0" "$1" "$2" "$3" "$4" "$5" "$6" "$7" "$8" "$9"' in text
    assert "git rev-parse --show-toplevel" in text
    assert "Authoritative bootstrap contract (do not reinterpret)" in normalized
    assert "Only `continue` may act" in normalized
    assert "python3 agent.py --target <target_shell>" not in normalized
    assert "python3 tools/hunt.py --target <target_shell> --agent" not in normalized
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

    assert "[--auth-file PATH]" in command
    assert "arguments.seed_url" in command
    assert "arguments.hunt_auth_flags" in command
    assert "arguments.auth_file_shell" in command
    assert "cd -- <repo_root_shell> &&" in command
    assert "/autopilot target.com --normal --auth-file .private/auth.json" in readme
    assert "/autopilot target.com --normal, use" not in readme


def test_bounded_deep_invocation_handoffs_instead_of_expanding_new_lanes():
    command = _read("commands/autopilot.md")
    agent = _read("agents/autopilot.md")

    assert "[--deep [--max-lanes N]]" in command
    assert "`--max-lanes` is valid only with `--deep`" in command
    assert "invocation_batch.bounded" in command
    assert "after lane N do not execute a newly discovered queue item" in command
    assert "Evidence import, owner write-back, cleanup, checkpoint, and closure are not new" in command
    assert "Newly discovered work becomes next-invocation work" in command
    assert "Reaching `max_lanes` ends target work for this invocation" in command
    assert "the budget alone never requires another round" in command
    assert "checkpoint/sync durable queue" in agent


def test_browser_first_use_probe_retries_only_transient_session_failures():
    command = " ".join(
        (_read("commands/autopilot.md"), _read("docs/autopilot-lanes.md"))
    ).lower()

    assert "browser actions use only visible playwright/chrome mcp" in command
    assert "browser_playwright_fallback.py" in command
    assert "when neither mcp backend is usable" in command
    assert "never run `agent-browser` or `playwright-cli` through bash" in command
    assert "first use" in command
    assert "harmless page-list/session probe" in command
    assert "retry once" in command
    assert "timeout, disconnect, or closed-context errors" in command
    assert "missing/configuration/permission/protocol errors do not retry" in command
    assert "checkpoint the blocker in the existing action queue" in command
    assert "pivot to js/source/api evidence" in command
    assert "next invocation, after repair, or on explicit operator retry" in command
    assert "one active backend at a time" in command
    assert "never probe both for availability" in command
    assert "sequentially or concurrently" in command
    assert "never run both concurrently" in command
    assert "reuse a matching" in command
    assert "close stale" in command
    assert "or switch mid-workflow" in command
    assert "switch only at a lane boundary after the current workflow is complete" in command
    assert "close the current session first" in command
    assert "persist/import browser artifacts and close its native session" in command
    assert "do not open a second session to replace an unclosed one" in command


def test_incomplete_durable_state_is_handoff_not_target_exhaustion():
    command = " ".join(_read("commands/autopilot.md").split()).lower()

    assert "active substantive queue work, pending validation/report" in command
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
    assert "the budget alone never requires another round" in command


def test_finish_contract_surfaces_high_value_memory_recommendations_without_auto_promotion():
    text = _read("commands/autopilot.md")
    command = " ".join(text.split()).lower()

    assert command.count("memory recommendations") == 1
    assert "in the final handoff/finish response" in command
    assert "exactly one presentation-only section per bounded invocation" in command
    assert "- promote:" in command
    assert "- target-only:" in command
    assert "- reject:" in command
    assert "locatable target-owned evidence ref" in command
    assert "reusable value" in command
    assert "one next action" in command
    assert "one stop/validation condition" in command
    assert "not the write commands" in command
    assert "recommendations never write state" in command
    assert "alter routing, budgets, queue/finding lifecycle, closure, or next action" in command


def test_versioned_hypothesis_contract_keeps_runner_observation_fields_tool_owned():
    command = " ".join(
        (_read("commands/autopilot.md") + _read("docs/autopilot-lanes.md")).split()
    ).lower()

    assert "runner alone writes `last_outcome`, `tested_dimensions`" in command
    assert "`runner_operation_id`" in command
    assert "versioned ai metadata never fabricates runner fields" in command
    assert "legacy/versionless" in command


def test_versioned_claim_uses_the_stored_cap_without_guessing_retries():
    command = " ".join(
        (_read("commands/autopilot.md") + _read("docs/autopilot-lanes.md")).split()
    ).lower()

    assert "`max_hypothesis_actions` limit" in command
    assert "never submit, repair, or increase it in claim metadata" in command
    assert "missing cap requires checkpoint re-ingest" in command
    assert "stop without guessing/retry" in command


def test_activation_contract_lists_required_fields_and_js_agent_route_boundary():
    lanes = " ".join(_read("docs/autopilot-lanes.md").split())
    js_command = " ".join(_read("commands/js-read.md").split())

    contract = activation_contract_projection()
    assert "activation_contract.required_fields" in lanes
    assert "depth_contract_version" in contract["required_fields"]
    for field in (
        "decision_reason",
        "input_boundary",
        "endpoint",
        "method",
        "evidence_ref",
        "baseline_ref",
        "risk_tier",
        "max_hypothesis_actions",
    ):
        assert field in contract["required_fields"]
    assert "`js-reader` is an Agent handoff" in lanes
    assert "not a Queue Skill" in js_command
    assert "skills/web2-recon/SKILL.md" in js_command


def test_controller_prompt_stays_within_utf8_budget():
    command = _read("commands/autopilot.md")
    lanes = _read("docs/autopilot-lanes.md")

    assert len(command.encode("utf-8")) <= 20 * 1024
    assert "docs/autopilot-lanes.md" in command
    assert "## State And Queue" in lanes


def test_durable_queue_work_is_claimed_before_replay():
    command = _read("docs/autopilot-lanes.md")

    assert "python3 tools/action_queue.py claim --target <target_shell>" in command
    assert "python3 tools/action_queue.py next --target <target_shell>" not in command


def test_case_state_continuation_has_an_explicit_controller_branch():
    command = _read("docs/autopilot-lanes.md")

    assert "`resume_case_state`" in command
    assert "state.case_state.top_next_action" in command


def test_substantive_lanes_obey_explicit_loop_guard_without_bypassing_owner_constraints():
    command = " ".join(_read("commands/autopilot.md").split()).lower()

    assert "after every substantive lane" in command
    assert "autopilot_state.py --target <target_shell> --bounded --loop-check --projection-only --json" in command
    assert "obey `loop_guard.verdict`" in command
    assert "do not continue the reported `endpoint_family` × `vuln_class`" in command
    assert "bounded `rotation_target` when present" in command
    assert "never overrides `state.hard_gate`, an already-claimed lane" in command
    assert "refresh the frontier before selecting the next lane" in command


def test_ai_priority_frontier_competes_across_owners_without_changing_evidence_rules():
    command = " ".join(_read("commands/autopilot.md").split()).lower()

    assert "choose one runnable item from `state.priority_frontier`" in command
    assert "array order is not priority" in command
    assert "business impact" in command
    assert "expected information gain" in command
    assert "a weaker historical queue/case/resume item must not automatically preempt" in command
    assert "never bypasses the selected item's evidence/owner contract" in command
    assert "use `state.fallback_action`" in command


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


def test_autopilot_keeps_free_hypotheses_separate_from_canonical_closure():
    command = " ".join(_read("commands/autopilot.md").split())
    agent = " ".join(_read("agents/autopilot.md").split())

    for text in (command, agent):
        assert "including RCE" in text
        assert "families outside the canonical Coverage taxonomy" in text
        assert "compatibility string" in text
        assert "Matrix terminal state" in text
        assert "Unknown or incomplete" in text or "unknown/incomplete" in text


def test_operator_docs_separate_inline_autopilot_from_legacy_agent_sessions():
    claude = " ".join(_read("CLAUDE.md").split())
    readme = " ".join(_read("README.md").split())

    assert "current Claude session" in claude
    assert "current Claude session" in readme
    assert "Continue this target in the current Claude session" in readme
    assert "tools/hunt.py --target target.com --agent" not in readme
    assert "agent_session.json" not in readme


def test_single_user_readme_does_not_publish_stale_inventory_counts():
    readme = _read("README.md")

    for stale in ("17 个命令", "提供 17 个", "9 个角色", "定义了 9 个", "提供 9 个安全"):
        assert stale not in readme
    for command in ("autopilot", "autopilot-round", "pickup"):
        assert (REPO_ROOT / "commands" / f"{command}.md").is_file()
    assert "## Optional Agent Compatibility Layer" in readme


def test_legacy_agent_resume_entrypoints_are_not_documented():
    readme = _read("README.md")

    assert "python3 tools/hunt.py --target target.com --agent" not in readme
    assert "--resume latest" not in readme
