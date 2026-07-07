"""Regression tests for autopilot mode wiring across hunt.py and agent.py."""

import os
import sys

import agent
import hunt
import pytest
from memory.hunt_journal import HuntJournal


def test_normalize_autopilot_mode_defaults_to_paranoid():
    assert agent._normalize_autopilot_mode(None) == "paranoid"
    assert agent._normalize_autopilot_mode("") == "paranoid"
    assert agent._normalize_autopilot_mode("YOLO") == "yolo"
    assert agent._normalize_autopilot_mode("unknown") == "paranoid"


def test_build_agent_system_includes_mode_guidance():
    paranoid_prompt = agent._build_agent_system(autopilot_mode="paranoid")
    normal_prompt = agent._build_agent_system(autopilot_mode="normal")
    yolo_prompt = agent._build_agent_system(autopilot_mode="yolo")
    deep_prompt = agent._build_agent_system(autopilot_mode="normal", deep_mode=True)

    assert "Checkpoint mode: paranoid" in paranoid_prompt
    assert "Checkpoint mode: normal" in normal_prompt
    assert "Checkpoint mode: yolo" in yolo_prompt
    assert "DEEP HUNT MODE" in deep_prompt
    assert "value-first comprehensive depth" in deep_prompt
    assert "not a separate workflow" in deep_prompt
    assert "high-pressure scan mode" in deep_prompt
    assert "step-padding mode" in deep_prompt
    assert "Aggressive persistence" in deep_prompt
    assert "Scanner-negative results are not a conclusion" in deep_prompt
    assert "value-first coverage model" in deep_prompt
    assert "do not lock onto authz/IDOR" in deep_prompt
    assert "SQLi/NoSQLi" in deep_prompt
    assert "SSRF" in deep_prompt
    assert "XXE" in deep_prompt
    assert "unsafe deserialization" in deep_prompt
    assert "LFI/RFI/path traversal" in deep_prompt
    assert "do not be timid" in deep_prompt
    assert "Exploitation strategy" in deep_prompt
    assert "Chain aggressively" in deep_prompt
    assert "demonstrable business impact" in deep_prompt
    assert "Bug bounty mindset" in deep_prompt
    assert "reward-worthy" in deep_prompt
    assert "Substantive actions must add, confirm, disprove, block, or record target evidence" in deep_prompt
    assert "Deep exhaustion checklist" in deep_prompt
    assert "coverage matrix was rebuilt" in deep_prompt
    assert "Evidence Ledger / actor matrix was reviewed" in deep_prompt
    assert "scanner-negative results received manual follow-up" in deep_prompt
    assert "TOOL FAILURE DISCIPLINE" in paranoid_prompt
    assert "A failed tool is not a failed hypothesis" in paranoid_prompt
    assert "Retry once with corrected arguments" in paranoid_prompt
    assert "silently killing the path" in paranoid_prompt
    assert "never overrides live-action boundaries" in deep_prompt.lower()
    assert "Authorization posture" in paranoid_prompt
    assert "active target context" in paranoid_prompt
    assert "frequent checkpoints" in paranoid_prompt.lower()
    assert "Autonomously choose the next best A/B/C action" in paranoid_prompt
    assert "do not ask the operator to pick the next branch" in paranoid_prompt
    assert "batch related findings" in normal_prompt.lower()
    assert "keep moving" in yolo_prompt.lower()
    assert "advisory telemetry" in paranoid_prompt.lower()


def test_build_agent_bootstrap_context_surfaces_guard_guidance(monkeypatch):
    from tools import autopilot_state as autopilot_state_tool

    fake_state = {
        "next_action": "hunt_p1",
        "next_tool_hint": "run_browser_probe",
        "enrichment_hints": [
            {
                "tool": "run_browser_probe",
                "reason": "app-like or GraphQL surface signals were detected, but no browser-observed surface exists yet",
            }
        ],
        "guard_hint": (
            "cooling hosts: api.target.com (25.0s); prefer the ready host "
            "files.target.com via https://files.target.com/download?id=1"
        ),
        "guard_status": {
            "tripped_hosts": [
                {"host": "api.target.com", "remaining_seconds": 25.0},
            ]
        },
        "resume_targets": ["/graphql"],
        "resume_summary": {
            "latest_session_summary": {
                "vuln_classes": ["idor"],
                "findings_count": 1,
            }
        },
        "recommended_targets": [
            {
                "url": "https://files.target.com/download?id=1",
                "suggested": "idor checks",
                "tripped": False,
            }
        ],
    }

    monkeypatch.setattr(autopilot_state_tool, "build_autopilot_state", lambda *args, **kwargs: fake_state)

    output = agent._build_agent_bootstrap_context("target.com", repo_root="/tmp/repo", memory_dir="/tmp/memory")

    assert "Next tool hint: run_browser_probe" in output
    assert "Enrichment hints:" in output
    assert "Guard hint:" in output
    assert "Cooling hosts: api.target.com (25.0s)" in output
    assert "Top ready target: https://files.target.com/download?id=1 (idor checks)" in output


def test_build_agent_bootstrap_context_surfaces_recent_guard_advisories(monkeypatch):
    from tools import autopilot_state as autopilot_state_tool

    fake_state = {
        "next_action": "hunt_p1",
        "guard_hint": (
            "cooling hosts: api.target.com (25.0s); prefer the ready host "
            "files.target.com via https://files.target.com/download?id=1"
        ),
        "guard_status": {
            "tripped_hosts": [
                {"host": "api.target.com", "remaining_seconds": 25.0},
            ]
        },
        "resume_targets": ["/graphql"],
        "resume_summary": {
            "latest_session_summary": {
                "vuln_classes": ["idor"],
                "findings_count": 1,
            }
        },
        "recommended_targets": [
            {
                "url": "https://files.target.com/download?id=1",
                "suggested": "idor checks",
                "tripped": False,
            }
        ],
        "recent_guard_advisories": [
            {
                "action": "hunt",
                "endpoint": "https://api.target.com/graphql",
                "notes": (
                    "request_guard advisory for GET https://api.target.com/graphql. "
                    "Host: api.target.com. Action: breaker_advisory. "
                    "Reason: circuit breaker active."
                ),
            }
        ],
    }

    monkeypatch.setattr(autopilot_state_tool, "build_autopilot_state", lambda *args, **kwargs: fake_state)

    output = agent._build_agent_bootstrap_context("target.com", repo_root="/tmp/repo", memory_dir="/tmp/memory")

    assert "Recent guard advisories:" in output
    assert "https://api.target.com/graphql" in output
    assert "breaker_advisory" in output


def test_build_agent_bootstrap_context_surfaces_repo_source_summary(monkeypatch):
    from tools import autopilot_state as autopilot_state_tool

    fake_state = {
        "next_action": "hunt_p1",
        "guard_hint": "",
        "guard_status": {"tripped_hosts": []},
        "resume_targets": [],
        "resume_summary": {"latest_session_summary": {}},
        "recommended_targets": [],
        "recent_guard_blocks": [],
        "repo_source_summary": {
            "summary_hint": "local_path, secrets=2, ci=1",
            "source_kind": "local_path",
            "secret_findings": 2,
            "ci_findings": 1,
        },
    }

    monkeypatch.setattr(autopilot_state_tool, "build_autopilot_state", lambda *args, **kwargs: fake_state)

    output = agent._build_agent_bootstrap_context("target.com", repo_root="/tmp/repo", memory_dir="/tmp/memory")

    assert "Repo source summary: local_path, secrets=2, ci=1" in output


def test_build_agent_bootstrap_context_surfaces_pivot_hint(monkeypatch):
    from tools import autopilot_state as autopilot_state_tool

    fake_state = {
        "next_action": "hunt_p1",
        "guard_hint": (
            "cooling hosts: api.target.com (25.0s); prefer the ready host "
            "files.target.com via https://files.target.com/download?id=1"
        ),
        "guard_status": {"tripped_hosts": [{"host": "api.target.com", "remaining_seconds": 25.0}]},
        "resume_targets": [],
        "resume_summary": {"latest_session_summary": {}},
        "recommended_targets": [],
        "recent_guard_advisories": [],
        "repo_source_summary": {
            "summary_hint": "local_path, secrets=2, ci=0",
            "secret_findings": 2,
            "ci_findings": 0,
        },
        "pivot_hint": "live API has guard advisories; inspect repo source findings first.",
    }

    monkeypatch.setattr(autopilot_state_tool, "build_autopilot_state", lambda *args, **kwargs: fake_state)

    output = agent._build_agent_bootstrap_context("target.com", repo_root="/tmp/repo", memory_dir="/tmp/memory")

    assert "Pivot hint: live API has guard advisories; inspect repo source findings first." in output


def test_build_agent_bootstrap_context_surfaces_workflow_leads(monkeypatch):
    from tools import autopilot_state as autopilot_state_tool

    fake_state = {
        "next_action": "hunt_p1",
        "guard_hint": "",
        "guard_status": {"tripped_hosts": []},
        "resume_targets": [],
        "resume_summary": {"latest_session_summary": {}},
        "recommended_targets": [],
        "surface": {
            "workflow_leads": [
                {
                    "priority": "high",
                    "category": "graphql",
                    "title": "GraphQL mutations discovered in JS bundle",
                    "next_action": "map GraphQL authz and IDOR paths",
                    "rationale": "Mutations plus account context usually justify authz checks first.",
                }
            ]
        },
    }

    monkeypatch.setattr(autopilot_state_tool, "build_autopilot_state", lambda *args, **kwargs: fake_state)

    output = agent._build_agent_bootstrap_context("target.com", repo_root="/tmp/repo", memory_dir="/tmp/memory")

    assert "Top workflow leads:" in output
    assert "[high] graphql: GraphQL mutations discovered in JS bundle" in output
    assert "Next: map GraphQL authz and IDOR paths" in output
    assert "Why: Mutations plus account context usually justify authz checks first." in output


def test_build_agent_bootstrap_context_parses_stringified_workflow_leads(monkeypatch):
    from tools import autopilot_state as autopilot_state_tool

    fake_state = {
        "next_action": "hunt_p1",
        "guard_hint": "",
        "guard_status": {"tripped_hosts": []},
        "resume_targets": [],
        "resume_summary": {"latest_session_summary": {}},
        "recommended_targets": [],
        "surface": {
            "workflow_leads": [
                (
                    '{"priority":"medium","category":"upload","title":"Upload endpoint '
                    'from source intel","next_action":"check extension/content-type '
                    'validation"}'
                )
            ]
        },
    }

    monkeypatch.setattr(autopilot_state_tool, "build_autopilot_state", lambda *args, **kwargs: fake_state)

    output = agent._build_agent_bootstrap_context("target.com", repo_root="/tmp/repo", memory_dir="/tmp/memory")

    assert "[medium] upload: Upload endpoint from source intel" in output
    assert "Next: check extension/content-type validation" in output


def test_build_agent_bootstrap_context_marks_demoted_leads_as_reversible(monkeypatch):
    from tools import autopilot_state as autopilot_state_tool

    fake_state = {
        "next_action": "hunt_p1",
        "guard_hint": "",
        "guard_status": {"tripped_hosts": []},
        "resume_targets": [],
        "resume_summary": {"latest_session_summary": {}},
        "recommended_targets": [],
        "surface": {
            "workflow_leads": [
                {
                    "priority": "medium",
                    "category": "public-metadata",
                    "title": "Standard public metadata endpoints were demoted from exposure findings",
                    "next_action": "review only when field content looks unusual",
                    "rationale": "Known metadata schema matched without separate high-value body evidence.",
                }
            ]
        },
    }

    monkeypatch.setattr(autopilot_state_tool, "build_autopilot_state", lambda *args, **kwargs: fake_state)

    output = agent._build_agent_bootstrap_context("target.com", repo_root="/tmp/repo", memory_dir="/tmp/memory")

    assert "Secondary sweep rule:" in output
    assert "re-promote only with concrete secret, chain, or pivot evidence" in output


def test_active_bootstrap_context_only_applies_on_first_step(tmp_path):
    memory = agent.HuntMemory(str(tmp_path / "agent-session.json"))
    memory.bootstrap_context = "resume target: /graphql"

    assert agent._active_bootstrap_context(memory) == "resume target: /graphql"

    memory.step_count = 1
    assert agent._active_bootstrap_context(memory) == ""


def test_bootstrap_tool_hint_only_applies_on_first_step(tmp_path):
    memory = agent.HuntMemory(str(tmp_path / "agent-session.json"))
    memory.bootstrap_state = {
        "next_tool_hint": "run_browser_probe",
        "enrichment_hints": [
            {
                "tool": "run_browser_probe",
                "reason": "app-like or GraphQL surface signals were detected, but no browser-observed surface exists yet",
            }
        ],
    }

    hint = agent._bootstrap_tool_hint(memory)
    assert hint == {
        "tool": "run_browser_probe",
        "reason": "app-like or GraphQL surface signals were detected, but no browser-observed surface exists yet",
    }

    memory.step_count = 1
    assert agent._bootstrap_tool_hint(memory) == {}


def test_bootstrap_tool_hint_falls_back_to_surface_summary_for_workflow_leads(tmp_path):
    memory = agent.HuntMemory(str(tmp_path / "agent-session.json"))
    memory.bootstrap_state = {
        "surface": {
            "workflow_leads": [
                {
                    "priority": "high",
                    "category": "graphql",
                    "title": "GraphQL mutation with object ids",
                    "next_action": "compare mutation authz across roles",
                }
            ]
        }
    }

    hint = agent._bootstrap_tool_hint(memory)

    assert hint == {
        "tool": "read_surface_summary",
        "reason": "workflow leads are available; read the ranked surface summary before picking the first focused lane",
    }


def test_bootstrap_tool_hint_prioritizes_secondary_sweep_for_demoted_leads(tmp_path):
    memory = agent.HuntMemory(str(tmp_path / "agent-session.json"))
    memory.bootstrap_state = {
        "surface": {
            "workflow_leads": [
                {
                    "priority": "medium",
                    "category": "out-of-target-intel",
                    "title": "External URLs were demoted from target-owned scanner findings",
                    "next_action": "review the raw artifact for third-party secret or chain signals",
                }
            ]
        }
    }

    hint = agent._bootstrap_tool_hint(memory)

    assert hint == {
        "tool": "read_surface_summary",
        "reason": "demoted manual-review leads are available; do one secondary sweep before declaring them noise",
    }


def test_bootstrap_tool_hint_does_not_repeat_surface_summary_when_already_read(tmp_path):
    memory = agent.HuntMemory(str(tmp_path / "agent-session.json"))
    memory.bootstrap_state = {
        "surface": {
            "workflow_leads": [
                {
                    "priority": "high",
                    "category": "idor",
                    "title": "/api/users/{id}",
                    "next_action": "compare object access across accounts",
                }
            ]
        }
    }
    memory.completed_steps = ["read_surface_summary"]

    assert agent._bootstrap_tool_hint(memory) == {}


def test_finish_floor_progress_count_ignores_read_only_and_bookkeeping_steps():
    completed_steps = [
        "read_autopilot_state",
        "read_surface_summary",
        "update_working_memory",
        "remember_finding",
        "generate_reports",
        "check_tools",
        "run_recon",
        "run_source_intel",
        "run_browser_probe",
    ]

    assert agent._finish_floor_progress_count(completed_steps) == 3


def test_react_agent_step_prioritizes_bootstrap_tool_hint(monkeypatch, tmp_path):
    memory = agent.HuntMemory(str(tmp_path / "agent-session.json"))
    memory.bootstrap_state = {
        "next_tool_hint": "run_js_read",
        "enrichment_hints": [
            {
                "tool": "run_js_read",
                "reason": "cached JS artifacts exist, but js_intel materials have not been prepared yet",
            }
        ],
    }

    called = {}

    class FakeDispatcher:
        def dispatch(self, name, args):
            called["name"] = name
            called["args"] = args
            memory.completed_steps.append(name)
            memory.step_count += 1
            return f"{name}: ok"

    reactor = agent.ReActAgent.__new__(agent.ReActAgent)
    reactor.done = False
    reactor.memory = memory
    reactor.dispatcher = FakeDispatcher()
    reactor.max_steps = 5
    reactor.time_start = 0.0
    reactor.time_budget_secs = 3600.0
    reactor.tracer = None
    reactor.bump_file = ""
    reactor.loop_detector = agent.LoopDetector()
    reactor.client = None
    reactor.model = "fake"
    reactor.system_prompt = ""
    reactor.min_steps_before_finish = 0
    monkeypatch.setattr(agent.time, "time", lambda: 1.0)

    output = reactor.step()

    assert called == {"name": "run_js_read", "args": {}}
    assert output.startswith("[BOOTSTRAP] Prioritizing run_js_read from runtime hint.")
    assert "run_js_read: ok" in output
    assert memory.step_count == 1


def test_build_agent_system_guides_workflow_leads_without_getting_stuck():
    prompt = agent._build_agent_system(autopilot_mode="paranoid")

    assert "If ranked workflow leads already exist" in prompt
    assert "Demoted/manual-review leads are not final rejections" in prompt
    assert "Do not get trapped in enrichment-only loops" in prompt


def test_react_agent_finish_floor_ignores_read_only_steps(monkeypatch, tmp_path):
    memory = agent.HuntMemory(str(tmp_path / "agent-session.json"))
    memory.step_count = 6
    memory.completed_steps = [
        "read_autopilot_state",
        "read_surface_summary",
        "read_recon_summary",
        "update_working_memory",
        "remember_finding",
        "generate_reports",
    ]

    class FakeClient:
        def chat(self, **kwargs):
            return {
                "message": {
                    "tool_calls": [
                        {
                            "function": {
                                "name": "finish",
                                "arguments": {"verdict": "done"},
                            }
                        }
                    ]
                }
            }

    class FakeDispatcher:
        def dispatch(self, name, args):
            raise AssertionError(f"dispatcher should not run {name} when finish is blocked")

    reactor = agent.ReActAgent.__new__(agent.ReActAgent)
    reactor.done = False
    reactor.memory = memory
    reactor.dispatcher = FakeDispatcher()
    reactor.max_steps = 8
    reactor.time_start = 0.0
    reactor.time_budget_secs = 3600.0
    reactor.tracer = None
    reactor.bump_file = ""
    reactor.loop_detector = agent.LoopDetector()
    reactor.client = FakeClient()
    reactor.model = "fake"
    reactor.system_prompt = ""
    reactor.min_steps_before_finish = 6
    reactor.domain = "example.com"
    reactor.autopilot_mode = "paranoid"
    reactor.quick_mode = False
    monkeypatch.setattr(agent.time, "time", lambda: 1.0)

    output = reactor.step()

    assert "Too early to finish" in output
    assert "0 substantive tools" in output
    assert reactor.done is False


def test_react_agent_finish_floor_advisory_in_yolo(monkeypatch, tmp_path):
    """In yolo mode the persistence floor is advisory: finish still dispatches."""
    memory = agent.HuntMemory(str(tmp_path / "agent-session.json"))
    memory.step_count = 3
    memory.completed_steps = [
        "read_autopilot_state",
        "read_surface_summary",
        "read_recon_summary",
    ]

    dispatched: dict = {}

    class FakeClient:
        def chat(self, **kwargs):
            return {
                "message": {
                    "tool_calls": [
                        {
                            "function": {
                                "name": "finish",
                                "arguments": {"verdict": "done"},
                            }
                        }
                    ]
                }
            }

    class FakeDispatcher:
        def dispatch(self, name, args):
            dispatched["name"] = name
            return f"{name}: ok"

    reactor = agent.ReActAgent.__new__(agent.ReActAgent)
    reactor.done = False
    reactor.memory = memory
    reactor.dispatcher = FakeDispatcher()
    reactor.max_steps = 8
    reactor.time_start = 0.0
    reactor.time_budget_secs = 3600.0
    reactor.tracer = None
    reactor.bump_file = ""
    reactor.loop_detector = agent.LoopDetector()
    reactor.client = FakeClient()
    reactor.model = "fake"
    reactor.system_prompt = ""
    reactor.min_steps_before_finish = 4  # yolo floor
    reactor.domain = "example.com"
    reactor.autopilot_mode = "yolo"
    reactor.quick_mode = False
    monkeypatch.setattr(agent.time, "time", lambda: 1.0)
    # Bypass F3/F4 gates: they pass when their evidence is absent / not blocking
    monkeypatch.setattr(agent, "_f3_coverage_gate", lambda domain: (True, ""))
    monkeypatch.setattr(agent, "_f4_intelligence_gate", lambda domain, steps: (True, ""))

    output = reactor.step()

    # Advisory text reaches the LLM but the finish dispatch was NOT blocked.
    assert "Too early to finish" in output
    assert dispatched.get("name") == "finish"


def test_run_agent_hunt_returns_autopilot_mode(monkeypatch, tmp_path):
    captured = {}

    class FakeHunt:
        def _activate_recon_session(self, domain, *, requested_session_id="new", create=True):
            captured["requested_session_id"] = requested_session_id
            recon_dir = tmp_path / "targets" / domain / "sessions" / "sess-001" / "recon"
            recon_dir.mkdir(parents=True, exist_ok=True)
            return "sess-001", str(recon_dir)

    class FakeTracer:
        def __init__(self, log_path):
            self.log_path = log_path

        def close(self):
            return None

    class FakeAgent:
        def __init__(
            self,
            *args,
            autopilot_mode,
            quick_mode,
            ctf_mode,
            deep_mode,
            max_steps,
            time_budget_hours,
            **kwargs,
        ):
            captured["autopilot_mode"] = autopilot_mode
            captured["quick_mode"] = quick_mode
            captured["ctf_mode"] = ctf_mode
            captured["deep_mode"] = deep_mode
            captured["max_steps"] = max_steps
            captured["time_budget_hours"] = time_budget_hours

        def run(self):
            return {"domain": "example.com", "success": True, "steps": 0, "findings": 0, "reports": 0}

    monkeypatch.setattr(agent, "_h", lambda: FakeHunt())
    monkeypatch.setattr(agent, "_resolve_ctf_mode", lambda explicit=None: True if explicit is None else explicit)
    monkeypatch.setattr(agent, "AgentTracer", FakeTracer)
    monkeypatch.setattr(agent, "ReActAgent", FakeAgent)

    result = agent.run_agent_hunt(
        "example.com",
        autopilot_mode="yolo",
        quick=True,
        deep_mode=True,
    )

    assert captured["autopilot_mode"] == "yolo"
    assert captured["quick_mode"] is True
    assert captured["ctf_mode"] is True
    assert captured["deep_mode"] is True
    assert captured["max_steps"] == 60
    assert captured["time_budget_hours"] == 4.0
    assert captured["requested_session_id"] == "new"
    assert result["autopilot_mode"] == "yolo"
    assert result["quick_mode"] is True
    assert result["deep_mode"] is True
    assert result["ctf_mode"] is True
    assert result["session_id"] == "sess-001"
    assert result["session_mode"] == "fresh"


def test_run_agent_hunt_explicit_resume_session(monkeypatch, tmp_path):
    captured = {}

    class FakeHunt:
        def _activate_recon_session(self, domain, *, requested_session_id="new", create=True):
            captured["requested_session_id"] = requested_session_id
            recon_dir = tmp_path / "targets" / domain / "sessions" / requested_session_id / "recon"
            recon_dir.mkdir(parents=True, exist_ok=True)
            return requested_session_id, str(recon_dir)

    class FakeTracer:
        def __init__(self, log_path):
            self.log_path = log_path

        def close(self):
            return None

    class FakeAgent:
        def __init__(self, *args, **kwargs):
            return None

        def run(self):
            return {"domain": "example.com", "success": True, "steps": 0, "findings": 0, "reports": 0}

    monkeypatch.setattr(agent, "_h", lambda: FakeHunt())
    monkeypatch.setattr(agent, "AgentTracer", FakeTracer)
    monkeypatch.setattr(agent, "ReActAgent", FakeAgent)

    result = agent.run_agent_hunt("example.com", resume_session_id="latest")

    assert captured["requested_session_id"] == "latest"
    assert result["session_id"] == "latest"
    assert result["session_mode"] == "resumed"


def test_hunt_compat_session_paths_use_target_storage_key(tmp_path):
    class FakeModule:
        BASE_DIR = str(tmp_path)
        TOOLS_DIR = str(tmp_path / "tools")
        TARGETS_DIR = str(tmp_path / "targets")
        RECON_DIR = str(tmp_path / "recon")
        FINDINGS_DIR = str(tmp_path / "findings")
        REPORTS_DIR = str(tmp_path / "reports")

        @staticmethod
        def _target_storage_key(target):
            return target.replace("/", "_")

    compat = agent._HuntCompat(FakeModule())
    session_id, recon_dir = compat._activate_recon_session("1.2.3.0/24")

    assert session_id
    assert recon_dir.startswith(str(tmp_path / "targets" / "1.2.3.0_24" / "sessions"))
    assert recon_dir.endswith("/recon")


def test_run_agent_hunt_canonicalizes_cidr_target_for_session_and_agent(monkeypatch, tmp_path):
    captured = {}

    class FakeHunt:
        BASE_DIR = str(tmp_path)

        def classify_target(self, target):
            captured["classified_input"] = target
            return {"kind": "cidr", "target": "1.2.3.0/24"}

        def _activate_recon_session(self, domain, *, requested_session_id="new", create=True):
            captured["session_target"] = domain
            recon_dir = tmp_path / "targets" / "1.2.3.0_24" / "sessions" / "sess-001" / "recon"
            recon_dir.mkdir(parents=True, exist_ok=True)
            return "sess-001", str(recon_dir)

    class FakeDispatcher:
        def __init__(self, domain, memory, **kwargs):
            captured["dispatcher_domain"] = domain

    class FakeTracer:
        def __init__(self, log_path):
            self.log_path = log_path

        def close(self):
            return None

    class FakeAgent:
        def __init__(self, *args, domain, **kwargs):
            captured["agent_domain"] = domain

        def run(self):
            return {"domain": "raw-input", "success": True, "steps": 0, "findings": 0, "reports": 0}

    monkeypatch.setattr(agent, "_h", lambda: FakeHunt())
    monkeypatch.setattr(agent, "ToolDispatcher", FakeDispatcher)
    monkeypatch.setattr(agent, "AgentTracer", FakeTracer)
    monkeypatch.setattr(agent, "ReActAgent", FakeAgent)
    monkeypatch.setattr(agent, "_build_agent_bootstrap_context", lambda domain, **_: captured.setdefault("bootstrap_domain", domain) or "")
    monkeypatch.setattr(agent, "_auto_log_agent_session_summary", lambda domain, *_args: captured.setdefault("summary_domain", domain))

    result = agent.run_agent_hunt("1.2.3.4/24")

    assert captured["classified_input"] == "1.2.3.4/24"
    assert captured["session_target"] == "1.2.3.0/24"
    assert captured["bootstrap_domain"] == "1.2.3.0/24"
    assert captured["dispatcher_domain"] == "1.2.3.0/24"
    assert captured["agent_domain"] == "1.2.3.0/24"
    assert captured["summary_domain"] == "1.2.3.0/24"
    assert result["domain"] == "1.2.3.0/24"


def test_run_agent_hunt_auto_logs_session_summary(monkeypatch, tmp_path):
    memory_dir = tmp_path / "hunt-memory"

    class FakeHunt:
        BASE_DIR = str(tmp_path)

        def _activate_recon_session(self, domain, *, requested_session_id="latest", create=True):
            recon_dir = tmp_path / "targets" / domain / "sessions" / "sess-002" / "recon"
            recon_dir.mkdir(parents=True, exist_ok=True)
            return "sess-002", str(recon_dir)

    class FakeTracer:
        def __init__(self, log_path):
            self.log_path = log_path

        def close(self):
            return None

    class FakeAgent:
        def __init__(self, *args, memory, **kwargs):
            memory.completed_steps.extend(["run_recon", "run_vuln_scan"])
            memory.findings_log.append(
                {
                    "tool": "run_vuln_scan",
                    "severity": "high",
                    "text": "IDOR on /api/users/1",
                    "ts": "2026-04-17T00:00:00",
                }
            )

        def run(self):
            return {"domain": "example.com", "success": True, "steps": 2, "findings": 1, "reports": 1}

    monkeypatch.setattr(agent, "_h", lambda: FakeHunt())
    monkeypatch.setattr(agent, "default_memory_dir", lambda _base=None: memory_dir)
    monkeypatch.setattr(agent, "AgentTracer", FakeTracer)
    monkeypatch.setattr(agent, "ReActAgent", FakeAgent)

    result = agent.run_agent_hunt("example.com", autopilot_mode="normal")
    entries = HuntJournal(memory_dir / "journal.jsonl").query(
        target="example.com",
        vuln_class="session_summary",
    )

    assert result["success"] is True
    assert len(entries) == 1
    assert entries[0]["action"] == "hunt"
    assert "auto_logged" in entries[0]["tags"]
    assert "sess-002" in entries[0]["notes"]
    assert "recon" in entries[0]["notes"]
    assert "vuln_scan" in entries[0]["notes"]


def test_run_agent_hunt_session_summary_uses_remembered_profile_findings(monkeypatch, tmp_path):
    memory_dir = tmp_path / "hunt-memory"

    class FakeHunt:
        BASE_DIR = str(tmp_path)

        def _activate_recon_session(self, domain, *, requested_session_id="latest", create=True):
            recon_dir = tmp_path / "targets" / domain / "sessions" / "sess-003" / "recon"
            recon_dir.mkdir(parents=True, exist_ok=True)
            return "sess-003", str(recon_dir)

    class FakeTracer:
        def __init__(self, log_path):
            self.log_path = log_path

        def close(self):
            return None

    class FakeAgent:
        def __init__(self, *args, domain, **kwargs):
            self.domain = domain

        def run(self):
            from remember import remember_finding

            remember_finding(
                memory_dir=memory_dir,
                target=self.domain,
                vuln_class="idor",
                endpoint="https://api.example.com/api/users/1",
                result="confirmed",
                severity="high",
                notes="Persisted through remember_finding",
            )
            return {"domain": self.domain, "success": True, "steps": 1, "findings": 0, "reports": 0}

    monkeypatch.setattr(agent, "_h", lambda: FakeHunt())
    monkeypatch.setattr(agent, "default_memory_dir", lambda _base=None: memory_dir)
    monkeypatch.setattr(agent, "AgentTracer", FakeTracer)
    monkeypatch.setattr(agent, "ReActAgent", FakeAgent)

    result = agent.run_agent_hunt("example.com")
    entries = HuntJournal(memory_dir / "journal.jsonl").query(
        target="example.com",
        vuln_class="session_summary",
    )

    assert result["success"] is True
    assert len(entries) == 1
    assert entries[0]["endpoint"] == "/api/users/1"
    assert "idor" in entries[0]["notes"]
    assert "Findings: 1." in entries[0]["notes"]


def test_hunt_main_passes_autopilot_mode_to_agent(monkeypatch, tmp_path):
    captured = {}

    def fake_run_agent_hunt(*args, **kwargs):
        captured["autopilot_mode"] = kwargs["autopilot_mode"]
        captured["quick"] = kwargs["quick"]
        captured["resume_session_id"] = kwargs["resume_session_id"]
        captured["ctf_mode"] = kwargs["ctf_mode"]
        captured["deep_mode"] = kwargs["deep_mode"]
        return {
            "domain": "example.com",
            "success": True,
            "steps": 0,
            "findings": 0,
            "reports": 0,
            "autopilot_mode": kwargs["autopilot_mode"],
            "ctf_mode": kwargs["ctf_mode"],
            "deep_mode": kwargs["deep_mode"],
        }

    common = tmp_path / "common.txt"
    common.write_text("admin\n", encoding="utf-8")

    monkeypatch.setattr(hunt, "load_config", lambda: {"ctf_mode": True})
    monkeypatch.setattr(hunt, "is_ctf_mode", lambda config=None: True)
    monkeypatch.setattr(hunt, "check_tools", lambda: ([], []))
    monkeypatch.setattr(hunt, "setup_wordlists", lambda: None)
    monkeypatch.setattr(hunt, "print_dashboard", lambda result: None)
    monkeypatch.setattr(hunt, "WORDLIST_DIR", str(tmp_path))
    monkeypatch.setattr(agent, "run_agent_hunt", fake_run_agent_hunt)
    monkeypatch.setattr(sys, "argv", ["hunt.py", "--target", "example.com", "--agent", "--yolo", "--deep"])

    hunt.main()

    assert captured["autopilot_mode"] == "yolo"
    assert captured["quick"] is False
    assert captured["resume_session_id"] is None
    assert captured["ctf_mode"] is True
    assert captured["deep_mode"] is True


def test_hunt_main_passes_quick_mode_to_agent(monkeypatch, tmp_path):
    captured = {}

    def fake_run_agent_hunt(*args, **kwargs):
        captured["quick"] = kwargs["quick"]
        return {
            "domain": "example.com",
            "success": True,
            "steps": 0,
            "findings": 0,
            "reports": 0,
            "quick_mode": kwargs["quick"],
        }

    common = tmp_path / "common.txt"
    common.write_text("admin\n", encoding="utf-8")

    monkeypatch.setattr(hunt, "check_tools", lambda: ([], []))
    monkeypatch.setattr(hunt, "setup_wordlists", lambda: None)
    monkeypatch.setattr(hunt, "print_dashboard", lambda result: None)
    monkeypatch.setattr(hunt, "WORDLIST_DIR", str(tmp_path))
    monkeypatch.setattr(agent, "run_agent_hunt", fake_run_agent_hunt)
    monkeypatch.setattr(sys, "argv", ["hunt.py", "--target", "example.com", "--agent", "--quick"])

    hunt.main()

    assert captured["quick"] is True


@pytest.mark.parametrize(
    ("argv", "expected_mode", "expected_quick", "expected_deep"),
    [
        (["hunt.py", "--target", "example.com", "--agent"], "paranoid", False, False),
        (["hunt.py", "--target", "example.com", "--agent", "--normal"], "normal", False, False),
        (["hunt.py", "--target", "example.com", "--agent", "--yolo"], "yolo", False, False),
        (["hunt.py", "--target", "example.com", "--agent", "--quick", "--normal"], "normal", True, False),
        (["hunt.py", "--target", "example.com", "--agent", "--deep", "--normal"], "normal", False, True),
    ],
)
def test_hunt_main_passes_mode_matrix_to_agent(
    monkeypatch,
    tmp_path,
    argv,
    expected_mode,
    expected_quick,
    expected_deep,
):
    captured = {}

    def fake_run_agent_hunt(*args, **kwargs):
        captured["autopilot_mode"] = kwargs["autopilot_mode"]
        captured["quick"] = kwargs["quick"]
        captured["deep_mode"] = kwargs["deep_mode"]
        return {
            "domain": "example.com",
            "success": True,
            "steps": 0,
            "findings": 0,
            "reports": 0,
            "autopilot_mode": kwargs["autopilot_mode"],
            "quick_mode": kwargs["quick"],
            "deep_mode": kwargs["deep_mode"],
        }

    common = tmp_path / "common.txt"
    common.write_text("admin\n", encoding="utf-8")

    monkeypatch.setattr(hunt, "check_tools", lambda: ([], []))
    monkeypatch.setattr(hunt, "setup_wordlists", lambda: None)
    monkeypatch.setattr(hunt, "print_dashboard", lambda result: None)
    monkeypatch.setattr(hunt, "WORDLIST_DIR", str(tmp_path))
    monkeypatch.setattr(agent, "run_agent_hunt", fake_run_agent_hunt)
    monkeypatch.setattr(sys, "argv", argv)

    hunt.main()

    assert captured["autopilot_mode"] == expected_mode
    assert captured["quick"] is expected_quick
    assert captured["deep_mode"] is expected_deep


def test_hunt_main_passes_resume_session_to_agent(monkeypatch, tmp_path):
    captured = {}

    def fake_run_agent_hunt(*args, **kwargs):
        captured["resume_session_id"] = kwargs["resume_session_id"]
        return {
            "domain": "example.com",
            "success": True,
            "steps": 0,
            "findings": 0,
            "reports": 0,
        }

    common = tmp_path / "common.txt"
    common.write_text("admin\n", encoding="utf-8")

    monkeypatch.setattr(hunt, "check_tools", lambda: ([], []))
    monkeypatch.setattr(hunt, "setup_wordlists", lambda: None)
    monkeypatch.setattr(hunt, "print_dashboard", lambda result: None)
    monkeypatch.setattr(hunt, "WORDLIST_DIR", str(tmp_path))
    monkeypatch.setattr(agent, "run_agent_hunt", fake_run_agent_hunt)
    monkeypatch.setattr(
        sys,
        "argv",
        ["hunt.py", "--target", "example.com", "--agent", "--resume", "latest"],
    )

    hunt.main()

    assert captured["resume_session_id"] == "latest"


def test_agent_main_passes_quick_and_mode_to_run_agent_hunt(monkeypatch):
    captured = {}

    class FakeModule:
        _AUTH_SESSION = None

    class FakeHunt:
        def __init__(self):
            self._module = FakeModule()

    def fake_run_agent_hunt(*args, **kwargs):
        captured["quick"] = kwargs["quick"]
        captured["autopilot_mode"] = kwargs["autopilot_mode"]
        captured["deep_mode"] = kwargs["deep_mode"]
        return {
            "domain": "example.com",
            "backend": "builtin-react",
            "model": "qwen3",
            "steps": 0,
            "findings": 0,
            "reports": 0,
            "session_id": "sess-001",
            "session_mode": "fresh",
            "session_file": "/tmp/agent_session.json",
            "quick_mode": kwargs["quick"],
            "autopilot_mode": kwargs["autopilot_mode"],
            "deep_mode": kwargs["deep_mode"],
        }

    monkeypatch.setattr(agent, "_h", lambda: FakeHunt())
    monkeypatch.setattr(agent, "run_agent_hunt", fake_run_agent_hunt)
    monkeypatch.setattr(
        sys,
        "argv",
        ["agent.py", "--target", "example.com", "--quick", "--deep", "--normal"],
    )

    agent.main()

    assert captured["quick"] is True
    assert captured["autopilot_mode"] == "normal"
    assert captured["deep_mode"] is True


def test_agent_main_help_mentions_target_types_and_mode_flags(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["agent.py", "--help"])

    with pytest.raises(SystemExit, match="0"):
        agent.main()

    output = capsys.readouterr().out
    assert "Target to hunt (domain, IP, CIDR, or primary-domain" in output
    assert "batch file)" in output
    assert "--quick" in output
    assert "--deep" in output
    assert "--normal" in output
    assert "--yolo" in output


def test_agent_main_applies_auth_session_to_hunt_bridge_and_env(monkeypatch, tmp_path, capsys):
    captured = {}

    class FakeModule:
        _AUTH_SESSION = None

    class FakeHunt:
        def __init__(self):
            self._module = FakeModule()

    auth_file = tmp_path / "auth.json"
    auth_file.write_text('{"headers": ["X-File: 1"], "api_key": "from-file"}', encoding="utf-8")
    fake_hunt = FakeHunt()

    def fake_run_agent_hunt(*args, **kwargs):
        captured["cookies"] = kwargs["cookies"]
        return {
            "domain": "example.com",
            "backend": "builtin-react",
            "model": "qwen3",
            "steps": 0,
            "findings": 0,
            "reports": 0,
            "session_id": "sess-001",
            "session_mode": "fresh",
            "session_file": "/tmp/agent_session.json",
        }

    monkeypatch.setattr(agent, "_h", lambda: fake_hunt)
    monkeypatch.setattr(agent, "run_agent_hunt", fake_run_agent_hunt)
    monkeypatch.delenv("BBHUNT_AUTH_HEADERS", raising=False)
    monkeypatch.delenv("BBHUNT_SESSION_ID", raising=False)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "agent.py",
            "--target",
            "example.com",
            "--auth-file",
            str(auth_file),
            "--auth-header",
            "X-Test: 1",
            "--bearer",
            "tok",
        ],
    )

    agent.main()

    session = fake_hunt._module._AUTH_SESSION
    assert session is not None
    assert session.headers_dict() == {
        "X-File": "1",
        "X-API-Key": "from-file",
        "X-Test": "1",
        "Authorization": "Bearer tok",
    }
    assert os.environ["BBHUNT_SESSION_ID"] == session.session_id()
    assert "Authorization: Bearer tok" in os.environ["BBHUNT_AUTH_HEADERS"]
    assert captured["cookies"] == ""
    assert "auth: session=" in capsys.readouterr().out


def test_agent_main_reuses_cookie_arg_for_auth_session_and_post_discovery(monkeypatch):
    captured = {}

    class FakeModule:
        _AUTH_SESSION = None

    class FakeHunt:
        def __init__(self):
            self._module = FakeModule()

    fake_hunt = FakeHunt()

    def fake_run_agent_hunt(*args, **kwargs):
        captured["cookies"] = kwargs["cookies"]
        return {
            "domain": "example.com",
            "backend": "builtin-react",
            "model": "qwen3",
            "steps": 0,
            "findings": 0,
            "reports": 0,
            "session_id": "sess-001",
            "session_mode": "fresh",
            "session_file": "/tmp/agent_session.json",
        }

    monkeypatch.setattr(agent, "_h", lambda: fake_hunt)
    monkeypatch.setattr(agent, "run_agent_hunt", fake_run_agent_hunt)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "agent.py",
            "--target",
            "example.com",
            "--cookie",
            "session=abc",
            "--bearer",
            "tok",
        ],
    )

    agent.main()

    session = fake_hunt._module._AUTH_SESSION
    assert session is not None
    assert session.headers_dict() == {
        "Cookie": "session=abc",
        "Authorization": "Bearer tok",
    }
    assert captured["cookies"] == "session=abc"


def test_autopilot_command_md_has_tool_index_prelude():
    """R1: prelude tells Claude to scan tool-index before non-default tool choice."""
    from pathlib import Path

    md = Path(__file__).resolve().parent.parent / "commands" / "autopilot.md"
    text = md.read_text(encoding="utf-8")
    assert "## Tool Index" in text
    assert "docs/tool-index.md" in text


def test_autopilot_command_md_bootstraps_recon_first_and_cache_aware():
    """Autopilot startup should keep context navigation without making state tools the steering wheel."""
    from pathlib import Path

    md = Path(__file__).resolve().parent.parent / "commands" / "autopilot.md"
    text = md.read_text(encoding="utf-8")

    assert "Fresh target startup is recon-first" in text
    assert "python3 tools/hunt.py --target target.com --recon-only" in text
    assert "Existing target startup is cache-aware" in text
    assert "python3 tools/autopilot_state.py --target target.com" in text
    assert "python3 tools/context_pack.py --target target.com" in text
    assert 'print({"ctf_mode": f(".")})' in text
    assert text.index('print({"ctf_mode": f(".")})') < text.index("python3 tools/autopilot_state.py --target target.com")
    assert "not a pre-flight checklist" in text
    assert "1-2 knowledge cards" in text


def test_autopilot_command_md_uses_checkpoint_tool_for_writeback():
    """Autopilot should use checkpoint automation for target-memory write-back."""
    from pathlib import Path

    md = Path(__file__).resolve().parent.parent / "commands" / "autopilot.md"
    text = md.read_text(encoding="utf-8")

    assert "python3 tools/checkpoint.py --target target.com" in text
    assert "target-memory write-back proposals" in text
    assert "apply target memory only when it is useful" in text


def test_autopilot_command_md_requires_next_action_queue_consumption():
    """Autopilot should consume checkpoint/memory queues instead of stopping at suggestions."""
    from pathlib import Path

    md = Path(__file__).resolve().parent.parent / "commands" / "autopilot.md"
    text = md.read_text(encoding="utf-8")

    assert "## Next Action Consumption Loop" in text
    assert "recommended_executable_action" in text
    assert "next_action_queue" in text
    assert "Memory action queue" in text
    assert "If coverage is near 0%" in text
    assert "do not end with only" in text


def test_autopilot_command_md_finish_is_invariant_check_not_checklist():
    """Phase 2 PR-7: '## Finish Pre-checklist' (7 mandatory checkboxes
    that gated finish behind a tool run set) is replaced with
    '## Finish Condition' — 4 state invariants on observed evidence.

    Prior shape (deleted): "- [ ] tools/role_diff.py has been run..."
    forced finish to wait on specific tool invocations regardless of
    whether they made sense for the current evidence. That is a flow
    gate, which design.md C3 explicitly forbids.

    New shape: invariants describing the STATE of evidence — active
    hypothesis resolved or killed, blind tests drained, matrix gap
    absent (Phase 3 guard), intelligence layer consulted.
    """
    from pathlib import Path

    md = Path(__file__).resolve().parent.parent / "commands" / "autopilot.md"
    text = md.read_text(encoding="utf-8")
    # Old heading MUST be gone.
    assert "## Finish Pre-checklist" not in text
    # New heading MUST be present.
    assert "## Finish Condition" in text
    # The four invariant subjects from design.md Contract 4 must each
    # be recognizable in the section (anchor-level, not sentence-level).
    invariant_anchors = (
        "working_hypothesis",         # F1: hypothesis resolved
        "oast_listen",                # F2: blind tests drained
        "matrix gap",                 # F3: coverage matrix (Phase 3 placeholder)
        "intelligence.md",            # F4: intelligence consulted
    )
    for anchor in invariant_anchors:
        assert anchor in text, f"finish invariant anchor missing: {anchor}"
    assert "python3 tools/coverage_matrix.py rebuild --target target.com" in text
    assert "python3 tools/coverage_matrix.py find-gaps --target target.com" in text
    assert "absent or empty matrix is not proof of coverage" in text
    # The framing must NOT reintroduce the checkbox idiom (state check,
    # not flow gate per C3).
    assert text.count("- [ ]") == 0 or "## Finish Pre-checklist" not in text


def test_autopilot_command_md_routes_subagents_via_question_to_tool_advisory():
    """Phase 2 PR-6: deterministic Sub-agent State Machine is replaced by
    a Question -> Tool advisory table. The five sub-agent names must
    still be reachable through the advisory; routing is no longer
    expressed as a state machine.

    Prior shape (deleted): '## Sub-agent State Machine' section with
    'recon completed -> spawn ...' rules. That was the options[]
    anti-pattern routing identified in aisuradd.md Part 2 audit.

    New shape: '## Question -> Tool Reference (advisory, not routing)'
    table mapping next_question text to the cheapest tool that answers
    it. Sub-agents appear as rows when their evidence shape calls for
    them.
    """
    from pathlib import Path

    md = Path(__file__).resolve().parent.parent / "commands" / "autopilot.md"
    text = md.read_text(encoding="utf-8")
    # Old state machine heading MUST be gone.
    assert "## Sub-agent State Machine" not in text
    # New advisory section heading MUST be present (accept either Unicode
    # arrow or ASCII arrow for portability).
    assert "## Question -> Tool Reference" in text or "## Question → Tool Reference" in text
    # All five sub-agent names from design.md must still appear somewhere
    # in the document so they remain reachable.
    for agent_name in ("recon-ranker", "js-reader", "validator", "chain-builder", "report-writer"):
        assert agent_name in text, f"sub-agent name missing from autopilot.md: {agent_name}"
    # The advisory must explicitly frame itself as non-routing to
    # prevent silent regression to a state machine.
    assert "advisory" in text.lower() or "not routing" in text.lower() or "not a state machine" in text.lower()


def test_autopilot_command_md_has_post_hunt_unsafe_review_gate():
    """Autopilot command prompt must not treat skipped side-effectful probes as clean."""
    from pathlib import Path

    md = Path(__file__).resolve().parent.parent / "commands" / "autopilot.md"
    text = md.read_text(encoding="utf-8")

    assert "After `run_vuln_scan`" in text
    assert "action-gated scanner leads" in text
    assert "weak template hits as `lead`" in text
    assert "stable diffs as `signal`" in text
    assert "practical impact as `candidate`" in text
    assert "unsafe_skipped.txt" in text
    assert "ALLOW_UNSAFE_HTTP_TESTS=1" in text
    assert "standard_public_metadata.txt" in text
    assert "checkpoint instead of finishing" in text


def test_autopilot_command_md_defines_deep_as_value_first_comprehensive_depth():
    """Deep mode should increase persistence without becoming a new workflow or favorite-class bias."""
    from pathlib import Path

    md = Path(__file__).resolve().parent.parent / "commands" / "autopilot.md"
    text = md.read_text(encoding="utf-8")
    flat = " ".join(text.split())

    assert "`--deep` is a value-first comprehensive depth flag" in flat
    assert "not a checkpoint mode" in flat
    assert "Substantive actions are actions that add, confirm, disprove, block, or record" in flat
    assert "do not pad the run with repeated scans or cosmetic steps" in flat
    assert "rules/hunting.md#high-intensity-hunting-posture" in text
    assert "value-first coverage model" in flat
    assert "do not lock onto authz/IDOR or any other fixed favorite class" in flat
    assert "SQLi/NoSQLi" in text
    assert "SSRF" in text
    assert "XXE" in text
    assert "RCE/SSTI/command injection" in text
    assert "unsafe deserialization" in flat
    assert "LFI/RFI/path traversal" in text
    assert "coverage matrix rebuilt" in flat
    assert "Evidence Ledger / actor matrix reviewed" in flat
    assert "python3 tools/evidence_ledger.py summary --target target.com" in text
    assert "python3 tools/checkpoint.py --target target.com" in text


def test_autopilot_agent_md_has_post_hunt_unsafe_review_gate():
    """Autopilot agent prompt should re-read surface after scanner coverage."""
    from pathlib import Path

    md = Path(__file__).resolve().parent.parent / "agents" / "autopilot.md"
    text = md.read_text(encoding="utf-8")

    assert "run_vuln_scan" in text
    assert "read_surface_summary" in text
    assert "action-gated scanner leads" in text
    assert "weak template hits are `lead`" in text
    assert "stable diffs are `signal`" in text
    assert "practical impact is `candidate`" in text
    assert "unsafe_skipped.txt" in text
    assert "ALLOW_UNSAFE_HTTP_TESTS=1" in text
    assert "standard_public_metadata.txt" in text
    assert "not tested-clean" in text


def test_autopilot_agent_md_defines_deep_as_value_first_comprehensive_depth():
    """Agent prompt should mirror /autopilot deep-mode coverage and exit discipline."""
    from pathlib import Path

    md = Path(__file__).resolve().parent.parent / "agents" / "autopilot.md"
    text = md.read_text(encoding="utf-8")
    flat = " ".join(text.split())

    assert "`--deep` is a" in text
    assert "value-first comprehensive depth flag" in flat
    assert "not a checkpoint mode" in flat
    assert "Substantive actions add, confirm, disprove, block, or record target evidence" in flat
    assert "do not pad the run with repeated scans or cosmetic steps" in flat
    assert "rules/hunting.md#high-intensity-hunting-posture" in text
    assert "value-first coverage model" in flat
    assert "do not lock onto authz/IDOR or any other fixed favorite class" in flat
    assert "SQLi/NoSQLi" in text
    assert "SSRF" in text
    assert "XXE" in text
    assert "RCE/SSTI/command injection" in text
    assert "unsafe deserialization" in flat
    assert "LFI/RFI/path traversal" in text
    assert "coverage matrix rebuilt" in flat
    assert "Evidence Ledger / actor" in text
    assert "high-value vuln-family directions tested, blocked, not applicable" in flat


def test_autopilot_agent_md_bootstraps_with_context_pack_without_coverage_first():
    """Agent prompt must keep recon/cache startup aligned without coverage/checkpoint first contact."""
    from pathlib import Path

    md = Path(__file__).resolve().parent.parent / "agents" / "autopilot.md"
    text = md.read_text(encoding="utf-8")

    assert "Fresh target startup is recon-first" in text
    assert "python3 tools/hunt.py --target <target> --recon-only" in text
    assert "Existing target startup is cache-aware" in text
    assert "python3 tools/context_pack.py --target <target>" in text
    assert "python3 tools/autopilot_state.py --target <target>" in text
    four_layer = text.split("## Four-Layer Runtime", 1)[1].split("## Case-State First", 1)[0]
    assert "python3 tools/coverage_matrix.py rebuild --target <target>" not in four_layer
    assert "python3 tools/coverage_matrix.py find-gaps --target <target>" not in four_layer
    assert "python3 tools/checkpoint.py --target <target>" not in four_layer
    assert "do not let them drive first contact" in four_layer
