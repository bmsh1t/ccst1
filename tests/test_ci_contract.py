"""Repository contract for the two-tier GitHub Actions workflow."""

from __future__ import annotations

import re
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW_PATH = ROOT / ".github" / "workflows" / "ci.yml"
LOCK_PATH = ROOT / "requirements-ci.lock"
CORE_TESTS = {
    "tests/test_core_foundation_tools.py",
    "tests/test_runtime_state.py",
    "tests/test_finding_index.py",
    "tests/test_action_queue.py",
    "tests/test_evidence_ledger.py",
    "tests/test_checkpoint.py",
    "tests/test_autopilot_round.py",
}


def _workflow() -> dict:
    payload = yaml.load(WORKFLOW_PATH.read_text(encoding="utf-8"), Loader=yaml.BaseLoader)
    assert isinstance(payload, dict)
    return payload


def _step(job: dict, name: str) -> dict:
    return next(step for step in job["steps"] if step.get("name") == name)


def test_ci_events_and_jobs_keep_fast_and_full_gates_separate() -> None:
    workflow = _workflow()

    assert set(workflow["on"]) == {"push", "pull_request", "schedule", "workflow_dispatch"}
    assert workflow["permissions"] == {"contents": "read"}
    assert set(workflow["jobs"]) == {"core-contracts", "full-suite"}

    core = workflow["jobs"]["core-contracts"]
    full = workflow["jobs"]["full-suite"]
    assert "if" not in core
    assert "workflow_dispatch" in full["if"]
    assert "schedule" in full["if"]
    assert "refs/heads/main" in full["if"]
    assert "pull_request" not in full["if"]

    for job in (core, full):
        assert job["runs-on"] == "ubuntu-latest"
        assert 0 < int(job["timeout-minutes"]) <= 30
        setup = next(step for step in job["steps"] if step.get("uses", "").startswith("actions/setup-python@"))
        assert setup["with"]["python-version"] == "3.13"
        assert setup["with"]["cache-dependency-path"] == "requirements-ci.lock"
        install = _step(job, "Install locked dependencies")["run"]
        assert install == "python -m pip install --require-hashes -r requirements-ci.lock"


def test_ci_commands_cover_each_core_owner_and_the_full_repository() -> None:
    workflow = _workflow()
    core_command = _step(workflow["jobs"]["core-contracts"], "Run core contracts")["run"]
    full_command = _step(workflow["jobs"]["full-suite"], "Run full test suite")["run"]
    audit_command = _step(workflow["jobs"]["full-suite"], "Run strict knowledge audit")["run"]

    assert CORE_TESTS <= set(core_command.split())
    assert full_command == "python -m pytest -q tests"
    assert audit_command == "python tools/knowledge_audit.py --strict"


def test_ci_actions_and_dependency_lock_are_immutable_inputs() -> None:
    workflow_text = WORKFLOW_PATH.read_text(encoding="utf-8")
    action_refs = re.findall(r"uses:\s*(actions/[^@\s]+)@([^\s#]+)", workflow_text)

    assert action_refs
    assert all(re.fullmatch(r"[0-9a-f]{40}", revision) for _, revision in action_refs)
    assert "${{ secrets." not in workflow_text
    assert "~/.claude" not in workflow_text

    lock_text = LOCK_PATH.read_text(encoding="utf-8")
    starts = [
        index
        for index, line in enumerate(lock_text.splitlines())
        if line and not line[0].isspace() and not line.startswith("#")
    ]
    lines = lock_text.splitlines()
    assert starts
    for position, start in enumerate(starts):
        stop = starts[position + 1] if position + 1 < len(starts) else len(lines)
        assert "==" in lines[start]
        assert any("--hash=sha256:" in line for line in lines[start:stop])

    normalized = lock_text.lower()
    for direct in (
        "anthropic",
        "badsecrets",
        "requests",
        "pyyaml",
        "pytest",
        "playwright",
        "pyarrow",
    ):
        assert re.search(rf"(?m)^{direct}==[^\s\\]+", normalized)
