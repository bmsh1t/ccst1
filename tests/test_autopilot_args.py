"""Inline `/autopilot` 参数契约回归测试。"""

from __future__ import annotations

import json
import shlex
from argparse import Namespace

import agent
import hunt
import pytest

from tools import autopilot_args


EXPECTED_KEYS = [
    "schema_version",
    "valid",
    "action",
    "argv",
    "target_input",
    "target",
    "target_kind",
    "target_shell",
    "seed_url",
    "seed_url_shell",
    "auth_file",
    "auth_file_shell",
    "hunt_auth_flags",
    "cadence",
    "checkpoint_policy",
    "checkpoint_trigger",
    "quick",
    "deep",
    "max_lanes",
    "invocation_batch",
    "recon_flags",
    "errors",
]


def test_parse_defaults_to_paranoid_and_accepts_flags_around_target():
    payload = autopilot_args.parse_autopilot_args(
        ["--quick", "https://Example.TEST/admin?x=1", "--deep", "--normal"]
    )

    assert list(payload) == EXPECTED_KEYS
    assert payload == {
        "schema_version": 3,
        "valid": True,
        "action": "continue",
        "argv": ["--quick", "https://Example.TEST/admin?x=1", "--deep", "--normal"],
        "target_input": "https://Example.TEST/admin?x=1",
        "target": "example.test",
        "target_kind": "domain",
        "target_shell": "example.test",
        "seed_url": "https://Example.TEST/admin?x=1",
        "seed_url_shell": "'https://Example.TEST/admin?x=1'",
        "auth_file": None,
        "auth_file_shell": None,
        "hunt_auth_flags": [],
        "cadence": "normal",
        "checkpoint_policy": "batched",
        "checkpoint_trigger": "checkpoint after each coherent evidence-lane batch",
        "quick": True,
        "deep": True,
        "max_lanes": None,
        "invocation_batch": {
            "bounded": False,
            "max_lanes": None,
            "handoff": "normal_finish_condition",
        },
        "recon_flags": ["--quick"],
        "errors": [],
    }

    default_payload = autopilot_args.parse_autopilot_args(["example.test"])
    assert default_payload["cadence"] == "paranoid"
    assert default_payload["checkpoint_policy"] == "frequent"
    assert default_payload["checkpoint_trigger"] == "checkpoint after every substantive state change"
    assert default_payload["recon_flags"] == []
    assert default_payload["seed_url"] is None


@pytest.mark.parametrize(
    ("target", "expected_kind", "expected_target"),
    (
        ("127.0.0.1:3000", "ip", "127.0.0.1:3000"),
        ("192.168.1.42/24", "cidr", "192.168.1.0/24"),
        ("app.example.test", "domain", "app.example.test"),
    ),
)
def test_parse_classifies_single_targets(target, expected_kind, expected_target):
    payload = autopilot_args.parse_autopilot_args(["--yolo", target, "--quick"])

    assert payload["valid"] is True
    assert payload["target_kind"] == expected_kind
    assert payload["target"] == expected_target
    assert payload["cadence"] == "yolo"
    assert payload["checkpoint_policy"] == "minimal"


def test_parse_resolves_readable_list_relative_to_explicit_cwd(tmp_path):
    scope = tmp_path / "primary targets.txt"
    scope.write_text("example.test\napi.example.test\n", encoding="utf-8")

    payload = autopilot_args.parse_autopilot_args([scope.name, "--normal"], cwd=tmp_path)

    assert payload["valid"] is True
    assert payload["target_input"] == scope.name
    assert payload["target"] == str(scope.resolve())
    assert payload["target_kind"] == "list"
    assert shlex.split(payload["target_shell"]) == [str(scope.resolve())]


def test_repeated_core_flags_are_idempotent():
    payload = autopilot_args.parse_autopilot_args(
        ["--quick", "--quick", "example.test", "--normal", "--normal", "--deep"]
    )

    assert payload["valid"] is True
    assert payload["cadence"] == "normal"
    assert payload["quick"] is True
    assert payload["deep"] is True


def test_auth_file_relative_path_and_full_eight_token_core_invocation(tmp_path):
    auth_file = tmp_path / "private auth.json"
    auth_file.write_text('{"cookie":"session=example"}\n', encoding="utf-8")

    payload = autopilot_args.parse_autopilot_args(
        [
            "example.test",
            "--normal",
            "--quick",
            "--deep",
            "--auth-file",
            auth_file.name,
            "--max-lanes",
            "4",
        ],
        cwd=tmp_path,
    )

    assert payload["valid"] is True
    assert payload["auth_file"] == str(auth_file.resolve())
    assert shlex.split(payload["auth_file_shell"]) == [str(auth_file.resolve())]
    assert payload["hunt_auth_flags"] == ["--auth-file", str(auth_file.resolve())]
    assert payload["recon_flags"] == ["--quick"]
    assert payload["max_lanes"] == 4
    assert payload["invocation_batch"] == {
        "bounded": True,
        "max_lanes": 4,
        "handoff": "checkpoint_and_handoff_after_max_lanes",
    }

    overflow = autopilot_args.parse_autopilot_args(
        [*payload["argv"], "--quick"],
        cwd=tmp_path,
    )
    assert overflow["valid"] is False
    assert [error["code"] for error in overflow["errors"]] == ["overflow"]


def test_auth_file_equal_form_resolves_absolute_path(tmp_path):
    auth_file = tmp_path / "auth.env"
    auth_file.write_text("BBHUNT_COOKIE=session=example\n", encoding="utf-8")

    payload = autopilot_args.parse_autopilot_args(
        ["--auth-file=" + str(auth_file), "https://example.test/account"],
        cwd=tmp_path / "unrelated",
    )

    assert payload["valid"] is True
    assert payload["auth_file"] == str(auth_file.resolve())
    assert payload["seed_url"] == "https://example.test/account"


@pytest.mark.parametrize(
    ("auth_args", "expected_code"),
    (
        (["--auth-file"], "missing_auth_file_value"),
        (["--auth-file="], "missing_auth_file_value"),
        (["--auth-file", "missing.json"], "invalid_auth_file"),
    ),
)
def test_invalid_auth_file_arguments_stop_before_runtime(tmp_path, auth_args, expected_code):
    payload = autopilot_args.parse_autopilot_args(
        ["example.test", *auth_args],
        cwd=tmp_path,
    )

    assert payload["valid"] is False
    assert payload["action"] == "stop_invalid_arguments"
    assert expected_code in [error["code"] for error in payload["errors"]]


def test_multiple_auth_files_are_rejected(tmp_path):
    first = tmp_path / "first.json"
    second = tmp_path / "second.json"
    first.write_text("{}\n", encoding="utf-8")
    second.write_text("{}\n", encoding="utf-8")

    payload = autopilot_args.parse_autopilot_args(
        ["example.test", "--auth-file=" + str(first), "--auth-file=" + str(second)],
        cwd=tmp_path,
    )

    assert payload["valid"] is False
    assert [error["code"] for error in payload["errors"]] == ["auth_file_conflict"]


def test_empty_claude_placeholder_slots_do_not_count_as_arguments():
    payload = autopilot_args.parse_autopilot_args(
        ["example.test", "--deep", "", "", "", "", ""]
    )

    assert payload["valid"] is True
    assert payload["argv"] == ["example.test", "--deep"]
    assert payload["recon_flags"] == ["--deep"]


def test_dynamic_command_shell_fallback_is_not_treated_as_target(tmp_path):
    shell_fallback = tmp_path / "zsh"
    shell_fallback.write_text("#!/bin/sh\n", encoding="utf-8")
    shell_fallback.chmod(0o755)

    payload = autopilot_args.parse_autopilot_args([str(shell_fallback)])

    assert payload["argv"] == []
    assert payload["action"] == "ask_target"
    assert [error["code"] for error in payload["errors"]] == ["missing_target"]


def test_missing_target_asks_without_continuing():
    payload = autopilot_args.parse_autopilot_args(["--quick", "--deep"])

    assert payload["valid"] is False
    assert payload["action"] == "ask_target"
    assert payload["target"] is None
    assert [error["code"] for error in payload["errors"]] == ["missing_target"]


@pytest.mark.parametrize(
    ("argv", "expected_codes"),
    (
        (["example.test", "--unknown"], ["unknown_flag"]),
        (["--normal", "example.test", "--yolo"], ["cadence_conflict"]),
        (["one.test", "two.test"], ["multiple_targets"]),
        (
            [
                "example.test", "--quick", "--deep", "--normal", "--quick", "--deep",
                "--max-lanes", "2", "extra",
            ],
            ["overflow", "multiple_targets"],
        ),
    ),
)
def test_invalid_core_arguments_stop_before_runtime_actions(argv, expected_codes):
    payload = autopilot_args.parse_autopilot_args(argv)

    assert payload["valid"] is False
    assert payload["action"] == "stop_invalid_arguments"
    assert [error["code"] for error in payload["errors"]] == expected_codes


@pytest.mark.parametrize(
    "legacy_argv",
    (
        ["--parallel"],
        ["--parallel-hypotheses"],
        ["--vision"],
        ["--self-review"],
        ["--calibrate-patterns"],
        ["--max-parallel", "4"],
        ["--max-screenshots=4"],
        ["--worker-timeout-secs", "60"],
        ["--resume", "latest"],
        ["--agent"],
    ),
)
def test_legacy_only_flags_are_rejected_with_direct_runtime_hint(legacy_argv):
    payload = autopilot_args.parse_autopilot_args(
        ["example.test", *legacy_argv]
    )

    assert payload["valid"] is False
    assert payload["action"] == "stop_invalid_arguments"
    legacy_error = next(
        error for error in payload["errors"] if error["code"] == "legacy_only_flag"
    )
    assert "agent.py --target <target>" in legacy_error["hint"]
    assert "tools/hunt.py --target <target> --agent" in legacy_error["hint"]


def test_target_shell_round_trips_shell_metacharacters_without_execution_semantics():
    target = "example.test; touch /tmp/not-executed; $(touch /tmp/still-not-executed)"
    payload = autopilot_args.parse_autopilot_args([target])

    assert payload["valid"] is True
    assert shlex.split(payload["target_shell"]) == [target]


def test_json_cli_is_compact_stable_and_returns_zero(capsys):
    assert autopilot_args.main(["--json", "--", "example.test", "--normal"]) == 0
    output = capsys.readouterr().out.strip()

    assert "\n" not in output
    assert json.loads(output) == autopilot_args.parse_autopilot_args(
        ["example.test", "--normal"]
    )


def test_deep_max_lanes_accepts_equal_form_and_rejects_invalid_boundaries():
    bounded = autopilot_args.parse_autopilot_args(
        ["example.test", "--deep", "--max-lanes=3", "--normal"]
    )
    no_deep = autopilot_args.parse_autopilot_args(
        ["example.test", "--max-lanes", "3"]
    )
    zero = autopilot_args.parse_autopilot_args(
        ["example.test", "--deep", "--max-lanes", "0"]
    )
    negative = autopilot_args.parse_autopilot_args(
        ["example.test", "--deep", "--max-lanes", "-1"]
    )
    duplicate = autopilot_args.parse_autopilot_args(
        ["example.test", "--deep", "--max-lanes", "2", "--max-lanes=3"]
    )

    assert bounded["valid"] is True
    assert bounded["max_lanes"] == 3
    assert bounded["invocation_batch"]["bounded"] is True
    assert [item["code"] for item in no_deep["errors"]] == ["max_lanes_requires_deep"]
    assert [item["code"] for item in zero["errors"]] == ["invalid_max_lanes"]
    assert [item["code"] for item in negative["errors"]] == ["invalid_max_lanes"]
    assert [item["code"] for item in duplicate["errors"]] == ["max_lanes_conflict"]


@pytest.mark.parametrize(
    ("namespace", "expected"),
    (
        (Namespace(), "paranoid"),
        (Namespace(paranoid=True, normal=False, yolo=False), "paranoid"),
        (Namespace(paranoid=False, normal=True, yolo=False), "normal"),
        (Namespace(paranoid=False, normal=False, yolo=True), "yolo"),
    ),
)
def test_cadence_from_namespace(namespace, expected):
    assert autopilot_args.cadence_from_namespace(namespace) == expected


def test_direct_cli_compatibility_wrappers_delegate_to_shared_helper(monkeypatch):
    namespace = Namespace()
    monkeypatch.setattr(hunt, "cadence_from_namespace", lambda value: "hunt-shared")
    monkeypatch.setattr(agent, "cadence_from_namespace", lambda value: "agent-shared")

    assert hunt.resolve_autopilot_mode(namespace) == "hunt-shared"
    assert agent._resolve_cli_autopilot_mode(namespace) == "agent-shared"
