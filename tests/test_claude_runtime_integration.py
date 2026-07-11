"""真实 Claude CLI 对 staged runtime 的 slash-command/agent wiring 集成测试。"""

from __future__ import annotations

import errno
import json
import os
import queue
import shlex
import shutil
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from tools import runtime_doctor
from tools.autopilot_args import (
    MAX_CAPTURED_TOKENS,
    parse_autopilot_args,
    render_autopilot_args_json,
)


REPO_ROOT = Path(__file__).resolve().parents[1]
FAKE_RESPONSE_TEXT = "runtime-probe-ok"
DYNAMIC_ARGUMENT_COMMAND = (
    '!`python3 tools/autopilot_args.py --json -- '
    '"$0" "$1" "$2" "$3" "$4" "$5" "$6"`'
)


class _CaptureServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, server_address, handler_class):
        super().__init__(server_address, handler_class)
        self.requests: queue.Queue[dict] = queue.Queue()


class _AnthropicHandler(BaseHTTPRequestHandler):
    def log_message(self, _format, *_args):
        return

    def do_POST(self):  # noqa: N802 - BaseHTTPRequestHandler API
        content_length = int(self.headers.get("content-length", "0"))
        raw_body = self.rfile.read(content_length)
        payload = json.loads(raw_body or b"{}")
        self.server.requests.put({  # type: ignore[attr-defined]
            "path": self.path,
            "payload": payload,
        })

        model = payload.get("model") or "claude-runtime-probe"
        events = (
            (
                "message_start",
                {
                    "type": "message_start",
                    "message": {
                        "id": "msg_runtime_probe",
                        "type": "message",
                        "role": "assistant",
                        "model": model,
                        "content": [],
                        "stop_reason": None,
                        "stop_sequence": None,
                        "usage": {"input_tokens": 1, "output_tokens": 0},
                    },
                },
            ),
            (
                "content_block_start",
                {
                    "type": "content_block_start",
                    "index": 0,
                    "content_block": {"type": "text", "text": ""},
                },
            ),
            (
                "content_block_delta",
                {
                    "type": "content_block_delta",
                    "index": 0,
                    "delta": {"type": "text_delta", "text": FAKE_RESPONSE_TEXT},
                },
            ),
            ("content_block_stop", {"type": "content_block_stop", "index": 0}),
            (
                "message_delta",
                {
                    "type": "message_delta",
                    "delta": {"stop_reason": "end_turn", "stop_sequence": None},
                    "usage": {"output_tokens": 1},
                },
            ),
            ("message_stop", {"type": "message_stop"}),
        )
        response = "".join(
            f"event: {event_name}\ndata: {json.dumps(event)}\n\n"
            for event_name, event in events
        ).encode()

        self.send_response(200)
        self.send_header("content-type", "text/event-stream")
        self.send_header("content-length", str(len(response)))
        self.end_headers()
        self.wfile.write(response)


@pytest.fixture(scope="module")
def fake_anthropic_server():
    try:
        server = _CaptureServer(("127.0.0.1", 0), _AnthropicHandler)
    except PermissionError as exc:
        if exc.errno == errno.EPERM:
            pytest.skip("sandbox forbids the localhost fake Anthropic endpoint")
        raise

    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


@pytest.fixture(scope="module")
def staged_claude_runtime(tmp_path_factory):
    claude_path = shutil.which("claude")
    if not claude_path:
        pytest.skip("Claude CLI is not installed")

    stage_root = tmp_path_factory.mktemp("claude-runtime")
    home = stage_root / "home"
    home.mkdir()
    env = os.environ.copy()
    env["HOME"] = str(home)
    env["XDG_CONFIG_HOME"] = str(stage_root / "xdg-config")
    result = subprocess.run(
        ["bash", str(REPO_ROOT / "install.sh")],
        cwd=REPO_ROOT,
        env=env,
        stdin=subprocess.DEVNULL,
        text=True,
        capture_output=True,
        check=False,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr + result.stdout

    parity = runtime_doctor.compare_runtime(
        repo_root=REPO_ROOT,
        runtime_root=home / ".claude",
    )
    assert parity["clean"] is True
    return {"claude": claude_path, "home": home, "stage_root": stage_root}


@pytest.fixture
def run_staged_claude(fake_anthropic_server, staged_claude_runtime):
    def run(*prompt_args: str) -> dict:
        while True:
            try:
                fake_anthropic_server.requests.get_nowait()
            except queue.Empty:
                break

        host, port = fake_anthropic_server.server_address
        env = os.environ.copy()
        for key in (
            "ANTHROPIC_AUTH_TOKEN",
            "CLAUDE_CODE_OAUTH_TOKEN",
            "CLAUDE_CODE_USE_BEDROCK",
            "CLAUDE_CODE_USE_VERTEX",
            "CLAUDE_CODE_USE_FOUNDRY",
            "CLAUDE_CONFIG_DIR",
        ):
            env.pop(key, None)
        env.update({
            "HOME": str(staged_claude_runtime["home"]),
            "XDG_CONFIG_HOME": str(staged_claude_runtime["stage_root"] / "xdg-config"),
            "ANTHROPIC_API_KEY": "staged-runtime-test-key",
            "ANTHROPIC_BASE_URL": f"http://{host}:{port}",
            "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1",
            "NO_PROXY": "127.0.0.1,localhost",
            "no_proxy": "127.0.0.1,localhost",
        })
        result = subprocess.run(
            [
                staged_claude_runtime["claude"],
                "-p",
                "--setting-sources",
                "user",
                "--tools",
                "Bash",
                "--no-session-persistence",
                *prompt_args,
            ],
            cwd=REPO_ROOT,
            env=env,
            stdin=subprocess.DEVNULL,
            text=True,
            capture_output=True,
            check=False,
            timeout=30,
        )
        assert result.returncode == 0, result.stderr + result.stdout
        assert result.stdout.strip() == FAKE_RESPONSE_TEXT
        try:
            captured = fake_anthropic_server.requests.get(timeout=2)
        except queue.Empty:
            pytest.fail("Claude CLI did not call the localhost fake endpoint")
        assert captured["path"].split("?", 1)[0].endswith("/v1/messages")
        return captured["payload"]

    return run


def _message_texts(payload: dict) -> list[str]:
    texts = []
    for message in payload.get("messages", []):
        content = message.get("content", []) if isinstance(message, dict) else []
        if isinstance(content, str):
            texts.append(content)
            continue
        for item in content if isinstance(content, list) else []:
            if isinstance(item, dict) and isinstance(item.get("text"), str):
                texts.append(item["text"])
    return texts


def _all_request_text(payload: dict) -> str:
    texts = _message_texts(payload)
    for item in payload.get("system", []):
        if isinstance(item, dict) and isinstance(item.get("text"), str):
            texts.append(item["text"])
    return "\n".join(texts)


def _installed_command_body(home: Path, arguments: str) -> str:
    text = (home / ".claude" / "commands" / "autopilot.md").read_text(encoding="utf-8")
    lines = text.splitlines(keepends=True)
    assert lines and lines[0].strip() == "---"
    closing_index = next(
        index for index, line in enumerate(lines[1:], 1) if line.strip() == "---"
    )
    body = "".join(lines[closing_index + 1:])
    assert body.count(DYNAMIC_ARGUMENT_COMMAND) == 1
    captured_tokens = shlex.split(arguments)[:MAX_CAPTURED_TOKENS] if arguments else []
    parsed_json = render_autopilot_args_json(
        parse_autopilot_args(captured_tokens, cwd=REPO_ROOT)
    )
    return body.replace(DYNAMIC_ARGUMENT_COMMAND, parsed_json)


def _parsed_argument_contract(command_body: str) -> dict:
    prefix = "Authoritative argument contract (do not reinterpret): "
    line = next(line for line in command_body.splitlines() if line.startswith(prefix))
    return json.loads(line.removeprefix(prefix))


@pytest.mark.parametrize(
    "arguments",
    (
        "example.test --normal",
        "--quick example.test --deep",
        "targets.txt --normal",
        "",
    ),
)
def test_real_claude_cli_expands_installed_autopilot_arguments(
    arguments,
    run_staged_claude,
    staged_claude_runtime,
):
    invocation = "/autopilot" + (f" {arguments}" if arguments else "")
    payload = run_staged_claude(invocation)
    message_texts = _message_texts(payload)
    metadata = next(text for text in message_texts if "<command-message>" in text)
    command_body = next(text for text in message_texts if text.startswith("# /autopilot"))

    assert "<command-message>autopilot</command-message>" in metadata
    assert "<command-name>/autopilot</command-name>" in metadata
    if arguments:
        assert f"<command-args>{arguments}</command-args>" in metadata
    else:
        assert "<command-args>" not in metadata
    assert command_body == _installed_command_body(
        staged_claude_runtime["home"],
        arguments,
    )
    assert "$ARGUMENTS" not in command_body
    assert "description: Expert Hunter" not in command_body
    assert _parsed_argument_contract(command_body) == parse_autopilot_args(
        shlex.split(arguments)[:MAX_CAPTURED_TOKENS] if arguments else [],
        cwd=REPO_ROOT,
    )


def test_real_claude_cli_expands_readable_batch_target(
    run_staged_claude,
    staged_claude_runtime,
):
    scope = staged_claude_runtime["stage_root"] / "primary targets.txt"
    scope.write_text("one.example.test\ntwo.example.test\n", encoding="utf-8")

    payload = run_staged_claude(f"/autopilot '{scope}' --normal")
    command_body = next(
        text for text in _message_texts(payload) if text.startswith("# /autopilot")
    )
    parsed = _parsed_argument_contract(command_body)

    assert parsed["valid"] is True
    assert parsed["target"] == str(scope.resolve())
    assert parsed["target_kind"] == "list"
    assert parsed["cadence"] == "normal"


def test_real_claude_cli_marks_seventh_argument_as_overflow(
    run_staged_claude,
):
    payload = run_staged_claude(
        "/autopilot example.test --quick --deep --normal --quick --deep --quick"
    )
    command_body = next(
        text for text in _message_texts(payload) if text.startswith("# /autopilot")
    )
    parsed = _parsed_argument_contract(command_body)

    assert parsed["valid"] is False
    assert parsed["action"] == "stop_invalid_arguments"
    assert parsed["deep"] is True
    assert [error["code"] for error in parsed["errors"]] == ["overflow"]


def test_real_claude_cli_discovers_installed_optional_autopilot_agent(
    run_staged_claude,
):
    payload = run_staged_claude(
        "--agent",
        "autopilot",
        "return only the staged-agent-probe result",
    )
    combined = _all_request_text(payload)

    assert "explicitly invoked optional Claude subagent" in combined
    assert "not the implicit backend of the `/autopilot` slash command" in combined
    assert "return only the staged-agent-probe result" in combined
