"""Release-only wiring evidence: real CLI, isolated runtime, local fake API."""

import errno
import json
import os
import shutil
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from tools.runtime_doctor import compare_runtime

REPO = Path(__file__).resolve().parents[1]


def test_installed_autopilot_loads_in_real_claude(tmp_path):
    claude = shutil.which("claude")
    if not claude:
        pytest.skip("Claude CLI not installed; release acceptance requires a real wiring run")
    checkout = tmp_path / "checkout"
    checkout.mkdir()
    for name in ("commands", "agents", "skills", "tools", "rules", "knowledge", "docs"):
        shutil.copytree(REPO / name, checkout / name, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    # Memory modules are flat; target state under memory/goals must stay outside the fixture.
    (checkout / "memory").mkdir()
    for source in (REPO / "memory").glob("*.py"):
        shutil.copy2(source, checkout / "memory" / source.name)
    shutil.copy2(REPO / "install.sh", checkout / "install.sh")
    subprocess.run(["git", "init", "-q", str(checkout)], check=True)
    user_dir = tmp_path / "user"
    runtime = user_dir / ".claude"
    # Build an allowlist rather than inheriting provider credentials or hooks.
    env = {
        "PATH": str(Path(sys.executable).parent) + os.pathsep + os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": str(user_dir), "XDG_CONFIG_HOME": str(tmp_path / "config"),
        "CLAUDE_CONFIG_DIR": str(runtime), "CCST_RUNTIME_ROOT": str(runtime),
        "ANTHROPIC_API_KEY": "fixture-only", "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1",
        "NO_PROXY": "127.0.0.1,localhost", "no_proxy": "127.0.0.1,localhost",
    }
    installed = subprocess.run(["bash", str(checkout / "install.sh")], env=env, cwd=checkout,
                               stdin=subprocess.DEVNULL, text=True, capture_output=True, timeout=30)
    assert installed.returncode == 0, installed.stdout + installed.stderr
    assert compare_runtime(checkout, runtime)["clean"]
    captured = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def do_POST(self):
            payload = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            captured.append((self.path, payload))
            message = {"id": "msg_fixture", "type": "message", "role": "assistant",
                       "model": payload.get("model", "fixture"), "content": [], "stop_reason": None,
                       "stop_sequence": None, "usage": {"input_tokens": 1, "output_tokens": 0}}
            events = [
                {"type": "message_start", "message": message},
                {"type": "content_block_start", "index": 0, "content_block": {"type": "text", "text": ""}},
                {"type": "content_block_delta", "index": 0,
                 "delta": {"type": "text_delta", "text": "LOCAL_WIRING_OK"}},
                {"type": "content_block_stop", "index": 0},
                {"type": "message_delta", "delta": {"stop_reason": "end_turn", "stop_sequence": None},
                 "usage": {"output_tokens": 1}},
                {"type": "message_stop"},
            ]
            body = "".join(f"event: {event['type']}\ndata: {json.dumps(event)}\n\n" for event in events).encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    try:
        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    except OSError as exc:
        if exc.errno in (errno.EPERM, errno.EACCES):
            pytest.skip("Local sockets denied; release acceptance requires a successful host run")
        raise
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    env["ANTHROPIC_BASE_URL"] = f"http://127.0.0.1:{server.server_port}"
    try:
        for arguments in ("", "--quick 127.0.0.1 --deep"):
            captured.clear()
            result = subprocess.run(
                [claude, "-p", "--setting-sources", "user", "--tools", "Bash",
                 "--allowedTools", "Bash(python3 *)", "--no-session-persistence", "--strict-mcp-config",
                 "--debug-file", str(tmp_path / "claude-debug.txt"),
                 "/autopilot" + (" " + arguments if arguments else "")],
                env=env, cwd=checkout, stdin=subprocess.DEVNULL, text=True, capture_output=True, timeout=45,
            )
            assert result.returncode == 0, result.stdout + result.stderr
            assert result.stdout.strip() == "LOCAL_WIRING_OK", (
                result.stdout + result.stderr + (tmp_path / "claude-debug.txt").read_text()[-6000:])
            messages = [payload for path, payload in captured if path.split("?", 1)[0] == "/v1/messages"]
            assert messages, "Claude did not call the local Messages endpoint"
            texts = [block["text"] for message in messages[-1]["messages"]
                     for block in message["content"] if isinstance(block, dict) and "text" in block]
            metadata = next(text for text in texts if "<command-name>/autopilot</command-name>" in text)
            body = next(text for text in texts if text.startswith("# /autopilot"))
            assert "<command-message>autopilot</command-message>" in metadata
            if arguments:
                assert f"<command-args>{arguments}</command-args>" in metadata
            prefix = "Authoritative bootstrap contract (do not reinterpret): "
            bootstrap = json.loads(next(line[len(prefix):] for line in body.splitlines() if line.startswith(prefix)))
            if arguments:
                assert bootstrap["arguments"]["target"] == "127.0.0.1"
                assert bootstrap["arguments"]["quick"] and bootstrap["arguments"]["deep"]
                assert bootstrap["runtime"]["clean"]
                assert bootstrap["repo_root"] == str(checkout)
            else:
                assert bootstrap["action"] == "ask_target"
            installed_body = (runtime / "commands/autopilot.md").read_text().split("---", 2)[2].lstrip("\n")
            expected = "\n".join(line for line in installed_body.splitlines() if not line.startswith(prefix))
            actual = "\n".join(line for line in body.splitlines() if not line.startswith(prefix))
            assert actual == expected
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
