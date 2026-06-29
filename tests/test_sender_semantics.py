import socket
import threading

import pytest

from tools.sender_semantics import (
    CAP_BYTE_EXACT,
    CAP_CONNECTION_REUSE,
    CAP_CONFLICTING_LENGTH,
    CAP_HTTP2,
    CAP_MALFORMED_HEADERS,
    RawHttp1Sender,
    get_sender_profile,
    select_sender,
)
from tools.smuggling_executor import (
    SmugglingEvidence,
    get_probe_spec,
    summarize_probe_specs,
)
from tools import sender_semantics, smuggling_executor


def _run_one_shot_server(captured: dict):
    try:
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    except PermissionError as exc:
        captured["error"] = exc
        captured["ready"].set()
        return
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        listener.bind(("127.0.0.1", 0))
    except PermissionError as exc:
        captured["error"] = exc
        captured["ready"].set()
        listener.close()
        return
    listener.listen(1)
    captured["port"] = listener.getsockname()[1]
    captured["ready"].set()
    conn, _addr = listener.accept()
    with conn:
        conn.settimeout(2)
        chunks = []
        while True:
            try:
                chunk = conn.recv(4096)
            except socket.timeout:
                break
            if not chunk:
                break
            chunks.append(chunk)
            if len(b"".join(chunks)) >= captured["expected_len"]:
                break
        captured["request"] = b"".join(chunks)
        conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
    listener.close()


def test_sender_profiles_separate_normal_fetch_from_byte_exact_sender():
    urllib_profile = get_sender_profile("urllib-fetch")
    raw_profile = get_sender_profile("raw-http1")

    assert not urllib_profile.supports({CAP_BYTE_EXACT, CAP_CONFLICTING_LENGTH})
    assert raw_profile.supports({CAP_BYTE_EXACT, CAP_CONFLICTING_LENGTH, CAP_CONNECTION_REUSE})


def test_select_sender_prefers_local_raw_http1_for_smuggling_requirements():
    selected = select_sender({CAP_BYTE_EXACT, CAP_CONFLICTING_LENGTH, CAP_CONNECTION_REUSE})

    assert selected is not None
    assert selected.name == "raw-http1"


def test_h2_requirement_has_no_local_sender_yet_but_has_external_route():
    assert select_sender({CAP_HTTP2, CAP_BYTE_EXACT}, local_only=True) is None

    selected = select_sender({CAP_HTTP2, CAP_BYTE_EXACT}, local_only=False)
    assert selected is not None
    assert selected.name in {"h2-lowlevel", "burp-compatible"}


def test_raw_http1_sender_preserves_request_bytes():
    payload = (
        b"POST /raw HTTP/1.1\r\n"
        b"Host: example.test\r\n"
        b"Transfer-Encoding:\tchunked\r\n"
        b"Content-Length: 3\r\n"
        b"\r\n"
        b"0\r\n\r\n"
    )
    captured = {"ready": threading.Event(), "expected_len": len(payload)}
    thread = threading.Thread(target=_run_one_shot_server, args=(captured,), daemon=True)
    thread.start()
    assert captured["ready"].wait(2)
    if isinstance(captured.get("error"), PermissionError):
        pytest.skip("sandbox forbids local TCP sockets")

    result = RawHttp1Sender(timeout=2).send("127.0.0.1", captured["port"], payload)
    thread.join(2)

    assert result.ok
    assert result.response.startswith(b"HTTP/1.1 200 OK")
    assert captured["request"] == payload


def test_smuggling_specs_encode_sender_capabilities_and_evidence():
    spec = get_probe_spec("0.CL")

    assert CAP_BYTE_EXACT in spec.required_capabilities
    assert CAP_CONFLICTING_LENGTH in spec.required_capabilities
    assert CAP_CONNECTION_REUSE in spec.required_capabilities
    assert SmugglingEvidence.VICTIM_DELIVERY in spec.evidence
    assert spec.choose_sender().name == "raw-http1"


def test_smuggling_summary_marks_h2_variants_as_missing_local_sender():
    rows = summarize_probe_specs(local_only=True)
    h2_rows = [row for row in rows if row["variant"].startswith("H2")]

    assert h2_rows
    assert all(row["selected_sender"] == "" for row in h2_rows)
    assert any(CAP_MALFORMED_HEADERS in row["required_capabilities"] for row in h2_rows)


def test_sender_semantics_cli_selects_raw_http1(capsys):
    rc = sender_semantics.main(
        ["--require", "byte_exact_payload,preserve_conflicting_length,connection_reuse_control"]
    )

    captured = capsys.readouterr()
    assert rc == 0
    assert '"selected_sender": "raw-http1"' in captured.out


def test_smuggling_executor_cli_reports_variant(capsys):
    rc = smuggling_executor.main(["--variant", "0.CL"])

    captured = capsys.readouterr()
    assert rc == 0
    assert '"variant": "0.CL"' in captured.out
    assert '"victim_delivery"' in captured.out


def test_autopilot_docs_route_byte_exact_work_to_sender_semantics():
    command_text = open("commands/autopilot.md", encoding="utf-8").read()
    agent_text = open("agents/autopilot.md", encoding="utf-8").read()

    assert "tools/sender_semantics.py --require" in command_text
    assert "tools/smuggling_executor.py --variant" in command_text
    assert "tools/sender_semantics.py --require" in agent_text
    assert "byte-exact" in agent_text
    assert "absence" in agent_text
