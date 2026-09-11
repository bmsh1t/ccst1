"""Tests for tools/probe.py (task 09-11-ai-capability-roadmap, batch B1).

Probe is the "transparently-ledgered curl": a single request with automatic
scope enforcement, on-disk raw evidence, and an evidence ledger append. The
tests below pin the safety design from the design doc:

- scope violations are rejected *before* any request leaves the process;
- a loopback target (localhost/127.0.0.1) unlocks only loopback hosts on the
  same port, never external URLs;
- ``state_changing``/``redline_checked`` default to False, cannot be silently
  enabled, and ``--state-changing`` without ``--redline-checked`` is refused
  before any request;
- ledger enum typos (vuln_class/actor/variant/result) are refused before the
  request instead of orphaning an unledgered probe file;
- ledger fields land with the agreed defaults (result=lead, source=probe);
- repeat requests produce independent ledger events (no silent dedupe), even
  for two identical bodies inside the same millisecond;
- ``--no-ledger`` skips the ledger but still marks the output NOT RECORDED;
- the on-disk probe JSON captures the full request and response.
"""

from __future__ import annotations

import json
import threading
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

import probe
from evidence_ledger import ledger_path, load_entries


def _forbid_network(*_args, **_kwargs):
    raise AssertionError("rejection must happen before any network I/O")


class RecordingHandler(BaseHTTPRequestHandler):
    """Echo handler that records every request it receives."""

    requests_seen: list[dict] = []

    def _record_and_respond(self) -> None:
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length).decode("utf-8", errors="replace") if length else ""
        type(self).requests_seen.append(
            {
                "method": self.command,
                "path": self.path,
                "headers": dict(self.headers.items()),
                "body": body,
            }
        )
        payload = b'{"echo": true}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):  # noqa: N802 - BaseHTTPRequestHandler API
        self._record_and_respond()

    def do_POST(self):  # noqa: N802 - BaseHTTPRequestHandler API
        self._record_and_respond()

    def do_PUT(self):  # noqa: N802 - BaseHTTPRequestHandler API
        self._record_and_respond()

    def log_message(self, *_args):  # silence test-server logging
        return


@pytest.fixture
def http_server():
    RecordingHandler.requests_seen = []
    try:
        server = ThreadingHTTPServer(("127.0.0.1", 0), RecordingHandler)
    except OSError as exc:  # pragma: no cover - restricted sandboxes
        pytest.skip(f"localhost listener unavailable: {exc}")
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"127.0.0.1:{server.server_port}", RecordingHandler
    server.shutdown()
    thread.join(timeout=2)
    server.server_close()


def _probe_dir(repo_root: Path, target: str) -> Path:
    return repo_root / "evidence" / probe.target_storage_key(
        probe.canonical_target_value(target)
    ) / "probe"


def test_scope_violation_rejected_without_request(tmp_path, http_server):
    """URL pointing outside the target is refused before any I/O."""
    target, handler = http_server

    with pytest.raises(probe.ProbeError, match="outside target scope"):
        probe.run_probe(
            target="127.0.0.1:1",
            url=f"http://{target}/anything",
            repo_root=tmp_path,
        )

    assert handler.requests_seen == []
    assert not _probe_dir(tmp_path, "127.0.0.1:1").exists()
    assert not ledger_path(tmp_path, "127.0.0.1:1").exists()


def test_scope_violation_other_host_rejected_without_request(tmp_path, http_server):
    target, handler = http_server

    with pytest.raises(probe.ProbeError, match="outside target scope"):
        probe.run_probe(
            target="other-host.example",
            url=f"http://{target}/",
            repo_root=tmp_path,
        )

    assert handler.requests_seen == []


def test_port_mismatch_rejected_without_request(tmp_path, http_server):
    target, _handler = http_server
    host = target.split(":")[0]

    with pytest.raises(probe.ProbeError, match="outside target scope"):
        probe.run_probe(
            target=f"{host}:{int(target.split(':')[1]) + 1}",
            url=f"http://{target}/",
            repo_root=tmp_path,
        )


def test_loopback_equivalence_accepted(tmp_path, http_server):
    """localhost and 127.0.0.1 name the same lab target."""
    target, handler = http_server
    port = target.split(":")[1]

    outcome = probe.run_probe(
        target=f"localhost:{port}",
        url=f"http://{target}/loopback",
        repo_root=tmp_path,
    )

    assert outcome["status"] == 200
    assert len(handler.requests_seen) == 1
    assert outcome["ledger"]["recorded"] is True


def test_loopback_target_cannot_reach_external_host(tmp_path, http_server, monkeypatch):
    """The loopback equivalence layer only bridges loopback literals.

    target=localhost:<port> must NOT unlock external hosts, and must stay
    port-strict across the localhost/127.0.0.1 bridge.
    """
    target, _handler = http_server
    port = target.split(":")[1]

    monkeypatch.setattr(probe.urllib.request, "build_opener", _forbid_network)

    with pytest.raises(probe.ProbeError, match="outside target scope"):
        probe.run_probe(
            target=f"localhost:{port}",
            url="http://example.com/anything",
            repo_root=tmp_path,
        )

    # Same host family, wrong port: still rejected (port-strict bridge).
    with pytest.raises(probe.ProbeError, match="outside target scope"):
        probe.run_probe(
            target=f"localhost:{port}",
            url=f"http://127.0.0.1:{int(port) + 1}/",
            repo_root=tmp_path,
        )


def test_bad_ledger_enum_rejected_before_request(tmp_path, http_server, monkeypatch):
    """A vuln_class/actor/variant/result typo fails pre-request.

    Otherwise the request would fire, the ledger append would raise, and the
    on-disk probe file would be orphaned evidence no ledger row points at.
    """
    target, handler = http_server

    monkeypatch.setattr(probe.urllib.request, "build_opener", _forbid_network)

    for kwargs, message in (
        ({"vuln_class": "NotAFamily"}, "unknown vuln_class"),
        ({"actor": "root"}, "unknown actor"),
        ({"variant": "freeform"}, "unknown variant"),
        ({"result": "maybe"}, "unknown result"),
    ):
        with pytest.raises(probe.ProbeError, match=message):
            probe.run_probe(
                target=target,
                url=f"http://{target}/",
                repo_root=tmp_path,
                **kwargs,
            )

    assert handler.requests_seen == []
    assert not ledger_path(tmp_path, target).exists()
    assert not _probe_dir(tmp_path, target).exists()


def test_defaults_record_lead_with_source_probe(tmp_path, http_server):
    target, _handler = http_server

    outcome = probe.run_probe(
        target=target,
        url=f"http://{target}/rest/basket/7",
        repo_root=tmp_path,
    )

    # Ledger defaults: a probe produces a lead, never a conclusion.
    entries = load_entries(tmp_path, target)
    assert len(entries) == 1
    entry = entries[0]
    assert entry["result"] == "lead"
    assert entry["source"] == "probe"
    assert entry["state_changing"] is False
    assert entry["redline_checked"] is False
    assert entry["method"] == "GET"
    assert entry["endpoint"] == "/rest/basket/7"

    # The outcome echoes the flags the AI must be able to see.
    ledger = outcome["ledger"]
    assert ledger["recorded"] is True
    assert ledger["state_changing"] is False
    assert ledger["redline_checked"] is False
    assert ledger["source"] == "probe"
    assert ledger["result"] == "lead"
    assert outcome["ledger_echo"].startswith("LEDGER: state_changing=False redline_checked=False ")
    assert outcome["ledger_echo"].endswith("source=probe")

    # evidence_ref points at the on-disk probe JSON and it exists.
    probe_file = tmp_path / entry["evidence_ref"]
    assert probe_file.is_file()
    assert entry["evidence_ref"].startswith("evidence/")
    assert "/probe/" in entry["evidence_ref"]
    assert outcome["probe_file"] == entry["evidence_ref"]


def test_state_changing_without_redline_checked_refused(tmp_path, http_server):
    """Same discipline as validation_runner: no request before the red-line flag."""
    target, handler = http_server

    with pytest.raises(probe.ProbeError, match="--redline-checked"):
        probe.run_probe(
            target=target,
            url=f"http://{target}/state-change",
            state_changing=True,
            redline_checked=False,
            repo_root=tmp_path,
        )

    assert handler.requests_seen == []
    assert not ledger_path(tmp_path, target).exists()


def test_state_changing_with_redline_checked_records_flags(tmp_path, http_server):
    target, _handler = http_server

    outcome = probe.run_probe(
        target=target,
        url=f"http://{target}/state-change",
        method="POST",
        data='{"qty": 2}',
        state_changing=True,
        redline_checked=True,
        repo_root=tmp_path,
    )

    assert outcome["status"] == 200
    entry = load_entries(tmp_path, target)[0]
    assert entry["state_changing"] is True
    assert entry["redline_checked"] is True
    assert "state_changing=True redline_checked=True" in outcome["ledger_echo"]


def test_repeat_requests_are_independent_ledger_events(tmp_path, http_server):
    """No silent dedupe: the same request twice is two events, two files."""
    target, _handler = http_server
    url = f"http://{target}/repeat"

    first = probe.run_probe(target=target, url=url, repo_root=tmp_path)
    second = probe.run_probe(target=target, url=url, repo_root=tmp_path)

    entries = load_entries(tmp_path, target)
    assert len(entries) == 2
    event_ids = {entry["event_id"] for entry in entries}
    assert first["ledger"]["event_id"] != second["ledger"]["event_id"]
    assert event_ids == {
        first["ledger"]["event_id"],
        second["ledger"]["event_id"],
    }
    assert first["probe_file"] != second["probe_file"]
    # Each append reports an updated write (no dedupe path taken).
    assert first["ledger"]["write_status"] == "updated"
    assert second["ledger"]["write_status"] == "updated"


def test_same_millisecond_collision_is_not_deduplicated(tmp_path, http_server):
    """Identical bodies in the same millisecond stay two events, two files.

    Both probes would derive the same ``<ts>-<hash8>`` stem; record_entry
    would answer ``deduplicated`` for the second one and the probe JSON
    would silently overwrite the first. The exclusive-create -N suffix and
    the unique event_id keep them independent.
    """
    target, handler = http_server
    url = f"http://{target}/same-ms"

    class FrozenDatetime(datetime):
        @classmethod
        def now(cls, tz=None):
            return datetime(2026, 9, 11, 12, 0, 0, 123456, tzinfo=tz or timezone.utc)

    monkey = pytest.MonkeyPatch()
    monkey.setattr(probe, "datetime", FrozenDatetime)
    try:
        first = probe.run_probe(target=target, url=url, repo_root=tmp_path)
        second = probe.run_probe(target=target, url=url, repo_root=tmp_path)
        third = probe.run_probe(target=target, url=url, repo_root=tmp_path)
    finally:
        monkey.undo()

    assert len(handler.requests_seen) == 3
    assert first["ledger"]["write_status"] == "updated"
    assert second["ledger"]["write_status"] == "updated"
    assert third["ledger"]["write_status"] == "updated"
    event_ids = {
        first["ledger"]["event_id"],
        second["ledger"]["event_id"],
        third["ledger"]["event_id"],
    }
    assert len(event_ids) == 3

    entries = load_entries(tmp_path, target)
    assert len(entries) == 3
    assert {entry["event_id"] for entry in entries} == event_ids

    # Three distinct probe files, and all three survive on disk.
    probe_files = {first["probe_file"], second["probe_file"], third["probe_file"]}
    assert len(probe_files) == 3
    for ref in probe_files:
        assert Path(tmp_path, ref).is_file()


def test_no_ledger_escape_hatch_marks_not_recorded(tmp_path, http_server):
    target, _handler = http_server
    url = f"http://{target}/browse"

    outcome = probe.run_probe(
        target=target,
        url=url,
        no_ledger=True,
        repo_root=tmp_path,
    )

    assert outcome["status"] == 200
    assert outcome["ledger"]["recorded"] is False
    assert outcome["ledger"]["skipped"] == "--no-ledger"
    assert outcome["ledger_echo"] == "LEDGER: NOT RECORDED (--no-ledger)"
    assert not ledger_path(tmp_path, target).exists()

    # Raw evidence is still written even when the ledger is skipped.
    assert Path(tmp_path, outcome["probe_file"]).is_file()


def test_probe_file_captures_request_and_response(tmp_path, http_server):
    target, _handler = http_server

    outcome = probe.run_probe(
        target=target,
        url=f"http://{target}/echo?x=1",
        method="POST",
        data='{"hello": "world"}',
        headers={"X-Probe-Test": "marker", "Content-Type": "application/json"},
        note="captured-request-test",
        repo_root=tmp_path,
    )

    payload = json.loads(
        (tmp_path / outcome["probe_file"]).read_text(encoding="utf-8")
    )
    assert payload["kind"] == "probe"
    assert payload["request"]["method"] == "POST"
    assert payload["request"]["url"] == f"http://{target}/echo?x=1"
    assert payload["request"]["body"] == '{"hello": "world"}'
    assert payload["request"]["headers"]["X-Probe-Test"] == "marker"
    assert payload["response"]["status"] == 200
    assert payload["response"]["body"] == '{"echo": true}'
    assert payload["response"]["body_sha256"] == outcome["body_sha256"]
    assert payload["elapsed_ms"] >= 0
    assert payload["flags"] == {"state_changing": False, "redline_checked": False}

    # The note travels with the ledger entry.
    entry = load_entries(tmp_path, target)[0]
    assert entry["notes"] == "captured-request-test"
    assert entry["endpoint"] == "/echo?x=1"


def test_ledger_fields_from_cli_options(tmp_path, http_server):
    target, _handler = http_server

    probe.run_probe(
        target=target,
        url=f"http://{target}/api/users/42",
        vuln_class="Authz",
        actor="peer",
        variant="id_swap",
        result="signal",
        repo_root=tmp_path,
    )

    entry = load_entries(tmp_path, target)[0]
    assert entry["vuln_class"] == "Authz"
    assert entry["actor"] == "peer"
    assert entry["variant"] == "id_swap"
    assert entry["result"] == "signal"


def test_ledger_failure_after_request_is_not_silent(tmp_path, http_server, monkeypatch):
    """A ledger write failure surfaces in the outcome instead of vanishing."""
    target, _handler = http_server

    def broken_record_entry(*_args, **_kwargs):
        raise ValueError("ledger exploded")

    monkeypatch.setattr(probe, "record_entry", broken_record_entry)

    outcome = probe.run_probe(
        target=target,
        url=f"http://{target}/still-probed",
        repo_root=tmp_path,
    )

    assert outcome["status"] == 200
    assert outcome["ledger"]["recorded"] is False
    assert "ledger exploded" in outcome["ledger"]["error"]
    assert "NOT RECORDED (ledger error:" in outcome["ledger_echo"]
    # Raw probe evidence survived the ledger failure.
    assert Path(tmp_path, outcome["probe_file"]).is_file()


def test_main_scope_rejection_exit_code(tmp_path, http_server, capsys):
    target, _handler = http_server

    exit_code = probe.main(
        [
            "--target",
            "127.0.0.1:1",
            "--url",
            f"http://{target}/",
            "--repo-root",
            str(tmp_path),
            "--json",
        ]
    )

    assert exit_code == 2
    stderr = capsys.readouterr().err
    assert "outside target scope" in stderr


def test_main_state_changing_without_redline_exit_code(tmp_path, http_server, capsys):
    target, _handler = http_server

    exit_code = probe.main(
        [
            "--target",
            target,
            "--url",
            f"http://{target}/",
            "--state-changing",
            "--repo-root",
            str(tmp_path),
        ]
    )

    assert exit_code == 2
    assert "--redline-checked" in capsys.readouterr().err


def test_main_success_and_echo(tmp_path, http_server, capsys):
    target, _handler = http_server

    exit_code = probe.main(
        [
            "--target",
            target,
            "--url",
            f"http://{target}/",
            "--repo-root",
            str(tmp_path),
        ]
    )

    assert exit_code == 0
    stdout = capsys.readouterr().out
    assert "STATUS 200" in stdout
    assert "LEDGER: state_changing=False redline_checked=False" in stdout
    assert "source=probe" in stdout
    assert "PROBE FILE" in stdout


def test_main_no_ledger_echo(tmp_path, http_server, capsys):
    target, _handler = http_server

    exit_code = probe.main(
        [
            "--target",
            target,
            "--url",
            f"http://{target}/",
            "--no-ledger",
            "--repo-root",
            str(tmp_path),
        ]
    )

    assert exit_code == 0
    assert "LEDGER: NOT RECORDED (--no-ledger)" in capsys.readouterr().out


def test_main_ledger_failure_exits_one(tmp_path, http_server, capsys, monkeypatch):
    """A ledger failure after a successful request exits 1, not 0.

    The probe JSON must survive and both streams must say what happened:
    stdout carries the NOT RECORDED echo, stderr carries the ledger error.
    """
    target, _handler = http_server

    def broken_record_entry(*_args, **_kwargs):
        raise ValueError("ledger exploded")

    monkeypatch.setattr(probe, "record_entry", broken_record_entry)

    exit_code = probe.main(
        [
            "--target",
            target,
            "--url",
            f"http://{target}/cli-failure",
            "--repo-root",
            str(tmp_path),
        ]
    )

    assert exit_code == 1
    captured = capsys.readouterr()
    assert "NOT RECORDED (ledger error: ledger exploded)" in captured.out
    assert "probe ledger error: ledger exploded" in captured.err
    probe_dir = _probe_dir(tmp_path, target)
    assert len(list(probe_dir.glob("*.json"))) == 1


def test_probe_gates_stay_bucketed():
    """probe.py's own docstring claims bucket discipline — pin it.

    probe.py is not one of the P0 OWNER_SOURCES (it postdates that batch),
    but it raises ``ProbeError(ValueError)`` gates of its own, and its
    docstring states they all belong to DANGER / BOUNDED_FAILSAFE / FORMAT.
    This reuses the P0 registry so the claim cannot silently regress when
    later batches (S1/A*) touch this file.
    """
    import ast

    from test_gate_buckets import _static_text, classify_gate_message

    tree = ast.parse(Path(probe.__file__).read_text(encoding="utf-8"))
    static_gates: list[tuple[int, str]] = []
    dynamic_gates: list[tuple[int, str]] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Raise):
            continue
        exc = node.exc
        target = exc.func if isinstance(exc, ast.Call) else exc
        if not (isinstance(target, ast.Name) and target.id == "ProbeError"):
            continue
        message = (
            _static_text(exc.args[0])
            if isinstance(exc, ast.Call) and exc.args
            else None
        )
        bucket = (static_gates if message is not None else dynamic_gates)
        bucket.append((node.lineno, message or "<dynamic>"))

    assert static_gates, "probe.py should still raise static ProbeError gates"

    unbucketed = [
        f"probe.py:{lineno}: {message!r}"
        for lineno, message in static_gates
        if classify_gate_message(message) is None
    ]
    assert not unbucketed, (
        "probe.py gate outside every bucket (content-level gate?):\n"
        + "\n".join(unbucketed)
    )

    # Exactly one dynamic raise is allowed: the pre-request passthrough of the
    # ledger owner's own normalizer message (validated before any I/O).
    assert len(dynamic_gates) == 1, dynamic_gates
