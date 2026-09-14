"""Tests for tools/oast_listen.py — OOB marker attribution.

Scope: the `markers` subcommand and poll-time attribution. The listener
lifecycle (start/poll/stop queue sync) is exercised via
tests/test_autopilot_hypothesis_replay.py and the spray-contract specs; the
deleted pre-db4c930 test file covered the retired payload-template library.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
TOOLS_DIR = REPO_ROOT / "tools"
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))

import oast_listen  # noqa: E402


@pytest.fixture
def isolated_findings(tmp_path, monkeypatch):
    """Redirect FINDINGS_ROOT to a tmp dir for test isolation."""
    monkeypatch.setattr(oast_listen, "FINDINGS_ROOT", tmp_path)
    monkeypatch.setattr(oast_listen, "REPO_ROOT", tmp_path)
    return tmp_path


def _register_marker(target: str, vuln_class: str, label: str = "") -> None:
    """Run the markers subcommand (output asserted via capsys by callers)."""
    rc = oast_listen.main(
        ["markers", "--target", target, "--vuln-class", vuln_class]
        + (["--label", label] if label else [])
    )
    assert rc == 0


def _seed_url(target: str, url: str) -> None:
    paths = oast_listen._paths(target)
    paths["base"].mkdir(parents=True, exist_ok=True)
    paths["url"].write_text(url)
    paths["backend"].write_text("interactsh")


# ─── markers subcommand ────────────────────────────────────────────────────

def test_markers_requires_started_listener(isolated_findings, capsys):
    rc = oast_listen.main(["markers", "--target", "demo.com", "--vuln-class", "ssrf"])
    assert rc == 2
    assert "no OAST URL recorded" in capsys.readouterr().err


def test_markers_requires_vuln_class(isolated_findings, capsys):
    _seed_url("demo.com", "abc.oast.fun")
    rc = oast_listen.main(["markers", "--target", "demo.com", "--vuln-class", ""])
    assert rc == 2
    assert "--vuln-class is required" in capsys.readouterr().err


def test_markers_mints_unique_host_and_persists(isolated_findings, capsys):
    _seed_url("demo.com", "abc.oast.fun")
    rc = oast_listen.main(
        ["markers", "--target", "demo.com", "--vuln-class", "SSRF", "--label", "login-img"]
    )
    assert rc == 0
    out = capsys.readouterr().out
    host = out.splitlines()[0]
    # label sanitized to lowercase, class stamped, unique id from the oast domain
    assert host.startswith("login-img-")
    assert host.endswith(".abc.oast.fun")
    assert "## CLAUDE_HINT" in out

    markers = json.loads(oast_listen._paths("demo.com")["markers"].read_text())
    assert len(markers) == 1
    assert markers[0]["vuln_class"] == "ssrf"
    assert markers[0]["marker_host"] == host

    # Second marker gets a different unique id (attribution depends on it).
    rc = oast_listen.main(
        ["markers", "--target", "demo.com", "--vuln-class", "SSRF", "--label", "login-img"]
    )
    assert rc == 0
    host2 = capsys.readouterr().out.splitlines()[0]
    assert host2 != host
    markers = json.loads(oast_listen._paths("demo.com")["markers"].read_text())
    assert len(markers) == 2


def test_markers_rejects_invalid_label(isolated_findings, capsys):
    _seed_url("demo.com", "abc.oast.fun")
    rc = oast_listen.main(
        ["markers", "--target", "demo.com", "--vuln-class", "ssrf", "--label", "Bad Label!"]
    )
    assert rc == 2
    assert "invalid --label" in capsys.readouterr().err


def test_markers_default_label(isolated_findings, capsys):
    _seed_url("demo.com", "abc.oast.fun")
    rc = oast_listen.main(["markers", "--target", "demo.com", "--vuln-class", "xxe"])
    assert rc == 0
    host = capsys.readouterr().out.splitlines()[0]
    assert host.startswith("xxe-x-")


# ─── poll-time attribution ─────────────────────────────────────────────────

def _seed_callbacks(target: str, records: list[dict]) -> None:
    paths = oast_listen._paths(target)
    paths["base"].mkdir(parents=True, exist_ok=True)
    with paths["callbacks"].open("w", encoding="utf-8") as handle:
        for record in records:
            handle.write(json.dumps(record) + "\n")


def test_poll_attributes_callback_to_marker(isolated_findings, capsys):
    _seed_url("demo.com", "abc.oast.fun")
    rc = oast_listen.main(
        ["markers", "--target", "demo.com", "--vuln-class", "ssrf", "--label", "img-fetch"]
    )
    assert rc == 0
    marker_host = capsys.readouterr().out.splitlines()[0]
    marker_id = json.loads(oast_listen._paths("demo.com")["markers"].read_text())[0]["marker_id"]

    # interactsh callback: full-id carries the marker host.
    _seed_callbacks("demo.com", [
        {"timestamp": "2026-09-14T10:00:00Z", "protocol": "http",
         "full-id": marker_host, "remote-address": "10.0.0.1"},
        {"timestamp": "2026-09-14T10:01:00Z", "protocol": "dns",
         "unique-id": "unrelated.oast.fun", "remote-address": "10.0.0.2"},
    ])
    rc = oast_listen.main(["poll", "--target", "demo.com", "--since-ts", "0"])
    assert rc == 0
    out = capsys.readouterr().out
    lines = [json.loads(l) for l in out.splitlines() if l.startswith("{")]
    attributed = [l for l in lines if l.get("marker_id") == marker_id]
    assert len(attributed) == 1
    assert attributed[0]["marker_vuln_class"] == "ssrf"
    assert attributed[0]["marker_label"] == "img-fetch"
    # the unrelated callback stays unattributed
    unattributed = [l for l in lines if "marker_id" not in l]
    assert len(unattributed) == 1
    assert "registered_markers: 1" in out


def test_poll_without_markers_passes_through(isolated_findings, capsys):
    _seed_url("demo.com", "abc.oast.fun")
    _seed_callbacks("demo.com", [
        {"timestamp": "2026-09-14T10:00:00Z", "protocol": "dns",
         "unique-id": "anything.oast.fun"},
    ])
    rc = oast_listen.main(["poll", "--target", "demo.com", "--since-ts", "0"])
    assert rc == 0
    out = capsys.readouterr().out
    lines = [json.loads(l) for l in out.splitlines() if l.startswith("{")]
    assert len(lines) == 1
    assert "marker_id" not in lines[0]


def test_attribution_is_pure_function():
    markers = [
        {"marker_id": "aaa111", "label": "l1", "vuln_class": "ssrf"},
        {"marker_id": "bbb222", "label": "l2", "vuln_class": "xxe"},
    ]
    hit = oast_listen._attribute_callback(
        {"name": "x-bbb222.abc.oast.fun", "protocol": "dns"}, markers
    )
    assert hit["marker_id"] == "bbb222"
    assert hit["marker_vuln_class"] == "xxe"
    miss = oast_listen._attribute_callback({"name": "other.oast.fun"}, markers)
    assert "marker_id" not in miss
