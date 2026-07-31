"""Focused contracts for the external EBurst Exchange lane."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from tools.eburst_lane import (
    build_probe_command,
    detect_exchange_hosts,
    resolve_eburst,
    run_exchange_lane,
)
from tools.target_paths import target_storage_key


def test_resolver_requires_python2_and_supports_external_home(tmp_path: Path):
    home = tmp_path / "EBurst"
    home.mkdir()
    (home / "EBurst.py").write_text("# external fixture\n", encoding="utf-8")

    missing = resolve_eburst(env={"EBURST_HOME": str(home)}, which=lambda _name: None)
    assert missing["status"] == "missing_interpreter"

    ready = resolve_eburst(
        env={"EBURST_HOME": str(home)},
        which=lambda name: "/fixture/python2" if name == "python2" else None,
    )
    assert ready["status"] == "ready"
    assert ready["script"] == str(home / "EBurst.py")


def test_exchange_detection_keeps_only_target_owned_evidence(tmp_path: Path):
    target = "example.com"
    recon = tmp_path / "recon" / target_storage_key(target) / "live"
    recon.mkdir(parents=True)
    (recon / "technology_inventory.json").write_text(
        json.dumps(
            {
                "hosts": [
                    {
                        "url": "https://mail.example.com/owa/",
                        "host": "mail.example.com",
                        "title": "Outlook Web Access",
                    },
                    {"url": "https://evil.example.net/owa/", "host": "evil.example.net"},
                ],
                "components": [{"name": "microsoft exchange", "host": "mail.example.com"}],
            }
        ),
        encoding="utf-8",
    )
    (recon / "urls.txt").write_text(
        "https://mail.example.com/ews/exchange.asmx\nhttps://evil.example.net/owa/\n",
        encoding="utf-8",
    )

    hosts = detect_exchange_hosts(tmp_path, target)
    assert [item["host"] for item in hosts] == ["mail.example.com"]
    assert hosts[0]["url"].startswith("https://mail.example.com/")


def test_probe_command_is_read_only_and_rejects_url_argument():
    resolution = {"status": "ready", "interpreter": "python2", "script": "/tmp/EBurst.py"}
    assert build_probe_command(resolution, "mail.example.com") == [
        "python2",
        "/tmp/EBurst.py",
        "-C",
        "-d",
        "mail.example.com",
    ]
    with pytest.raises(ValueError):
        build_probe_command(resolution, "https://mail.example.com/owa")

    assert build_probe_command(
        {"status": "ready", "interpreter": "/tmp/eburst", "script": "", "mode": "binary"},
        "mail.example.com",
    ) == ["/tmp/eburst", "-C", "-d", "mail.example.com"]


def test_run_lane_scopes_hosts_and_persists_bounded_raw_evidence(tmp_path: Path):
    home = tmp_path / "EBurst"
    home.mkdir()
    (home / "EBurst.py").write_text("# external fixture\n", encoding="utf-8")
    calls = []

    def fake_run(argv, **kwargs):
        calls.append((argv, kwargs))
        return subprocess.CompletedProcess(argv, 0, stdout="URL: /owa code:200\n", stderr="")

    summary = run_exchange_lane(
        tmp_path,
        "example.com",
        hosts=["https://mail.example.com/owa"],
        env={"EBURST_HOME": str(home)},
        which=lambda name: "/fixture/python2" if name == "python2" else None,
        runner=fake_run,
    )

    assert summary["status"] == "ok"
    assert len(calls) == 1
    assert calls[0][0][-2:] == ["-d", "mail.example.com"]
    summary_path = tmp_path / "recon" / target_storage_key("example.com") / "exchange" / "eburst" / "summary.json"
    assert summary_path.is_file()
    raw = next(summary_path.parent.joinpath("raw").glob("*.txt"))
    assert "code:200" in raw.read_text(encoding="utf-8")


def test_run_lane_rejects_off_target_explicit_host(tmp_path: Path):
    with pytest.raises(ValueError, match="outside target scope"):
        run_exchange_lane(tmp_path, "example.com", hosts=["https://evil.example.net/owa"])
