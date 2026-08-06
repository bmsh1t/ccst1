"""Legacy CVE hunter 必须复用 Intel v2 owner。"""

import pytest

from tools import cve_hunter


def test_hunt_cves_delegates_advisory_lookup_to_intel_v2(tmp_path, monkeypatch):
    captured = {}
    monkeypatch.setattr(cve_hunter, "FINDINGS_DIR", str(tmp_path / "findings"))
    monkeypatch.setattr(cve_hunter, "check_exposed_configs", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(
        cve_hunter,
        "detect_technologies",
        lambda *_args, **_kwargs: {"next.js:15.2.1": 1},
    )
    monkeypatch.setattr(cve_hunter, "run_nuclei_cve_scan", lambda *_args, **_kwargs: [])

    def fake_build(repo_root, target, *, techs, memory, include_identity):
        captured.update({
            "repo_root": repo_root,
            "target": target,
            "techs": techs,
            "include_identity": include_identity,
        })
        return {
            "advisories": [{
                "id": "CVE-2026-0001",
                "summary": "Middleware bypass",
                "severity": "HIGH",
                "cvss": 8.8,
                "applicability": "affected",
                "kev": True,
                "epss": 0.8,
                "component": {"name": "next.js", "version": "15.2.1"},
            }],
        }

    monkeypatch.setattr(cve_hunter, "build_target_intel", fake_build)

    advisories, nuclei = cve_hunter.hunt_cves("target.test")

    assert captured["target"] == "target.test"
    assert captured["techs"] == ["next.js:15.2.1"]
    assert captured["include_identity"] is False
    assert advisories == [{
        "id": "CVE-2026-0001",
        "description": "Middleware bypass",
        "cvss_score": 8.8,
        "severity": "high",
        "technology": "next.js",
        "applicability": "affected",
        "kev": True,
        "epss": 0.8,
    }]
    assert nuclei == []


def test_detect_technologies_uses_argv_for_target_bearing_probes(monkeypatch):
    calls = []

    def fake_run_argv(argv, timeout=30):
        calls.append((argv, timeout))
        return False, ""

    monkeypatch.setattr(cve_hunter, "run_argv", fake_run_argv)

    assert cve_hunter.detect_technologies("Example.TEST") == {}
    assert calls[0] == (
        ["httpx", "-silent", "-json", "-tech-detect", "-status-code", "-u", "Example.TEST"],
        30,
    )
    assert calls[1] == (
        ["curl", "-sI", "https://Example.TEST", "--max-time", "10"],
        15,
    )
    assert all(isinstance(argv, list) for argv, _timeout in calls)


def test_nuclei_scan_passes_space_bearing_input_path_as_one_argument(tmp_path, monkeypatch):
    recon_dir = tmp_path / "recon output"
    live_file = recon_dir / "live" / "urls.txt"
    live_file.parent.mkdir(parents=True)
    live_file.write_text("https://example.test/a?x=1&y=2\n", encoding="utf-8")
    captured = {}

    def fake_run_argv(argv, timeout=30):
        captured["argv"] = argv
        captured["timeout"] = timeout
        return True, "[cve-test] hit"

    monkeypatch.setattr(cve_hunter, "run_argv", fake_run_argv)

    assert cve_hunter.run_nuclei_cve_scan("example.test", str(recon_dir)) == ["[cve-test] hit"]
    assert captured["argv"][:3] == ["nuclei", "-l", str(live_file)]
    assert captured["timeout"] == 300


def test_invalid_cve_target_fails_before_execution_or_state_write(tmp_path, monkeypatch):
    findings_dir = tmp_path / "findings"
    monkeypatch.setattr(cve_hunter, "FINDINGS_DIR", str(findings_dir))
    monkeypatch.setattr(
        cve_hunter,
        "run_argv",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("must not execute")),
    )

    with pytest.raises(ValueError):
        cve_hunter.hunt_cves("example.test;touch marker")
    assert not findings_dir.exists()
