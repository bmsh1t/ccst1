"""Legacy CVE hunter 必须复用 Intel v2 owner。"""

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
