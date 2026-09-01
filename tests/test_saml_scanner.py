from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path


def test_saml_lane_is_passive_and_clears_old_active_artifacts(tmp_path):
    repo_root = Path(__file__).resolve().parents[1]
    target = "saml.example"
    recon_dir = tmp_path / "recon" / target
    findings_dir = tmp_path / "findings"
    (recon_dir / "live").mkdir(parents=True)
    (recon_dir / "urls").mkdir()
    (recon_dir / "live" / "urls.txt").write_text(
        "https://saml.example\n", encoding="utf-8"
    )
    candidate = "https://saml.example/sso/callback?samlresponse=TOKEN"
    (recon_dir / "urls" / "all.txt").write_text(candidate + "\n", encoding="utf-8")

    stale_dir = findings_dir / "saml"
    stale_dir.mkdir(parents=True)
    (stale_dir / "findings.txt").write_text("stale\n", encoding="utf-8")
    (stale_dir / "certs.txt").write_text("stale\n", encoding="utf-8")

    env = {
        **os.environ,
        "FINDINGS_OUT_DIR": str(findings_dir),
        "BBHUNT_RUNTIME_PHASE_LOCKED": "scan",
        "BBHUNT_RUNTIME_LOCK_TARGET": target,
        "PATH": "/usr/bin:/bin",
    }
    completed = subprocess.run(
        [
            "bash",
            str(repo_root / "tools" / "vuln_scanner.sh"),
            str(recon_dir),
            "--quick",
            "--skip",
            "upload,sqli,xss,ssti,takeover,misconfig,exposure,ssrf,cves,redirects,idor,auth_bypass,auth_flow,mfa",
        ],
        cwd=repo_root,
        env=env,
        text=True,
        capture_output=True,
        timeout=30,
        check=False,
    )

    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert not (findings_dir / "saml" / "findings.txt").exists()
    assert not (findings_dir / "saml" / "certs.txt").exists()
    assert (findings_dir / "saml" / "endpoints.txt").read_text().splitlines() == [candidate]

    summary = json.loads((findings_dir / "summary.json").read_text())
    lane = summary["lane_coverage"]["saml_candidates"]
    assert lane["execution_kind"] == "candidate_only"
    assert lane["selected"] == 0
    assert lane["remaining"] == 1
    assert "SAML-SIG-STRIP" not in completed.stdout
