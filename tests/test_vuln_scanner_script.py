"""Regression tests for vuln_scanner.sh stability guards."""

import json
import os
import shutil
import subprocess
from pathlib import Path

from tools.runtime_state import runtime_phase_lock


SCANNER_SKIP_MODULES = [
    "upload",
    "sqli",
    "xss",
    "ssti",
    "takeover",
    "misconfig",
    "exposure",
    "ssrf",
    "cves",
    "redirects",
    "idor",
    "auth_bypass",
    "auth_flow",
    "mfa",
    "saml",
]


def _skip_modules_except(*enabled_modules: str) -> str:
    enabled = set(enabled_modules)
    return ",".join(module for module in SCANNER_SKIP_MODULES if module not in enabled)


def test_vuln_scanner_bash_syntax_is_valid():
    script = Path(__file__).resolve().parent.parent / "tools" / "vuln_scanner.sh"

    result = subprocess.run(
        ["bash", "-n", str(script)],
        cwd=script.resolve().parent.parent,
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr + result.stdout


def test_vuln_scanner_accepts_normalized_inherited_lock_for_url_manifest(tmp_path):
    script = Path(__file__).resolve().parent.parent / "tools" / "vuln_scanner.sh"
    target = "127.0.0.1:43123"
    recon_dir = tmp_path / "recon" / target
    findings_dir = tmp_path / "findings"
    (recon_dir / "live").mkdir(parents=True)
    (recon_dir / "recon_manifest.jsonl").write_text(
        json.dumps({"record_type": "recon_phase", "target": f"http://{target}"}) + "\n",
        encoding="utf-8",
    )
    (recon_dir / "live" / "urls.txt").write_text(f"http://{target}\n", encoding="utf-8")

    env = os.environ.copy()
    env.update(
        {
            "FINDINGS_OUT_DIR": str(findings_dir),
            "BBHUNT_RUNTIME_PHASE_LOCKED": "scan",
            "BBHUNT_RUNTIME_LOCK_TARGET": target,
        }
    )
    repo_root = script.resolve().parent.parent
    with runtime_phase_lock(repo_root, target, "scan") as lock_path:
        result = subprocess.run(
            ["bash", str(script), str(recon_dir), "--quick", "--skip", _skip_modules_except()],
            cwd=repo_root,
            env=env,
            text=True,
            capture_output=True,
            check=False,
            timeout=30,
        )
    lock_path.unlink(missing_ok=True)

    assert result.returncode == 0, result.stderr + result.stdout
    assert "runtime phase busy" not in result.stderr


def test_vuln_scanner_does_not_execute_dalfox_or_nuclei_xss():
    script = Path(__file__).resolve().parent.parent / "tools" / "vuln_scanner.sh"
    text = script.read_text(encoding="utf-8")

    assert "run_with_timeout()" in text
    assert "timeout_bin()" in text
    assert "dal" + "fox" not in text.lower()
    assert "-tags xss" not in text
    assert "nuclei XSS" not in text
    assert 'xss/nuclei_xss.txt' not in text
    assert "run_with_timeout" in text


def test_vuln_scanner_marks_auth_flows_for_manual_review():
    script = Path(__file__).resolve().parent.parent / "tools" / "vuln_scanner.sh"
    text = script.read_text(encoding="utf-8").lower()

    assert "auth_flow_review.txt" in text
    assert "manual_review" in text
    assert "mfa" in text
    assert "otp" in text
    assert "saml" in text
    assert "sso" in text
    assert "relaystate" in text


def test_vuln_scanner_gates_only_explicit_state_changes():
    script = Path(__file__).resolve().parent.parent / "tools" / "vuln_scanner.sh"
    text = script.read_text(encoding="utf-8")

    assert "scanner_probe_guard()" in text
    assert "state_changing" in text
    assert "ALLOW_UNSAFE_HTTP_TESTS" in text
    assert "Skipping $label" in text
    assert "manual_review/unsafe_skipped.txt" in text
    assert ': > "$FINDINGS_DIR/manual_review/unsafe_skipped.txt"' in text
    assert 'scanner_probe_guard "upload canary probe"' not in text
    assert 'scanner_probe_guard "HTTP method tampering" "1" "$url" "$METHOD"' in text
    assert 'scanner_probe_guard "MFA rate-limit probe"' not in text
    assert 'scanner_probe_guard "MFA response-manipulation canary"' not in text
    assert 'scanner_probe_guard "SAML signature-stripping probe"' not in text


def test_upload_lane_is_candidate_only_and_never_posts(tmp_path):
    script = Path(__file__).resolve().parent.parent / "tools" / "vuln_scanner.sh"
    recon_dir = tmp_path / "recon" / "upload.test"
    findings_dir = tmp_path / "findings"
    (recon_dir / "live").mkdir(parents=True)
    (recon_dir / "urls").mkdir()
    (recon_dir / "live" / "urls.txt").write_text("https://upload.test\n", encoding="utf-8")
    (recon_dir / "urls" / "with_params.txt").write_text(
        "https://upload.test/upload?filename=report.txt\n", encoding="utf-8"
    )

    env = os.environ.copy()
    env.update({
        "FINDINGS_OUT_DIR": str(findings_dir),
        "PATH": "/usr/bin:/bin",
        "BBHUNT_RUNTIME_PHASE_LOCKED": "scan",
        "BBHUNT_RUNTIME_LOCK_TARGET": "upload.test",
    })
    result = subprocess.run(
        ["bash", str(script), str(recon_dir), "--quick", "--skip", _skip_modules_except("upload")],
        cwd=script.resolve().parent.parent,
        env=env,
        text=True,
        capture_output=True,
        check=False,
        timeout=30,
    )

    assert result.returncode == 0, result.stderr + result.stdout
    candidates = (findings_dir / "upload" / "upload_candidates.txt").read_text()
    assert candidates.splitlines() == ["https://upload.test/upload?filename=report.txt"]
    summary = json.loads((findings_dir / "summary.json").read_text())
    lane = summary["lane_coverage"]["upload_candidates"]
    assert lane["execution_kind"] == "candidate_only"
    assert lane["selected"] == 0
    assert lane["remaining"] == 1
    assert "-F" not in result.stdout
    assert "upload.php" not in result.stdout


def _run_method_tampering_gate_fixture(tmp_path: Path, *, approved: bool):
    script = Path(__file__).resolve().parent.parent / "tools" / "vuln_scanner.sh"
    run_dir = tmp_path / ("method-approved" if approved else "method-default")
    recon_dir = run_dir / "recon" / "method.test"
    findings_dir = run_dir / "findings"
    shim_dir = run_dir / "bin"
    curl_log = run_dir / "curl.log"
    (recon_dir / "live").mkdir(parents=True)
    shim_dir.mkdir(parents=True)
    (recon_dir / "live" / "urls.txt").write_text("https://method.test/profile\n", encoding="utf-8")
    curl_shim = shim_dir / "curl"
    curl_shim.write_text(
        "#!/bin/sh\n"
        "printf '%s\\n' \"$*\" >> \"$CURL_LOG\"\n"
        "printf '405'\n",
        encoding="utf-8",
    )
    curl_shim.chmod(0o755)

    env = os.environ.copy()
    env.update(
        {
            "CURL_LOG": str(curl_log),
            "FINDINGS_OUT_DIR": str(findings_dir),
            "PATH": f"{shim_dir}:/usr/bin:/bin",
            "BBHUNT_RUNTIME_PHASE_LOCKED": "scan",
            "BBHUNT_RUNTIME_LOCK_TARGET": "method.test",
        }
    )
    if approved:
        env["ALLOW_UNSAFE_HTTP_TESTS"] = "1"
    else:
        env.pop("ALLOW_UNSAFE_HTTP_TESTS", None)
    result = subprocess.run(
        [
            "bash",
            str(script),
            str(recon_dir),
            "--quick",
            "--skip",
            _skip_modules_except("auth_bypass"),
        ],
        cwd=script.resolve().parent.parent,
        env=env,
        text=True,
        capture_output=True,
        check=False,
        timeout=30,
    )

    calls = curl_log.read_text(encoding="utf-8") if curl_log.exists() else ""
    return result, findings_dir, calls


def test_method_tampering_requires_explicit_opt_in(tmp_path):
    default, default_findings, default_calls = _run_method_tampering_gate_fixture(
        tmp_path, approved=False
    )

    assert default.returncode == 0, default.stderr + default.stdout
    assert "-X PUT" not in default_calls
    assert "-X DELETE" not in default_calls
    assert "-X PATCH" not in default_calls
    skipped = (default_findings / "manual_review" / "unsafe_skipped.txt").read_text(
        encoding="utf-8"
    )
    assert "label=HTTP method tampering" in skipped
    assert "method=PUT" in skipped
    assert "method=DELETE" in skipped
    assert "method=PATCH" in skipped

    approved, approved_findings, approved_calls = _run_method_tampering_gate_fixture(
        tmp_path, approved=True
    )

    assert approved.returncode == 0, approved.stderr + approved.stdout
    assert "-X PUT" in approved_calls
    assert "-X DELETE" in approved_calls
    assert "-X PATCH" in approved_calls
    assert not (approved_findings / "manual_review" / "unsafe_skipped.txt").exists()


def test_vuln_scanner_supports_auth_session_env():
    script = Path(__file__).resolve().parent.parent / "tools" / "vuln_scanner.sh"
    text = script.read_text(encoding="utf-8")

    assert "_auth_helper.sh" in text
    assert 'bb_auth_active && bb_auth_banner' in text
    assert 'bb_auth_bind_target "$SCANNER_AUTH_TARGET"' in text
    assert 'bb_auth_filter_file "$ORDERED_SCAN" "$AUTH_ORDERED_SCAN"' in text
    assert '"${BB_AUTH_ARGS[@]}"' in text
    assert 'run_nuclei_timeout "$CVE_TIMEOUT"' in text
    assert 'BBHUNT_ENABLE_NUCLEI_SQLI' not in text
    assert 'BBHUNT_ENABLE_NUCLEI_SSRF' not in text
    assert 'nuclei_sqli_targets' not in text
    assert 'nuclei_ssrf_targets' not in text
    assert 'curl -s "${BB_AUTH_ARGS[@]}"' in text
    assert 'nuclei -fhr "$@"' in text


def test_vuln_scanner_auth_bypass_lane_uses_public_exposure_classifier():
    script = Path(__file__).resolve().parent.parent / "tools" / "vuln_scanner.sh"
    text = script.read_text(encoding="utf-8")

    assert 'public_exposure_signals.py' in text
    assert '--authz-candidate' in text
    assert ': > "$FINDINGS_DIR/auth_bypass/unauth_api_access.txt"' in text
    assert 'curl -s "${BB_ANON_AUTH_ARGS[@]}" -o /dev/null' in text
    assert 'curl -s "${BB_ANON_AUTH_ARGS[@]}" --max-time 5 "$api_url"' in text


def test_vuln_scanner_sensitive_path_lane_clears_output_and_skips_standard_public_metadata():
    script = Path(__file__).resolve().parent.parent / "tools" / "vuln_scanner.sh"
    text = script.read_text(encoding="utf-8")

    assert ': > "$FINDINGS_DIR/exposure/verified_sensitive.txt"' in text
    assert '--standard-public-metadata' in text
    assert '--candidate-ready' in text
    assert 'manual_review/standard_public_metadata.txt' in text
    assert 'manual_review/public_exposure_review.txt' in text
    assert '[STANDARD-PUBLIC-METADATA]' in text
    assert '[PUBLIC-EXPOSURE-REVIEW]' in text
    assert text.index('--candidate-ready') < text.index('verified_sensitive.txt', text.index('--candidate-ready'))


def test_vuln_scanner_keeps_recon_url_artifacts_discovery_first():
    script = Path(__file__).resolve().parent.parent / "tools" / "vuln_scanner.sh"
    text = script.read_text(encoding="utf-8")

    assert 'filter_target_urls_copy()' in text
    assert 'Discovery-first' in text
    assert 'api_endpoints.target.txt' in text
    assert 'sensitive_paths.target.txt' in text
    assert ': > "$FINDINGS_DIR/idor/idor_candidates.txt"' in text
    assert ': > "$FINDINGS_DIR/idor/api_sequential_ids.txt"' in text
    assert 'url_belongs_to_target(value, target)' in text
    assert 'Raw recon artifacts remain discovery-first' in text
    assert '[OUT-OF-TARGET:{lane}]' in text
    assert 'No target-owned scan targets found' in text


def test_vuln_scanner_filters_direct_findings_but_keeps_external_chain_context():
    script = Path(__file__).resolve().parent.parent / "tools" / "vuln_scanner.sh"
    text = script.read_text(encoding="utf-8")

    assert "filter_direct_finding_urls_copy()" in text
    assert "direct findings must stay target-owned" in text
    assert "manual_review/external_chain_context.txt" in text
    assert '"$FINDINGS_DIR/.tmp/idor_candidates.raw.txt"' in text
    assert 'filter_direct_finding_urls_copy \\' in text
    assert '"$FINDINGS_DIR/idor/idor_candidates.txt"' in text
    assert 'python3 -m tools.recon_filters' in text


def test_vuln_scanner_has_upstream_v5_scan_surface():
    script = Path(__file__).resolve().parent.parent / "tools" / "vuln_scanner.sh"
    text = script.read_text(encoding="utf-8")

    assert "[--quick] [--full] [--skip module1,module2]" in text
    assert "--skip=*" in text
    assert 'FINDINGS_DIR="${FINDINGS_OUT_DIR:-$DEFAULT_FINDINGS_DIR}"' in text
    assert 'ORDERED_SCAN="$FINDINGS_DIR/ordered_scan_targets.txt"' in text

    assert "collect_candidate_urls()" in text
    assert "AI-selected validation" in text
    assert "SQLI-POC-VERIFIED" not in text
    assert "replace_all_param_values" not in text
    assert "SSTI-CONFIRMED" not in text
    assert "MFA/2FA review candidates" in text
    assert "SAML-SIG-STRIP" not in text
    assert "PROBE_PATHS" not in text


def test_vuln_scanner_adds_iis_shortscan_lane_without_hard_dependency():
    script = Path(__file__).resolve().parent.parent / "tools" / "vuln_scanner.sh"
    text = script.read_text(encoding="utf-8")

    assert "detect_iis_shortname_targets()" in text
    assert "run_iis_shortname_checks" in text
    assert "Microsoft-IIS" in text
    assert "X-AspNet-Version" in text
    assert "X-Powered-By" in text
    assert "ASP\\.NET" in text
    assert 'tool_ok shortscan' in text
    assert 'shortscan "$url" -s -p 1' in text
    assert "misconfig/iis_shortnames.txt" in text
    assert "manual_review/iis_shortnames.txt" in text
    assert "shortscan missing; run: shortscan" in text


def test_vuln_scanner_writes_structured_summary_json(tmp_path):
    script = Path(__file__).resolve().parent.parent / "tools" / "vuln_scanner.sh"
    recon_dir = tmp_path / "recon" / "example.com"
    live_dir = recon_dir / "live"
    findings_dir = tmp_path / "findings"
    live_dir.mkdir(parents=True)
    (live_dir / "urls.txt").write_text("https://example.com\n", encoding="utf-8")

    env = os.environ.copy()
    env["FINDINGS_OUT_DIR"] = str(findings_dir)

    result = subprocess.run(
        ["bash", str(script), str(recon_dir), "--quick", "--skip", "all"],
        cwd=script.resolve().parent.parent,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr + result.stdout

    summary_path = findings_dir / "summary.json"
    assert summary_path.is_file()
    index_path = findings_dir / "findings.json"
    assert index_path.is_file()

    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    assert summary["schema_version"] == 1
    assert summary["target"] == "example.com"
    assert summary["mode"] == "quick"
    assert summary["input_contract"] == "live-priority-targets"
    assert summary["raw_url_count"] == 0
    assert summary["active_url_count"] == 0
    assert summary["parameter_url_count"] == 0
    assert summary["live_count"] == 1
    assert summary["ordered_scan_count"] == 1
    assert summary["skipped_checks"] == ["all"]
    assert summary["nuclei_cve"] == {
        "enabled": True,
        "status": "skipped",
        "input": "origin-bounded",
        "candidate_count": 1,
    }
    assert summary["lane_coverage"]["xss_reflection"]["status"] == "skipped"
    assert summary["lane_coverage"]["cve"]["remaining"] == 1
    assert summary["lane_coverage"]["idor_candidates"]["execution_kind"] == (
        "candidate_only"
    )
    assert summary["totals"]["findings"] == 0
    assert summary["totals"]["high_value"]["verified_sqli_pocs"] == 0
    assert "mfa" in summary["categories"]

    index = json.loads(index_path.read_text(encoding="utf-8"))
    assert index["schema_version"] == 1
    assert index["target"] == "example.com"
    assert index["total"] == 0
    assert index["findings"] == []


def test_vuln_scanner_keeps_historical_corpus_out_of_ordered_scan(tmp_path):
    script = Path(__file__).resolve().parent.parent / "tools" / "vuln_scanner.sh"
    recon_dir = tmp_path / "recon" / "large.example"
    live_dir = recon_dir / "live"
    urls_dir = recon_dir / "urls"
    priority_dir = recon_dir / "priority"
    findings_dir = tmp_path / "findings"
    live_dir.mkdir(parents=True)
    urls_dir.mkdir()
    priority_dir.mkdir()

    (live_dir / "urls.txt").write_text(
        "https://large.example:10\nhttps://large.example:11\n",
        encoding="utf-8",
    )
    (priority_dir / "critical_hosts.txt").write_text(
        "https://large.example:9\nhttps://large.example:10\n",
        encoding="utf-8",
    )
    raw_urls = "".join(
        f"https://large.example/archive/{index}?id={index}\n"
        for index in range(19_000)
    )
    (urls_dir / "all.txt").write_text(raw_urls, encoding="utf-8")
    (urls_dir / "raw").mkdir()
    (urls_dir / "raw" / "all.txt").write_text(raw_urls, encoding="utf-8")
    (urls_dir / "with_params.txt").write_text(
        "https://large.example/a?id=1\n"
        "https://large.example/a?id=2\n"
        "https://large.example/a?id=2&id=1\n"
        "https://large.example/a?id=1&id=2\n",
        encoding="utf-8",
    )

    env = os.environ.copy()
    env["FINDINGS_OUT_DIR"] = str(findings_dir)
    env["PATH"] = "/usr/bin:/bin"

    result = subprocess.run(
        ["bash", str(script), str(recon_dir), "--quick", "--skip", "all"],
        cwd=script.resolve().parent.parent,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr + result.stdout
    summary = json.loads((findings_dir / "summary.json").read_text(encoding="utf-8"))
    assert summary["input_contract"] == "live-priority-targets"
    assert summary["raw_url_count"] == 19_000
    assert summary["active_url_count"] == 19_000
    assert summary["parameter_url_count"] == 4
    assert summary["ordered_scan_count"] == 3
    assert summary["nuclei_target_available_count"] == 3
    assert summary["nuclei_target_count"] == 3
    assert summary["nuclei_targets_truncated"] is False
    assert len((urls_dir / "all.txt").read_text(encoding="utf-8").splitlines()) == 19_000


def test_vuln_scanner_deduplicates_origins_and_bounds_quick_nuclei_input(tmp_path):
    script = Path(__file__).resolve().parent.parent / "tools" / "vuln_scanner.sh"
    recon_dir = tmp_path / "recon" / "large.example"
    live_dir = recon_dir / "live"
    findings_dir = tmp_path / "findings"
    live_dir.mkdir(parents=True)
    urls = [f"http://large.example:{20000 + index}/path/{index}" for index in range(80)]
    urls.extend(f"http://large.example:{20000 + index}/other" for index in range(10))
    (live_dir / "urls.txt").write_text("\n".join(urls) + "\n", encoding="utf-8")

    env = os.environ.copy()
    env["FINDINGS_OUT_DIR"] = str(findings_dir)
    env["PATH"] = "/usr/bin:/bin"

    result = subprocess.run(
        ["bash", str(script), str(recon_dir), "--quick", "--skip", "all"],
        cwd=script.resolve().parent.parent,
        env=env,
        text=True,
        capture_output=True,
        check=False,
        timeout=30,
    )

    assert result.returncode == 0, result.stderr + result.stdout
    summary = json.loads((findings_dir / "summary.json").read_text(encoding="utf-8"))
    assert summary["ordered_scan_count"] == 90
    assert summary["nuclei_target_available_count"] == 80
    assert summary["nuclei_target_count"] == 50
    assert summary["nuclei_target_limit"] == 50
    assert summary["nuclei_targets_truncated"] is True
    selected = (findings_dir / ".tmp" / "nuclei_targets.txt").read_text(encoding="utf-8").splitlines()
    assert selected[0] == "http://large.example:20000"
    assert selected[-1] == "http://large.example:20049"


def test_vuln_scanner_keeps_off_target_urls_as_inert_chain_context(tmp_path):
    script = Path(__file__).resolve().parent.parent / "tools" / "vuln_scanner.sh"
    recon_dir = tmp_path / "recon" / "example.com"
    live_dir = recon_dir / "live"
    urls_dir = recon_dir / "urls"
    findings_dir = tmp_path / "findings"
    live_dir.mkdir(parents=True)
    urls_dir.mkdir()
    (live_dir / "urls.txt").write_text(
        "https://app.example.com\nhttps://third-party.test/callback\n",
        encoding="utf-8",
    )
    (urls_dir / "api_endpoints.txt").write_text(
        "https://api.example.com/search\n"
        "https://third-party.test/search\n",
        encoding="utf-8",
    )

    env = os.environ.copy()
    env["FINDINGS_OUT_DIR"] = str(findings_dir)
    env["PATH"] = "/usr/bin:/bin"
    result = subprocess.run(
        ["bash", str(script), str(recon_dir), "--quick", "--skip", "all"],
        cwd=script.resolve().parent.parent,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr + result.stdout
    assert (findings_dir / "ordered_scan_targets.txt").read_text().splitlines() == [
        "https://app.example.com"
    ]
    assert (findings_dir / ".tmp" / "api_endpoints.target.txt").read_text().splitlines() == [
        "https://api.example.com/search"
    ]
    chain = (findings_dir / "manual_review" / "external_chain_context.txt").read_text()
    assert "https://third-party.test/callback" in chain
    assert "https://third-party.test/search" in chain


def test_vuln_scanner_clears_stale_summary_before_early_exit(tmp_path):
    script = Path(__file__).resolve().parent.parent / "tools" / "vuln_scanner.sh"
    recon_dir = tmp_path / "recon" / "missing-live.example"
    findings_dir = tmp_path / "findings"
    recon_dir.mkdir(parents=True)
    findings_dir.mkdir()
    (findings_dir / "summary.txt").write_text("stale\n", encoding="utf-8")
    (findings_dir / "summary.json").write_text('{"stale": true}\n', encoding="utf-8")
    (findings_dir / "findings.json").write_text('{"preserve": true}\n', encoding="utf-8")

    env = os.environ.copy()
    env["FINDINGS_OUT_DIR"] = str(findings_dir)
    env["PATH"] = "/usr/bin:/bin"

    result = subprocess.run(
        ["bash", str(script), str(recon_dir), "--quick", "--skip", "all"],
        cwd=script.resolve().parent.parent,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode != 0
    assert not (findings_dir / "summary.txt").exists()
    assert not (findings_dir / "summary.json").exists()
    assert (findings_dir / "findings.json").is_file()


def test_vuln_scanner_publishes_summary_json_only_after_success(tmp_path):
    script = Path(__file__).resolve().parent.parent / "tools" / "vuln_scanner.sh"
    recon_dir = tmp_path / "recon" / "summary-failure.example"
    live_dir = recon_dir / "live"
    findings_dir = tmp_path / "findings"
    shim_dir = tmp_path / "bin"
    live_dir.mkdir(parents=True)
    shim_dir.mkdir()
    (live_dir / "urls.txt").write_text("https://summary-failure.example:9\n", encoding="utf-8")

    real_python = shutil.which("python3")
    assert real_python
    python_shim = shim_dir / "python3"
    python_shim.write_text(
        "#!/bin/sh\n"
        "last=''\n"
        "for arg in \"$@\"; do last=\"$arg\"; done\n"
        "case \"$last\" in\n"
        "  */.summary.json.tmp) printf '{' > \"$last\"; exit 1 ;;\n"
        "esac\n"
        f'exec "{real_python}" "$@"\n',
        encoding="utf-8",
    )
    python_shim.chmod(0o755)

    env = os.environ.copy()
    env["FINDINGS_OUT_DIR"] = str(findings_dir)
    env["PATH"] = f"{shim_dir}:/usr/bin:/bin"

    result = subprocess.run(
        ["bash", str(script), str(recon_dir), "--quick", "--skip", "all"],
        cwd=script.resolve().parent.parent,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode != 0
    assert "scan remains incomplete" in result.stdout
    assert not (findings_dir / "summary.txt").exists()
    assert not (findings_dir / "summary.json").exists()
    assert not (findings_dir / ".summary.txt.tmp").exists()
    assert not (findings_dir / ".summary.json.tmp").exists()


def test_vuln_scanner_keeps_scan_incomplete_when_nuclei_fails(tmp_path):
    script = Path(__file__).resolve().parent.parent / "tools" / "vuln_scanner.sh"
    recon_dir = tmp_path / "recon" / "nuclei-failure.example"
    live_dir = recon_dir / "live"
    findings_dir = tmp_path / "findings"
    shim_dir = tmp_path / "bin"
    live_dir.mkdir(parents=True)
    shim_dir.mkdir()
    (live_dir / "urls.txt").write_text("https://nuclei-failure.example:9\n", encoding="utf-8")
    nuclei_shim = shim_dir / "nuclei"
    nuclei_shim.write_text(
        "#!/bin/sh\n"
        "output=''\n"
        "while [ \"$#\" -gt 0 ]; do\n"
        "  if [ \"$1\" = '-output' ]; then shift; output=\"$1\"; fi\n"
        "  shift\n"
        "done\n"
        "[ -z \"$output\" ] || printf '%s\\n' "
        "'[CVE-test] [http] [high] https://nuclei-failure.example:9/test' > \"$output\"\n"
        "exit 124\n",
        encoding="utf-8",
    )
    nuclei_shim.chmod(0o755)

    env = os.environ.copy()
    env["FINDINGS_OUT_DIR"] = str(findings_dir)
    env["BB_CVE_TIMEOUT"] = "1"
    env["BBHUNT_ENABLE_NUCLEI_CVES"] = "1"
    env["PATH"] = f"{shim_dir}:/usr/bin:/bin"

    result = subprocess.run(
        [
            "bash",
            str(script),
            str(recon_dir),
            "--quick",
            "--skip",
            _skip_modules_except("cves"),
        ],
        cwd=script.resolve().parent.parent,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode != 0
    assert "Nuclei lane failed" in result.stdout
    assert "scan remains incomplete" in result.stdout
    assert "CVEs: incomplete" in result.stdout
    assert "CVEs: clean" not in result.stdout
    assert not (findings_dir / "summary.json").exists()
    index = json.loads((findings_dir / "findings.json").read_text(encoding="utf-8"))
    assert any(item["url"] == "https://nuclei-failure.example:9/test" for item in index["findings"])


def test_vuln_scanner_requires_finding_index_before_completion(tmp_path):
    script = Path(__file__).resolve().parent.parent / "tools" / "vuln_scanner.sh"
    recon_dir = tmp_path / "recon" / "index-failure.example"
    live_dir = recon_dir / "live"
    findings_dir = tmp_path / "findings"
    shim_dir = tmp_path / "bin"
    live_dir.mkdir(parents=True)
    shim_dir.mkdir()
    (live_dir / "urls.txt").write_text("https://index-failure.example:9\n", encoding="utf-8")

    real_python = shutil.which("python3")
    assert real_python
    python_shim = shim_dir / "python3"
    python_shim.write_text(
        "#!/bin/sh\n"
        "case \"$1\" in\n"
        "  */tools/finding_index.py) exit 17 ;;\n"
        "esac\n"
        f'exec "{real_python}" "$@"\n',
        encoding="utf-8",
    )
    python_shim.chmod(0o755)

    env = os.environ.copy()
    env["FINDINGS_OUT_DIR"] = str(findings_dir)
    env["PATH"] = f"{shim_dir}:/usr/bin:/bin"

    result = subprocess.run(
        ["bash", str(script), str(recon_dir), "--quick", "--skip", "all"],
        cwd=script.resolve().parent.parent,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode != 0
    assert "Unable to write structured findings index; scan remains incomplete" in result.stdout
    assert not (findings_dir / "summary.txt").exists()
    assert not (findings_dir / "summary.json").exists()


def test_vuln_scanner_records_xss_candidates_without_active_probe(tmp_path):
    script = Path(__file__).resolve().parent.parent / "tools" / "vuln_scanner.sh"
    recon_dir = tmp_path / "recon" / "example.com"
    live_dir = recon_dir / "live"
    findings_dir = tmp_path / "findings"
    live_dir.mkdir(parents=True)
    (live_dir / "urls.txt").write_text("https://example.com\n", encoding="utf-8")

    env = os.environ.copy()
    env["FINDINGS_OUT_DIR"] = str(findings_dir)
    env["PATH"] = "/usr/bin:/bin"

    result = subprocess.run(
        [
            "bash",
            str(script),
            str(recon_dir),
            "--skip",
            _skip_modules_except("xss"),
        ],
        cwd=script.resolve().parent.parent,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr + result.stdout
    assert "Default skip: xss" not in result.stdout
    assert "Check 1: XSS candidates (AI/browser-selected validation)" in result.stdout
    assert "XSS candidates: none found" in result.stdout

    summary = json.loads((findings_dir / "summary.json").read_text(encoding="utf-8"))
    assert summary["mode"] == "standard"
    assert "xss" not in summary["skipped_checks"]
    assert "ssti" in summary["skipped_checks"]
    assert summary["lane_coverage"]["xss_reflection"]["status"] == "candidate_only"
    assert summary["lane_coverage"]["xss_reflection"]["execution_kind"] == "candidate_only"
    assert summary["lane_coverage"]["xss_reflection"]["selected"] == 0


def test_vuln_scanner_full_mode_keeps_xss_candidate_only(tmp_path):
    script = Path(__file__).resolve().parent.parent / "tools" / "vuln_scanner.sh"
    recon_dir = tmp_path / "recon" / "example.com"
    live_dir = recon_dir / "live"
    findings_dir = tmp_path / "findings"
    live_dir.mkdir(parents=True)
    (live_dir / "urls.txt").write_text("https://example.com\n", encoding="utf-8")

    env = os.environ.copy()
    env["FINDINGS_OUT_DIR"] = str(findings_dir)
    env["PATH"] = "/usr/bin:/bin"

    result = subprocess.run(
        [
            "bash",
            str(script),
            str(recon_dir),
            "--full",
            "--skip",
            _skip_modules_except("xss"),
        ],
        cwd=script.resolve().parent.parent,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr + result.stdout
    assert "Default skip: xss" not in result.stdout
    assert "Skipping XSS checks" not in result.stdout
    assert "Check 1: XSS candidates (AI/browser-selected validation)" in result.stdout

    summary = json.loads((findings_dir / "summary.json").read_text(encoding="utf-8"))
    assert summary["mode"] == "full"
    assert "xss" not in summary["skipped_checks"]
    assert "ssti" in summary["skipped_checks"]
    assert summary["lane_coverage"]["xss_reflection"]["execution_kind"] == "candidate_only"
    assert summary["lane_coverage"]["xss_reflection"]["selected"] == 0


def test_vuln_scanner_writes_iis_manual_review_when_shortscan_missing(tmp_path):
    script = Path(__file__).resolve().parent.parent / "tools" / "vuln_scanner.sh"
    recon_dir = tmp_path / "recon" / "iis.example"
    live_dir = recon_dir / "live"
    findings_dir = tmp_path / "findings"
    live_dir.mkdir(parents=True)
    (live_dir / "urls.txt").write_text("https://iis.example\n", encoding="utf-8")
    (live_dir / "httpx_full.txt").write_text(
        "https://iis.example [200] [App] [Microsoft-IIS,ASP.NET] [100]\n",
        encoding="utf-8",
    )

    env = os.environ.copy()
    env["FINDINGS_OUT_DIR"] = str(findings_dir)
    env["PATH"] = "/usr/bin:/bin"
    skip_checks = ",".join(
        [
            "upload",
            "sqli",
            "xss",
            "ssti",
            "takeover",
            "exposure",
            "ssrf",
            "cves",
            "redirects",
            "idor",
            "auth_bypass",
            "auth_flow",
            "mfa",
            "saml",
        ]
    )

    result = subprocess.run(
        ["bash", str(script), str(recon_dir), "--quick", "--skip", skip_checks],
        cwd=script.resolve().parent.parent,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr + result.stdout

    manual_path = findings_dir / "manual_review" / "iis_shortnames.txt"
    assert manual_path.is_file()
    manual_text = manual_path.read_text(encoding="utf-8")
    assert "[IIS-SHORTNAME-MANUAL]" in manual_text
    assert "shortscan https://iis.example -s -p 1" in manual_text

    summary = json.loads((findings_dir / "summary.json").read_text(encoding="utf-8"))
    assert summary["totals"]["manual_review_items"] == 1
    assert summary["manual_review"] == [
        {"path": "manual_review/iis_shortnames.txt", "count": 1}
    ]
