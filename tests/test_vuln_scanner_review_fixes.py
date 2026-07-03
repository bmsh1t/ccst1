"""Regression checks for the PR #7 review fixes in tools/vuln_scanner.sh."""

from pathlib import Path


SCANNER_PATH = Path(__file__).resolve().parents[1] / "tools" / "vuln_scanner.sh"


def test_saml_signature_stripping_is_opt_in_and_policy_gated():
    scanner = SCANNER_PATH.read_text()

    assert "scanner_probe_guard()" in scanner
    assert "SafeMethodPolicy" in scanner
    assert "ALLOW_UNSAFE_HTTP_TESTS" in scanner
    assert "require_approval" in scanner
    assert 'scanner_probe_guard "POST" "$BASE" "MFA rate-limit probe"' in scanner
    assert 'scanner_probe_guard "POST" "$BASE" "MFA response-manipulation canary"' in scanner
    assert 'scanner_probe_guard "POST" "$ACS_URL" "SAML signature-stripping probe"' in scanner


def test_scanner_uses_current_repo_paths():
    scanner = SCANNER_PATH.read_text()

    assert 'BASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"' in scanner
    assert 'DEFAULT_FINDINGS_DIR="$BASE_DIR/findings/$TARGET"' in scanner
    assert 'LIVE_URLS="$RECON_DIR/live/urls.txt"' in scanner
    assert 'ORDERED_SCAN="$FINDINGS_DIR/ordered_scan_targets.txt"' in scanner
    assert "httpx_live.txt" not in scanner
