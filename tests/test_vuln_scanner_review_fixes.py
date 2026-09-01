"""Regression checks for the PR #7 review fixes in tools/vuln_scanner.sh."""

from pathlib import Path


SCANNER_PATH = Path(__file__).resolve().parents[1] / "tools" / "vuln_scanner.sh"


def test_fixed_active_lanes_are_removed_but_generic_guard_remains():
    scanner = SCANNER_PATH.read_text()

    assert "scanner_probe_guard()" in scanner
    assert "ALLOW_UNSAFE_HTTP_TESTS" in scanner
    assert 'scanner_probe_guard "HTTP method tampering" "1" "$url" "$METHOD"' in scanner
    assert "scanner_probe_guard \"upload canary probe\"" not in scanner
    assert "SAML signature-stripping" not in scanner
    assert "MFA rate-limit probe" not in scanner
    assert "SAML_PATH" not in scanner


def test_scanner_uses_current_repo_paths():
    scanner = SCANNER_PATH.read_text()

    assert 'BASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"' in scanner
    assert 'DEFAULT_FINDINGS_DIR="$BASE_DIR/findings/$TARGET"' in scanner
    assert 'LIVE_URLS="$RECON_DIR/live/urls.txt"' in scanner
    assert 'ORDERED_SCAN="$FINDINGS_DIR/ordered_scan_targets.txt"' in scanner
    assert "httpx_live.txt" not in scanner


def test_mfa_observations_are_manual_review_only():
    scanner = SCANNER_PATH.read_text()

    assert 'MFA_REVIEW_FILE="$FINDINGS_DIR/manual_review/mfa_review.txt"' in scanner
    assert 'collect_candidate_urls' in scanner
    assert '>> "$FINDINGS_DIR/mfa/findings.txt"' not in scanner


def test_nuclei_cve_lane_is_bounded_and_stops_after_timeout():
    scanner = SCANNER_PATH.read_text()

    assert 'run_nuclei_timeout()' in scanner
    assert 'CVE_TIMEOUT="${BB_CVE_TIMEOUT:-180}"' in scanner
    assert '"$timeout_cmd" --preserve-status "$limit" nuclei' in scanner
    assert 'NUCLEI_FAILURE_MARKER=' in scanner
    assert 'cat "$NUCLEI_TARGETS"' not in scanner
    assert 'run_nuclei()' not in scanner
    assert '-tags exposure,file' not in scanner
    assert '-tags panel,login' not in scanner
    assert '-tags default-login' not in scanner
