"""Static regression locks for live A/B case artifacts.

The live A/B runs are intentionally not re-executed in pytest: they depend on
external model variance and are too expensive for a normal local suite. These
checks keep the case files plus the decision-anchor text that made the enhanced
arms correct. They catch accidental deletion of Q7 precedence, severity rows,
route gates, stop conditions, and web2 lane-ordering anchors.
"""

from __future__ import annotations

import json
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
CASES_DIR = REPO_ROOT / "tests" / "skill-validator" / "cases"
RUNS_DIR = REPO_ROOT / "tests" / "skill-validator" / "runs"

TRIAGE_CASES = CASES_DIR / "triage_ab_cases.json"
WEB2_CASES = CASES_DIR / "web2_vuln_ab_cases.json"
WEB2_HARD_CASES = CASES_DIR / "web2_vuln_ab_hard_cases.json"

TRIAGE_REPORT = RUNS_DIR / "report_triage_ab_live.md"
WEB2_REPORT = RUNS_DIR / "report_web2_vuln_ab_live.md"
WEB2_HARD_REPORT = RUNS_DIR / "report_web2_vuln_ab_hard.md"


def _json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _text(*paths: str) -> str:
    return "\n".join((REPO_ROOT / path).read_text(encoding="utf-8") for path in paths).lower()


def _assert_groups(text: str, groups: dict[str, tuple[str, ...]]) -> None:
    missing: dict[str, list[str]] = {}
    for label, fragments in groups.items():
        absent = [fragment for fragment in fragments if fragment.lower() not in text]
        if absent:
            missing[label] = absent
    assert not missing


def test_triage_live_ab_artifacts_and_answers_are_locked():
    payload = _json(TRIAGE_CASES)
    cases = {case["id"]: case for case in payload["cases"]}

    assert len(cases) == 14
    assert payload["meta"]["ground_truth_source"].startswith("skills/triage-validation/SKILL.md")
    assert {case["verdict"] for case in cases.values()} <= {"REPORT", "DO_NOT_REPORT", "CHAIN_REQUIRED"}
    assert {case["severity"] for case in cases.values()} <= {"Critical", "High", "Medium", "Low", "None"}

    expected = {
        "T01": ("DO_NOT_REPORT", "None"),
        "T02": ("REPORT", "Critical"),
        "T03": ("CHAIN_REQUIRED", "None"),
        "T05": ("DO_NOT_REPORT", "None"),
        "T06": ("REPORT", "Critical"),
        "T08": ("REPORT", "High"),
        "T10": ("REPORT", "Medium"),
        "T11": ("REPORT", "High"),
        "T12": ("REPORT", "Critical"),
        "T13": ("REPORT", "High"),
        "T14": ("DO_NOT_REPORT", "None"),
    }
    for case_id, (verdict, severity) in expected.items():
        assert cases[case_id]["verdict"] == verdict
        assert cases[case_id]["severity"] == severity

    report = TRIAGE_REPORT.read_text(encoding="utf-8")
    assert "Verdict accuracy | 13/14" in report
    assert "Severity accuracy | 12/14" in report
    assert "Fully-correct cases (both) | 11/14" in report
    assert "Enhanced" in report and "14/14 = 100%" in report


def test_triage_validation_keeps_live_ab_decision_anchors():
    triage = _text("skills/triage-validation/SKILL.md")

    _assert_groups(
        triage,
        {
            "q7 precedence": (
                "route with this precedence",
                "full chain end to end",
                "chain_required",
                "do not report",
                "standalone / alone",
            ),
            "open redirect chain": (
                "open redirect alone",
                "oauth redirect_uri",
                "auth code theft",
                "ato (critical)",
            ),
            "ssrf dns-only": (
                "ssrf dns callback only",
                "internal service access",
                "data returned",
            ),
            "cors credentialed exfil": (
                "cors wildcard",
                "credentialed request exfils user pii",
                "high",
            ),
            "host reset poisoning": (
                "host header injection",
                "password reset email uses injected host",
                "high",
            ),
            "graphql introspection": (
                "graphql introspection alone",
                "auth bypass mutation",
                "idor on node()",
            ),
            "severity calibration": (
                "idor read pii, any user, auth required",
                "medium",
                "idor write/delete, any user",
                "high",
                "auth bypass → admin panel",
                "critical",
                "ssrf → cloud metadata",
            ),
        },
    )


def test_web2_live_ab_artifacts_and_answers_are_locked():
    easy = _json(WEB2_CASES)
    hard = _json(WEB2_HARD_CASES)

    assert len(easy["cases"]) == 12
    assert len(hard["cases"]) == 12
    assert [case["answer"] for case in easy["cases"]] == [
        "B", "C", "B", "B", "A", "B", "B", "B", "B", "B", "B", "B"
    ]
    assert [case["answer"] for case in hard["cases"]] == [
        "B", "A", "B", "A", "A", "A", "A", "A", "A", "A", "A", "A"
    ]

    report = WEB2_REPORT.read_text(encoding="utf-8")
    hard_report = WEB2_HARD_REPORT.read_text(encoding="utf-8")
    assert "Accuracy | 12/12 = 100% | 12/12 = 100%" in report
    assert "Accuracy | 12/12 = 100% | 12/12 = 100%" in hard_report
    assert "Round 2" in hard_report and "Plausible Distractors" in hard_report


def test_web2_vuln_classes_keeps_live_ab_decision_anchors():
    material = _text(
        "skills/web2-vuln-classes/SKILL.md",
        "skills/security-arsenal/references/bypass-patterns.md",
        "skills/security-arsenal/references/payload-families.md",
        "skills/security-arsenal/references/recon-tool-usage.md",
        "skills/security-arsenal/references/sink-and-grep-patterns.md",
        "knowledge/cards/missing-parameter-discovery.md",
        "knowledge/cards/sqli-hidden-surfaces.md",
        "knowledge/cards/ssrf-internal-impact.md",
        "knowledge/cards/ssrf-url-fetch.md",
        "knowledge/cards/graphql.md",
        "knowledge/cards/proxy-cache-boundaries.md",
        "knowledge/cards/race-conditions.md",
        "knowledge/cards/auth-sso-token-edge-cases.md",
    )

    _assert_groups(
        material,
        {
            "parser discipline": ("change one boundary at a time", "baseline", "read-only"),
            "missing parameter": ("missing parameter", "target-specific wordlist", "低频"),
            "ssrf gate": ("dns-only", "second signal", "server-side fetch"),
            "idor two identities": ("two owned identities", "object-level auth matrix"),
            "upload safe verification": ("safe verification", "storage", "read-back", "execution proof"),
            "graphql introspection": ("introspection alone is informational", "node/global id", "field-level auth matrix"),
            "proxy cache": ("cache key", "victim", "private response"),
            "sql hidden surfaces": ("hidden surfaces", "headers", "path segments", "second-order"),
            "sql confirmation": ("baseline", "boolean", "time/oob"),
            "oauth pkce": ("pkce", "state", "account linking"),
            "transport diff": ("raw api request", "one changed axis"),
            "race target": ("state machine", "bounded", "current user/test resource"),
            "email linking boundary": ("自有/测试账号", "account linking", "email"),
            "waf backend mismatch": ("waf", "backend", "baseline"),
        },
    )
