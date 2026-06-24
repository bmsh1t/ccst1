"""tests/test_chain_hints.py — chain hint injection tests."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from tools.chain_hints import derive_chain_hint  # noqa: E402


# ---------------------------------------------------------------------
#  Severity gating
# ---------------------------------------------------------------------

class TestSeverityHandling:
    """The severity gate was intentionally removed — many high-leverage
    chains start at info-level signals (S3 listable, GraphQL introspection
    enabled, JWT alg=none observed, subdomain takeover candidate). The
    regex patterns themselves are specific enough to discriminate noise.
    """

    def test_info_severity_still_fires_when_pattern_matches(self):
        # Info-level IDOR text matches the IDOR regex → hint MUST fire
        f = {"severity": "info", "text": "IDOR confirmed on /api/users/1"}
        out = derive_chain_hint(f)
        assert "[CHAIN HINT" in out
        assert "PUT/PATCH/DELETE" in out

    def test_empty_severity_still_fires_when_pattern_matches(self):
        # Missing severity field is fine — only the regex match matters
        f = {"severity": "", "text": "IDOR on /api/users/1 (GET)"}
        assert "[CHAIN HINT" in derive_chain_hint(f)

    def test_info_signal_with_no_pattern_match_returns_empty(self):
        # Info-level finding that matches NO chain rule → empty (regex
        # specificity, not severity, is what discriminates noise)
        f = {"severity": "info", "text": "interesting tech stack: Django"}
        assert derive_chain_hint(f) == ""

    def test_low_severity_qualifies(self):
        f = {"severity": "low", "text": "Open redirect on /go?url=…"}
        assert "[CHAIN HINT" in derive_chain_hint(f)

    def test_critical_severity_qualifies(self):
        f = {"severity": "critical", "text": "Stored XSS in support ticket"}
        assert "[CHAIN HINT" in derive_chain_hint(f)


# ---------------------------------------------------------------------
#  Pattern coverage (one assertion per chain rule)
# ---------------------------------------------------------------------

class TestPatternCoverage:
    def test_idor_read_hint(self):
        f = {"severity": "medium", "text": "GET IDOR confirmed on /api/users/1"}
        out = derive_chain_hint(f)
        assert "PUT/PATCH/DELETE" in out
        assert "/export" in out or "/share" in out

    def test_auth_bypass_hint(self):
        f = {"severity": "high", "text": "Auth bypass on admin endpoint"}
        out = derive_chain_hint(f)
        assert "controller" in out.lower()
        assert "/v1" in out or "legacy" in out.lower()

    def test_stored_xss_hint(self):
        f = {"severity": "medium", "text": "Stored XSS in profile bio"}
        out = derive_chain_hint(f)
        assert "admin" in out.lower()
        assert "ATO" in out

    def test_ssrf_callback_hint_has_metadata(self):
        f = {"severity": "high", "text": "SSRF DNS callback fired"}
        out = derive_chain_hint(f)
        assert "169.254.169.254" in out
        assert "metadata.google.internal" in out

    def test_open_redirect_hint(self):
        f = {"severity": "low", "text": "Open redirect on /next?url=…"}
        out = derive_chain_hint(f)
        assert "OAuth" in out and "redirect_uri" in out

    def test_s3_listing_hint(self):
        f = {"severity": "medium", "text": "S3 bucket listable: ListObjects ok"}
        out = derive_chain_hint(f)
        assert "JWT_SECRET" in out or "AWS_KEY" in out

    def test_graphql_introspection_hint(self):
        f = {"severity": "medium", "text": "GraphQL introspection enabled"}
        out = derive_chain_hint(f)
        assert "mutation" in out.lower()
        assert "Relay" in out or "node(id" in out

    def test_prompt_injection_hint(self):
        f = {"severity": "medium", "text": "Prompt injection in chatbot confirmed"}
        out = derive_chain_hint(f)
        assert "system prompt" in out.lower() or "IDOR via AI" in out

    def test_lfi_hint_has_environ(self):
        f = {"severity": "medium", "text": "LFI on ?file=../../etc/passwd"}
        out = derive_chain_hint(f)
        assert "/proc/self/environ" in out

    def test_subdomain_takeover_hint(self):
        f = {"severity": "medium", "text": "Subdomain takeover on dev.target.com"}
        out = derive_chain_hint(f)
        assert "OAuth" in out
        assert "ATO" in out

    def test_jwt_weak_hint(self):
        f = {"severity": "high", "text": "JWT signed with weak HS256 key"}
        out = derive_chain_hint(f)
        assert "alg:none" in out or "role:admin" in out

    def test_file_upload_hint(self):
        f = {"severity": "medium",
             "text": "File upload extension bypass via .pHp"}
        out = derive_chain_hint(f)
        assert "SVG" in out
        assert ".phtml" in out or "phtml" in out.lower()

    def test_webhook_hint(self):
        f = {"severity": "low", "text": "Webhook URL config field discovered"}
        out = derive_chain_hint(f)
        assert "169.254.169.254" in out
        assert "gopher" in out

    def test_sqli_hint(self):
        f = {"severity": "high", "text": "Boolean-based blind SQL injection on /catalog"}
        out = derive_chain_hint(f)
        assert "UNION" in out
        assert "information_schema" in out

    def test_sqli_short_form(self):
        f = {"severity": "high", "text": "sqli confirmed via 1=1 / 1=2 diff",
             "vuln_class": "SQLi"}
        out = derive_chain_hint(f)
        assert "[CHAIN HINT" in out
        assert "UNION" in out

    def test_dom_xss_hint(self):
        f = {"severity": "high",
             "text": "DOM XSS via prototype pollution in deparam.js"}
        out = derive_chain_hint(f)
        assert "postMessage" in out or "0-click ATO" in out
        assert "localStorage" in out or "CSRF" in out

    def test_prototype_pollution_alone_triggers_dom_xss_hint(self):
        f = {"severity": "medium", "text": "prototype pollution sink found"}
        out = derive_chain_hint(f)
        assert "[CHAIN HINT" in out


# ---------------------------------------------------------------------
#  Edge cases / robustness
# ---------------------------------------------------------------------

class TestRobustness:
    def test_no_match_returns_empty(self):
        f = {"severity": "medium", "text": "interesting tech stack: Django"}
        assert derive_chain_hint(f) == ""

    def test_empty_text_returns_empty(self):
        assert derive_chain_hint({"severity": "high", "text": ""}) == ""

    def test_non_dict_returns_empty(self):
        assert derive_chain_hint("not a dict") == ""  # type: ignore[arg-type]
        assert derive_chain_hint(None) == ""  # type: ignore[arg-type]
        assert derive_chain_hint([]) == ""  # type: ignore[arg-type]

    def test_multiple_matches_join_with_separator(self):
        # Stored XSS + file upload bypass mention in same finding
        f = {"severity": "high",
             "text": "Stored XSS via file upload extension bypass on profile"}
        out = derive_chain_hint(f)
        # Should contain both bodies separated by " // "
        assert " // " in out

    def test_hint_format_has_timestamp_prefix(self):
        f = {"severity": "medium", "text": "GET IDOR on /api/users/1"}
        out = derive_chain_hint(f)
        # Format: "[CHAIN HINT HH:MM] …"
        assert out.startswith("[CHAIN HINT ")
        # Indices: [12]=H1 [13]=H2 [14]=':' [15]=M1 [16]=M2 [17]=']'
        assert out[14] == ":"
        assert out[17] == "]"

    def test_uses_vuln_class_field_if_text_silent(self):
        f = {"severity": "medium", "text": "Issue X",
             "vuln_class": "stored xss"}
        out = derive_chain_hint(f)
        assert "[CHAIN HINT" in out

    def test_uses_tool_field_for_match(self):
        f = {"severity": "medium",
             "text": "endpoint hit",
             "tool": "graphql_introspection_check"}
        out = derive_chain_hint(f)
        assert "[CHAIN HINT" in out


# ---------------------------------------------------------------------
#  HuntMemory integration
# ---------------------------------------------------------------------

class TestHuntMemoryIntegration:
    def test_add_finding_appends_hint_to_working_memory(self, tmp_path):
        from agent import HuntMemory
        m = HuntMemory(str(tmp_path / "sess.json"))
        m.working_memory = "existing notes"
        m.add_finding("scanner", "high", "GET IDOR on /api/users/1 confirmed")
        assert "existing notes" in m.working_memory
        assert "[CHAIN HINT" in m.working_memory
        assert "PUT/PATCH/DELETE" in m.working_memory

    def test_info_severity_still_appends_when_pattern_matches(self, tmp_path):
        """Severity gate was removed — info-level IDOR/SSRF/etc. still
        produce chain hints because the regex patterns themselves
        discriminate noise. High-leverage chains often start at info-level
        signals (S3 listable, GraphQL introspection, JWT alg=none)."""
        from agent import HuntMemory
        m = HuntMemory(str(tmp_path / "sess.json"))
        m.working_memory = "existing notes"
        m.add_finding("scanner", "info", "GET IDOR on /api/users/1")
        assert "existing notes" in m.working_memory
        assert "[CHAIN HINT" in m.working_memory
        assert "PUT/PATCH/DELETE" in m.working_memory

    def test_info_finding_with_no_pattern_match_is_a_no_op(self, tmp_path):
        """An info-level finding that matches NO chain rule leaves
        working_memory untouched. Regex specificity, not severity,
        is what discriminates noise."""
        from agent import HuntMemory
        m = HuntMemory(str(tmp_path / "sess.json"))
        m.working_memory = "existing notes"
        m.add_finding("scanner", "info", "interesting tech stack: Django")
        assert m.working_memory == "existing notes"

    def test_hint_never_breaks_add_finding(self, tmp_path, monkeypatch):
        """Even if chain_hints raises, add_finding still records the finding."""
        from agent import HuntMemory
        import tools.chain_hints as ch
        monkeypatch.setattr(ch, "derive_chain_hint",
                            lambda f: (_ for _ in ()).throw(RuntimeError("boom")))
        m = HuntMemory(str(tmp_path / "sess.json"))
        m.add_finding("scanner", "high", "Stored XSS in bio")
        assert len(m.findings_log) == 1

    def test_working_memory_capped_at_8k(self, tmp_path):
        from agent import HuntMemory
        m = HuntMemory(str(tmp_path / "sess.json"))
        m.working_memory = "X" * 9000
        m.add_finding("scanner", "high", "Stored XSS in bio")
        assert len(m.working_memory) <= 8000
        # Hint preserved at the tail
        assert "[CHAIN HINT" in m.working_memory[-1000:]

    def test_hint_persists_across_save_load(self, tmp_path):
        from agent import HuntMemory
        sess = tmp_path / "sess.json"
        m1 = HuntMemory(str(sess))
        m1.add_finding("scanner", "high", "SSRF DNS callback fired")
        m1.save()
        m2 = HuntMemory(str(sess))
        assert "[CHAIN HINT" in m2.working_memory
        assert "169.254.169.254" in m2.working_memory
