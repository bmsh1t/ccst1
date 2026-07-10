"""Tests for tools/intelligence_extractor.py.

Discipline:
    - Test what is extracted (category presence + at least one expected item),
      NOT exact item counts or specific output strings.
    - Use real fixture-style files written to tmp_path to exercise the
      file-walking path.
"""

from pathlib import Path

from intelligence_extractor import (
    EXTRACTORS,
    IntelligenceCorpus,
    extract_intelligence,
    render_markdown,
    write_intelligence,
)


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


class TestExtractorCoverage:
    """Each extractor category must catch its canonical signal."""

    def test_emails(self, tmp_path):
        _write(
            tmp_path / "recon" / "x.com" / "urls" / "all.txt",
            "Contact alice@target.com or bob.smith+ops@target.io for help.\n",
        )
        corpus = extract_intelligence("x.com", tmp_path)
        assert "alice@target.com" in corpus.items["emails"]
        assert "bob.smith+ops@target.io" in corpus.items["emails"]

    def test_internal_hostnames(self, tmp_path):
        _write(
            tmp_path / "recon" / "x.com" / "live" / "hosts.txt",
            "https://internal-api.target.com\nhttps://staging.target.com\n",
        )
        corpus = extract_intelligence("x.com", tmp_path)
        values = corpus.items["internal_hostnames"]
        assert any("internal-api.target.com" in v.lower() for v in values)
        assert any("staging.target.com" in v.lower() for v in values)

    def test_webhook_urls(self, tmp_path):
        _write(
            tmp_path / "recon" / "x.com" / "urls" / "all.txt",
            "POST https://api.target.com/webhook/stripe-events\n"
            "POST https://api.target.com/callback/oauth-finish/abc123\n",
        )
        corpus = extract_intelligence("x.com", tmp_path)
        assert any("webhook/stripe" in v for v in corpus.items["webhook_urls"])
        assert any("callback/oauth" in v for v in corpus.items["webhook_urls"])

    def test_secret_prefixes(self, tmp_path):
        _write(
            tmp_path / "recon" / "x.com" / "js" / "bundle.js",
            'const KEY = "sk_live_AbCdEf12345";\n'
            'const TOKEN = "ghp_abc12345defXYZ";\n'
            'const AWS = "AKIAIOSFODNN7EXAMPLE";\n',
        )
        corpus = extract_intelligence("x.com", tmp_path)
        assert any(v.startswith("sk_live") for v in corpus.items["secret_prefixes"])
        assert any(v.startswith("ghp_") for v in corpus.items["secret_prefixes"])
        assert any(v.startswith("AKIA") for v in corpus.items["secret_prefixes"])

    def test_customer_mentions(self, tmp_path):
        _write(
            tmp_path / "recon" / "x.com" / "data.json",
            '{"customer_id": "cust_42", "tenantId": "acme-corp"}',
        )
        corpus = extract_intelligence("x.com", tmp_path)
        assert "cust_42" in corpus.items["customer_mentions"]
        assert "acme-corp" in corpus.items["customer_mentions"]

    def test_internal_api_paths(self, tmp_path):
        _write(
            tmp_path / "recon" / "x.com" / "js" / "bundle.js",
            'fetch("/internal/users/sync");\n'
            'fetch("/_admin/billing/dump");\n'
            'fetch("/staff/console");\n',
        )
        corpus = extract_intelligence("x.com", tmp_path)
        paths = corpus.items["internal_api_paths"]
        assert "/internal/users/sync" in paths
        assert any("admin" in p for p in paths)

    def test_employee_handles(self, tmp_path):
        _write(
            tmp_path / "recon" / "x.com" / "github" / "commits.txt",
            "Author: @alice-dev\nReviewed by @bob, @charlie-2\n",
        )
        corpus = extract_intelligence("x.com", tmp_path)
        handles = corpus.items["employee_handles"]
        assert "@alice-dev" in handles
        assert "@bob" in handles


class TestSourceTraceability:
    """Each extracted item must record where it came from."""

    def test_source_recorded(self, tmp_path):
        _write(
            tmp_path / "recon" / "x.com" / "urls" / "all.txt",
            "support@target.com\n",
        )
        corpus = extract_intelligence("x.com", tmp_path)
        sources = corpus.items["emails"]["support@target.com"]
        assert any("urls/all.txt" in s for s in sources)
        assert any(s.startswith("recon:") for s in sources)

    def test_multiple_sources_merged(self, tmp_path):
        # Same email in two files — sources accumulate
        _write(
            tmp_path / "recon" / "x.com" / "urls" / "a.txt",
            "support@target.com\n",
        )
        _write(
            tmp_path / "recon" / "x.com" / "urls" / "b.txt",
            "support@target.com\n",
        )
        corpus = extract_intelligence("x.com", tmp_path)
        sources = corpus.items["emails"]["support@target.com"]
        assert len(sources) == 2


class TestResilience:
    """Missing artifacts, binary files, huge files must not crash."""

    def test_empty_target(self, tmp_path):
        corpus = extract_intelligence("ghost.com", tmp_path)
        assert sum(corpus.counts().values()) == 0

    def test_skips_huge_files(self, tmp_path):
        big = tmp_path / "recon" / "x.com" / "huge.txt"
        big.parent.mkdir(parents=True)
        # 6 MB file — over the 5 MB cap
        big.write_text("alice@target.com\n" * 400_000)
        corpus = extract_intelligence("x.com", tmp_path)
        # Should not have extracted from the huge file
        assert corpus.counts().get("emails", 0) == 0

    def test_skips_binary_extensions(self, tmp_path):
        # File with email content but binary-ish extension should be ignored
        binary = tmp_path / "recon" / "x.com" / "logo.png"
        binary.parent.mkdir(parents=True)
        binary.write_text("alice@target.com\n")
        corpus = extract_intelligence("x.com", tmp_path)
        assert corpus.counts().get("emails", 0) == 0

    def test_marketing_email_noise_filtered(self, tmp_path):
        _write(
            tmp_path / "recon" / "x.com" / "page.html",
            "Email: name@example.com (placeholder)\n",
        )
        corpus = extract_intelligence("x.com", tmp_path)
        assert "name@example.com" not in corpus.items.get("emails", {})


class TestRenderMarkdown:

    def test_empty_corpus_renders_placeholder(self):
        out = render_markdown("ghost.com", IntelligenceCorpus())
        assert "Intelligence — ghost.com" in out
        assert "No intelligence items extracted yet" in out

    def test_populated_corpus_lists_items(self, tmp_path):
        _write(
            tmp_path / "recon" / "x.com" / "data.txt",
            "alice@target.com\n",
        )
        corpus = extract_intelligence("x.com", tmp_path)
        out = render_markdown("x.com", corpus)
        assert "## Emails" in out
        assert "alice@target.com" in out
        assert "Total items: 1" in out


class TestWriteIntelligence:

    def test_writes_to_evidence_dir(self, tmp_path):
        _write(
            tmp_path / "recon" / "x.com" / "data.txt",
            "alice@target.com\n",
        )
        path = write_intelligence("x.com", tmp_path)
        assert path == tmp_path / "evidence" / "x.com" / "intelligence.md"
        assert path.exists()
        assert "alice@target.com" in path.read_text()

    def test_idempotent(self, tmp_path):
        _write(
            tmp_path / "recon" / "x.com" / "data.txt",
            "alice@target.com\n",
        )
        p1 = write_intelligence("x.com", tmp_path)
        first = p1.read_text()
        # Re-run with same input — content must be substantially identical
        # (timestamp may differ; the body must not duplicate)
        p2 = write_intelligence("x.com", tmp_path)
        second = p2.read_text()
        assert first.count("alice@target.com") == second.count("alice@target.com")

    def test_custom_output_path(self, tmp_path):
        _write(
            tmp_path / "recon" / "x.com" / "data.txt",
            "alice@target.com\n",
        )
        custom = tmp_path / "out" / "intel.md"
        path = write_intelligence("x.com", tmp_path, output_path=custom)
        assert path == custom
        assert custom.exists()

    def test_url_target_uses_canonical_storage_key_and_preserves_identity(self, tmp_path):
        target = "http://127.0.0.1:3002/#/login"
        _write(
            tmp_path / "recon" / "127.0.0.1:3002" / "data.txt",
            "ops@target.test\n",
        )
        intel_path = tmp_path / "evidence" / "127.0.0.1:3002" / "intelligence.md"
        _write(intel_path, "# Identity Intel — 127.0.0.1:3002\n\n- existing identity hint\n")

        path = write_intelligence(target, tmp_path)
        write_intelligence(target, tmp_path)
        content = path.read_text(encoding="utf-8")

        assert path == intel_path
        assert "ops@target.test" in content
        assert "existing identity hint" in content
        assert content.count("ccst:intelligence:local-extractor:start") == 1
        assert not (tmp_path / "evidence" / "http:").exists()


class TestExtractorContract:
    """Surface-level contract checks — anchor field names, not regex bodies."""

    def test_all_extractors_have_three_tuple(self):
        for entry in EXTRACTORS:
            assert len(entry) == 3
            name, pattern, idx = entry
            assert isinstance(name, str) and name
            assert hasattr(pattern, "finditer")
            assert isinstance(idx, int)

    def test_expected_categories_present(self):
        names = {e[0] for e in EXTRACTORS}
        for required in (
            "emails",
            "internal_hostnames",
            "webhook_urls",
            "secret_prefixes",
            "customer_mentions",
            "internal_api_paths",
            "employee_handles",
        ):
            assert required in names
