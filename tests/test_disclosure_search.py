"""Tests for tools/disclosure_search.py + agents/disclosed-researcher.md.

Discipline (PRD C4): tests assert on structural invariants and anchor
names. They do NOT pin specific report titles, severity strings, or
seed sentences (those vary by what HackerOne actually returns).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from disclosure_search import (
    COVERAGE_STATUS_VALUES,
    DEFAULT_COVERAGE_STATUS,
    DisclosedReport,
    render_disclosed_patterns_md,
    synthesize_hypothesis_seeds,
    write_disclosed_patterns,
    _cache_path,
    _load_cache,
    _save_cache,
)


REPO_ROOT = Path(__file__).resolve().parent.parent


def _fake_report(**overrides) -> DisclosedReport:
    defaults = dict(
        title="GraphQL IDOR allows reading other tenants' orders",
        severity="HIGH",
        disclosed_at="2026-01-15",
        url="https://hackerone.com/reports/12345",
        state="Resolved",
        program="acme",
        program_name="Acme Corp",
    )
    defaults.update(overrides)
    return DisclosedReport(**defaults)


class TestDisclosedReportShape:
    def test_from_h1_safe_on_empty(self):
        # Tool must tolerate missing fields from MCP
        r = DisclosedReport.from_h1({})
        assert r.title == ""
        assert r.severity == "unknown"

    def test_from_h1_truncates_disclosed_at(self):
        r = DisclosedReport.from_h1({"disclosed_at": "2026-01-15T10:30:00Z"})
        assert r.disclosed_at == "2026-01-15"


class TestSynthesizeSeeds:
    """Free-text seed generation — Contract 1 + C1 anti-options[]."""

    def test_empty_inputs_still_produces_at_least_one_seed(self):
        seeds = synthesize_hypothesis_seeds([], [])
        assert len(seeds) >= 1
        # A "green field" message is acceptable; we do not pin its text.
        assert all(isinstance(s, str) and s.strip() for s in seeds)

    def test_same_target_seed_mentions_pattern(self):
        seeds = synthesize_hypothesis_seeds(
            same=[_fake_report(title="IDOR on /api/v1/orders/{id}")],
            similar=[],
        )
        # At least one seed should reference the same-target signal idea
        # without us pinning the exact phrasing.
        assert any("pattern" in s.lower() or "previously" in s.lower() for s in seeds)

    def test_recurring_similar_pattern_consolidated(self):
        seeds = synthesize_hypothesis_seeds(
            same=[],
            similar=[
                _fake_report(title="OAuth redirect_uri bypass on /auth/cb"),
                _fake_report(title="OAuth redirect_uri bypass via attacker", program="other"),
                _fake_report(title="OAuth redirect_uri abuse",  program="third"),
            ],
        )
        # When a pattern recurs across 2+ reports, the seed should hint at
        # industry-recurring shape, not list individual reports.
        joined = " ".join(seeds).lower()
        assert "recurring" in joined or "industry" in joined or "pattern" in joined

    def test_seeds_are_free_text_not_enum(self):
        """C1: seeds must be free text, not a fixed taxonomy menu."""
        seeds = synthesize_hypothesis_seeds([_fake_report()], [])
        # No seed should look like a choose-one-of-these enum line
        for s in seeds:
            assert not s.strip().startswith("[")
            assert not s.strip().startswith("{")
            assert "|" not in s  # not a table row


class TestRenderMarkdown:
    def test_render_includes_all_three_mandatory_section_headers(self):
        md = render_disclosed_patterns_md(
            "example.com",
            same=[_fake_report()],
            similar=[_fake_report(program="other")],
            seeds=["seed 1", "seed 2"],
        )
        assert "# Disclosed Patterns — example.com" in md
        assert "## Same-target reports" in md
        assert "## Similar-target reports" in md
        assert "## Inferred hypothesis seeds" in md

    def test_render_includes_summary_line(self):
        md = render_disclosed_patterns_md(
            "example.com",
            same=[_fake_report()],
            similar=[_fake_report(program="other"), _fake_report(program="x")],
            seeds=["one", "two", "three"],
        )
        # Summary line counts (anchor: the labels, not the numbers)
        assert "Same-target reports:" in md
        assert "Similar-target reports:" in md
        assert "Hypothesis seeds:" in md

    def test_empty_buckets_show_placeholder_text(self):
        md = render_disclosed_patterns_md(
            "example.com", same=[], similar=[], seeds=["none"]
        )
        assert "## Same-target reports" in md
        assert "No same-target reports surfaced" in md
        assert "## Similar-target reports" in md
        assert "No similar-target reports surfaced" in md

    def test_table_pipe_in_title_is_escaped(self):
        md = render_disclosed_patterns_md(
            "example.com",
            same=[_fake_report(title="weird | title")],
            similar=[],
            seeds=["s"],
        )
        # Title row shows escaped pipe so the table doesn't break
        assert "weird \\| title" in md


class TestCacheRoundTrip:
    def test_cache_write_then_read(self, tmp_path):
        payload = {"target": "x.com", "same": [], "similar": []}
        _save_cache(tmp_path, "x.com", payload)
        loaded = _load_cache(tmp_path, "x.com", ttl_hours=72)
        assert loaded is not None
        assert loaded.get("target") == "x.com"

    def test_cache_ignored_when_stale(self, tmp_path):
        payload = {"target": "x.com", "same": [], "similar": []}
        _save_cache(tmp_path, "x.com", payload)
        # Negative TTL forces stale
        loaded = _load_cache(tmp_path, "x.com", ttl_hours=-1)
        assert loaded is None

    def test_cache_missing_returns_none(self, tmp_path):
        loaded = _load_cache(tmp_path, "never-cached.com", ttl_hours=72)
        assert loaded is None

    def test_cache_path_sanitizes_separators(self, tmp_path):
        p = _cache_path(tmp_path, "weird/host:port")
        # Slashes / colons are replaced so the cache file is creatable
        assert "/" not in p.name
        assert ":" not in p.name


class TestWriteFullPipeline:
    """End-to-end (no-MCP mode) — proves the tool degrades gracefully."""

    def test_no_mcp_produces_document_with_all_sections(self, tmp_path):
        out = write_disclosed_patterns(
            "fresh-target.example",
            repo_root=tmp_path,
            no_mcp=True,
        )
        assert out.exists()
        text = out.read_text(encoding="utf-8")
        assert "## Same-target reports" in text
        assert "## Similar-target reports" in text
        assert "## Inferred hypothesis seeds" in text

    def test_no_mcp_does_not_crash_without_recon_dir(self, tmp_path):
        # No recon directory exists; tool must still produce a valid doc
        out = write_disclosed_patterns(
            "fresh-target.example", repo_root=tmp_path, no_mcp=True
        )
        assert out.exists()
        assert out.stat().st_size > 0

    def test_custom_output_path_honored(self, tmp_path):
        custom = tmp_path / "custom" / "out.md"
        out = write_disclosed_patterns(
            "x.com", repo_root=tmp_path, output_path=custom, no_mcp=True
        )
        assert out == custom
        assert custom.exists()


class TestQuestionToToolDiscoverability:
    """Phase 3 R5 + Contract 6: every new tool ships with a Q->Tool row."""

    def test_autopilot_md_has_disclosed_researcher_row(self):
        md = (REPO_ROOT / "commands" / "autopilot.md").read_text(encoding="utf-8")
        # The subagent must be reachable through the advisory table.
        # Anchor on the agent name (the row is between table delimiters,
        # so this also implicitly checks the row landed in the table region).
        assert "disclosed-researcher" in md


class TestSubagentDefinition:
    """The subagent file's frontmatter must parse and name the right agent."""

    def test_subagent_file_exists(self):
        assert (REPO_ROOT / "agents" / "disclosed-researcher.md").is_file()

    def test_subagent_frontmatter_valid(self):
        text = (REPO_ROOT / "agents" / "disclosed-researcher.md").read_text(
            encoding="utf-8"
        )
        # Naive frontmatter splitter — sufficient for shape check
        assert text.startswith("---")
        parts = text.split("---", 2)
        assert len(parts) >= 3
        frontmatter = parts[1]
        assert "name: disclosed-researcher" in frontmatter
        assert "description:" in frontmatter
        assert "tools:" in frontmatter

    def test_subagent_does_not_claim_auto_spawn(self):
        """C3 + new R1: subagent invocation pattern must NOT describe
        itself as auto-spawned by /intel or any other command."""
        text = (REPO_ROOT / "agents" / "disclosed-researcher.md").read_text(
            encoding="utf-8"
        )
        lowered = text.lower()
        # Forbidden phrases that would indicate auto-spawning
        assert "auto-spawn" not in lowered or "not auto-spawned" in lowered
        # The frontmatter must affirm the invocation pattern (anchor only)
        assert "invoked by claude" in lowered or "task tool" in lowered


class TestCoverageStatus:
    """PR-13: 3-value enum on the cache payload + render header line.
    Pilot 2026-05-15 (baronpa.com) showed the previous "no reports
    surfaced" message conflated MCP-unavailable, MCP-no-coverage, and
    MCP-covered-but-empty. Each state must now be distinguishable.
    """

    def test_enum_has_three_values(self):
        # Anchor on the enum tuple shape; not on the string ordering.
        assert set(COVERAGE_STATUS_VALUES) == {
            "mcp_unavailable", "no_mcp_coverage", "covered",
        }
        assert DEFAULT_COVERAGE_STATUS in COVERAGE_STATUS_VALUES

    def test_render_includes_coverage_status_anchor(self):
        for status in COVERAGE_STATUS_VALUES:
            md = render_disclosed_patterns_md(
                "example.com", same=[], similar=[], seeds=["s"],
                coverage_status=status,
            )
            assert "MCP coverage:" in md
            assert status in md

    def test_render_default_status_is_covered(self):
        # Calling render without coverage_status must still surface a
        # status line; default is `covered`.
        md = render_disclosed_patterns_md(
            "example.com", same=[], similar=[], seeds=["s"],
        )
        assert "MCP coverage:" in md
        assert DEFAULT_COVERAGE_STATUS in md

    def test_seeds_branch_on_status(self):
        """Each status produces a factually distinct fallback seed.
        The seeds describe what the search returned (facts) without
        instructing Claude where to pivot — C1 anti-routing discipline.
        """
        unavail = synthesize_hypothesis_seeds(
            [], [], coverage_status="mcp_unavailable"
        )
        no_cov = synthesize_hypothesis_seeds(
            [], [], coverage_status="no_mcp_coverage"
        )
        covered = synthesize_hypothesis_seeds(
            [], [], coverage_status="covered"
        )
        # Each branch produces at least one seed
        assert unavail and no_cov and covered
        # The 3 fallback texts differ — anchored on a distinguishing
        # noun unique to each branch (the language is factual and stable
        # across rewrites of the surrounding prose).
        assert "not connected" in unavail[0].lower()
        assert "no records" in no_cov[0].lower()
        assert "green field" in covered[0].lower()
        # No seed should contain routing/instruction language (C1)
        for branch_seeds in (unavail, no_cov, covered):
            for seed in branch_seeds:
                lowered = seed.lower()
                assert "pivot" not in lowered
                assert "drop this" not in lowered

    def test_status_field_round_trips_through_cache(self, tmp_path):
        """Write a payload with a known status; reload the cache and
        verify the status survives. Anchor: the field name + value
        appear in the cached JSON.
        """
        for status in COVERAGE_STATUS_VALUES:
            target = f"x-{status}.com"
            payload = {
                "target": target,
                "same": [],
                "similar": [],
                "coverage_status": status,
            }
            _save_cache(tmp_path, target, payload)
            loaded = _load_cache(tmp_path, target, ttl_hours=72)
            assert loaded is not None
            assert loaded.get("coverage_status") == status

    def test_no_mcp_pipeline_writes_mcp_unavailable_status(self, tmp_path):
        """End-to-end: --no-mcp forces h1_client=None which must yield
        coverage_status=mcp_unavailable in the rendered document.
        """
        out = write_disclosed_patterns(
            "fresh-target.example", repo_root=tmp_path, no_mcp=True
        )
        text = out.read_text(encoding="utf-8")
        assert "MCP coverage: mcp_unavailable" in text

    def test_legacy_cache_without_status_field_does_not_crash(self, tmp_path):
        """Old caches written before PR-13 lack `coverage_status`. The
        loader must back-fill (`covered` if buckets non-empty,
        otherwise `no_mcp_coverage`) instead of crashing.
        """
        target = "legacy.example"
        # Simulate an old cache with reports but no status field
        legacy_payload = {
            "target": target,
            "same": [vars(_fake_report())],
            "similar": [],
            # NB: no 'coverage_status' key
        }
        _save_cache(tmp_path, target, legacy_payload)
        # Pipeline runs, derives status from buckets, writes document
        out = write_disclosed_patterns(target, repo_root=tmp_path)
        text = out.read_text(encoding="utf-8")
        assert "MCP coverage: covered" in text

    def test_legacy_empty_cache_without_status_renders_no_mcp_coverage(self, tmp_path):
        """Old empty cache (both buckets []) without status field must
        render as `no_mcp_coverage`, NOT `covered`, because the empty
        result IS the signal of no coverage.
        """
        target = "legacy-empty.example"
        legacy_payload = {
            "target": target,
            "same": [],
            "similar": [],
        }
        _save_cache(tmp_path, target, legacy_payload)
        out = write_disclosed_patterns(target, repo_root=tmp_path)
        text = out.read_text(encoding="utf-8")
        assert "MCP coverage: no_mcp_coverage" in text
