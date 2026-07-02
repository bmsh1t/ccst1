"""Tests for tools/distill_reports.py.

Discipline: fixture-driven, asserts structural invariants. Does NOT pin
volatile content (specific report titles). Does NOT require network or
pyarrow — all tests work on pre-built dicts that mimic normalized rows.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from distill_reports import (
    CANDIDATES_DIR,
    CARDS_DIR,
    WHITELIST_FIELDS,
    _assert_safe_output_dir,
    _bullet_block,
    _slug,
    _weakness_name,
    batch_reports,
    candidate_to_card_md,
    dedupe_by_id,
    ingest_candidates,
    is_placeholder_only,
    normalize_report,
    passes_prefilter,
    prepare_reports,
    scrub_text,
    write_batches,
)


# --------------------------------------------------------------------------- #
# Fixtures
# --------------------------------------------------------------------------- #
def _report(**overrides) -> dict:
    base = {
        "id": 100001,
        "title": "SSRF via webhook URL",
        "vulnerability_information": "Steps to reproduce: 1. Set webhook to http://169.254.169.254...",
        "substate": "resolved",
        "weakness": {"name": "Server-Side Request Forgery (SSRF)"},
        "has_bounty?": True,
        "vote_count": 12,
        "reporter": {"username": "hunter42", "profile_picture_urls": {"small": "https://..."}},
        "team": {"handle": "target-corp"},
        "structured_scope": {"asset_type": "URL", "asset_identifier": "*.target.com"},
    }
    base.update(overrides)
    return base


def _candidate(**overrides) -> dict:
    base = {
        "knowledge_point": "Ghost Bits 语义差",
        "card_title": "Java Ghost Bits 绕过",
        "source_report_ids": [838510],
        "value_score": 8,
        "verdict": "保留，高优先级",
        "category": "框架行为利用",
        "is_ai_likely_known": False,
        "worth_skill": True,
        "applies_when": ["char 转 byte 的输入处理"],
        "trigger_signals": ["(byte)ch 截断"],
        "divergent_questions": ["三视图是否一致?"],
        "recommended_actions": ["拆三视图"],
        "related_skills": ["web2-vuln-classes"],
        "stop_conditions": ["无截断路径"],
        "validation_requirements": ["可 replay 请求"],
        "promotable_experience": ["视图分离时优先测此模式"],
    }
    base.update(overrides)
    return base


# --------------------------------------------------------------------------- #
# Pre-filter
# --------------------------------------------------------------------------- #
class TestPrefilter:
    def test_empty_info_dropped(self):
        assert not passes_prefilter(_report(vulnerability_information=""))

    def test_none_info_dropped(self):
        assert not passes_prefilter(_report(vulnerability_information=None))

    def test_placeholder_only_dropped(self):
        assert not passes_prefilter(_report(vulnerability_information="{F123456}  {FXXXXXX}"))

    def test_real_info_passes(self):
        assert passes_prefilter(_report())

    def test_mixed_placeholder_and_text_passes(self):
        assert passes_prefilter(_report(vulnerability_information="{F1} real steps here"))


class TestPlaceholder:
    def test_blank(self):
        assert is_placeholder_only("")
        assert is_placeholder_only("   ")

    def test_only_placeholders(self):
        assert is_placeholder_only("{F999}")
        assert is_placeholder_only("{F123} {F456}")

    def test_real_content(self):
        assert not is_placeholder_only("The endpoint /api/v1")


# --------------------------------------------------------------------------- #
# Normalization
# --------------------------------------------------------------------------- #
class TestNormalize:
    def test_only_whitelist_fields_survive(self):
        result = normalize_report(_report())
        assert set(result.keys()).issubset(set(WHITELIST_FIELDS))

    def test_reporter_pii_dropped(self):
        result = normalize_report(_report())
        assert "reporter" not in result
        assert "team" not in result
        assert "structured_scope" not in result
        assert "profile_picture_urls" not in result

    def test_weakness_flattened_to_name(self):
        result = normalize_report(_report())
        assert result["weakness"] == "Server-Side Request Forgery (SSRF)"

    def test_weakness_none(self):
        result = normalize_report(_report(weakness=None))
        assert result["weakness"] == ""

    def test_weakness_string(self):
        result = normalize_report(_report(weakness="XSS"))
        assert result["weakness"] == "XSS"

    def test_has_bounty_alternate_key(self):
        r = _report()
        r.pop("has_bounty", None)
        result = normalize_report(r)
        assert result["has_bounty"] is True


# --------------------------------------------------------------------------- #
# Dedup
# --------------------------------------------------------------------------- #
class TestDedupe:
    def test_removes_duplicates(self):
        rows = [_report(id=1), _report(id=1), _report(id=2)]
        assert len(dedupe_by_id(rows)) == 2

    def test_no_id_dropped(self):
        rows = [_report(id=None), _report(id=1)]
        assert len(dedupe_by_id(rows)) == 1


# --------------------------------------------------------------------------- #
# Full prepare pipeline
# --------------------------------------------------------------------------- #
class TestPrepare:
    def test_basic_flow(self):
        rows = [
            _report(id=1),
            _report(id=2, vulnerability_information=""),  # dropped
            _report(id=1),  # dup
            _report(id=3, substate="informative"),
        ]
        result = prepare_reports(rows)
        ids = [r["id"] for r in result]
        assert ids == [1, 3]

    def test_substate_filter(self):
        rows = [
            _report(id=1, substate="resolved"),
            _report(id=2, substate="duplicate"),
        ]
        result = prepare_reports(rows, substates={"resolved"})
        assert len(result) == 1
        assert result[0]["id"] == 1

    def test_max_cap(self):
        rows = [_report(id=i) for i in range(100)]
        result = prepare_reports(rows, max_reports=10)
        assert len(result) == 10


# --------------------------------------------------------------------------- #
# Batching
# --------------------------------------------------------------------------- #
class TestBatching:
    def test_even_split(self):
        reports = [{"id": i} for i in range(50)]
        batches = batch_reports(reports, 25)
        assert len(batches) == 2
        assert len(batches[0]) == 25

    def test_remainder(self):
        reports = [{"id": i} for i in range(30)]
        batches = batch_reports(reports, 25)
        assert len(batches) == 2
        assert len(batches[1]) == 5

    def test_invalid_size(self):
        with pytest.raises(ValueError):
            batch_reports([], 0)


class TestWriteBatches:
    def test_writes_manifest_and_jsonl(self, tmp_path):
        reports = [{"id": i, "title": f"r{i}"} for i in range(7)]
        manifest = write_batches(reports, work_dir=tmp_path, size=3)
        assert manifest["total_reports"] == 7
        assert manifest["batch_count"] == 3
        for name in manifest["batch_files"]:
            assert (tmp_path / name).is_file()
        assert (tmp_path / "manifest.json").is_file()

    def test_stale_batches_cleaned(self, tmp_path):
        (tmp_path / "batch_old.jsonl").write_text("old")
        write_batches([{"id": 1}], work_dir=tmp_path, size=5)
        assert not (tmp_path / "batch_old.jsonl").exists()


# --------------------------------------------------------------------------- #
# Scrubbing
# --------------------------------------------------------------------------- #
class TestScrub:
    def test_email_redacted(self):
        assert "[email-redacted]" in scrub_text("contact hunter@evil.com now")

    def test_long_token_redacted(self):
        token = "A" * 40
        assert "[token-redacted]" in scrub_text(f"Bearer {token}")

    def test_short_strings_untouched(self):
        assert scrub_text("short") == "short"

    def test_none_safe(self):
        assert scrub_text(None) == ""


# --------------------------------------------------------------------------- #
# Ingest
# --------------------------------------------------------------------------- #
class TestIngest:
    def test_writes_only_worth_skill(self, tmp_path):
        candidates = [
            _candidate(worth_skill=True, card_title="good"),
            _candidate(worth_skill=False, card_title="bad"),
        ]
        written = ingest_candidates(candidates, out_dir=tmp_path)
        assert len(written) == 1
        assert "good" in written[0].name

    def test_keep_rejected_flag(self, tmp_path):
        candidates = [_candidate(worth_skill=False, card_title="bad")]
        written = ingest_candidates(candidates, out_dir=tmp_path, keep_rejected=True)
        assert len(written) == 1

    def test_refuses_cards_dir(self, tmp_path):
        with pytest.raises(ValueError, match="refusing"):
            _assert_safe_output_dir(CARDS_DIR)

    def test_card_md_contains_template_sections(self, tmp_path):
        candidates = [_candidate()]
        written = ingest_candidates(candidates, out_dir=tmp_path)
        content = written[0].read_text()
        assert "STAGING CANDIDATE" in content
        assert "## 适用场景" in content
        assert "## 停止条件" in content
        assert "## 触发信号" in content
        assert "/kb promote" in content

    def test_no_reporter_pii_in_card(self, tmp_path):
        c = _candidate()
        c["applies_when"] = ["email hunter@evil.com leaked"]
        written = ingest_candidates([c], out_dir=tmp_path)
        content = written[0].read_text()
        assert "hunter@evil.com" not in content
        assert "[email-redacted]" in content

    def test_dedup_filename(self, tmp_path):
        candidates = [_candidate(card_title="same"), _candidate(card_title="same")]
        written = ingest_candidates(candidates, out_dir=tmp_path)
        assert len(written) == 2
        assert written[0] != written[1]


# --------------------------------------------------------------------------- #
# Card rendering helpers
# --------------------------------------------------------------------------- #
class TestCardRendering:
    def test_slug_cjk(self):
        assert _slug("Java Ghost Bits 绕过") == "java-ghost-bits-绕过"

    def test_slug_fallback(self):
        assert _slug("") == "candidate"

    def test_bullet_block_list(self):
        result = _bullet_block(["a", "b"])
        assert result == "- a\n- b"

    def test_bullet_block_empty(self):
        assert "待补充" in _bullet_block([])
        assert "待补充" in _bullet_block(None)


# --------------------------------------------------------------------------- #
# weakness helper
# --------------------------------------------------------------------------- #
class TestWeaknessName:
    def test_dict(self):
        assert _weakness_name({"name": "IDOR"}) == "IDOR"

    def test_none(self):
        assert _weakness_name(None) == ""

    def test_string(self):
        assert _weakness_name("XSS") == "XSS"
