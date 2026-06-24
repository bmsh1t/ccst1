"""Tests for tools/sibling_generator.py.

Discipline (PRD C4): tests assert on STRUCTURAL invariants and
ANCHOR fields. No test pins specific sibling endpoint strings —
those depend on the synthetic URL set passed in.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from sibling_generator import (
    DEFAULT_MAX_SIBLINGS,
    PathTemplate,
    _is_id_segment,
    extract_template,
    find_siblings,
    queue_sibling_probes,
)


REPO_ROOT = Path(__file__).resolve().parent.parent


class TestIsIdSegment:
    def test_numeric_id(self):
        assert _is_id_segment("123") is True
        assert _is_id_segment("99999") is True

    def test_uuid(self):
        assert _is_id_segment("11111111-2222-3333-4444-555555555555") is True

    def test_long_alphanumeric_with_digit(self):
        assert _is_id_segment("abc123def456") is True

    def test_plain_word_not_id(self):
        assert _is_id_segment("orders") is False
        assert _is_id_segment("api") is False

    def test_empty(self):
        assert _is_id_segment("") is False


class TestExtractTemplate:
    def test_classic_id_at_tail(self):
        t = extract_template("/api/v1/orders/123")
        assert t.resource == "orders"
        assert t.prefix == "/api/v1"
        assert t.suffix == "/{id}"

    def test_url_strips_scheme_host(self):
        t = extract_template("https://api.target.com/api/v1/orders/123")
        assert t.resource == "orders"
        assert t.prefix == "/api/v1"

    def test_nested_resource_with_id_in_middle(self):
        t = extract_template("/api/v2/users/abc-123-def/orders")
        # IDs in the middle are abstracted into the prefix
        assert t.resource == "orders"
        assert "{id}" in t.prefix
        assert "users" in t.prefix

    def test_single_segment(self):
        t = extract_template("/orders")
        assert t.resource == "orders"
        assert t.prefix == ""

    def test_query_string_stripped(self):
        t = extract_template("/api/v1/orders/123?foo=bar")
        assert t.resource == "orders"
        assert t.suffix == "/{id}"

    def test_empty(self):
        t = extract_template("")
        assert t.resource == ""

    def test_full_template_built(self):
        t = extract_template("/api/v1/orders/123")
        assert t.full_template == "/api/v1/orders/{id}"


class TestFindSiblings:
    def test_same_prefix_different_resource(self):
        template = extract_template("/api/v1/orders/123")
        urls = [
            "/api/v1/orders/123",
            "/api/v1/invoices/456",
            "/api/v1/exports/789",
            "/api/v2/orders/1",      # different prefix
            "/blog/post-1",          # unrelated
        ]
        siblings = find_siblings(template, urls)
        endpoints = {s["endpoint"] for s in siblings}
        assert "/api/v1/invoices/456" in endpoints
        assert "/api/v1/exports/789" in endpoints
        # Primary resource must NOT appear in siblings
        assert all("orders" not in s["endpoint"].split("/") or "/orders/" not in s["endpoint"]
                   for s in siblings)
        # Different-prefix URL must NOT appear
        assert not any("v2" in s["endpoint"] for s in siblings)

    def test_suffix_compatibility(self):
        template = extract_template("/api/v1/orders/123")  # suffix /{id}
        urls = [
            "/api/v1/invoices/9",      # /{id} — compatible
            "/api/v1/exports",         # no suffix — INCOMPATIBLE
            "/api/v1/comments/22/likes/1",  # different shape
        ]
        siblings = find_siblings(template, urls)
        endpoints = {s["endpoint"] for s in siblings}
        assert "/api/v1/invoices/9" in endpoints
        assert "/api/v1/exports" not in endpoints

    def test_cap_honored(self):
        template = extract_template("/api/v1/orders/123")
        urls = [f"/api/v1/resource{i}/1" for i in range(100)]
        siblings = find_siblings(template, urls, max_count=5)
        assert len(siblings) == 5

    def test_default_cap_is_20(self):
        template = extract_template("/api/v1/orders/123")
        urls = [f"/api/v1/r{i}/1" for i in range(50)]
        siblings = find_siblings(template, urls)
        assert len(siblings) <= DEFAULT_MAX_SIBLINGS

    def test_empty_url_list(self):
        template = extract_template("/api/v1/orders/123")
        assert find_siblings(template, []) == []

    def test_empty_template(self):
        template = PathTemplate()
        assert find_siblings(template, ["/api/v1/foo/1"]) == []

    def test_dedupes_repeat_urls(self):
        template = extract_template("/api/v1/orders/123")
        urls = [
            "/api/v1/invoices/1",
            "/api/v1/invoices/2",
            "/api/v1/invoices/3",
        ]
        siblings = find_siblings(template, urls)
        # invoices is one resource — only one sibling row regardless of ID
        assert len(siblings) == 1
        assert siblings[0]["endpoint"] == "/api/v1/invoices/1"

    def test_rationale_is_free_text_not_enum(self):
        """C1: rationale must be free text, not a fixed taxonomy value."""
        template = extract_template("/api/v1/orders/123")
        siblings = find_siblings(template, ["/api/v1/invoices/9"])
        assert len(siblings) == 1
        rationale = siblings[0]["rationale"]
        # Rationale is descriptive — not "category: X" key-value form
        assert isinstance(rationale, str) and len(rationale) > 10


class TestQueueSiblingProbes:
    def _setup(self, tmp_path: Path) -> Path:
        urls_dir = tmp_path / "recon" / "x.com" / "urls"
        urls_dir.mkdir(parents=True)
        (urls_dir / "all.txt").write_text(
            "\n".join([
                "/api/v1/orders/100",
                "/api/v1/invoices/200",
                "/api/v1/exports/300",
                "/blog/post-1",
            ]),
            encoding="utf-8",
        )
        return tmp_path

    def test_writes_queue_file(self, tmp_path):
        self._setup(tmp_path)
        out = queue_sibling_probes(
            "x.com",
            {"id": "F-1", "endpoint": "/api/v1/orders/100"},
            repo_root=tmp_path,
        )
        assert out.exists()
        assert "siblings_F-1.json" in out.name

    def test_queue_payload_shape(self, tmp_path):
        self._setup(tmp_path)
        out = queue_sibling_probes(
            "x.com",
            {"id": "F-1", "endpoint": "/api/v1/orders/100"},
            repo_root=tmp_path,
        )
        payload = json.loads(out.read_text(encoding="utf-8"))
        assert payload["source_finding_id"] == "F-1"
        assert payload["source_endpoint"] == "/api/v1/orders/100"
        assert payload["extracted_resource"] == "orders"
        assert "extracted_template" in payload
        assert "siblings" in payload
        assert payload["queued_count"] == len(payload["siblings"])
        assert payload["executed_count"] == 0

    def test_no_recon_dir_yields_empty_queue(self, tmp_path):
        # No recon URLs available — queue still writes, siblings empty
        out = queue_sibling_probes(
            "ghost.com",
            {"id": "F-1", "endpoint": "/api/v1/orders/100"},
            repo_root=tmp_path,
        )
        payload = json.loads(out.read_text(encoding="utf-8"))
        assert payload["queued_count"] == 0
        assert payload["siblings"] == []

    def test_uses_finding_url_when_endpoint_missing(self, tmp_path):
        self._setup(tmp_path)
        out = queue_sibling_probes(
            "x.com",
            {"id": "F-2", "url": "/api/v1/orders/100"},  # 'url' instead of 'endpoint'
            repo_root=tmp_path,
        )
        payload = json.loads(out.read_text(encoding="utf-8"))
        assert payload["source_endpoint"] == "/api/v1/orders/100"


class TestQuestionToToolDiscoverability:
    """PRD R5 + Contract 6: tool must appear in the Q->Tool table."""

    def test_autopilot_md_has_sibling_generator_row(self):
        md = (REPO_ROOT / "commands" / "autopilot.md").read_text(encoding="utf-8")
        assert "tools/sibling_generator.py" in md
        # Anchor: the question shape mentioned in implement.md
        assert "sibling endpoints" in md.lower()
