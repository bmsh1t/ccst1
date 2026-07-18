"""中性 recon observation inventory 的持久化与集成契约。"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest

from tools.observation_inventory import (
    InventoryError,
    inventory_path,
    load_inventory,
    observation_summary_path,
    page_inventory,
    peek_inventory_summary,
    summarize_inventory,
    sync_inventory,
    sync_inventory_summary,
    touch_observation,
)
from tools.autopilot_state import build_autopilot_state, format_autopilot_state
from tools.checkpoint import build_checkpoint
from tools.surface import load_surface_context, rank_surface


def _write_recon(repo_root, target: str = "target.com", *, count: int = 20):
    recon_dir = repo_root / "recon" / target
    (recon_dir / "urls").mkdir(parents=True)
    (recon_dir / "live").mkdir()
    urls = [f"https://api.target.com/resource/{index}" for index in range(count)]
    (recon_dir / "urls" / "all.txt").write_text("\n".join(urls) + "\n", encoding="utf-8")
    (recon_dir / "urls" / "api_endpoints.txt").write_text(
        "\n".join(urls[:2]) + "\n",
        encoding="utf-8",
    )
    (recon_dir / "live" / "httpx_full.txt").write_text(
        "https://api.target.com [200] [API] [Python] [100]\n",
        encoding="utf-8",
    )
    return recon_dir, urls


def test_sync_dedupes_sources_and_preserves_review_state(tmp_path):
    recon_dir, urls = _write_recon(tmp_path, count=3)

    first = sync_inventory(tmp_path, "target.com")
    url_item = next(item for item in first["observations"] if item["value"] == urls[0])
    assert url_item["sources"] == ["urls/all.txt", "urls/api_endpoints.txt"]
    assert url_item["status"] == "untouched"
    assert url_item["seen_count"] == 1

    touch_observation(
        tmp_path,
        "target.com",
        url_item["id"],
        status="reviewed",
        notes="AI reviewed the raw observation; no execution result implied.",
    )

    unchanged = sync_inventory(tmp_path, "target.com")
    unchanged_item = next(item for item in unchanged["observations"] if item["id"] == url_item["id"])
    assert unchanged_item["seen_count"] == 1
    assert unchanged_item["status_updated_at"] == unchanged_item["reviewed_at"]

    with (recon_dir / "urls" / "all.txt").open("a", encoding="utf-8") as handle:
        handle.write("https://api.target.com/new\n")
    refreshed = sync_inventory(tmp_path, "target.com")
    refreshed_item = next(item for item in refreshed["observations"] if item["id"] == url_item["id"])
    assert refreshed_item["status"] == "reviewed"
    assert refreshed_item["notes"].startswith("AI reviewed")
    assert refreshed_item["seen_count"] == 2
    assert any(item["value"].endswith("/new") for item in refreshed["observations"])


def test_summary_exposes_stale_and_bounded_neutral_samples(tmp_path):
    _write_recon(tmp_path, count=24)
    payload = sync_inventory(tmp_path, "target.com")
    now = datetime(2026, 7, 11, tzinfo=timezone.utc)
    old = (now - timedelta(days=3)).strftime("%Y-%m-%dT%H:%M:%SZ")
    for item in payload["observations"]:
        item["first_seen"] = old
    inventory_path(tmp_path, "target.com").write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )

    summary = summarize_inventory(payload, now=now, sample_limit=5)

    assert summary["total"] > 16
    assert summary["untouched"] == summary["total"]
    assert summary["stale"] == summary["total"]
    assert len(summary["sample"]) == 5
    assert all(set(item) == {"id", "kind", "value", "sources", "status", "stale"} for item in summary["sample"])
    assert "skill" not in json.dumps(summary).lower()
    assert "priority" not in json.dumps(summary).lower()


def test_invalid_state_fails_explicitly_without_overwriting_file(tmp_path):
    path = inventory_path(tmp_path, "target.com")
    path.parent.mkdir(parents=True)
    path.write_text("{broken", encoding="utf-8")

    with pytest.raises(InventoryError, match="invalid observation inventory"):
        load_inventory(tmp_path, "target.com")
    with pytest.raises(InventoryError, match="invalid observation inventory"):
        sync_inventory(tmp_path, "target.com")

    assert path.read_text(encoding="utf-8") == "{broken"


def test_atomic_replace_failure_preserves_previous_inventory(tmp_path, monkeypatch):
    recon_dir, _ = _write_recon(tmp_path, count=2)
    sync_inventory(tmp_path, "target.com")
    path = inventory_path(tmp_path, "target.com")
    original = path.read_text(encoding="utf-8")
    original_replace = type(path).replace

    def fail_inventory_replace(self, target):
        if self.name.startswith(".observations.json."):
            raise OSError("simulated inventory replace failure")
        return original_replace(self, target)

    monkeypatch.setattr(type(path), "replace", fail_inventory_replace)
    with (recon_dir / "urls" / "all.txt").open("a", encoding="utf-8") as handle:
        handle.write("https://api.target.com/new-after-failure\n")

    with pytest.raises(OSError, match="simulated inventory replace failure"):
        sync_inventory(tmp_path, "target.com")

    assert path.read_text(encoding="utf-8") == original
    assert not list(path.parent.glob(".observations.json.*.tmp"))


def test_surface_syncs_inventory_and_keeps_full_window_outside_review_pool(tmp_path):
    _write_recon(tmp_path, count=30)

    ranked = rank_surface(load_surface_context(tmp_path, "target.com"))

    inventory = ranked["observation_inventory"]
    assert inventory["available"] is True
    assert inventory["total"] >= 30
    assert inventory["untouched"] == inventory["total"]
    assert len(ranked["review_pool"]) <= 16
    assert ranked["stats"]["observation_total"] == inventory["total"]
    assert ranked["stats"]["observation_untouched"] == inventory["untouched"]


def test_touch_rejects_unknown_status_and_id(tmp_path):
    _write_recon(tmp_path, count=1)
    sync_inventory(tmp_path, "target.com")

    with pytest.raises(ValueError, match="invalid observation status"):
        touch_observation(tmp_path, "target.com", "missing", status="tested")
    with pytest.raises(KeyError, match="observation not found"):
        touch_observation(tmp_path, "target.com", "missing", status="reviewed")


def test_autopilot_and_checkpoint_expose_counts_without_promoting_actions(tmp_path):
    _write_recon(tmp_path, count=22)

    state = build_autopilot_state(str(tmp_path), "target.com", memory_dir=str(tmp_path / "memory"))
    rendered = format_autopilot_state(state)
    checkpoint = build_checkpoint(
        tmp_path,
        target="target.com",
        memory_dir=str(tmp_path / "memory"),
        refresh_coverage=False,
    )

    inventory = state["surface"]["observation_inventory"]
    assert inventory["total"] >= 22
    assert f"untouched={inventory['untouched']}" in rendered
    assert checkpoint["surface"]["observation_total"] == inventory["total"]
    assert checkpoint["surface"]["observation_untouched"] == inventory["untouched"]
    queue_blob = json.dumps(checkpoint["next_action_queue"]).lower()
    assert "observation_inventory" not in queue_blob
    assert "observation inventory" not in queue_blob


def test_surface_reports_corrupt_inventory_instead_of_zeroing_it(tmp_path):
    _write_recon(tmp_path, count=2)
    path = inventory_path(tmp_path, "target.com")
    path.parent.mkdir(parents=True)
    path.write_text("{broken", encoding="utf-8")

    ranked = rank_surface(load_surface_context(tmp_path, "target.com"))

    assert ranked["observation_inventory"]["available"] is False
    assert "invalid observation inventory" in ranked["observation_inventory"]["error"]


def test_summary_sidecar_hit_never_loads_monolithic_inventory(tmp_path, monkeypatch):
    _write_recon(tmp_path, count=20)
    payload = sync_inventory(tmp_path, "target.com")
    summary_path = observation_summary_path(tmp_path, "target.com")
    assert summary_path.is_file()

    hit = peek_inventory_summary(tmp_path, "target.com")
    assert hit["status"] == "valid"
    assert hit["total"] == len(payload["observations"])

    monkeypatch.setattr(
        "tools.observation_inventory.load_inventory",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("valid summary hit must not load observations.json")
        ),
    )
    fast = sync_inventory_summary(tmp_path, "target.com")
    assert fast["status"] == "valid"
    assert fast["total"] == hit["total"]


def test_summary_sidecar_detects_source_body_and_corrupt_drift(tmp_path):
    recon_dir, _ = _write_recon(tmp_path, count=2)
    sync_inventory(tmp_path, "target.com")

    with (recon_dir / "urls" / "all.txt").open("a", encoding="utf-8") as handle:
        handle.write("https://api.target.com/source-change\n")
    source_stale = peek_inventory_summary(tmp_path, "target.com")
    assert source_stale["status"] == "stale"
    assert source_stale["reason"] == "source-fingerprint-mismatch"
    assert source_stale["total"] > 0

    sync_inventory(tmp_path, "target.com")
    body = inventory_path(tmp_path, "target.com")
    body.write_text(body.read_text(encoding="utf-8") + " ", encoding="utf-8")
    body_stale = peek_inventory_summary(tmp_path, "target.com")
    assert body_stale["status"] == "stale"
    assert body_stale["reason"] == "inventory-binding-mismatch"

    summary_path = observation_summary_path(tmp_path, "target.com")
    summary_path.write_text("{broken", encoding="utf-8")
    invalid = peek_inventory_summary(tmp_path, "target.com")
    assert invalid["status"] == "invalid"
    assert "invalid-json" in invalid["reason"]


def test_touch_atomically_refreshes_summary_binding(tmp_path):
    _write_recon(tmp_path, count=1)
    payload = sync_inventory(tmp_path, "target.com")
    observation_id = payload["observations"][0]["id"]
    before = peek_inventory_summary(tmp_path, "target.com")

    touch_observation(tmp_path, "target.com", observation_id, status="reviewing")

    after = peek_inventory_summary(tmp_path, "target.com")
    assert after["status"] == "valid"
    assert after["reviewing"] == 1
    assert after["inventory_binding"] != before["inventory_binding"]


def test_explicit_sync_repairs_legacy_missing_summary_without_incrementing_seen_count(tmp_path):
    _write_recon(tmp_path, count=2)
    payload = sync_inventory(tmp_path, "target.com")
    before_counts = {item["id"]: item["seen_count"] for item in payload["observations"]}
    observation_summary_path(tmp_path, "target.com").unlink()

    missing = peek_inventory_summary(tmp_path, "target.com")
    assert missing["status"] == "summary_missing"
    assert missing["needs_sync"] is True

    repaired = sync_inventory_summary(tmp_path, "target.com")
    after = load_inventory(tmp_path, "target.com")
    assert repaired["status"] == "valid"
    assert {item["id"]: item["seen_count"] for item in after["observations"]} == before_counts


def test_page_cursor_reaches_each_matching_observation_once_without_mutation(tmp_path):
    _write_recon(tmp_path, count=37)
    payload = sync_inventory(tmp_path, "target.com")
    body = inventory_path(tmp_path, "target.com")
    original = body.read_bytes()
    expected_ids = {
        item["id"]
        for item in payload["observations"]
        if item["kind"] == "url" and "urls/all.txt" in item["sources"]
    }

    cursor = ""
    seen = []
    while True:
        page = page_inventory(
            tmp_path,
            "target.com",
            kind="url",
            source="urls/all.txt",
            limit=7,
            cursor=cursor,
        )
        seen.extend(item["id"] for item in page["items"])
        cursor = page["next_cursor"]
        if not cursor:
            assert page["remaining"] == 0
            break

    assert set(seen) == expected_ids
    assert len(seen) == len(set(seen)) == len(expected_ids)
    assert body.read_bytes() == original


def test_page_cursor_rejects_filter_changes_and_stale_snapshot(tmp_path):
    _write_recon(tmp_path, count=6)
    payload = sync_inventory(tmp_path, "target.com")
    first = page_inventory(tmp_path, "target.com", status="untouched", limit=2)
    assert first["next_cursor"]

    with pytest.raises(ValueError, match="filter mismatch"):
        page_inventory(
            tmp_path,
            "target.com",
            status="reviewed",
            limit=2,
            cursor=first["next_cursor"],
        )

    touch_observation(
        tmp_path,
        "target.com",
        payload["observations"][-1]["id"],
        status="reviewing",
    )
    with pytest.raises(InventoryError, match="snapshot changed"):
        page_inventory(
            tmp_path,
            "target.com",
            status="untouched",
            limit=2,
            cursor=first["next_cursor"],
        )
