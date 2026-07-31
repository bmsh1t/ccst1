"""Behavior tests for bounded rotating directory-fuzz target selection."""

import json
from pathlib import Path

import pytest

from tools.recon_target_selector import record_results, select_targets


def _fixture(tmp_path: Path) -> dict[str, Path]:
    httpx = tmp_path / "httpx_full.txt"
    urls = tmp_path / "urls.txt"
    state = tmp_path / "ffuf_target_state.json"
    plan = tmp_path / "ffuf_target_plan.json"
    targets = tmp_path / "ffuf_targets.txt"
    wordlist = tmp_path / "common.txt"
    wordlist.write_text("index\nadmin\n", encoding="utf-8")
    httpx.write_text(
        "\n".join(
            [
                "https://target.test [200] [100] [Home] [nginx]",
                "https://www.target.test [200] [100] [WWW] [nginx]",
                "https://api.target.test [200] [100] [API] [nginx,GraphQL]",
                "https://admin.target.test [403] [100] [Admin] [nginx]",
                "https://auth.target.test [401] [100] [Login] [nginx]",
                "https://target.test:8443 [200] [100] [Alt] [Spring]",
                "https://static.target.test [200] [100] [Static] [Cloudflare]",
                "https://outside.example [200] [100] [Out] [nginx]",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    urls.write_text("\n".join(line.split()[0] for line in httpx.read_text().splitlines()) + "\n", encoding="utf-8")
    return {
        "httpx": httpx,
        "urls": urls,
        "state": state,
        "plan": plan,
        "targets": targets,
        "wordlist": wordlist,
    }


def _select(paths: dict[str, Path], limit: int) -> dict:
    return select_targets(
        target="target.test",
        httpx_path=paths["httpx"],
        urls_path=paths["urls"],
        state_path=paths["state"],
        plan_path=paths["plan"],
        targets_path=paths["targets"],
        wordlist_path=paths["wordlist"],
        limit=limit,
    )


def _record(paths: dict[str, Path], statuses: dict[str, str]) -> dict:
    paths["results"] = paths["state"].with_name("results.tsv")
    paths["results"].write_text(
        "".join(f"{url}\t{status}\n" for url, status in statuses.items()),
        encoding="utf-8",
    )
    return record_results(target="target.test", state_path=paths["state"], results_path=paths["results"])


def test_initial_batch_preserves_root_and_spreads_across_signals(tmp_path):
    paths = _fixture(tmp_path)
    plan = _select(paths, 5)
    selected = {item["url"] for item in plan["selected"]}

    assert "https://target.test" in selected
    assert "https://api.target.test" in selected
    assert "https://admin.target.test" in selected
    assert "https://auth.target.test" in selected
    assert "https://target.test:8443" in selected
    assert "https://outside.example" not in selected
    assert paths["targets"].read_text(encoding="utf-8").splitlines() == [
        item["url"] for item in plan["selected"]
    ]


def test_completed_targets_rotate_and_failed_targets_remain_pending(tmp_path):
    paths = _fixture(tmp_path)
    first = _select(paths, 2)
    first_urls = [item["url"] for item in first["selected"]]
    _record(paths, {first_urls[0]: "ok", first_urls[1]: "partial"})

    second = _select(paths, 2)
    second_urls = {item["url"] for item in second["selected"]}
    assert first_urls[0] not in second_urls
    assert first_urls[1] in second_urls


def test_new_live_service_is_added_without_resetting_completed_hosts(tmp_path):
    paths = _fixture(tmp_path)
    first = _select(paths, 1)
    first_url = first["selected"][0]["url"]
    _record(paths, {first_url: "ok"})

    with paths["httpx"].open("a", encoding="utf-8") as handle:
        handle.write("https://new-api.target.test [200] [100] [New API] [Django]\n")
    with paths["urls"].open("a", encoding="utf-8") as handle:
        handle.write("https://new-api.target.test\n")

    plan = _select(paths, 10)
    selected = {item["url"] for item in plan["selected"]}
    assert first_url not in selected
    assert "https://new-api.target.test" in selected


def test_all_successful_targets_report_exhaustion(tmp_path):
    paths = _fixture(tmp_path)
    first = _select(paths, 20)
    _record(paths, {item["url"]: "ok" for item in first["selected"]})

    exhausted = _select(paths, 5)
    assert exhausted["selected"] == []
    assert exhausted["exhausted"] is True
    assert exhausted["pending_count"] == 0
    assert exhausted["remaining_count"] == 0


def test_corrupt_state_fails_closed(tmp_path):
    paths = _fixture(tmp_path)
    paths["state"].write_text("{not-json", encoding="utf-8")

    with pytest.raises(ValueError, match="invalid FFUF target state"):
        _select(paths, 2)


def test_state_records_only_successful_active_targets(tmp_path):
    paths = _fixture(tmp_path)
    plan = _select(paths, 2)
    _record(paths, {item["url"]: "ok" for item in plan["selected"]})

    state = json.loads(paths["state"].read_text(encoding="utf-8"))
    assert set(state["completed"]) == {item["url"] for item in plan["selected"]}
    assert state["active"] == []
