"""Source metadata and category words must not choose the default work window."""

import json

from tools import recon_target_selector as selector
from tools import surface
from tools.autopilot_state import _build_recommended_targets
from tools.scope_source import load_scope_source, publish_scope_source
from tools.surface_index import build_surface_index, iter_surface_index
from tools.target_store import TargetStore


def test_ffuf_uses_url_order_and_retains_pending_tail_across_restarts(tmp_path):
    target = "selection.test"
    TargetStore(tmp_path, target).initialize()
    current = load_scope_source(tmp_path, target)
    publish_scope_source(tmp_path, target, {
        "schema_version": 1, "root_target": target,
        "in_scope": [target, "*.selection.test"], "out_of_scope": ["excluded.selection.test"],
    }, expected_sha256=current["sha256"])
    urls = ["https://selection.test", "https://z-api.selection.test", "https://y-admin.selection.test",
            "https://a.selection.test", "https://b.selection.test", "https://c.selection.test"]
    httpx = tmp_path / "httpx.txt"
    httpx.write_text("\n".join(f"{url} [403] [Fixture] [nginx]" for url in urls)
                     + "\nhttps://excluded.selection.test [200]\nhttps://other.test [200]\n")
    wordlist = tmp_path / "words.txt"
    wordlist.write_text("fixture\n")
    state, plan, selected = (tmp_path / name for name in ("state.json", "plan.json", "selected.txt"))
    kwargs = dict(target=target, repo_root=tmp_path, httpx_path=httpx, urls_path=tmp_path / "missing.txt",
                  state_path=state, plan_path=plan, targets_path=selected, wordlist_path=wordlist, limit=2)
    seen = []
    for index in range(3):
        batch = selector.select_targets(**kwargs)
        batch_urls = [row["url"] for row in batch["selected"]]
        assert batch["order"] == "url" and batch_urls == sorted(urls)[index * 2:index * 2 + 2]
        assert batch["remaining_count"] == 4 - index * 2
        assert all("tags" not in row and "score" not in row for row in batch["selected"])
        seen.extend(batch_urls)
        result = tmp_path / "results.tsv"
        result.write_text("".join(f"{url}\tok\n" for url in batch_urls))
        selector.record_results(target=target, state_path=state, results_path=result, repo_root=tmp_path)
        # Input enumeration order is not a priority or cursor.
        httpx.write_text("\n".join(reversed(httpx.read_text().splitlines())))
    assert seen == sorted(urls)
    assert selector.select_targets(**kwargs)["exhausted"] is True


def test_surface_keeps_exact_url_window_independent_of_source_and_shape(tmp_path):
    target = "selection.test"
    store = TargetStore(tmp_path, target)
    store.initialize()
    recon = tmp_path / "recon" / target
    urls_dir = recon / "urls"
    urls_dir.mkdir(parents=True)
    urls = [f"https://{target}/same?item={i:03d}" for i in range(40)]
    preferred = f"https://{target}/zz-admin/graphql?secret=abc"
    urls.append(preferred)
    (urls_dir / "all.txt").write_text("\n".join(reversed(urls)))
    build_surface_index(tmp_path, target)
    baseline = surface.rank_surface(surface.load_surface_context(tmp_path, target, memory_dir=tmp_path / "memory"))
    assert [row["url"] for row in baseline["review_pool"]] == sorted(urls)[:16]
    assert baseline["review_window"] == {"order": "url", "total": 41, "returned": 16, "remaining": 25, "limit": 16}

    browser = recon / "browser"
    browser.mkdir()
    (browser / "xhr_endpoints.txt").write_text(preferred + "\n" + urls[0] + "\n")
    store.create_finding(command_id="scanner-claim", finding_id="scanner-claim", endpoint=preferred,
                         method="GET", family="Authz", title="Unassessed claim",
                         claim="Review source evidence", actor="operator")
    build_surface_index(tmp_path, target)
    context = surface.load_surface_context(tmp_path, target, memory_dir=tmp_path / "memory")
    context["profile"] = {"untested_endpoints": ["/zz-admin/graphql?secret=abc"],
                          "tested_endpoints": ["/same?item=000"]}
    for finding in context["scanner_findings"]:
        finding.update(severity="critical", confidence="confirmed")
    ranked = surface.rank_surface(context)
    assert [row["url"] for row in ranked["review_pool"]] == sorted(urls)[:16]
    assert ranked["review_window"] == baseline["review_window"]
    assert ranked["p1"] == ranked["p2"] == ranked["kill"] == []
    assert ranked["review_pool"][0]["browser_observed"] is True
    assert all("score" not in row and "score_breakdown" not in row for row in ranked["review_pool"])
    recommended = _build_recommended_targets(ranked["review_pool"], {"hosts": []})
    assert [row["url"] for row in recommended] == sorted(urls)[:5]
    assert all("score" not in row for row in recommended)
    assert {row["url"] for row in iter_surface_index(tmp_path, target)} == set(urls)
    assert ranked["surface_index"]["continuation"]["starts_at"] == "first-page"
    text = surface.format_surface_output(ranked, target)
    assert "Score hint" not in text and "remaining: 25" in text


def test_ffuf_sample_joins_surface_by_url_without_reserved_seats(tmp_path):
    urls = [f"https://selection.test/{i:02d}" for i in range(20)]
    context = {"available": True, "target": "selection.test", "repo_root": tmp_path,
               "recon_dir": tmp_path, "hosts": {}, "status403_hosts": set(), "api_urls": urls,
               "ffuf_summary": {"available": True, "review_sample": [
                   {"url": urls[-1], "status": 200}, {"url": "https://selection.test/00-extra", "status": 403},
                   {"url": "https://selection.test/00-extra", "status": 403},
               ]}}
    ranked = surface.rank_surface(context)
    assert [row["url"] for row in ranked["review_pool"]] == sorted([*urls, "https://selection.test/00-extra"])[:16]
    assert ranked["review_window"]["total"] == 21
    assert ranked["review_window"]["remaining"] == 5
    assert ranked["review_pool"][1]["ffuf_observed"] is True
    leads = [json.loads(row) for row in ranked["workflow_leads"]]
    assert all("priority" not in row for row in leads)
