"""Autopilot routing for the bounded FFUF rotation ledger."""

import json
from pathlib import Path

import pytest

from tools.autopilot_gate import build_control_projection
from tools.recon_target_selector import (
    FFUF_INPUT_POLICY, load_rotation_status, record_results, select_targets,
)
from tools.scope_source import load_scope_context


def test_pending_directory_rotation_remains_advisory(tmp_path):
    recon_dir = tmp_path / "recon" / "target.test" / "dirs"
    recon_dir.mkdir(parents=True)
    scope_hash = load_scope_context(tmp_path, "target.test").scope_hash
    (recon_dir / "ffuf_target_plan.json").write_text(
        json.dumps({"schema": 1, "eligible_count": 3, "scope_hash": scope_hash,
                    "input_policy_sha256": FFUF_INPUT_POLICY}), encoding="utf-8"
    )
    (recon_dir / "ffuf_target_state.json").write_text(
        json.dumps({"schema": 1, "completed": {"https://target.test": {"status": "ok"}},
                    "scope_hash": scope_hash, "input_policy_sha256": FFUF_INPUT_POLICY}),
        encoding="utf-8",
    )

    status = load_rotation_status(tmp_path, "target.test")
    assert status["status"] == "pending"
    assert status["remaining"] == 2
    projection = build_control_projection({"has_recon": True, "dir_fuzz_rotation": status})
    assert projection["next_action"] == "continue_investigation"
    assert projection["owner_continuations"] == []


def test_rotation_does_not_preempt_surface_or_finding_work(tmp_path):
    state = {"has_recon": True, "dir_fuzz_rotation": {"pending": True},
             "surface_review_candidates": [{"url": "https://target.test/admin"}]}
    assert build_control_projection(state)["next_action"] == "continue_investigation"
    state["structured_findings"] = {"next_validation": {"id": "candidate"}}
    projection = build_control_projection(state)
    assert projection["next_action"] == "validate_finding"
    assert [item["owner"] for item in projection["owner_continuations"]] == ["finding"]


def test_invalid_rotation_ledger_is_advisory_not_an_infinite_recon_loop(tmp_path):
    recon_dir = tmp_path / "recon" / "target.test" / "dirs"
    recon_dir.mkdir(parents=True)
    (recon_dir / "ffuf_target_plan.json").write_text("not-json", encoding="utf-8")
    (recon_dir / "ffuf_target_state.json").write_text("{}", encoding="utf-8")

    status = load_rotation_status(tmp_path, "target.test")
    assert status["status"] == "invalid"
    assert status["pending"] is False


def _word_selection(root, run, contents=None):
    recon = root / "recon/target.test"
    (recon / "live").mkdir(parents=True, exist_ok=True)
    (recon / "live/urls.txt").write_text("https://target.test\n")
    words = root / "words.txt"
    if contents is not None:
        words.write_bytes(contents)
    return select_targets(
        target="target.test", repo_root=root, httpx_path=recon / "live/httpx_full.txt",
        urls_path=recon / "live/urls.txt", state_path=recon / "dirs/ffuf_target_state.json",
        plan_path=recon / "dirs/ffuf_target_plan.json", targets_path=recon / "dirs/ffuf_targets.txt",
        wordlist_path=words, limit=1, word_limit=2, wordlist_dir=root / run,
    )


def _record_word_page(root, plan, status="ok", receipt=None):
    item = plan["selected"][0]
    result = root / "results.tsv"
    result.write_text(f"{item['url']}\t{status}\t{receipt or item['word_page']['receipt']}\n")
    return record_results(target="target.test", repo_root=root,
                          state_path=root / "recon/target.test/dirs/ffuf_target_state.json",
                          results_path=result)


def test_deep_word_pages_resume_and_only_complete_after_last_page(tmp_path):
    original = b"one\r\n\n#comment\none\nlast"
    first = _word_selection(tmp_path, "first", original)
    _record_word_page(tmp_path, first)
    status = load_rotation_status(tmp_path, "target.test")
    assert (status["completed"], status["remaining"], status["words_completed"], status["words_remaining"]) == (0, 1, 2, 3)
    assert build_control_projection({"has_recon": True, "dir_fuzz_rotation": status})["next_action"] == "continue_investigation"
    second = _word_selection(tmp_path, "second")
    _record_word_page(tmp_path, second)
    third = _word_selection(tmp_path, "third")
    _record_word_page(tmp_path, third)
    assert b"".join(Path(plan["selected"][0]["word_page"]["path"]).read_bytes()
                    for plan in (first, second, third)) == original
    assert [plan["selected"][0]["word_page"]["start"] for plan in (first, second, third)] == [0, 2, 4]
    assert load_rotation_status(tmp_path, "target.test")["words_remaining"] == 0
    assert _word_selection(tmp_path, "done")["selected"] == []


@pytest.mark.parametrize("status", ["failed", "partial"])
def test_failed_word_page_preserves_previous_progress_and_rejects_stale_receipt(tmp_path, status):
    first = _word_selection(tmp_path, "first", b"one\ntwo\nthree\nfour\n")
    _record_word_page(tmp_path, first)
    second = _word_selection(tmp_path, "second")
    state = tmp_path / "recon/target.test/dirs/ffuf_target_state.json"
    before = state.read_bytes()
    with pytest.raises(ValueError, match="active word page"):
        _record_word_page(tmp_path, second, receipt=first["selected"][0]["word_page"]["receipt"])
    assert state.read_bytes() == before
    _record_word_page(tmp_path, second, status)
    retry = _word_selection(tmp_path, "retry")
    assert retry["selected"][0]["word_page"]["start"] == 2
    assert load_rotation_status(tmp_path, "target.test")["words_completed"] == 2


@pytest.mark.parametrize("change", ["wordlist", "scope", "policy", "corrupt"])
def test_word_progress_binding_and_corruption(tmp_path, change):
    first = _word_selection(tmp_path, "first", b"one\ntwo\nthree\nfour\n")
    _record_word_page(tmp_path, first)
    state = tmp_path / "recon/target.test/dirs/ffuf_target_state.json"
    data = json.loads(state.read_text())
    if change == "wordlist":
        (tmp_path / "words.txt").write_bytes(b"new\nlist\nwords\n")
    elif change == "scope":
        data["scope_hash"] = "previous-scope"
    elif change == "policy":
        data["input_policy_sha256"] = "previous-policy"
    else:
        data["word_offsets"]["https://target.test"] = True
    state.write_text(json.dumps(data))
    if change == "corrupt":
        with pytest.raises(ValueError, match="word progress"):
            _word_selection(tmp_path, "next")
    else:
        assert _word_selection(tmp_path, "next")["selected"][0]["word_page"]["start"] == 0


def test_missing_active_page_binding_cannot_complete_a_target(tmp_path):
    plan = _word_selection(tmp_path, "first", b"one\ntwo\nthree\n")
    state = tmp_path / "recon/target.test/dirs/ffuf_target_state.json"
    data = json.loads(state.read_text())
    data["active_word_pages"] = {}
    state.write_text(json.dumps(data))
    before = state.read_bytes()
    with pytest.raises(ValueError, match="active word pages"):
        _record_word_page(tmp_path, plan)
    assert state.read_bytes() == before


def test_legacy_completion_and_new_inventory_keep_existing_word_progress(tmp_path):
    first = _word_selection(tmp_path, "first", b"one\ntwo\nthree\n")
    _record_word_page(tmp_path, first)
    root = tmp_path / "recon/target.test"
    state = root / "dirs/ffuf_target_state.json"
    data = json.loads(state.read_text())
    data["completed"]["https://old.target.test"] = {"status": "ok", "completed_at": "before-pages"}
    state.write_text(json.dumps(data))
    urls = root / "live/urls.txt"
    urls.write_text("https://old.target.test\nhttps://target.test\nhttps://new.target.test\n")
    plan = select_targets(
        target="target.test", repo_root=tmp_path, httpx_path=root / "live/httpx_full.txt",
        urls_path=urls, state_path=state, plan_path=root / "dirs/ffuf_target_plan.json",
        targets_path=root / "dirs/ffuf_targets.txt", wordlist_path=tmp_path / "words.txt",
        limit=5, word_limit=2, wordlist_dir=tmp_path / "next",
    )
    starts = {item["url"]: item["word_page"]["start"] for item in plan["selected"]}
    assert starts == {"https://target.test": 2, "https://new.target.test": 0}
    assert plan["words_completed"] == 5 and plan["words_remaining"] == 4
