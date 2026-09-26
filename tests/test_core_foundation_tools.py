"""Behavior tests for core autopilot foundation tools.

These tests cover the small deterministic helpers that sit underneath the
/autopilot loop. They avoid network access and assert behavior at public helper
or CLI-function boundaries instead of implementation details.
"""

from __future__ import annotations

import argparse
import json
import shlex
import subprocess
from pathlib import Path

from tools.target_store import TargetStore

import pytest

from tools import action_queue, noise_filter, runtime_config, target_memory, target_paths


def test_resolve_target_url_preserves_protocol_relative_authority():
    assert target_paths.resolve_target_url(
        "//api.external.test/v1",
        "https://app.target.test",
    ) == "https://api.external.test/v1"
    assert target_paths.resolve_target_url(
        "//api.target.test/v1",
        "https://app.target.test",
    ) == "https://api.target.test/v1"
    assert target_paths.resolve_target_url(
        "/api/users",
        "https://app.target.test",
    ) == "https://app.target.test/api/users"


def test_target_paths_canonicalizes_host_port_cidr_and_lists(tmp_path):
    scope = tmp_path / "scope.txt"
    scope.write_text("api.example.test\nshop.example.test\n", encoding="utf-8")

    assert target_paths.classify_target("127.0.0.1:3000") == {
        "kind": "ip",
        "target": "127.0.0.1:3000",
    }
    assert target_paths.classify_target("192.168.1.1/24") == {
        "kind": "cidr",
        "target": "192.168.1.0/24",
    }
    assert target_paths.canonical_target_value(str(scope)) == str(scope.resolve())
    assert target_paths.target_storage_key(str(scope)).startswith("scope--")
    assert target_paths.legacy_list_storage_key(str(scope)) == "scope"
    assert target_paths.target_storage_key("192.168.1.0/24") == "192.168.1.0_24"
    assert target_paths.target_storage_key("app.example.test:8443") == "app.example.test:8443"
    assert target_paths.classify_target("http://127.0.0.1:3002/#/login") == {
        "kind": "ip",
        "target": "127.0.0.1:3002",
    }
    assert target_paths.classify_target("https://Example.COM/admin?x=1") == {
        "kind": "domain",
        "target": "example.com",
    }
    assert target_paths.classify_target("Example.COM:8443") == {
        "kind": "domain",
        "target": "example.com:8443",
    }
    assert target_paths.canonical_target_value("Example.COM") == "example.com"
    assert target_paths.target_storage_key("Example.COM") == target_paths.target_storage_key(
        "https://Example.COM"
    )
    assert target_paths.canonical_target_value("http://127.0.0.1:3002/#/login") == "127.0.0.1:3002"
    assert target_paths.target_storage_key("http://127.0.0.1:3002/#/login") == "127.0.0.1:3002"


def test_target_paths_accepts_wildcards_single_labels_and_unambiguous_ipv6():
    assert target_paths.classify_target("*.example.test") == {
        "kind": "domain",
        "target": "*.example.test",
    }
    assert target_paths.classify_target("localhost") == {
        "kind": "domain",
        "target": "localhost",
    }
    assert target_paths.classify_target("[2001:db8::1]:8443") == {
        "kind": "ip",
        "target": "[2001:db8::1]:8443",
    }
    assert target_paths.classify_target("https://[2001:db8::1]:8443/api?a=1&b=2") == {
        "kind": "ip",
        "target": "[2001:db8::1]:8443",
    }
    assert target_paths.classify_target("example.test.") == {
        "kind": "domain",
        "target": "example.test",
    }
    assert target_paths.classify_target("https://example.test./") == {
        "kind": "domain",
        "target": "example.test",
    }
    assert target_paths.target_https_url("2001:db8::1") == "https://[2001:db8::1]"
    assert target_paths.target_https_url("[2001:db8::1]:8443") == "https://[2001:db8::1]:8443"


@pytest.mark.parametrize(
    "target",
    (
        "",
        " example.test",
        "example.test ",
        "example.test bad",
        "example.test\nnext.test",
        "example.test;touch",
        "$(touch marker)",
        "https://user@example.test",
        "ftp://example.test",
        "https://https://example.test",
        "https://example.test:0",
        "https://example.test:99999",
        "http://2001:db8::1",
        "[2001:db8::1",
        "[example.test]",
        "https://[example.test]/",
        "example.test..",
        "https://example.test../",
        "missing/scope.txt",
        "täst.example",
    ),
)
def test_target_paths_rejects_invalid_active_targets(target):
    with pytest.raises(ValueError):
        target_paths.classify_target(target)


def test_canonical_target_value_keeps_invalid_legacy_lookup_fallback():
    assert target_paths.canonical_target_value("legacy target") == "legacy target"


def test_target_paths_isolates_same_stem_lists_by_canonical_path(tmp_path):
    first = tmp_path / "a" / "scope.txt"
    second = tmp_path / "b" / "scope.txt"
    first.parent.mkdir()
    second.parent.mkdir()
    first.write_text("same.test\n", encoding="utf-8")
    second.write_text("same.test\n", encoding="utf-8")

    first_key = target_paths.target_storage_key(str(first))
    second_key = target_paths.target_storage_key(str(second))

    assert first_key.startswith("scope--")
    assert second_key.startswith("scope--")
    assert first_key != second_key


def test_url_belongs_to_target_distinguishes_direct_evidence_from_chain_context():
    assert target_paths.url_belongs_to_target(
        "http://127.0.0.1:3002/rest/admin",
        "http://127.0.0.1:3002/#/",
    )
    assert not target_paths.url_belongs_to_target(
        "https://steamcommunity.com/sharedfiles/filedetails/?id=1969196030",
        "http://127.0.0.1:3002/#/",
    )
    assert target_paths.url_belongs_to_target(
        "https://api.example.com/v1/users",
        "example.com",
    )
    assert not target_paths.url_belongs_to_target(
        "http://127.0.0.1:3002application/vnd.ms-word.do",
        "http://127.0.0.1:3002/#/",
    )
    assert not target_paths.url_belongs_to_target(
        "https://example.com../api",
        "example.com",
    )


def test_url_belongs_to_target_handles_protocol_relative_wildcard_and_default_ports(tmp_path):
    scope = tmp_path / "scope.txt"
    scope.write_text("*.example.com\n", encoding="utf-8")

    assert target_paths.classify_target("//Example.COM/path") == {
        "kind": "domain",
        "target": "example.com",
    }
    assert target_paths.canonical_target_value("https://*.Example.COM/path") == "*.example.com"
    assert target_paths.url_belongs_to_target("//api.example.com/v1", "example.com")
    assert not target_paths.url_belongs_to_target("//evil.example.net/v1", "example.com")
    assert target_paths.url_belongs_to_target("https://api.example.com/v1", "*.example.com")
    assert not target_paths.url_belongs_to_target("https://example.com/v1", "*.example.com")
    assert target_paths.url_belongs_to_target("https://api.example.com/v1", str(scope))
    assert not target_paths.url_belongs_to_target("https://example.com/v1", str(scope))
    assert target_paths.url_belongs_to_target("https://example.com/v1", "example.com:443")
    assert target_paths.url_belongs_to_target("//example.com/v1", "example.com:443")
    assert target_paths.url_belongs_to_target("http://example.com/v1", "example.com:80")
    assert target_paths.url_belongs_to_target("https://example.com:443/v1", "https://example.com")
    assert not target_paths.url_belongs_to_target("http://example.com/v1", "https://example.com")


def test_url_belongs_to_target_checks_each_primary_target_in_list(tmp_path):
    scope = tmp_path / "scope.txt"
    scope.write_text(
        "# primary roots\n*.example.com\napi.example.test:8443\n",
        encoding="utf-8",
    )

    assert target_paths.url_belongs_to_target(
        "https://shop.example.com/orders",
        str(scope),
    )
    assert target_paths.url_belongs_to_target(
        "https://api.example.test:8443/v1/users",
        str(scope),
    )
    assert not target_paths.url_belongs_to_target(
        "https://api.example.test/v1/users",
        str(scope),
    )
    assert not target_paths.url_belongs_to_target(
        "https://third-party.test/callback",
        str(scope),
    )


def test_url_belongs_to_target_does_not_recurse_into_nested_lists(tmp_path, monkeypatch):
    nested = tmp_path / "nested.txt"
    nested.write_text("nested.example.test\n", encoding="utf-8")
    scope = tmp_path / "scope.txt"
    scope.write_text(f"{nested.name}\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)

    assert not target_paths.url_belongs_to_target(
        "https://nested.example.test/api",
        str(scope),
    )


def test_target_memory_set_append_and_handoff_use_canonical_paths(tmp_path, monkeypatch):
    monkeypatch.setattr(target_memory, "BASE_DIR", tmp_path)
    monkeypatch.setattr(target_memory, "GOALS_DIR", tmp_path / "memory" / "goals")
    monkeypatch.setattr(target_memory, "ACTIVE_PATH", tmp_path / "memory" / "goals" / "active.json")
    monkeypatch.setattr(target_memory, "TARGETS_DIR", tmp_path / "memory" / "goals" / "targets")
    monkeypatch.setattr(target_memory, "SESSIONS_DIR", tmp_path / "memory" / "goals" / "sessions")

    with pytest.raises(ValueError, match="not initialized"):
        target_memory.set_active(argparse.Namespace(target="Example.COM"))
    store = TargetStore(tmp_path, "example.com")
    store.initialize()
    target_memory.set_active(argparse.Namespace(target="Example.COM", goal="map auth boundaries"))
    saved = target_memory.load_target_memory("Example.COM")
    assert saved["active_goal"] == "map auth boundaries"
    target_memory.append_entry(argparse.Namespace(target=None, text=["Try two-account read-only diff"]),
                               "next_actions", "NEXT")
    receipt = target_memory.write_handoff(argparse.Namespace(
        target="Example.COM", summary=["Recon complete"], command_id="handoff-1", json=True,
    ))
    assert receipt["receipt"]["entity_id"] == "handoff-1"
    assert store.experience("handoff-1")["statement"] == "Recon complete"
    entries = store.experience_page()["items"]
    assert {item["statement"] for item in entries} == {"Recon complete", "Try two-account read-only diff"}
    assert not target_memory.target_memory_path("Example.COM").exists()


def test_target_memory_fact_preserves_advisory_history_and_renders_it(tmp_path):
    store = TargetStore(tmp_path, "example.com")
    store.initialize()
    for command_id, statement in (("fact-1", "502 may be filtered"), ("fact-2", "Random-miss also returns 502")):
        saved = target_memory.upsert_fact(argparse.Namespace(
            key="cdn-filtering", text=[statement], target="example.com", repo_root=tmp_path,
            command_id=command_id, json=True,
        ))
        assert saved["receipt"]["entity_id"] == command_id
    entries = store.experience_page()["items"]
    assert len(entries) == 2
    assert all(item["kind"] == "note" and item["evidence"] == [] for item in entries)
    output = target_memory.show(argparse.Namespace(target="example.com", repo_root=tmp_path))
    assert "502 may be filtered" in output and "Random-miss also returns 502" in output
    for key, text in (("Bad Key!", ["x"]), ("ok-key", [])):
        with pytest.raises(SystemExit):
            target_memory.upsert_fact(argparse.Namespace(key=key, text=text, target="example.com", repo_root=tmp_path))


def test_target_memory_legacy_writer_is_fenced_after_primary_activation(tmp_path, monkeypatch):
    from tools.target_store import StoreError, TargetStore

    monkeypatch.setattr(target_memory, "BASE_DIR", tmp_path)
    monkeypatch.setattr(target_memory, "GOALS_DIR", tmp_path / "memory" / "goals")
    monkeypatch.setattr(target_memory, "ACTIVE_PATH", tmp_path / "memory" / "goals" / "active.json")
    monkeypatch.setattr(target_memory, "TARGETS_DIR", tmp_path / "memory" / "goals" / "targets")
    monkeypatch.setattr(target_memory, "SESSIONS_DIR", tmp_path / "memory" / "goals" / "sessions")
    TargetStore(tmp_path, "example.com").initialize()

    with pytest.raises(StoreError, match="retired target-memory flags"):
        target_memory.set_active(
            argparse.Namespace(
                target="example.com", mode="hunt", phase="recon", goal="", hypothesis="",
                skill=[], knowledge=[],
            )
        )


def test_target_memory_primary_selection_and_goal_are_store_owned(tmp_path, monkeypatch):
    from tools.target_store import StoreError, TargetStore

    monkeypatch.setattr(target_memory, "BASE_DIR", tmp_path)
    monkeypatch.setattr(target_memory, "ACTIVE_PATH", tmp_path / "memory" / "goals" / "active.json")
    monkeypatch.setattr(target_memory, "TARGETS_DIR", tmp_path / "memory" / "goals" / "targets")
    store = TargetStore(tmp_path, "example.com")
    store.initialize()
    before = store.binding()["revision"]

    assert target_memory.main(["set", "example.com"]) == 0
    assert store.binding()["revision"] == before
    assert target_memory.load_active()["target"] == "example.com"
    assert not target_memory.target_memory_path("example.com").exists()
    assert target_memory.main(["set", "example.com", "--goal", "Map authorization boundary",
                               "--command-id", "goal-1", "--expected-revision", str(before)]) == 0
    assert store.active_goal() == "Map authorization boundary"
    assert store.binding()["revision"] == before + 1
    assert target_memory.main(["set", "example.com", "--goal", "Map authorization boundary",
                               "--command-id", "goal-1", "--expected-revision", str(before)]) == 0
    assert store.binding()["revision"] == before + 1
    with pytest.raises(StoreError, match="retired target-memory flags"):
        target_memory.set_active(argparse.Namespace(target="example.com", mode=None,
                                                    phase=None, goal=None, hypothesis=None,
                                                    skill=["legacy-route"], knowledge=None))
    store.remember(command_id="note-1", kind="note", statement="Header may affect routing",
                   conditions="unverified", reopen_when="", next_intent="Inspect response",
                   evidence=[], actor="operator")
    projection = target_memory.load_goal_memory(tmp_path, "example.com")
    assert projection["target"]["active_goal"] == "Map authorization boundary"
    assert projection["target"]["scope_notes"][0]["text"] == "Header may affect routing"
    assert "Map authorization boundary" in target_memory.show(argparse.Namespace(target="example.com"))
    assert target_memory.main(["note", "Header may affect routing", "--target", "example.com",
                               "--command-id", "note-2"]) == 0
    assert target_memory.main(["lead", "Compare peer account", "--target", "example.com",
                               "--conditions", "same tenant", "--next-intent", "Read control",
                               "--command-id", "lead-1"]) == 0
    assert target_memory.main(["next", "Review response", "--target", "example.com",
                               "--command-id", "next-1"]) == 0
    assert target_memory.main(["fact", "--key", "route-header", "Header changed route",
                               "--target", "example.com", "--command-id", "fact-1"]) == 0
    assert target_memory.main(["handoff", "Resume comparison", "--target", "example.com",
                               "--command-id", "handoff-1"]) == 0
    projection = target_memory.load_goal_memory(tmp_path, "example.com")
    assert [item["text"] for item in projection["target"]["next_actions"]] == ["Review response"]
    shown = target_memory.show(argparse.Namespace(target="example.com"))
    assert "conditions: same tenant" in shown
    assert "next_intent: Read control" in shown
    assert "[lead-1]" in shown
    assert "--id EXPERIENCE_ID" in shown
    assert {item["kind"] for item in store.experience_page(limit=20)["items"]} == {
        "note", "hypothesis", "handoff"
    }
    assert store.experience("fact-1")["statement"] == "route-header: Header changed route"
    assert not target_memory.target_memory_path("example.com").exists()
    assert target_memory.main(["dead-end", "No peer read", "--target", "example.com",
                               "--conditions", "same tenant", "--reopen-when", "new session"]) == 2
    assert target_memory.main(["pattern", "Check role switch", "--target", "example.com"]) == 2
    assert target_memory.main(["set", "fresh.example"]) == 2
    assert not (tmp_path / "state" / "fresh.example" / "metadata.sqlite3").exists()


def test_target_memory_show_reports_bounded_store_history(tmp_path, monkeypatch):
    from tools.target_store import TargetStore

    monkeypatch.setattr(target_memory, "BASE_DIR", tmp_path)
    monkeypatch.setattr(target_memory, "ACTIVE_PATH", tmp_path / "memory" / "goals" / "active.json")
    store = TargetStore(tmp_path, "example.com")
    store.initialize()
    for index in range(21):
        store.remember(command_id=f"note-{index}", kind="note", statement=f"Note {index}",
                       conditions="test session", reopen_when="when role changes",
                       next_intent="compare response", evidence=[], actor="operator")

    shown = target_memory.show(argparse.Namespace(target="example.com"))
    assert "More target experiences: 1" in shown
    assert "Next cursor: " in shown
    assert "[note-0]" not in shown
    assert "[note-20]" in shown
    assert "reopen_when: when role changes" in shown
    assert len(target_memory.load_goal_memory(tmp_path, "example.com")["recent_entries"]) == 20
    command = next(line.removeprefix("Next page: ") for line in shown.splitlines()
                   if line.startswith("Next page: "))
    before = store.binding()
    page = subprocess.run(shlex.split(command) + ["--json"], cwd=Path(__file__).resolve().parents[1],
                          text=True, capture_output=True, check=True)
    assert [entry["entry_id"] for entry in json.loads(page.stdout)["target_entries"]] == ["note-0"]
    expand = next(line.removeprefix("Expand: ") for line in shown.splitlines()
                  if line.startswith("Expand: "))
    expanded = subprocess.run(shlex.split(expand)[:-1] + ["note-20", "--json"],
                              cwd=Path(__file__).resolve().parents[1],
                              text=True, capture_output=True, check=True)
    assert [entry["entry_id"] for entry in json.loads(expanded.stdout)["target_entries"]] == ["note-20"]
    assert store.binding() == before


def test_target_memory_reads_one_bounded_snapshot_without_loading_full_case(tmp_path, monkeypatch):
    from tools.target_store import TargetStore

    store = TargetStore(tmp_path, "example.com")
    store.initialize()
    store.set_active_goal(command_id="goal", goal="Original intent", actor="operator", expected_revision=0)
    for index in range(25):
        store.remember_hypothesis(command_id=f"case-{index:02}", hypothesis_id=f"H-{index:02}",
                                  vuln_class="authz", why_now=f"Context {index}", actor="operator")

    def no_full_case(*args, **kwargs):
        raise AssertionError("memory display must not load full Case or private material")

    monkeypatch.setattr(TargetStore, "case_context", no_full_case)
    before = store.binding()
    projection = target_memory.load_goal_memory(tmp_path, store.target, experience_limit=5)
    assert projection["source"]["revision"] == before["revision"]
    assert projection["target"]["active_goal"] == "Original intent"
    assert projection["target"]["current_hypothesis"] == "Context 24"
    assert len(projection["recent_entries"]) == 5
    assert projection["source"]["experience_window"]["remaining"] == 20
    assert store.binding() == before


def test_target_memory_primary_projection_ignores_archived_json(tmp_path):
    from tools.target_store import TargetStore

    store = TargetStore(tmp_path, "example.com")
    store.initialize()
    store.remember(
        command_id="primary-hypothesis",
        kind="hypothesis",
        statement="Peer object may cross the actor boundary",
        conditions="Both actor sessions are available",
        reopen_when="",
        next_intent="Compare the peer response",
        evidence=[],
        actor="operator",
    )
    legacy = tmp_path / "memory" / "goals" / "targets" / "example.com.json"
    legacy.parent.mkdir(parents=True)
    legacy.write_text("{broken", encoding="utf-8")

    projection = target_memory.load_goal_memory(tmp_path, "example.com")

    assert projection["source"]["kind"] == "store"
    assert projection["target"]["active_leads"][0]["text"] == (
        "Peer object may cross the actor boundary"
    )
    assert projection["target"]["active_leads"][0]["structured"]["conditions"] == (
        "Both actor sessions are available"
    )
    active_path = tmp_path / "memory" / "goals" / "active.json"
    target_memory.write_json(active_path, {"schema_version": 1, "target": "example.com",
                                           "active_goal": "stale legacy goal", "phase": "stale phase"})
    projection = target_memory.load_goal_memory(tmp_path, "example.com")
    assert projection["active"] == {"schema_version": 1, "target": "example.com"}
    assert projection["target"]["active_goal"] == ""


@pytest.mark.parametrize("selected", ["ordinary", "keyword-rich"])
def test_action_queue_claim_uses_explicit_id_without_value_ranking(tmp_path, selected):
    store = TargetStore(tmp_path, "example.com")
    store.initialize()
    for action_id, intent, priority in (("ordinary", "Review observed input", 10),
                                        ("keyword-rich", "admin GraphQL secret SQLi RCE", 99)):
        store.create_action(command_id="create:" + action_id, action_id=action_id,
                            intent=intent, priority=priority, kind="work", subject={"target": "example.com"},
                            execution_key=action_id, actor="test", metadata={"relevance_score": priority})
    action_queue.claim_next_action(tmp_path, "example.com", action_id=selected)
    assert store.action(selected)["status"] == "claimed"
    other = "keyword-rich" if selected == "ordinary" else "ordinary"
    assert store.action(other)["status"] == "ready"


def test_noise_filter_extracts_urls_and_builtin_dedup_keeps_param_signatures(tmp_path):
    raw = tmp_path / "urls.txt"
    out = tmp_path / "dedup.txt"
    raw.write_text(
        "prefix https://app.example.test/api/items?id=1&sort=asc extra\n"
        "https://app.example.test/api/items?sort=desc&id=2\n"
        "https://app.example.test/api/items?page=1\n"
        "not a url\n",
        encoding="utf-8",
    )

    assert noise_filter._extract_url("see https://app.example.test/x?q=1 now") == "https://app.example.test/x?q=1"
    assert noise_filter._extract_url("not a url") == ""

    kept_count = noise_filter._builtin_dedup(raw, out)
    kept = out.read_text(encoding="utf-8").splitlines()
    assert kept_count == 2
    assert kept == [
        "https://app.example.test/api/items?id=1&sort=asc",
        "https://app.example.test/api/items?page=1",
    ]


def test_runtime_config_is_fail_open_and_explicit_override_wins(tmp_path):
    assert runtime_config.load_runtime_config(tmp_path) == {}
    assert runtime_config.is_ctf_mode_enabled(tmp_path) is False
    assert runtime_config.is_ctf_mode_enabled(tmp_path, explicit=True) is True

    (tmp_path / "config.json").write_text(
        '{"ctf_mode": true, "cf_solver": {"headful": true}, "other": 1}\n',
        encoding="utf-8",
    )
    assert runtime_config.load_runtime_config(tmp_path)["ctf_mode"] is True
    assert runtime_config.load_config_section(tmp_path, "cf_solver") == {"headful": True}
    assert runtime_config.load_config_section(tmp_path, "missing") == {}
    assert runtime_config.is_ctf_mode_enabled(tmp_path) is True
    assert runtime_config.is_ctf_mode_enabled(tmp_path, explicit=False) is False

    (tmp_path / "config.json").write_text("not-json", encoding="utf-8")
    assert runtime_config.load_runtime_config(tmp_path) == {}


def test_user_intent_ledger_survives_session_summary_to_resume(tmp_path, monkeypatch):
    """The operator's original instruction must survive compaction/resume.

    Chain: make_session_summary_entry(user_intent) -> journal entry ->
    latest_session_summary -> resume output -> autopilot bootstrap line.
    """
    monkeypatch.setattr(target_memory, "BASE_DIR", tmp_path)
    monkeypatch.setattr(target_memory, "GOALS_DIR", tmp_path / "memory" / "goals")
    monkeypatch.setattr(target_memory, "ACTIVE_PATH", tmp_path / "memory" / "goals" / "active.json")
    monkeypatch.setattr(target_memory, "TARGETS_DIR", tmp_path / "memory" / "goals" / "targets")
    monkeypatch.setattr(target_memory, "SESSIONS_DIR", tmp_path / "memory" / "goals" / "sessions")

    # 1. schema 层: user_intent 作为可选字段通过校验并保留原文
    from memory.schemas import make_session_summary_entry
    entry = make_session_summary_entry(
        target="target.com",
        action="hunt",
        endpoints_tested=["/api/users"],
        vuln_classes_tried=["IDOR"],
        findings_count=0,
        user_intent="重点测 RCE 和上传链",
    )
    assert entry["user_intent"] == "重点测 RCE 和上传链"

    # 无 intent 的旧条目保持合法（向后兼容）
    legacy = make_session_summary_entry(
        target="target.com", action="hunt", endpoints_tested=[], vuln_classes_tried=[], findings_count=0,
    )
    assert "user_intent" not in legacy

    # 2. journal -> resume 解析链
    from tools.resume import parse_session_summary_entry, latest_session_summary
    parsed = parse_session_summary_entry(entry)
    assert parsed["user_intent"] == "重点测 RCE 和上传链"
    latest = latest_session_summary([entry])
    assert latest["user_intent"] == "重点测 RCE 和上传链"

    # 3. handoff 摘要中 [intent=...] 提取（checkpoint --note 注入的形态）
    import re as _re
    summary = "target.com checkpoint [intent=重点测 RCE 和上传链]: Decision=continue; next_action=coverage-gap"
    intent_match = _re.search(r"\[intent=(.+?)\]", summary)
    assert intent_match and intent_match.group(1).strip() == "重点测 RCE 和上传链"

    # 4. 无 intent 的 handoff 摘要不误提取
    plain = "target.com checkpoint: Decision=continue"
    assert _re.search(r"\[intent=(.+?)\]", plain) is None
