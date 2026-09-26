import pytest

import hunt
from memory.hunt_journal import HuntJournal
from tools.target_store import StoreError, TargetStore


def test_primary_hunt_summary_uses_store_without_rewriting_legacy_profile(tmp_path, monkeypatch):
    target = "hunt-summary.test"
    store = TargetStore(tmp_path, target)
    store.initialize()
    store.create_finding(
        command_id="current-finding", finding_id="current-finding",
        endpoint=f"https://{target}/current", method="GET", family="Authz",
        title="Current claim", claim="Review owner boundary", actor="operator",
    )
    memory_dir = tmp_path / "hunt-memory"
    profile_path = memory_dir / "targets" / f"{target}.json"
    profile_path.parent.mkdir(parents=True)
    profile_path.write_text("{retired profile", encoding="utf-8")
    report_dir = tmp_path / "reports" / target
    report_dir.mkdir(parents=True)
    (report_dir / "INDEX.json").write_text(
        '{"reports":[{"id":"retired","type":"SQLi"}]}', encoding="utf-8",
    )
    monkeypatch.setattr(hunt, "BASE_DIR", str(tmp_path))
    monkeypatch.setattr(hunt, "HUNT_MEMORY_DIR", memory_dir)
    monkeypatch.setattr(hunt, "REPORTS_DIR", str(tmp_path / "reports"))

    hunt._auto_log_session_summary(target, recon_completed=True)

    entries = HuntJournal(memory_dir / "journal.jsonl").query(target=target)
    assert profile_path.read_text(encoding="utf-8") == "{retired profile"
    assert len(entries) == 1
    assert "authz" in entries[0]["notes"]
    assert "sqli" not in entries[0]["notes"]
    assert "Findings: 1" in entries[0]["notes"]


def test_hunt_rejects_legacy_target_before_binding_auth_or_execution(tmp_path, monkeypatch):
    target = "legacy.test"
    legacy_path = tmp_path / "state" / target / "case_state.json"
    legacy_path.parent.mkdir(parents=True)
    legacy_bytes = b'{"sessions":[]}'
    legacy_path.write_bytes(legacy_bytes)
    monkeypatch.setattr(hunt, "BASE_DIR", str(tmp_path))
    class AuthSession:
        bound_target = ""

        def is_empty(self):
            return False

        def bind_target(self, value):
            self.bound_target = value

    auth_session = AuthSession()
    monkeypatch.setattr(hunt, "_active_auth_session", lambda: auth_session)
    monkeypatch.setattr(
        hunt,
        "_hunt_target_impl",
        lambda *args, **kwargs: pytest.fail("target execution started after initialization refusal"),
    )

    with pytest.raises(StoreError, match="legacy target state exists"):
        hunt.hunt_target(target)

    assert auth_session.bound_target == target
    assert legacy_path.read_bytes() == legacy_bytes
    assert not (legacy_path.parent / "metadata.sqlite3").exists()


def test_hunt_initializes_after_auth_binding_and_before_target_work(tmp_path, monkeypatch):
    from tools.target_store import TargetStore

    target = "fresh.test"
    monkeypatch.setattr(hunt, "BASE_DIR", str(tmp_path))
    monkeypatch.setattr(hunt, "WORDLIST_DIR", str(tmp_path / "wordlists"))
    monkeypatch.setattr(hunt, "setup_wordlists", lambda: None)

    class AuthSession:
        def is_empty(self):
            return False

        def bind_target(self, value):
            assert value == target
            assert not TargetStore(tmp_path, target).path.exists()

    monkeypatch.setattr(hunt, "_active_auth_session", AuthSession)
    monkeypatch.setattr(
        hunt,
        "_hunt_target_impl",
        lambda value, **kwargs: (
            value,
            TargetStore(tmp_path, target).backend(),
            kwargs,
        ),
    )

    result = hunt.hunt_target(target, quick=True)

    assert result[0:2] == (target, "primary")
    assert result[2]["quick"] is True


def test_hunt_batch_list_does_not_initialize_a_list_store(tmp_path, monkeypatch):
    from tools.target_store import TargetStore

    target_list = tmp_path / "targets.txt"
    target_list.write_text("one.test\ntwo.test\n", encoding="utf-8")
    monkeypatch.setattr(hunt, "BASE_DIR", str(tmp_path))
    monkeypatch.setattr(hunt, "WORDLIST_DIR", str(tmp_path / "wordlists"))
    monkeypatch.setattr(hunt, "setup_wordlists", lambda: None)
    monkeypatch.setattr(hunt, "_active_auth_session", lambda: type("Auth", (), {"is_empty": lambda self: True})())
    monkeypatch.setattr(
        hunt,
        "_hunt_target_impl",
        lambda value, **kwargs: (value, kwargs),
    )

    result = hunt.hunt_target(str(target_list), recon_only=True)

    list_target = hunt.classify_target(str(target_list))["target"]
    assert result[0] == str(target_list)
    assert not TargetStore(tmp_path, list_target).path.exists()
