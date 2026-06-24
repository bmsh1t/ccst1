"""Tests for tools/auth_session.py."""

import argparse
import os

import pytest

from tools.auth_session import (
    AuthSession,
    ENV_API_KEY,
    ENV_BEARER,
    ENV_COOKIE,
    ENV_HEADER_IN,
    ENV_HEADERS,
    ENV_SESSION_ID,
    add_cli_args,
    session_from_args,
)


class TestAuthSessionBasic:

    def test_empty_session_is_inert(self):
        session = AuthSession()
        assert session.is_empty()
        assert session.headers_list() == []
        assert session.curl_args() == []
        assert session.session_id() == ""
        assert session.env_overlay() == {}

    def test_add_header_simple(self):
        session = AuthSession()
        session.add_header("Cookie: session=abc")
        assert session.headers_list() == ["Cookie: session=abc"]
        assert session.headers_dict() == {"Cookie": "session=abc"}

    def test_add_header_rejects_malformed(self):
        session = AuthSession()
        with pytest.raises(ValueError, match="invalid header"):
            session.add_header("no-colon-here")

    def test_add_header_rejects_crlf_injection(self):
        session = AuthSession()
        with pytest.raises(ValueError, match="CR/LF"):
            session.add_header("X-Foo: bar\r\nInjected: pwn")

    def test_add_header_deduplicates_same_name(self):
        session = AuthSession()
        session.add_header("Cookie: old=1")
        session.add_header("Cookie: new=2")
        assert session.headers_list() == ["Cookie: new=2"]

    def test_helpers_add_cookie_bearer_apikey(self):
        session = AuthSession()
        session.add_cookie("session=abc")
        session.add_bearer("eyJabc")
        session.add_api_key("secret-key")
        assert session.headers_dict() == {
            "Cookie": "session=abc",
            "Authorization": "Bearer eyJabc",
            "X-API-Key": "secret-key",
        }


class TestFromEnv:

    def test_empty_env_yields_empty_session(self):
        assert AuthSession.from_env({}).is_empty()

    def test_all_env_sources_merge(self):
        env = {
            ENV_HEADER_IN: "X-Foo: 1",
            ENV_COOKIE: "session=abc",
            ENV_BEARER: "tok",
            ENV_API_KEY: "key",
        }
        session = AuthSession.from_env(env)
        assert sorted(session.headers_dict().keys()) == ["Authorization", "Cookie", "X-API-Key", "X-Foo"]


class TestFromFile:

    def test_missing_file_returns_empty(self, tmp_path):
        assert AuthSession.from_file(tmp_path / "nope.json").is_empty()

    def test_json_cookie_bearer_apikey(self, tmp_path):
        path = tmp_path / "auth.json"
        path.write_text(
            '{"cookie": "s=1", "bearer": "tok", "api_key": "k", "api_key_header": "X-Token"}',
            encoding="utf-8",
        )
        session = AuthSession.from_file(path)
        assert session.headers_dict() == {
            "Cookie": "s=1",
            "Authorization": "Bearer tok",
            "X-Token": "k",
        }

    def test_env_style_file(self, tmp_path):
        path = tmp_path / "auth.env"
        path.write_text(
            "# comment\n"
            "BBHUNT_COOKIE=session=abc\n"
            "BBHUNT_BEARER=eyJtoken\n"
            "API_KEY=mykey\n",
            encoding="utf-8",
        )
        session = AuthSession.from_file(path)
        assert session.headers_dict() == {
            "Cookie": "session=abc",
            "Authorization": "Bearer eyJtoken",
            "X-API-Key": "mykey",
        }


class TestSessionId:

    def test_session_id_is_stable_across_instances(self):
        first = AuthSession(["Cookie: abc", "X-Foo: bar"])
        second = AuthSession(["X-Foo: bar", "Cookie: abc"])
        assert first.session_id() == second.session_id()

    def test_session_id_changes_with_value(self):
        assert AuthSession(["Cookie: a"]).session_id() != AuthSession(["Cookie: b"]).session_id()


class TestOutput:

    def test_export_to_env_sets_vars(self):
        session = AuthSession(["Cookie: abc"])
        env = {}
        session.export_to_env(env)
        assert env[ENV_HEADERS] == "Cookie: abc"
        assert env[ENV_SESSION_ID] == session.session_id()

    def test_export_to_env_clears_stale_values_when_empty(self):
        env = {ENV_HEADERS: "stale", ENV_SESSION_ID: "stale"}
        AuthSession().export_to_env(env)
        assert ENV_HEADERS not in env
        assert ENV_SESSION_ID not in env


class TestSecrets:

    SECRET = "super-secret-value-that-must-not-leak"

    def test_repr_str_and_describe_do_not_expose_value(self):
        session = AuthSession([f"Cookie: {self.SECRET}"])
        assert self.SECRET not in repr(session)
        assert self.SECRET not in str(session)
        assert self.SECRET not in session.describe()

    def test_redacted_masks_value(self):
        session = AuthSession([f"Cookie: {self.SECRET}"])
        assert self.SECRET not in session.redacted()["Cookie"]
        assert "***" in session.redacted()["Cookie"]


class TestCliArgs:

    @staticmethod
    def _parser(include_cookie: bool = True):
        parser = argparse.ArgumentParser()
        add_cli_args(parser, include_cookie=include_cookie)
        return parser

    def test_no_flags_yields_empty_session(self):
        args = self._parser().parse_args([])
        assert session_from_args(args, env={}).is_empty()

    def test_auth_header_repeatable(self):
        args = self._parser().parse_args([
            "--auth-header", "X-A: 1",
            "--auth-header", "X-B: 2",
        ])
        session = session_from_args(args, env={})
        assert sorted(session.headers_dict().keys()) == ["X-A", "X-B"]

    def test_cookie_bearer_apikey_shorthand(self):
        args = self._parser().parse_args([
            "--cookie", "s=1",
            "--bearer", "tok",
            "--api-key", "k",
        ])
        session = session_from_args(args, env={})
        assert session.headers_dict() == {
            "Cookie": "s=1",
            "Authorization": "Bearer tok",
            "X-API-Key": "k",
        }

    def test_auth_file_flag(self, tmp_path):
        path = tmp_path / "auth.json"
        path.write_text('{"cookie": "session=abc"}', encoding="utf-8")
        args = self._parser().parse_args(["--auth-file", str(path)])
        session = session_from_args(args, env={})
        assert session.headers_dict() == {"Cookie": "session=abc"}

    def test_env_auto_detect_without_flag(self):
        args = self._parser().parse_args([])
        session = session_from_args(args, env={ENV_COOKIE: "session=abc"})
        assert session.headers_dict() == {"Cookie": "session=abc"}

    def test_existing_cookie_arg_can_be_reused_when_group_omits_cookie(self):
        parser = self._parser(include_cookie=False)
        parser.add_argument("--cookie", default=None)
        args = parser.parse_args(["--cookie", "session=abc", "--bearer", "tok"])
        session = session_from_args(args, env={})
        assert session.headers_dict() == {
            "Cookie": "session=abc",
            "Authorization": "Bearer tok",
        }
