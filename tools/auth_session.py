"""Auth-aware request header session helpers for hunt workflows.

Supports three input sources (any combination, deduped):
  1. Environment vars:  BBHUNT_AUTH_HEADER (repeatable via newlines),
                        BBHUNT_COOKIE, BBHUNT_BEARER, BBHUNT_API_KEY
  2. JSON file:         {"headers": ["Cookie: x", "X-Foo: y"]}
                        or {"cookie": "...", "bearer": "...", "api_key": "..."}
  3. CLI args:          --auth-header "Name: value" (repeatable),
                        --cookie "...", --bearer "...", --api-key "..."

The session can:
  • return a Python dict of headers for urllib / SDK callers
  • export a stable, non-secret session_id derived from canonical headers
  • export env vars for downstream subprocesses
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from pathlib import Path

_HEADER_RE = re.compile(r"^([A-Za-z0-9!#$%&'*+\-.^_`|~]+)\s*:\s*(.+)$")

ENV_HEADERS = "BBHUNT_AUTH_HEADERS"
ENV_SESSION_ID = "BBHUNT_SESSION_ID"

ENV_HEADER_IN = "BBHUNT_AUTH_HEADER"
ENV_COOKIE = "BBHUNT_COOKIE"
ENV_BEARER = "BBHUNT_BEARER"
ENV_API_KEY = "BBHUNT_API_KEY"


class AuthSession:
    """A bag of HTTP auth headers with a stable, hashed session_id."""

    def __init__(self, headers: list[str] | None = None):
        self._headers: list[str] = []
        for header in headers or []:
            self.add_header(header)

    def add_header(self, raw: str) -> None:
        """Add a 'Name: value' header. Reject malformed or CRLF-tainted input."""
        if not raw or not isinstance(raw, str):
            return
        if "\r" in raw or "\n" in raw:
            raise ValueError("header contains CR/LF — refusing (injection risk)")
        raw = raw.strip()
        if not raw:
            return

        match = _HEADER_RE.match(raw)
        if not match:
            raise ValueError(f"invalid header (expected 'Name: value'): {raw[:40]!r}")

        name = match.group(1)
        value = match.group(2)
        canonical = f"{name}: {value}"
        lowered_name = name.lower()
        self._headers = [
            header
            for header in self._headers
            if not header.lower().startswith(lowered_name + ":")
        ]
        self._headers.append(canonical)

    def add_cookie(self, cookie: str) -> None:
        if cookie:
            self.add_header(f"Cookie: {cookie}")

    def add_bearer(self, token: str) -> None:
        if token:
            self.add_header(f"Authorization: Bearer {token}")

    def add_api_key(self, key: str, header_name: str = "X-API-Key") -> None:
        if key:
            self.add_header(f"{header_name}: {key}")

    @classmethod
    def from_env(cls, env: dict[str, str] | None = None) -> "AuthSession":
        env = env if env is not None else os.environ
        session = cls()
        raw = env.get(ENV_HEADER_IN, "")
        if raw:
            for line in raw.splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    session.add_header(line)
        if env.get(ENV_COOKIE):
            session.add_cookie(env[ENV_COOKIE])
        if env.get(ENV_BEARER):
            session.add_bearer(env[ENV_BEARER])
        if env.get(ENV_API_KEY):
            session.add_api_key(env[ENV_API_KEY])
        return session

    @classmethod
    def from_file(cls, path: str | Path) -> "AuthSession":
        """Load from a JSON file (preferred) or a .env-style key=value file."""
        file_path = Path(path)
        if not file_path.exists():
            return cls()

        text = file_path.read_text(encoding="utf-8")
        session = cls()
        stripped = text.lstrip()

        if stripped.startswith("{") or stripped.startswith("["):
            data = json.loads(text)
            if isinstance(data, list):
                for header in data:
                    session.add_header(header)
                return session
            if not isinstance(data, dict):
                raise ValueError(f"auth file {file_path}: top level must be object or array")

            for header in data.get("headers", []) or []:
                session.add_header(header)
            if data.get("cookie"):
                session.add_cookie(data["cookie"])
            if data.get("bearer"):
                session.add_bearer(data["bearer"])
            if data.get("api_key"):
                session.add_api_key(data["api_key"], data.get("api_key_header", "X-API-Key"))
            return session

        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            key = key.strip()
            value = value.strip().strip('"').strip("'")
            if key == ENV_COOKIE or key == "COOKIE":
                session.add_cookie(value)
            elif key == ENV_BEARER or key in ("BEARER", "TOKEN"):
                session.add_bearer(value)
            elif key == ENV_API_KEY or key == "API_KEY":
                session.add_api_key(value)
            elif key == ENV_HEADER_IN or key == "AUTH_HEADER":
                for header in value.splitlines():
                    session.add_header(header)

        return session

    @classmethod
    def from_sources(
        cls,
        env: dict[str, str] | None = None,
        file: str | Path | None = None,
        headers: list[str] | None = None,
        cookie: str | None = None,
        bearer: str | None = None,
        api_key: str | None = None,
    ) -> "AuthSession":
        """Merge env + file + explicit args. Explicit wins on name collisions."""
        session = cls.from_env(env)
        if file:
            for header in cls.from_file(file).headers_list():
                session.add_header(header)
        for header in headers or []:
            session.add_header(header)
        if cookie:
            session.add_cookie(cookie)
        if bearer:
            session.add_bearer(bearer)
        if api_key:
            session.add_api_key(api_key)
        return session

    def is_empty(self) -> bool:
        return not self._headers

    def headers_list(self) -> list[str]:
        return list(self._headers)

    def headers_dict(self) -> dict[str, str]:
        headers: dict[str, str] = {}
        for header in self._headers:
            name, _, value = header.partition(":")
            headers[name.strip()] = value.strip()
        return headers

    def curl_args(self) -> list[str]:
        """Return args as `-H value` pairs for subprocess callers."""
        args: list[str] = []
        for header in self._headers:
            args.extend(["-H", header])
        return args

    def session_id(self) -> str:
        """Stable 12-char hex hash of canonical headers. Empty session → ''."""
        if not self._headers:
            return ""
        canonical = "\n".join(sorted(self._headers)) + "\n"
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:12]

    def env_overlay(self) -> dict[str, str]:
        """Return env vars to pass to subprocesses."""
        if self.is_empty():
            return {}
        return {
            ENV_HEADERS: "\n".join(self._headers),
            ENV_SESSION_ID: self.session_id(),
        }

    def export_to_env(self, env: dict[str, str] | None = None) -> None:
        """Mutate an env mapping in place, clearing stale auth vars when empty."""
        target_env = env if env is not None else os.environ
        overlay = self.env_overlay()
        if overlay:
            target_env.update(overlay)
        else:
            target_env.pop(ENV_HEADERS, None)
            target_env.pop(ENV_SESSION_ID, None)

    def redacted(self) -> dict[str, str]:
        """Human-safe view: show header names with masked values."""
        redacted: dict[str, str] = {}
        for header in self._headers:
            name, _, value = header.partition(":")
            value = value.strip()
            if len(value) <= 6:
                masked = "***"
            else:
                masked = value[:3] + "***" + value[-2:]
            redacted[name.strip()] = masked
        return redacted

    def describe(self) -> str:
        """One-line description safe for logs."""
        if self.is_empty():
            return "auth: none (anonymous)"
        names = sorted({header.partition(":")[0].strip() for header in self._headers})
        return f"auth: session={self.session_id()} headers=[{', '.join(names)}]"

    def __repr__(self) -> str:
        return f"AuthSession(session_id={self.session_id()!r}, n_headers={len(self._headers)})"

    def __str__(self) -> str:
        return self.describe()


def add_cli_args(parser, *, include_cookie: bool = True) -> None:
    """Attach auth flags to an argparse parser."""
    group = parser.add_argument_group("auth (optional — enables auth-aware hunting)")
    group.add_argument(
        "--auth-header",
        action="append",
        default=[],
        metavar="'Name: value'",
        help="Add an HTTP header to outbound requests (repeatable).",
    )
    if include_cookie:
        group.add_argument(
            "--cookie",
            default=None,
            help="Shorthand for --auth-header 'Cookie: ...'.",
        )
    group.add_argument(
        "--bearer",
        default=None,
        help="Shorthand for --auth-header 'Authorization: Bearer ...'.",
    )
    group.add_argument(
        "--api-key",
        dest="api_key",
        default=None,
        help="Shorthand for --auth-header 'X-API-Key: ...'.",
    )
    group.add_argument(
        "--auth-file",
        default=None,
        metavar="PATH",
        help="Load headers from a JSON or .env file.",
    )
    group.add_argument(
        "--auth-from-env",
        action="store_true",
        help=(
            f"Pick up auth from env vars ({ENV_HEADER_IN}, {ENV_COOKIE}, "
            f"{ENV_BEARER}, {ENV_API_KEY}). Implied if any are already set."
        ),
    )


def session_from_args(args, env: dict[str, str] | None = None) -> AuthSession:
    """Build an AuthSession from an argparse namespace."""
    env = env if env is not None else os.environ
    env_arg = env if (
        getattr(args, "auth_from_env", False)
        or any(env.get(key) for key in (ENV_HEADER_IN, ENV_COOKIE, ENV_BEARER, ENV_API_KEY))
    ) else {}
    return AuthSession.from_sources(
        env=env_arg,
        file=getattr(args, "auth_file", None),
        headers=getattr(args, "auth_header", []) or [],
        cookie=getattr(args, "cookie", None),
        bearer=getattr(args, "bearer", None),
        api_key=getattr(args, "api_key", None),
    )
