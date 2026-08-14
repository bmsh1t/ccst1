#!/usr/bin/env python3
"""Offline ASP.NET ViewState machineKey check via Badsecrets."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from functools import lru_cache
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit


MAX_BODY_BYTES = 1024 * 1024
MAX_COOKIES_BYTES = 64 * 1024
MAX_COOKIES = 64
MACHINE_KEYS = Path(__file__).parent / "vendor" / "badsecrets_telerik" / "aspnet_machinekeys.txt"
VALIDATION_RE = re.compile(r"validationKey:\s*([0-9A-Fa-f]+)\s+validationAlgo:\s*(\w+)")
ENCRYPTION_RE = re.compile(r"encryptionKey:\s*([0-9A-Fa-f]+)\s+encryptionAlgo:\s*(\w+)")
MODE_RE = re.compile(r"Mode \[([^]]+)]")


def _fingerprint(value: str) -> str:
    return hashlib.sha256(value.upper().encode("ascii")).hexdigest()


@lru_cache(maxsize=1)
def _machine_key_records() -> tuple[tuple[int, str, str], ...]:
    records = []
    for line_number, line in enumerate(MACHINE_KEYS.read_text(encoding="utf-8").splitlines(), start=1):
        values = line.split(",")
        if len(values) == 2:
            records.append((line_number, values[0].upper(), values[1].upper()))
    return tuple(records)


def _checker():
    try:
        from badsecrets.modules.passive.aspnet_viewstate import ASPNET_Viewstate
    except ImportError as exc:  # pragma: no cover - requirements.txt guarantees it
        raise RuntimeError("missing dependency: install badsecrets==1.2.1") from exc
    return ASPNET_Viewstate(custom_resource=MACHINE_KEYS)


def _page_url(value: str) -> str:
    parsed = urlsplit(str(value or "").strip())
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("page_url must be an absolute http(s) URL")
    if parsed.username or parsed.password:
        raise ValueError("page_url must not contain credentials")
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", "", ""))


def _source_line(validation_key: str) -> int | None:
    expected = validation_key.upper()
    return next(
        (line_number for line_number, validation, _ in _machine_key_records() if validation == expected),
        None,
    )


def _match_result(result: dict, index: int, *, reveal_keys: bool) -> dict:
    details = str(result.get("details") or "")
    if details == "MAC_DISABLED":
        return {"viewstate_index": index, "kind": "mac-disabled"}

    secret = str(result.get("secret") or "")
    validation = VALIDATION_RE.search(secret)
    if not validation:
        raise RuntimeError("Badsecrets returned an unsupported ASP.NET ViewState result")
    validation_key = validation.group(1).upper()
    match = {
        "viewstate_index": index,
        "kind": "known-machine-key",
        "machine_key_line": _source_line(validation_key),
        "validation_key_fingerprint": _fingerprint(validation_key),
        "validation_algorithm": validation.group(2),
    }
    if reveal_keys:
        match["validation_key"] = validation_key

    encryption = ENCRYPTION_RE.search(secret)
    if encryption:
        decryption_key = encryption.group(1).upper()
        match.update({
            "decryption_key_fingerprint": _fingerprint(decryption_key),
            "decryption_algorithm": encryption.group(2),
        })
        if reveal_keys:
            match["decryption_key"] = decryption_key
    mode = MODE_RE.search(details)
    if mode:
        match["framework_mode"] = mode.group(1)
    return match


def match_aspnet_viewstate_response(
    body: str,
    *,
    page_url: str,
    cookies: dict[str, str] | None = None,
    reveal_keys: bool = False,
) -> dict:
    """Check captured ViewState values without network or state mutation."""
    text = str(body or "")
    if len(text.encode("utf-8")) > MAX_BODY_BYTES:
        raise ValueError(f"body exceeds {MAX_BODY_BYTES} bytes")
    cookie_values = dict(cookies or {})
    if len(cookie_values) > MAX_COOKIES or any(
        not isinstance(name, str) or not isinstance(value, str)
        for name, value in cookie_values.items()
    ):
        raise ValueError(f"cookies must contain at most {MAX_COOKIES} string pairs")

    results = _checker().carve(
        body=text,
        cookies=cookie_values or None,
        url=_page_url(page_url),
    )
    matches = [
        _match_result(result, index, reveal_keys=reveal_keys)
        for index, result in enumerate(results or [])
        if result.get("type") == "SecretFound"
    ]
    return {
        "mode": "offline-captured-response",
        "matcher": "badsecrets.ASPNET_Viewstate",
        "key_source": "tools/vendor/badsecrets_telerik/aspnet_machinekeys.txt",
        "machine_key_records": len(MACHINE_KEYS.read_text(encoding="utf-8").splitlines()),
        "validation_keys": sum(bool(validation) for _, validation, _ in _machine_key_records()),
        "complete_key_pairs": sum(bool(validation and decryption) for _, validation, decryption in _machine_key_records()),
        "keys_revealed": reveal_keys,
        "network_requests": 0,
        "queue_actions": 0,
        "viewstates_recognized": len(results or []),
        "matches": matches,
    }


def _read_text(path: Path, max_bytes: int, label: str) -> str:
    if path.stat().st_size > max_bytes:
        raise ValueError(f"{label} exceeds {max_bytes} bytes")
    return path.read_text(encoding="utf-8")


def _read_cookies(path: Path | None) -> dict[str, str]:
    if path is None:
        return {}
    value = json.loads(_read_text(path, MAX_COOKIES_BYTES, "cookies file"))
    if not isinstance(value, dict):
        raise ValueError("cookies file must contain a JSON object")
    return value


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check a captured ASP.NET ViewState with the project Badsecrets machineKey list; no network request is made.")
    parser.add_argument("--body-file", type=Path, required=True, help="Captured response body.")
    parser.add_argument("--page-url", required=True, help="Captured page URL used only for ViewState key derivation; query is discarded.")
    parser.add_argument("--cookies-file", type=Path, help="Optional private JSON cookie object for ViewStateUserKey binding.")
    parser.add_argument("--reveal-key", action="store_true", help="Explicitly include matched key material for controlled validation.")
    args = parser.parse_args(argv)

    try:
        result = match_aspnet_viewstate_response(
            _read_text(args.body_file, MAX_BODY_BYTES, "body file"),
            page_url=args.page_url,
            cookies=_read_cookies(args.cookies_file),
            reveal_keys=args.reveal_key,
        )
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, RuntimeError, ValueError) as exc:
        parser.error(str(exc))
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
