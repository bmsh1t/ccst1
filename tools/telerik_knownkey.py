#!/usr/bin/env python3
"""Offline Telerik DialogParameters known-key check via vendored Badsecrets data."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path

try:
    from tools.vendor.badsecrets_telerik.telerik_hashkey import check_secret
except ImportError:  # pragma: no cover - direct tools/ execution
    from vendor.badsecrets_telerik.telerik_hashkey import check_secret

MAX_BODY_BYTES = 1024 * 1024
MAX_SERIALIZED_PARAMETERS = 8
SERIALIZED_PARAMETERS_RE = re.compile(r'"SerializedParameters"\s*:\s*"([^"\\]+)"')
def _fingerprint(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def match_telerik_response(body: str, *, max_values: int = MAX_SERIALIZED_PARAMETERS) -> dict:
    """Check captured values using Badsecrets' default machine/Telerik key lists."""
    if max_values < 1 or max_values > MAX_SERIALIZED_PARAMETERS:
        raise ValueError(f"max_values must be between 1 and {MAX_SERIALIZED_PARAMETERS}")
    values = SERIALIZED_PARAMETERS_RE.findall(str(body or ""))[:max_values]
    matches = []
    for index, value in enumerate(values):
        key = check_secret(value)
        if key:
            matches.append({
                "serialized_parameters_index": index,
                "key_fingerprint": _fingerprint(key),
            })
    return {
        "mode": "offline-captured-response",
        "matcher": "vendored-badsecrets.telerik_hashkey",
        "key_sources": ["aspnet_machinekeys.txt", "telerik_hash_keys.txt"],
        "network_requests": 0,
        "queue_actions": 0,
        "serialized_parameters_found": len(values),
        "matches": matches,
    }


def _read_body(path: Path) -> str:
    if path.stat().st_size > MAX_BODY_BYTES:
        raise ValueError(f"body file exceeds {MAX_BODY_BYTES} bytes")
    return path.read_text(encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check captured Telerik response text with local Badsecrets keys only.")
    parser.add_argument("--body-file", type=Path, required=True, help="Captured response body; no target URL is accepted.")
    parser.add_argument("--max-values", type=int, default=MAX_SERIALIZED_PARAMETERS, help=f"Captured-value limit (1-{MAX_SERIALIZED_PARAMETERS}).")
    args = parser.parse_args(argv)

    try:
        result = match_telerik_response(_read_body(args.body_file), max_values=args.max_values)
    except (OSError, UnicodeDecodeError, ValueError) as exc:
        parser.error(str(exc))
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
