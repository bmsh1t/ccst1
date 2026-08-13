"""Minimal offline Telerik hash-key check derived from Badsecrets 1.2.1."""

from __future__ import annotations

import base64
import binascii
import hmac
import re
from functools import lru_cache
from pathlib import Path
from urllib.parse import unquote


RESOURCE_DIR = Path(__file__).parent
IDENTIFY_RE = re.compile(r"^(?!eyJ)(?:[A-Za-z0-9+/=%]{32,})$")


@lru_cache(maxsize=1)
def _keys() -> tuple[str, ...]:
    keys = []
    for line in (RESOURCE_DIR / "aspnet_machinekeys.txt").read_text(encoding="utf-8").splitlines():
        parts = line.split(",", 1)
        if len(parts) == 2 and parts[0]:
            keys.append(parts[0])
    keys.extend(
        line.strip()
        for line in (RESOURCE_DIR / "telerik_hash_keys.txt").read_text(encoding="utf-8").splitlines()
        if line.strip()
    )
    return tuple(keys)


def check_secret(serialized_parameters: str) -> str | None:
    """Return the matching key from the vendored Badsecrets lists, if any."""
    value = unquote(str(serialized_parameters or ""))
    if not IDENTIFY_RE.fullmatch(value) or len(value) <= 44:
        return None
    encoded, signature = value[:-44].encode(), value[-44:].encode()
    try:
        if len(base64.b64decode(signature, validate=True)) != 32:
            return None
    except binascii.Error:
        return None
    for key in _keys():
        expected = base64.b64encode(hmac.new(key.encode(), encoded, "sha256").digest())
        if hmac.compare_digest(expected, signature):
            return key
    return None
