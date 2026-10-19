"""Pure identity and applicability declarations shared by Store and projections."""
from __future__ import annotations

import re
from datetime import datetime, timezone

ENTITY_FIELDS = ("target", "store_id", "owner", "record_id", "version", "content_sha256")
ENTITY_OWNERS = frozenset({"actor", "object", "session", "action", "operation", "artifact", "experience", "assessment"})
CLAIM_PREDICATES = frozenset({"observed_access", "uses", "produces", "requires", "enables"})


def normalize_experience_text(kind, statement, conditions, reopen_when, next_intent):
    """The exact text admission used by both the Experience owner and import."""
    values = []
    for field, value, empty in (
        ("statement", statement, False), ("conditions", conditions, False),
        ("reopen_when", reopen_when, kind != "negative"), ("next_intent", next_intent, True),
    ):
        if not isinstance(value, str) or (not empty and not value.strip()) or "\x00" in value:
            raise ValueError(f"{field} must be {'a' if empty else 'a non-empty'} string without NUL")
        values.append(value.strip())
    return tuple(values)


def entity_binding(value, *, binding=None):
    """Validate a declared identity, not its existence or current health."""
    if not isinstance(value, dict) or any(key not in value for key in ENTITY_FIELDS):
        raise ValueError("exact entity binding required")
    result = {key: value[key] for key in ENTITY_FIELDS}
    if any(not isinstance(result[key], str) or not result[key].strip()
           for key in ENTITY_FIELDS if key != "version"):
        raise ValueError("invalid entity identity")
    if result["owner"] not in ENTITY_OWNERS:
        raise ValueError("unsupported experience entity owner")
    if type(result["version"]) is not int or result["version"] < 0:
        raise ValueError("invalid entity version")
    if not re.fullmatch(r"[0-9a-f]{64}", result["content_sha256"]):
        raise ValueError("invalid entity content hash")
    if binding is not None and any(result[key] != binding[key] for key in ("target", "store_id")):
        raise ValueError("foreign target or Store entity")
    return result


def condition_bindings(value, *, binding=None):
    """A role is a comparison key, never an entity inferred from its label."""
    if value is None:
        return None
    if not isinstance(value, dict) or not 1 <= len(value) <= 32:
        raise ValueError("condition_bindings requires 1..32 exact role bindings, or null for unknown")
    result = {}
    if any(not isinstance(role, str) or not re.fullmatch(r"[a-z][a-z0-9_.:-]{0,63}", role) for role in value):
        raise ValueError("invalid condition role")
    for role, entity in sorted(value.items()):
        result[role] = entity_binding(entity, binding=binding)
    return result


def validity_window(value):
    """An explicit half-open interval; observation timestamps imply no validity."""
    if value is None:
        return None
    if not isinstance(value, dict) or set(value) != {"from", "until"}:
        raise ValueError("validity requires from and until, or null for unknown")
    parsed = {}
    for key, text in value.items():
        if not isinstance(text, str):
            raise ValueError("validity timestamp must be timezone-aware ISO8601")
        try:
            instant = datetime.fromisoformat(text.replace("Z", "+00:00"))
            if instant.tzinfo is None:
                raise ValueError("validity timestamp needs timezone")
            parsed[key] = instant.astimezone(timezone.utc)
        except (ValueError, OverflowError) as exc:
            raise ValueError(f"invalid timezone-aware validity timestamp: {key}") from exc
    if parsed["from"] >= parsed["until"]:
        raise ValueError("validity from must precede until")
    return {key: instant.isoformat() for key, instant in parsed.items()}
