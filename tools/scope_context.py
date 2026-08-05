"""One deterministic scope owner for discovery context and active requests.

``ScopeContext`` composes the existing target canonicalisation and URL matcher.
It does not own findings, queues, or execution state; callers still decide how
to persist those records.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urlsplit

try:
    from tools.target_paths import (
        classify_target,
        url_belongs_to_target,
    )
except ImportError:  # pragma: no cover - direct ``python3 tools/*.py`` use
    from target_paths import classify_target, url_belongs_to_target


SCHEMA_VERSION = 1
_HTTP_SCHEMES = {"http", "https"}
_HIGH_CONFIDENCE_PROVENANCE = {
    "controlling",
    "certificate",
    "registrant",
    "ownership",
    "subsidiary",
    "scope-review",
    "high-confidence",
    "target-linked",
}


class ScopeContextError(ValueError):
    """Raised when a scope source is missing or violates its contract."""


def _dedupe(values: Iterable[str], *, field: str) -> tuple[str, ...]:
    result: list[str] = []
    seen: set[str] = set()
    for raw in values:
        if not isinstance(raw, str):
            raise ScopeContextError(f"{field} entries must be strings")
        value = raw.strip().strip("\ufeff")
        if not value:
            continue
        if any(character in value for character in "\r\n\x00"):
            raise ScopeContextError(f"{field} contains control characters")
        value = value.rstrip("/") if value not in {"/", "//"} else value
        value = value.lower()
        if value not in seen:
            seen.add(value)
            result.append(value)
    return tuple(result)


def _validate_pattern(value: str, *, field: str) -> str:
    """Validate a host/IP/CIDR pattern without changing scheme/port intent."""
    if not value:
        raise ScopeContextError(f"{field} contains an empty pattern")
    if any(character.isspace() for character in value):
        raise ScopeContextError(f"{field} contains whitespace: {value!r}")
    if value.startswith("/") and not value.startswith("//"):
        raise ScopeContextError(f"{field} must contain a host pattern: {value!r}")

    if "://" in value or value.startswith("//"):
        try:
            parsed = urlsplit(value if "://" in value else f"https:{value}")
            host = parsed.hostname
            if parsed.scheme.lower() not in _HTTP_SCHEMES or not host:
                raise ValueError
            parsed.port  # force invalid-port validation
        except (ValueError, UnicodeError) as exc:
            raise ScopeContextError(f"invalid {field} pattern: {value!r}") from exc
    else:
        candidate = value[2:] if value.startswith("*.") else value
        try:
            classify_target(candidate)
        except ValueError as exc:
            raise ScopeContextError(f"invalid {field} pattern: {value!r}") from exc
        if not re.fullmatch(r"\*?[A-Za-z0-9._:/-]+", value):
            raise ScopeContextError(f"invalid {field} pattern: {value!r}")
    return value


def _normalise_candidate(value: str) -> tuple[str, str | None]:
    """Return an HTTP(S) URL and a parser reason.

    ``None`` means the value is a valid network asset. ``unknown`` is reserved
    for inert discovery values such as relative paths or ASNs; malformed HTTP
    URLs return ``invalid`` so active callers can fail closed.
    """
    raw = (value or "").strip()
    if not raw:
        return "", "unknown"
    if raw.startswith("/") and not raw.startswith("//"):
        return raw, "unknown"
    if any(character in raw for character in "\r\n\x00"):
        return raw, "invalid"

    has_scheme = "://" in raw or raw.startswith("//")
    candidate = raw if has_scheme else f"https://{raw}"
    try:
        parsed = urlsplit(candidate if not raw.startswith("//") else f"https:{raw}")
        scheme = parsed.scheme.lower()
        host = parsed.hostname
        parsed.port
    except (ValueError, UnicodeError):
        return raw, "invalid"
    if has_scheme and scheme not in _HTTP_SCHEMES:
        return raw, "invalid"
    if not host:
        return raw, "invalid"
    if any(character.isspace() for character in raw):
        return raw, "unknown" if not has_scheme else "invalid"
    # A bare value containing a clearly non-host token remains inert context.
    if not has_scheme and re.fullmatch(r"AS\d+", raw, flags=re.IGNORECASE):
        return raw, "unknown"
    if not has_scheme and not re.fullmatch(r"[A-Za-z0-9._:/\[\]-]+(?:/[^\s]*)?", raw):
        return raw, "unknown"
    return candidate, None


def _pattern_matches(url: str, pattern: str) -> bool:
    """Match an explicit manifest entry with exact-host semantics.

    Wildcards remain subdomain-only. A plain explicit host is exact; the root
    target keeps the historical subdomain-compatible matcher separately.
    """
    return url_belongs_to_target(url, pattern, allow_subdomains=False)


class ScopeContext:
    """Immutable scope definition shared by active and discovery callers."""

    def __init__(
        self,
        root_target: str = "",
        in_scope: Iterable[str] | None = None,
        out_of_scope: Iterable[str] | None = None,
        *,
        source_ref: str = "",
        notes: str = "",
        excluded_classes: Iterable[str] | None = None,
        schema_version: int = SCHEMA_VERSION,
    ) -> None:
        if schema_version != SCHEMA_VERSION:
            raise ScopeContextError(f"unsupported scope schema_version: {schema_version!r}")
        self.schema_version = SCHEMA_VERSION
        self.root_target = str(root_target or "").strip()
        if self.root_target:
            try:
                classify_target(self.root_target)
            except ValueError as exc:
                raise ScopeContextError(f"invalid root target: {self.root_target!r}") from exc
        self.in_scope = tuple(
            _validate_pattern(value, field="in_scope")
            for value in _dedupe(in_scope or (), field="in_scope")
        )
        self.out_of_scope = tuple(
            _validate_pattern(value, field="out_of_scope")
            for value in _dedupe(out_of_scope or (), field="out_of_scope")
        )
        self.excluded_classes = tuple(
            value.lower()
            for value in _dedupe(excluded_classes or (), field="excluded_classes")
        )
        self.source_ref = str(source_ref or "")
        self.notes = str(notes or "")[:500]
        self.fingerprint = self._compute_fingerprint()

    @classmethod
    def from_target(cls, target: str, *, source_ref: str = "") -> "ScopeContext":
        value = str(target or "").strip()
        if not value:
            raise ScopeContextError("target is required")
        if os.path.isfile(value):
            return cls.from_file(value)
        return cls(root_target=value, source_ref=source_ref)

    @classmethod
    def from_file(
        cls,
        path: str | os.PathLike[str],
        *,
        root_target: str | None = None,
    ) -> "ScopeContext":
        resolved = Path(path).expanduser().resolve()
        try:
            text = resolved.read_text(encoding="utf-8")
        except OSError as exc:
            raise ScopeContextError(f"scope file is not readable: {resolved}") from exc
        if not text.strip():
            raise ScopeContextError(f"scope file is empty: {resolved}")

        if text.lstrip().startswith("{"):
            try:
                payload = json.loads(text)
            except json.JSONDecodeError as exc:
                raise ScopeContextError(f"invalid scope manifest JSON: {resolved}: {exc.msg}") from exc
            if not isinstance(payload, dict):
                raise ScopeContextError("scope manifest must be a JSON object")
            version = payload.get("schema_version")
            if version != SCHEMA_VERSION:
                raise ScopeContextError(
                    f"scope manifest schema_version must be {SCHEMA_VERSION}"
                )
            in_scope = payload.get("in_scope", [])
            out_of_scope = payload.get("out_of_scope", [])
            excluded_classes = payload.get("excluded_classes", [])
            for field, values in (
                ("in_scope", in_scope),
                ("out_of_scope", out_of_scope),
                ("excluded_classes", excluded_classes),
            ):
                if not isinstance(values, list):
                    raise ScopeContextError(f"scope manifest {field} must be a list")
            target = payload.get("root_target", payload.get("target", root_target or ""))
            if target is not None and not isinstance(target, str):
                raise ScopeContextError("scope manifest root_target must be a string")
            return cls(
                root_target=target or "",
                in_scope=in_scope,
                out_of_scope=out_of_scope,
                source_ref=str(resolved),
                notes=str(payload.get("notes") or ""),
                excluded_classes=excluded_classes,
                schema_version=version,
            )

        entries = []
        for line in text.splitlines():
            value = line.strip().strip("\ufeff")
            if value and not value.startswith("#"):
                entries.append(value)
        if not entries:
            raise ScopeContextError(f"scope file has no usable entries: {resolved}")
        # Keep the path as root_target so existing list semantics (ports, CIDR,
        # and one-level expansion) remain owned by target_paths.
        return cls(
            root_target=str(resolved),
            in_scope=entries,
            source_ref=str(resolved),
        )

    @classmethod
    def from_manifest(cls, payload: dict[str, Any], *, source_ref: str = "") -> "ScopeContext":
        if not isinstance(payload, dict):
            raise ScopeContextError("scope manifest must be a JSON object")
        version = payload.get("schema_version")
        if version != SCHEMA_VERSION:
            raise ScopeContextError(f"scope manifest schema_version must be {SCHEMA_VERSION}")
        in_scope = payload.get("in_scope", [])
        out_of_scope = payload.get("out_of_scope", [])
        excluded_classes = payload.get("excluded_classes", [])
        for field, values in (
            ("in_scope", in_scope),
            ("out_of_scope", out_of_scope),
            ("excluded_classes", excluded_classes),
        ):
            if not isinstance(values, list):
                raise ScopeContextError(f"scope manifest {field} must be a list")
        target = payload.get("root_target", payload.get("target", ""))
        if target is not None and not isinstance(target, str):
            raise ScopeContextError("scope manifest root_target must be a string")
        return cls(
            root_target=target or "",
            in_scope=in_scope,
            out_of_scope=out_of_scope,
            source_ref=source_ref,
            notes=str(payload.get("notes") or ""),
            excluded_classes=excluded_classes,
            schema_version=version,
        )

    def _compute_fingerprint(self) -> str:
        payload = {
            "schema_version": self.schema_version,
            "root_target": self.root_target.lower(),
            "in_scope": list(self.in_scope),
            "out_of_scope": list(self.out_of_scope),
            "excluded_classes": list(self.excluded_classes),
        }
        encoded = json.dumps(payload, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
        return f"sha256:{hashlib.sha256(encoded.encode('utf-8')).hexdigest()}"

    @property
    def scope_hash(self) -> str:
        return self.fingerprint

    def _matches(self, url: str, patterns: Iterable[str]) -> str:
        for pattern in patterns:
            if _pattern_matches(url, pattern):
                return pattern
        return ""

    def classify(
        self,
        value: str,
        *,
        provenance: str | None = None,
    ) -> dict[str, Any]:
        normalized, parser_status = _normalise_candidate(value)
        if parser_status in {"invalid", "unknown"}:
            return {
                "status": parser_status,
                "value": value,
                "normalized": normalized,
                "matched_pattern": "",
                "reason": "invalid HTTP(S) asset" if parser_status == "invalid" else "non-network discovery value",
                "scope_hash": self.fingerprint,
            }

        excluded = self._matches(normalized, self.out_of_scope)
        if excluded:
            return {
                "status": "excluded",
                "value": value,
                "normalized": normalized,
                "matched_pattern": excluded,
                "reason": "matched explicit out_of_scope pattern",
                "scope_hash": self.fingerprint,
            }

        matched = ""
        if self.root_target:
            try:
                if url_belongs_to_target(normalized, self.root_target):
                    matched = self.root_target
            except (OSError, ValueError):
                matched = ""
        if not matched:
            matched = self._matches(normalized, self.in_scope)
        if matched:
            return {
                "status": "in_scope",
                "value": value,
                "normalized": normalized,
                "matched_pattern": matched,
                "reason": "matched active scope",
                "scope_hash": self.fingerprint,
            }

        provenance_value = str(provenance or "").strip().lower()
        status = (
            "scope-review"
            if provenance_value in _HIGH_CONFIDENCE_PROVENANCE
            else "external-chain-context"
        )
        reason = (
            "unlisted high-confidence relationship requires explicit scope review"
            if status == "scope-review"
            else "unlisted network asset retained as discovery context"
        )
        return {
            "status": status,
            "value": value,
            "normalized": normalized,
            "matched_pattern": "",
            "reason": reason,
            "scope_hash": self.fingerprint,
        }

    def allows_active(
        self,
        value: str,
        method: str | None = None,
        *,
        redirect: bool = False,
    ) -> bool:
        """Return whether a request destination is target-owned and executable."""
        classification = self.classify(value)
        return classification["status"] == "in_scope"

    def allows_vulnerability_class(self, vuln_class: str) -> bool:
        return str(vuln_class or "").strip().lower() not in set(self.excluded_classes)

    def summary(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "root_target": self.root_target,
            "source_ref": self.source_ref,
            "in_scope_count": len(self.in_scope),
            "out_of_scope_count": len(self.out_of_scope),
            "excluded_class_count": len(self.excluded_classes),
            "scope_hash": self.fingerprint,
            "notes": self.notes,
        }


__all__ = ["SCHEMA_VERSION", "ScopeContext", "ScopeContextError"]
