#!/usr/bin/env python3
"""Versioned endpoint and closure-cell identity contracts.

This module owns only closure identity.  Surface URL indexes, target storage,
and Finding IDs deliberately remain separate identities.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Mapping

try:
    from tools.evidence_identity import canonical_endpoint_identity, canonical_vuln_class, exact_endpoint_identity, normalize_family
except ImportError:  # pragma: no cover - direct ``python tools/...`` execution
    from evidence_identity import canonical_endpoint_identity, canonical_vuln_class, exact_endpoint_identity, normalize_family  # type: ignore


IDENTITY_SCHEMA_VERSION = 3
MIN_CANDIDATE_CONFIDENCE = 0.75

# Historical v2 decoder only. New v3 conditions are authored, never selected
# or declared complete by a family policy.
FAMILY_POLICIES: dict[str, tuple[str, ...]] = {
    "SQLi": ("method", "parameter"),
    "NoSQLi": ("method", "parameter"),
    "IDOR": ("path_template", "method", "actor_relation", "object_scope"),
    "GraphQL": ("operation", "field", "argument"),
    "XSS": ("source", "sink"),
    "PrototypePollution": ("source", "sink"),
    "Authz": ("method", "actor_role", "object_scope"),
    "OAuth": ("flow", "transition", "actor", "redirect_target"),
    "JWT": ("method", "token_location", "claim_algorithm"),
    "CSRF": ("method", "state_change", "actor"),
    "SSRF": ("method", "input_field", "destination_class"),
    "Race": ("method", "operation", "concurrency_profile"),
    "Upload": ("method", "input_field", "content_type"),
    "Webhook": ("method", "event", "authentication_scheme"),
    "XXE": ("method", "input_field", "entity_type"),
    "RCE": ("method", "input_field", "sink"),
    "Path": ("method", "input_field", "path_template"),
    "Workflow": ("workflow", "transition", "actor"),
    "OpenRedirect": ("method", "parameter", "redirect_target"),
    "BusinessLogic": ("workflow", "transition", "actor"),
}

def _canonical_technique(value: Any, family: str = "") -> str:
    """Return only an explicitly supplied stable technique token."""
    text = str(value or "").strip().lower().replace("-", "_").replace(" ", "_")
    return "_".join(part for part in text.split("_") if part)


def family_dimensions(family: str) -> tuple[str, ...]:
    """Inspect historical v2 requirements; never use for v3 admission."""
    canonical = canonical_vuln_class(family) or ("Workflow" if str(family or "").strip().lower() == "workflow" else "")
    return FAMILY_POLICIES.get(canonical, ())


def _canonical_dimensions(
    family: str,
    dimensions: Mapping[str, Any] | None,
) -> tuple[dict[str, str], tuple[str, ...]]:
    required = ("method",)
    if not isinstance(dimensions, Mapping):
        return {}, ("method", "dimensions_must_be_object")
    values: dict[str, str] = {}
    conflicts: list[str] = []
    for raw_field, raw_value in (dimensions or {}).items():
        field = raw_field
        value = raw_value
        if (not isinstance(field, str) or not field.strip() or field != field.strip() or len(field) > 64
                or not isinstance(value, str) or not value.strip() or value != value.strip() or len(value) > 256
                or any(ord(c) < 32 or ord(c) == 127 for c in field + value)):
            conflicts.append(f"invalid_dimension:{raw_field}")
            continue
        previous = values.get(field)
        if previous is not None and previous != value:
            conflicts.append(f"dimension_conflict:{field}")
        else:
            values[field] = value
    missing = tuple(field for field in required if not values.get(field))
    return values, tuple(sorted(set((*missing, *conflicts))))


@dataclass(frozen=True, slots=True)
class EndpointKey:
    """Exact v3 asset identity; v2 remains decodable historical metadata."""

    endpoint: str
    schema_version: int = IDENTITY_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if type(self.schema_version) is not int or self.schema_version not in {2, IDENTITY_SCHEMA_VERSION}:
            raise ValueError(f"unsupported endpoint identity schema: {self.schema_version}")
        normalized = (exact_endpoint_identity(self.endpoint) if self.schema_version == 3
                      else canonical_endpoint_identity(self.endpoint))
        if not normalized:
            raise ValueError("endpoint identity is required")
        object.__setattr__(self, "endpoint", normalized)

    @classmethod
    def from_value(cls, value: str) -> "EndpointKey":
        return cls(str(value or ""))

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "EndpointKey":
        if not isinstance(payload, Mapping):
            raise ValueError("endpoint identity must be an object")
        if payload.get("kind") != "endpoint":
            raise ValueError("endpoint identity kind must be 'endpoint'")
        if type(payload.get("schema_version")) is not int or payload.get("schema_version") not in {2, IDENTITY_SCHEMA_VERSION}:
            raise ValueError("endpoint identity schema must be version 2 or 3")
        if payload["schema_version"] == 3 and set(payload) != {"schema_version", "kind", "endpoint"}:
            raise ValueError("exact endpoint identity contains missing or unknown fields")
        return cls(str(payload.get("endpoint") or payload.get("canonical") or ""), payload["schema_version"])

    @property
    def canonical(self) -> str:
        return self.endpoint

    @property
    def canonical_endpoint(self) -> str:
        return self.endpoint

    @property
    def base_key(self) -> str:
        return self.endpoint

    def to_dict(self) -> dict[str, Any]:
        return {"schema_version": self.schema_version, "kind": "endpoint", "endpoint": self.endpoint}

    as_dict = to_dict


@dataclass(frozen=True, slots=True)
class ClosureCellKey:
    """Complete family-aware closure identity."""

    endpoint_key: EndpointKey
    family: str
    dimensions: Mapping[str, str]
    technique: str = ""
    schema_version: int = IDENTITY_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if type(self.schema_version) is not int or self.schema_version not in {2, IDENTITY_SCHEMA_VERSION}:
            raise ValueError(f"unsupported closure identity schema: {self.schema_version}")
        if self.endpoint_key.schema_version != self.schema_version:
            raise ValueError("closure and endpoint identity versions must match")
        normalize_family(self.family)
        if not isinstance(self.dimensions, Mapping):
            raise ValueError("closure dimensions must be an object")
        if self.schema_version == 2:
            required = FAMILY_POLICIES.get(self.family)
            if required is None or set(self.dimensions) != set(required):
                raise ValueError("invalid historical family dimensions")
        else:
            required = ("method",)
        normalized = dict(self.dimensions)
        if len(normalized) > 16 or any(not isinstance(k, str) or not k.strip() or k != k.strip() or len(k) > 64
               or not isinstance(v, str) or not v.strip() or v != v.strip() or len(v) > 256
               or any(ord(c) < 32 or ord(c) == 127 for c in k + v)
               for k, v in normalized.items()):
            raise ValueError("closure dimensions require non-empty string keys and values")
        missing = [field for field in required if not normalized.get(field)]
        if missing:
            raise ValueError(f"incomplete closure identity: {', '.join(missing)}")
        if self.schema_version == 3 and not re.fullmatch(r"[A-Z][A-Z0-9_-]*", normalized["method"]):
            raise ValueError("closure method must be an explicit uppercase HTTP method")
        if len(json.dumps(normalized, ensure_ascii=True).encode()) > 4096:
            raise ValueError("closure dimensions exceed 4096 bytes")
        technique = _canonical_technique(self.technique)
        if not technique:
            raise ValueError("closure identity technique is required")
        object.__setattr__(self, "dimensions", MappingProxyType(dict(sorted(normalized.items()))))
        object.__setattr__(self, "technique", technique)

    @property
    def endpoint(self) -> str:
        return self.endpoint_key.endpoint

    @property
    def endpoint_identity(self) -> EndpointKey:
        return self.endpoint_key

    @property
    def dimension_map(self) -> dict[str, str]:
        return dict(self.dimensions)

    @property
    def canonical_encoding(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=True, sort_keys=True, separators=(",", ":"))

    @property
    def identity_key(self) -> str:
        return self.canonical_encoding

    def encode(self) -> str:
        """Return the stable JSON encoding carried through evidence/projections."""
        return self.canonical_encoding

    def __hash__(self) -> int:
        return hash(self.canonical_encoding)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "kind": "closure_cell",
            "endpoint": self.endpoint_key.to_dict(),
            "family": self.family,
            "technique": self.technique,
            "dimensions": dict(self.dimensions),
        }

    as_dict = to_dict

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "ClosureCellKey":
        if not isinstance(payload, Mapping):
            raise ValueError("closure identity must be an object")
        if payload.get("kind") != "closure_cell":
            raise ValueError("closure identity kind must be 'closure_cell'")
        if type(payload.get("schema_version")) is not int or payload.get("schema_version") not in {2, IDENTITY_SCHEMA_VERSION}:
            raise ValueError("closure identity schema must be version 2 or 3")
        if payload["schema_version"] == 3 and set(payload) != {"schema_version", "kind", "endpoint", "family", "technique", "dimensions"}:
            raise ValueError("closure identity contains missing or unknown fields (including technique)")
        endpoint = payload.get("endpoint")
        if not isinstance(endpoint, Mapping):
            raise ValueError("closure identity endpoint must be an EndpointKey")
        return cls(
            EndpointKey.from_dict(endpoint),
            str(payload.get("family") or ""),
            payload.get("dimensions") if isinstance(payload.get("dimensions"), Mapping) else {},
            str(payload.get("technique") or ""),
            payload["schema_version"],
        )


@dataclass(frozen=True, slots=True)
class IdentityBuildResult:
    family: str
    key: ClosureCellKey | None
    missing_fields: tuple[str, ...] = ()
    conflicts: tuple[str, ...] = ()

    @property
    def complete(self) -> bool:
        return self.key is not None and not self.missing_fields and not self.conflicts

    @property
    def closeable(self) -> bool:
        return self.complete

    @property
    def incomplete(self) -> bool:
        return not self.complete

    @property
    def missing(self) -> tuple[str, ...]:
        return self.missing_fields

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": IDENTITY_SCHEMA_VERSION,
            "family": self.family,
            "identity_v2": self.key.to_dict() if self.key else None,
            "missing_fields": list(self.missing_fields),
            "conflicts": list(self.conflicts),
            "complete": self.complete,
        }


def build_closure_cell(
    endpoint: str | EndpointKey,
    family: str,
    dimensions: Mapping[str, Any] | None = None,
    *,
    technique: str = "",
) -> IdentityBuildResult:
    """Validate declared equality conditions, not semantic sufficiency."""
    try:
        canonical_family = normalize_family(family)
    except ValueError:
        return IdentityBuildResult(str(family or ""), None, ("family",), ())
    try:
        endpoint_key = endpoint if isinstance(endpoint, EndpointKey) else EndpointKey.from_value(endpoint)
    except (TypeError, ValueError):
        endpoint_key = None
    values, issues = _canonical_dimensions(canonical_family, dimensions)
    missing = tuple(item for item in issues if item == "method")
    conflicts = tuple(item for item in issues if item not in missing)
    if endpoint_key is None or endpoint_key.schema_version != 3:
        missing = tuple((*missing, "endpoint"))
    technique_value = _canonical_technique(technique)
    if not technique_value:
        missing = tuple((*missing, "technique"))
    if missing or conflicts:
        return IdentityBuildResult(canonical_family, None, tuple(sorted(set(missing))), tuple(sorted(set(conflicts))))
    try:
        key = ClosureCellKey(endpoint_key, canonical_family, values, technique_value)
    except ValueError as exc:
        return IdentityBuildResult(canonical_family, None, (), (str(exc),))
    return IdentityBuildResult(canonical_family, key, (), ())


@dataclass(frozen=True, slots=True)
class IdentityCandidate:
    """Persistable, untrusted AI proposal after deterministic normalization."""

    family: str
    endpoint: str
    dimensions: Mapping[str, str]
    confidence: float
    technique: str = ""
    provenance: tuple[str, ...] = ()
    evidence_refs: tuple[str, ...] = ()
    aliases: Mapping[str, str] = MappingProxyType({})
    missing_fields: tuple[str, ...] = ()
    conflicts: tuple[str, ...] = ()
    follow_up_tests: tuple[Any, ...] = ()
    schema_version: int = IDENTITY_SCHEMA_VERSION

    def __post_init__(self) -> None:
        object.__setattr__(self, "technique", _canonical_technique(self.technique))

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "kind": "ai_identity_candidate",
            "family": self.family,
            "endpoint": self.endpoint,
            "dimensions": dict(self.dimensions),
            "technique": self.technique,
            "confidence": self.confidence,
            "provenance": list(self.provenance),
            "evidence_refs": list(self.evidence_refs),
            "aliases": dict(self.aliases),
            "missing_fields": list(self.missing_fields),
            "conflicts": list(self.conflicts),
            "follow_up_tests": list(self.follow_up_tests),
        }

    as_dict = to_dict


@dataclass(frozen=True, slots=True)
class CandidateValidation:
    candidate: IdentityCandidate
    identity: ClosureCellKey | None
    accepted: bool
    follow_up_required: bool

    @property
    def closeable(self) -> bool:
        return self.accepted and self.identity is not None

    @property
    def follow_up_action(self) -> dict[str, Any] | None:
        if not self.follow_up_required:
            return None
        return {
            "kind": "identity_follow_up",
            "family": self.candidate.family,
            "endpoint": self.candidate.endpoint,
            "missing_fields": list(self.candidate.missing_fields),
            "conflicts": list(self.candidate.conflicts),
            "evidence_refs": list(self.candidate.evidence_refs),
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "candidate": self.candidate.to_dict(),
            "identity_v2": self.identity.to_dict() if self.identity else None,
            "accepted": self.accepted,
            "follow_up_required": self.follow_up_required,
            "follow_up_action": self.follow_up_action,
        }


def _as_strings(value: Any) -> tuple[str, ...]:
    if isinstance(value, str):
        value = [value]
    if not isinstance(value, (list, tuple, set)):
        return ()
    return tuple(sorted({str(item).strip() for item in value if str(item).strip()}))


def _as_follow_ups(value: Any) -> tuple[Any, ...]:
    if value is None:
        return ()
    if isinstance(value, (list, tuple)):
        return tuple(value)
    return (value,)


def normalize_identity_candidate(candidate: Mapping[str, Any]) -> IdentityCandidate:
    """Normalize an AI proposal without treating it as terminal evidence."""
    if not isinstance(candidate, Mapping):
        raise ValueError("identity candidate must be an object")
    raw_family = str(candidate.get("family") or candidate.get("vuln_class") or "").strip()
    family = canonical_vuln_class(raw_family) or raw_family
    raw_endpoint = str(candidate.get("endpoint") or candidate.get("route") or "").strip()
    try:
        endpoint = exact_endpoint_identity(raw_endpoint)
    except ValueError:
        endpoint = ""
    raw_dimensions = candidate.get("dimensions")
    if not isinstance(raw_dimensions, Mapping):
        raw_dimensions = {
            key: value for key, value in candidate.items()
            if key not in {"family", "vuln_class", "endpoint", "route", "technique", "confidence", "provenance", "evidence_refs", "aliases", "missing_fields", "conflicts", "follow_up_tests", "follow_up"}
        }
    canonical_family = canonical_vuln_class(family) or ("Workflow" if str(family or "").strip().lower() == "workflow" else "")
    values, issues = _canonical_dimensions(family, raw_dimensions)
    explicit_missing = _as_strings(candidate.get("missing_fields"))
    explicit_conflicts = _as_strings(candidate.get("conflicts"))
    confidence_raw = candidate.get("confidence", 0.0)
    try:
        confidence = float(confidence_raw)
    except (TypeError, ValueError):
        confidence = 0.0
        explicit_conflicts = tuple((*explicit_conflicts, "confidence_invalid"))
    if not 0.0 <= confidence <= 1.0:
        confidence = max(0.0, min(1.0, confidence))
        explicit_conflicts = tuple((*explicit_conflicts, "confidence_out_of_range"))
    required_or_policy = {"method"}
    missing_items = list(explicit_missing)
    missing_items.extend(item for item in issues if item in required_or_policy)
    if not endpoint:
        missing_items.append("endpoint")
    missing = tuple(sorted(set(missing_items)))
    conflict_items = list(explicit_conflicts)
    conflict_items.extend(item for item in issues if item not in required_or_policy)
    if confidence < MIN_CANDIDATE_CONFIDENCE:
        conflict_items.append("low_confidence")
    if not _as_strings(candidate.get("provenance")):
        conflict_items.append("missing_provenance")
    if not _as_strings(candidate.get("evidence_refs")):
        conflict_items.append("missing_evidence_refs")
    conflicts = tuple(sorted(set(conflict_items)))
    aliases_raw = candidate.get("aliases")
    aliases = {str(k): str(v) for k, v in aliases_raw.items()} if isinstance(aliases_raw, Mapping) else {}
    return IdentityCandidate(
        family=family,
        endpoint=endpoint,
        dimensions=MappingProxyType(dict(sorted(values.items()))),
        confidence=confidence,
        technique=_canonical_technique(candidate.get("technique"), canonical_family),
        provenance=_as_strings(candidate.get("provenance")),
        evidence_refs=_as_strings(candidate.get("evidence_refs")),
        aliases=MappingProxyType(dict(sorted(aliases.items()))),
        missing_fields=missing,
        conflicts=conflicts,
        follow_up_tests=_as_follow_ups(candidate.get("follow_up_tests") or candidate.get("follow_up")),
    )


def validate_identity_candidate(candidate: Mapping[str, Any] | IdentityCandidate) -> CandidateValidation:
    """Apply deterministic completeness/confidence/conflict gates to a proposal."""
    normalized = candidate if isinstance(candidate, IdentityCandidate) else normalize_identity_candidate(candidate)
    result = build_closure_cell(
        normalized.endpoint,
        normalized.family,
        normalized.dimensions,
        technique=normalized.technique,
    )
    missing = tuple(sorted(set((*normalized.missing_fields, *result.missing_fields))))
    conflicts = tuple(sorted(set((*normalized.conflicts, *result.conflicts))))
    if missing or conflicts:
        if missing != normalized.missing_fields or conflicts != normalized.conflicts:
            normalized = IdentityCandidate(
                family=normalized.family, endpoint=normalized.endpoint, dimensions=normalized.dimensions,
                confidence=normalized.confidence, technique=normalized.technique,
                provenance=normalized.provenance, evidence_refs=normalized.evidence_refs,
                aliases=normalized.aliases, missing_fields=missing, conflicts=conflicts,
                follow_up_tests=normalized.follow_up_tests,
            )
        return CandidateValidation(normalized, None, False, True)
    return CandidateValidation(normalized, result.key, True, False)


# Short aliases keep call sites readable while preserving one implementation.
FAMILY_DIMENSIONS = FAMILY_POLICIES
POLICIES = FAMILY_POLICIES
build_identity = build_closure_cell
normalize_candidate = normalize_identity_candidate
validate_candidate = validate_identity_candidate


__all__ = [
    "IDENTITY_SCHEMA_VERSION", "MIN_CANDIDATE_CONFIDENCE", "FAMILY_POLICIES", "FAMILY_DIMENSIONS", "POLICIES",
    "EndpointKey", "ClosureCellKey", "IdentityBuildResult", "IdentityCandidate", "CandidateValidation",
    "family_dimensions", "build_closure_cell", "build_identity", "normalize_identity_candidate",
    "normalize_candidate", "validate_identity_candidate", "validate_candidate",
]
