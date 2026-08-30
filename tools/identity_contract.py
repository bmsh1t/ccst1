#!/usr/bin/env python3
"""Versioned endpoint and closure-cell identity contracts.

This module owns only closure identity.  Surface URL indexes, target storage,
and Finding IDs deliberately remain separate identities.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Mapping

try:
    from tools.closure_resolver import canonical_endpoint_identity, canonical_vuln_class
except ImportError:  # pragma: no cover - direct ``python tools/...`` execution
    from closure_resolver import canonical_endpoint_identity, canonical_vuln_class  # type: ignore


IDENTITY_SCHEMA_VERSION = 2
MIN_CANDIDATE_CONFIDENCE = 0.75

# Endpoint is always part of a ClosureCellKey through EndpointKey.  These are
# the additional family-specific dimensions, kept explicit instead of inferred
# from display text or a universal identity key.
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

# A small, deterministic alias table for candidate field names.  Values remain
# evidence supplied by the caller; aliases never grant completeness by
# themselves.
_FIELD_ALIASES: dict[str, dict[str, str]] = {
    "SQLi": {
        "http_method": "method",
        "body_field": "parameter",
        "input_field": "parameter",
        "parameter_name": "parameter",
        "body_parameter": "parameter",
    },
    "NoSQLi": {
        "http_method": "method",
        "body_field": "parameter",
        "input_field": "parameter",
        "parameter_name": "parameter",
        "body_parameter": "parameter",
    },
    "IDOR": {"route_template": "path_template", "actor": "actor_relation", "object": "object_scope"},
    "GraphQL": {"op": "operation", "arg": "argument"},
    "XSS": {"source_parameter": "source", "parameter": "source", "output_sink": "sink"},
    "PrototypePollution": {"source_parameter": "source", "parameter": "source", "output_sink": "sink"},
    "Authz": {"http_method": "method", "role": "actor_role", "actor": "actor_role", "object": "object_scope"},
    "OAuth": {"redirect_uri": "redirect_target", "role": "actor"},
    "JWT": {"http_method": "method", "token": "token_location", "claim": "claim_algorithm", "algorithm": "claim_algorithm"},
    "CSRF": {"http_method": "method", "action": "state_change", "role": "actor"},
    "SSRF": {"http_method": "method", "parameter": "input_field", "body_field": "input_field", "destination": "destination_class"},
    "Race": {"http_method": "method", "concurrency": "concurrency_profile"},
    "Upload": {"http_method": "method", "parameter": "input_field", "body_field": "input_field", "mime_type": "content_type"},
    "Webhook": {"http_method": "method", "event_type": "event", "auth_scheme": "authentication_scheme", "authentication": "authentication_scheme"},
    "XXE": {"http_method": "method", "parameter": "input_field", "body_field": "input_field", "entity": "entity_type"},
    "RCE": {"http_method": "method", "parameter": "input_field", "body_field": "input_field", "output_sink": "sink"},
    "Path": {"http_method": "method", "parameter": "input_field", "body_field": "input_field", "route_template": "path_template"},
    "Workflow": {"flow": "workflow", "step": "transition", "role": "actor"},
    "OpenRedirect": {"http_method": "method", "input_field": "parameter", "redirect_uri": "redirect_target"},
    "BusinessLogic": {"flow": "workflow", "step": "transition", "role": "actor"},
}


def _canonical_technique(value: Any, family: str) -> str:
    """Return the stable technique token carried by a closure identity."""
    text = str(value or family or "").strip().lower().replace("-", "_").replace(" ", "_")
    return "_".join(part for part in text.split("_") if part)


def family_dimensions(family: str) -> tuple[str, ...]:
    """Return required dimensions for a canonical family, or ``()`` unknown."""
    canonical = canonical_vuln_class(family) or ("Workflow" if str(family or "").strip().lower() == "workflow" else "")
    return FAMILY_POLICIES.get(canonical, ())


def _canonical_scalar(field: str, value: Any) -> str:
    if value is None or isinstance(value, (Mapping, list, tuple, set)):
        return ""
    text = str(value).strip()
    if field == "method":
        return text.upper()
    if field in {"path_template", "route", "source_route"} and text:
        return canonical_endpoint_identity(text)
    return text


def _canonical_dimensions(
    family: str,
    dimensions: Mapping[str, Any] | None,
) -> tuple[dict[str, str], tuple[str, ...]]:
    required = FAMILY_POLICIES.get(family)
    if required is None:
        return {}, ("family_policy",)
    aliases = _FIELD_ALIASES.get(family, {})
    values: dict[str, str] = {}
    conflicts: list[str] = []
    for raw_field, raw_value in (dimensions or {}).items():
        field = str(raw_field).strip().lower().replace("-", "_").replace(" ", "_")
        field = aliases.get(field, field)
        if field not in required:
            conflicts.append(f"unexpected_dimension:{raw_field}")
            continue
        value = _canonical_scalar(field, raw_value)
        if not value:
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
    """The v2 endpoint base identity, independent of Surface/Finding keys."""

    endpoint: str
    schema_version: int = IDENTITY_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.schema_version != IDENTITY_SCHEMA_VERSION:
            raise ValueError(f"unsupported endpoint identity schema: {self.schema_version}")
        normalized = canonical_endpoint_identity(self.endpoint)
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
        if payload.get("schema_version") != IDENTITY_SCHEMA_VERSION:
            raise ValueError("endpoint identity schema must be version 2")
        return cls(str(payload.get("endpoint") or payload.get("canonical") or ""))

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
        if self.schema_version != IDENTITY_SCHEMA_VERSION:
            raise ValueError(f"unsupported closure identity schema: {self.schema_version}")
        if self.family not in FAMILY_POLICIES:
            raise ValueError(f"unsupported closure family: {self.family!r}")
        required = FAMILY_POLICIES[self.family]
        normalized = {field: str(self.dimensions.get(field, "")) for field in required}
        missing = [field for field, value in normalized.items() if not value]
        if missing:
            raise ValueError(f"incomplete closure identity: {', '.join(missing)}")
        if set(self.dimensions) != set(required):
            raise ValueError("closure identity contains unexpected dimensions")
        technique = _canonical_technique(self.technique, self.family)
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
        if payload.get("schema_version") != IDENTITY_SCHEMA_VERSION:
            raise ValueError("closure identity schema must be version 2")
        endpoint = payload.get("endpoint")
        if not isinstance(endpoint, Mapping):
            raise ValueError("closure identity endpoint must be an EndpointKey")
        return cls(
            EndpointKey.from_dict(endpoint),
            str(payload.get("family") or ""),
            payload.get("dimensions") if isinstance(payload.get("dimensions"), Mapping) else {},
            str(payload.get("technique") or payload.get("family") or ""),
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
    """Normalize one planned test cell; incomplete cells are fail-open."""
    canonical_family = canonical_vuln_class(family) or ("Workflow" if str(family or "").strip().lower() == "workflow" else "")
    if not canonical_family or canonical_family not in FAMILY_POLICIES:
        return IdentityBuildResult(str(family or "").strip(), None, ("family_policy",), ())
    try:
        endpoint_key = endpoint if isinstance(endpoint, EndpointKey) else EndpointKey.from_value(endpoint)
    except (TypeError, ValueError):
        endpoint_key = None
    values, issues = _canonical_dimensions(canonical_family, dimensions)
    missing = tuple(item for item in issues if item in FAMILY_POLICIES[canonical_family] or item == "family_policy")
    conflicts = tuple(item for item in issues if item not in missing)
    if endpoint_key is None:
        missing = tuple((*missing, "endpoint"))
    if missing or conflicts:
        return IdentityBuildResult(canonical_family, None, tuple(sorted(set(missing))), tuple(sorted(set(conflicts))))
    return IdentityBuildResult(
        canonical_family,
        ClosureCellKey(endpoint_key, canonical_family, values, technique),
        (),
        (),
    )


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
        object.__setattr__(self, "technique", _canonical_technique(self.technique, self.family))

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
    endpoint = canonical_endpoint_identity(raw_endpoint) if raw_endpoint else ""
    raw_dimensions = candidate.get("dimensions")
    if not isinstance(raw_dimensions, Mapping):
        raw_dimensions = {
            key: value for key, value in candidate.items()
            if key not in {"family", "vuln_class", "endpoint", "route", "technique", "confidence", "provenance", "evidence_refs", "aliases", "missing_fields", "conflicts", "follow_up_tests", "follow_up"}
        }
    canonical_family = canonical_vuln_class(family) or ("Workflow" if str(family or "").strip().lower() == "workflow" else "")
    values, issues = _canonical_dimensions(canonical_family, raw_dimensions) if canonical_family else ({}, ("family_policy",))
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
    required_or_policy = set(FAMILY_POLICIES.get(canonical_family, ())) | {"family_policy"}
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
