"""Pure contracts for byte-reviewed method relationships, never target facts."""
from __future__ import annotations

import re
import unicodedata

METHOD_PREDICATES = frozenset({"requires", "enables", "alternative_to", "refutes"})
PATTERN_OWNER = "knowledge-pattern"


def heading_anchors(body: str) -> set[str]:
    """Markdown heading slugs, including duplicate suffixes and the whole document."""
    anchors, fence, previous = {""}, None, ""
    for line in body.splitlines():
        marker = re.match(r"^ {0,3}(`{3,}|~{3,})", line)
        if marker:
            token = marker[1]
            if fence is None:
                fence = token
            elif token[0] == fence[0] and len(token) >= len(fence) and not line[marker.end():].strip():
                fence = None
            previous = ""
            continue
        if fence or line.startswith(("    ", "\t")):
            previous = ""
            continue
        heading = re.match(r"^ {0,3}#{1,6}\s+(.+?)(?:\s+#+\s*)?$", line)
        title = heading[1] if heading else previous if previous and re.fullmatch(r" {0,3}(?:=+|-+)\s*", line) else None
        if title is not None:
            title = re.sub(r"!?\[([^\]]*)\]\([^)]*\)", r"\1", title)
            title = re.sub(r"<[^>]*>", "", title).lower()
            slug = "".join(c for c in title if c in "-_ " or unicodedata.category(c)[0] in "LN")
            slug = slug.replace(" ", "-")
            value, index = slug, 0
            while value in anchors:
                index += 1
                value = f"{slug}-{index}"
            anchors.add(value)
        previous = "" if heading or title is not None else line.strip()
    return anchors


def pattern_binding(value: dict) -> dict:
    """Knowledge patterns occupy an identity domain separate from Store entities."""
    required = {"owner", "method_id", "content_sha256", "anchor"}
    if not isinstance(value, dict) or set(value) != required or value.get("owner") != PATTERN_OWNER:
        raise ValueError("pattern endpoint requires owner, method_id, content_sha256 and anchor")
    if not isinstance(value["method_id"], str) or not value["method_id"].strip():
        raise ValueError("pattern method_id must be nonempty")
    if not isinstance(value["content_sha256"], str) or not re.fullmatch(r"[0-9a-f]{64}", value["content_sha256"]):
        raise ValueError("pattern content_sha256 must be an exact published SHA256")
    if not isinstance(value["anchor"], str):
        raise ValueError("pattern anchor must be a string; empty means the whole method")
    return dict(value)


def method_descriptor(entry: dict, metadata: dict, body: str, content_sha256: str, review: dict) -> dict:
    """Describe an endpoint using the existing publication reader's decision."""
    reason = None
    if entry.get("status", "active") != "active" or metadata.get("status", "active") != "active":
        reason = "method is not active"
    elif metadata.get("id") != entry.get("id"):
        reason = "method identity differs from registry"
    elif metadata.get("maturity") not in ("tested", "proven") or entry.get("maturity", metadata.get("maturity")) not in ("tested", "proven"):
        reason = "method is not reviewed tested/proven knowledge"
    elif review.get("status") != "ready" or review.get("published_sha256") != content_sha256:
        reason = review.get("reason") or "method publication review does not bind current bytes"
    return {"status": "unavailable" if reason else "ready", "reason": reason,
            "content_sha256": content_sha256, "anchors": heading_anchors(body)}


def parse_method_relations(metadata: dict, *, method_id: str, methods: dict) -> list[dict]:
    """Resolve only explicit frontmatter declarations against a closed owner catalog.

    Catalog descriptors contain current review/byte/anchor decisions. No I/O or
    natural-language extraction occurs here. A malformed declaration rejects the
    method's relation list, without approving or invalidating its textual content.
    """
    if "method_relations" not in metadata:
        return []
    declarations = metadata["method_relations"]
    if not isinstance(declarations, list):
        raise ValueError("method_relations must be a list")
    result, seen = [], set()
    for index, declaration in enumerate(declarations):
        location = f"method_relations[{index}]"
        required = {"id", "subject", "predicate", "object", "conditions", "rationale"}
        if not isinstance(declaration, dict) or set(declaration) != required:
            raise ValueError(f"{location} requires exactly {', '.join(sorted(required))}")
        for field in ("id", "conditions", "rationale"):
            if not isinstance(declaration[field], str) or not declaration[field].strip():
                raise ValueError(f"{location}.{field} must be nonempty; use unknown for unknown conditions")
        if declaration["id"] in seen:
            raise ValueError(f"{location}: duplicate relation id {declaration['id']}")
        seen.add(declaration["id"])
        if not isinstance(declaration["predicate"], str) or declaration["predicate"] not in METHOD_PREDICATES:
            raise ValueError(f"{location}: unsupported method predicate")
        endpoints = {}
        for side in ("subject", "object"):
            ref = declaration[side]
            if not isinstance(ref, dict):
                raise ValueError(f"{location}.{side} must be an anchor reference")
            local = set(ref) == {"anchor"}
            if not local and (side == "subject" or set(ref) != {"method_id", "content_sha256", "anchor"}):
                raise ValueError(f"{location}.{side}: invalid endpoint fields")
            identity = method_id if local else ref["method_id"]
            if not isinstance(identity, str) or not identity.strip():
                raise ValueError(f"{location}.{side}: invalid method_id")
            if not local and identity == method_id:
                raise ValueError(f"{location}.{side}: self reference must use implicit published hash")
            descriptor = methods.get(identity)
            if not descriptor or descriptor.get("status") != "ready":
                reason = descriptor.get("reason") if descriptor else "method is not registered"
                raise ValueError(f"{location}.{side}: {identity}: {reason}")
            content_hash = descriptor["content_sha256"]
            if not local and ref["content_sha256"] != content_hash:
                raise ValueError(f"{location}.{side}: {identity}: published hash mismatch")
            anchor = ref["anchor"]
            if not isinstance(anchor, str) or anchor not in descriptor["anchors"]:
                raise ValueError(f"{location}.{side}: {identity}: unknown heading anchor {anchor!r}")
            endpoints[side] = pattern_binding({"owner": PATTERN_OWNER, "method_id": identity,
                                               "content_sha256": content_hash, "anchor": anchor})
        result.append({**declaration, **endpoints})
    return result
