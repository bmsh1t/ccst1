"""Shared helpers for canonical target typing and on-disk storage keys."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
from pathlib import Path
from urllib.parse import urlparse, urlsplit


_HOST_LABEL = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?")
URL_DISPLAY_LIMIT = 240


def compact_url(value: str, *, limit: int = URL_DISPLAY_LIMIT) -> str:
    """Bound an AI-facing URL preview without changing replay identity."""
    raw = str(value or "").strip()
    if not raw:
        return ""
    limit = max(64, int(limit))
    if len(raw) <= limit:
        return raw

    digest = hashlib.sha256(raw.encode("utf-8", errors="replace")).hexdigest()[:12]
    marker = f"[url_len={len(raw)} sha256={digest}]"
    try:
        parsed = urlsplit(raw)
        # Userinfo is never useful for routing and may contain credentials.
        authority = parsed.netloc.rsplit("@", 1)[-1]
        prefix = f"{parsed.scheme}://{authority}" if parsed.scheme or authority else ""
        path = parsed.path or "/"
        if len(path) > 120:
            path = path[:80] + "...[path]..." + path[-24:]
        query_parts = []
        if parsed.query:
            raw_parts = parsed.query.split("&")
            for part in raw_parts[:8]:
                key, separator, _value = part.partition("=")
                key = key[:48] or "(empty)"
                query_parts.append(key + ("=..." if separator else ""))
            remaining = len(raw_parts) - len(query_parts)
            if remaining > 0:
                query_parts.append(f"...(+{remaining} params)")
        preview = prefix + path
        if query_parts:
            preview += "?" + "&".join(query_parts)
    except (TypeError, ValueError, UnicodeError):
        preview = raw

    available = limit - len(marker) - 1
    if available <= 4:
        return marker[:limit]
    if len(preview) > available:
        preview = preview[: available - 3] + "..."
    return f"{preview} {marker}"


def _parse_port(value: str) -> int:
    if not value.isdigit() or not 1 <= int(value) <= 65535:
        raise ValueError("invalid target port")
    return int(value)


def _classify_host(host: str, port: int | None = None) -> dict:
    wildcard = host.startswith("*.")
    bare_host = host[2:] if wildcard else host
    if not bare_host or not bare_host.isascii() or "%" in bare_host:
        raise ValueError("invalid target host")

    try:
        address = ipaddress.ip_address(bare_host)
    except ValueError:
        address = None
    if address is not None:
        if wildcard:
            raise ValueError("wildcard IP targets are invalid")
        normalized = str(address)
        if port is not None:
            normalized = f"[{normalized}]:{port}" if address.version == 6 else f"{normalized}:{port}"
        return {"kind": "ip", "target": normalized}

    if re.fullmatch(r"[0-9.:]+", bare_host):
        raise ValueError("invalid IP/CIDR target")
    normalized_host = (bare_host[:-1] if bare_host.endswith(".") else bare_host).lower()
    if (
        not normalized_host
        or len(normalized_host) > 253
        or any(not _HOST_LABEL.fullmatch(label) for label in normalized_host.split("."))
    ):
        raise ValueError("invalid domain target")
    normalized = f"*.{normalized_host}" if wildcard else normalized_host
    if port is not None:
        normalized = f"{normalized}:{port}"
    return {"kind": "domain", "target": normalized}


def _classify_url(value: str) -> dict:
    try:
        parsed = urlparse(value)
        scheme = parsed.scheme.lower()
        host = parsed.hostname
        port = parsed.port
    except (ValueError, UnicodeError) as exc:
        raise ValueError("invalid target URL") from exc
    if (
        (scheme and scheme not in {"http", "https"})
        or not parsed.netloc
        or not host
        or parsed.netloc.endswith(":")
    ):
        raise ValueError("target URL must use HTTP(S) and include a host")
    if parsed.username is not None or parsed.password is not None or "@" in parsed.netloc:
        raise ValueError("target URL must not contain userinfo")
    if port is not None and not 1 <= port <= 65535:
        raise ValueError("invalid target port")
    if "[" in parsed.netloc or "]" in parsed.netloc:
        if not re.fullmatch(r"\[[^\[\]]+\](?::\d+)?", parsed.netloc):
            raise ValueError("invalid bracketed target host")
        try:
            ipaddress.IPv6Address(host)
        except ValueError as exc:
            raise ValueError("bracketed target hosts must be IPv6") from exc
    elif ":" in host:
        raise ValueError("IPv6 URL hosts must be bracketed")
    return _classify_host(host, port)


def canonical_target_value(target: str) -> str:
    """Return the normalized runtime target string used for state lookups."""
    value = (target or "").strip()
    if not value:
        return value

    try:
        return classify_target(value)["target"]
    except ValueError:
        return value


def classify_target(target: str) -> dict:
    """Classify a target as domain, IP, CIDR, or readable host list."""
    raw_value = target or ""
    value = raw_value.strip()
    if not value:
        raise ValueError("target is required")

    if any(ord(character) < 32 or ord(character) == 127 for character in raw_value):
        raise ValueError("target must not contain control characters")

    if os.path.isfile(value):
        return {"kind": "list", "target": os.path.abspath(value)}

    if any(character.isspace() for character in raw_value):
        raise ValueError("target must not contain whitespace")

    # URL-form targets should share the same state/recon key as the equivalent
    # host or host:port. This keeps `/autopilot http://127.0.0.1:3002` from
    # creating a separate `http:_127...` tree that later tools cannot resume.
    if "://" in value or value.startswith("//"):
        return _classify_url(value)

    try:
        network = ipaddress.ip_network(value, strict=False)
    except ValueError:
        network = None
    else:
        if "/" in value:
            return {"kind": "cidr", "target": str(network)}

    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        address = None
    else:
        return {"kind": "ip", "target": str(address)}

    if value.startswith("["):
        match = re.fullmatch(r"\[([^\[\]]+)\](?::([^:]+))?", value)
        if not match:
            raise ValueError("invalid bracketed target host")
        host, raw_port = match.groups()
        try:
            ipaddress.IPv6Address(host)
        except ValueError as exc:
            raise ValueError("bracketed target hosts must be IPv6") from exc
        return _classify_host(host, _parse_port(raw_port) if raw_port is not None else None)
    if "[" in value or "]" in value:
        raise ValueError("invalid bracketed target host")

    # host:port form — local lab targets like 127.0.0.1:3000 or app.test:8080.
    # Must precede the strict-digits check below, which would otherwise reject
    # all-numeric host:port strings as "invalid IP/CIDR".
    if value.count(":") == 1:
        host, _, port = value.rpartition(":")
        if host and port.isdigit():
            return _classify_host(host, _parse_port(port))

    if re.fullmatch(r"[0-9./:]+", value):
        raise ValueError("invalid IP/CIDR target")
    if "/" in value:
        raise ValueError("target path must be an existing file or HTTP(S) URL")
    return _classify_host(value)


def target_https_url(target: str) -> str:
    """Return an HTTPS origin with a URL-safe target authority."""
    target_info = classify_target(target)
    if target_info["kind"] not in {"domain", "ip"}:
        raise ValueError("HTTPS target must be a domain or IP")
    authority = target_info["target"]
    try:
        address = ipaddress.ip_address(authority)
    except ValueError:
        pass
    else:
        if address.version == 6:
            authority = f"[{authority}]"
    return f"https://{authority}"


def _list_storage_stem(normalized_target: str) -> str:
    basename = os.path.basename(normalized_target)
    stem = os.path.splitext(basename)[0] or basename.strip(".") or "scope-list"
    return re.sub(r"[^A-Za-z0-9._-]+", "_", stem) or "scope-list"


def legacy_list_storage_key(target: str) -> str:
    """Return the pre-digest list key for explicit compatibility handling."""
    target_info = classify_target(target)
    if target_info["kind"] != "list":
        return target_storage_key(target)
    return _list_storage_stem(target_info["target"])


def target_storage_key(target: str) -> str:
    """Return the canonical on-disk storage key for a target."""
    try:
        target_info = classify_target(target)
    except ValueError:
        # Legacy cache/read callers use this helper to sanitize historical
        # labels that were never active targets (for example `weird/host`).
        normalized_target = canonical_target_value(target)
        target_info = {"kind": "domain", "target": normalized_target}
    normalized_target = target_info["target"]
    if target_info["kind"] == "list":
        stem = _list_storage_stem(normalized_target)
        canonical_path = os.path.realpath(normalized_target)
        digest = hashlib.sha256(canonical_path.encode("utf-8")).hexdigest()[:10]
        return f"{stem}--{digest}"
    if target_info["kind"] == "cidr":
        return normalized_target.replace("/", "_")
    return re.sub(r"[^A-Za-z0-9._:-]+", "_", normalized_target).strip("._-") or "unknown-target"


def migrate_legacy_list_storage(repo_root: str | Path, target: str) -> dict:
    """Move an owned stem-only batch state/recon tree to the digest key.

    A stem-only directory is ambiguous by definition. Migration therefore
    requires the old runtime session to name the same canonical list path;
    otherwise the old data remains untouched for explicit operator review.
    """
    target_info = classify_target(target)
    if target_info["kind"] != "list":
        return {"status": "not_list", "migrated": []}

    resolved_target = target_info["target"]
    old_key = _list_storage_stem(resolved_target)
    new_key = target_storage_key(resolved_target)
    if old_key == new_key:
        return {"status": "current", "old_key": old_key, "new_key": new_key, "migrated": []}

    repo = Path(repo_root)
    old_state = repo / "state" / old_key
    session_path = old_state / "session.json"
    try:
        session = json.loads(session_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        session = {}
    recorded_target = str(session.get("target") or "") if isinstance(session, dict) else ""
    owner_matches = bool(
        recorded_target
        and os.path.realpath(recorded_target) == os.path.realpath(resolved_target)
    )
    if not owner_matches:
        return {
            "status": "owner_unverified",
            "old_key": old_key,
            "new_key": new_key,
            "migrated": [],
        }

    migrated = []
    skipped = []
    for root_name in ("state", "recon"):
        old_path = repo / root_name / old_key
        new_path = repo / root_name / new_key
        if not old_path.exists():
            continue
        if new_path.exists():
            skipped.append(str(old_path))
            continue
        new_path.parent.mkdir(parents=True, exist_ok=True)
        old_path.replace(new_path)
        migrated.append(str(new_path))
        if root_name == "state":
            migrated_session = new_path / "session.json"
            try:
                session_payload = json.loads(migrated_session.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                session_payload = {}
            if isinstance(session_payload, dict):
                session_payload["storage_key"] = new_key
                temp_path = migrated_session.with_name(f".{migrated_session.name}.migrating")
                temp_path.write_text(
                    json.dumps(session_payload, ensure_ascii=False, indent=2) + "\n",
                    encoding="utf-8",
                )
                temp_path.replace(migrated_session)
    return {
        "status": "migrated" if migrated else "nothing_to_migrate",
        "old_key": old_key,
        "new_key": new_key,
        "migrated": migrated,
        "skipped": skipped,
    }


def _scope_endpoint(
    value: str,
    *,
    inherited_scheme: str = "",
) -> tuple[str, int | None, str, bool]:
    """Parse target-scope host, effective port, scheme, and wildcard semantics."""
    candidate = (value or "").strip()
    if not candidate:
        return "", None, "", False
    try:
        parsed = urlparse(
            candidate
            if "://" in candidate or candidate.startswith("//")
            else f"//{candidate}"
        )
    except ValueError:
        return "", None, "", False
    try:
        port = parsed.port
    except ValueError:
        return "", None, "", False
    scheme = parsed.scheme.lower() or inherited_scheme.lower()
    if port is None:
        port = {"http": 80, "https": 443}.get(scheme)
    host = (parsed.hostname or "").lower()
    if host.endswith(".."):
        return "", None, "", False
    if host.endswith("."):
        host = host[:-1]
    wildcard = host.startswith("*.")
    if wildcard:
        host = host[2:]
    return host, port, scheme, wildcard


def target_list_entries(path: str, *, preserve_wildcards: bool = False) -> list[str]:
    """Return normalized primary domains from a readable batch list."""
    if str(path).lower().endswith(".json"):
        try:
            from tools.scope_context import ScopeContext
        except ImportError:  # pragma: no cover - direct script compatibility
            from scope_context import ScopeContext
        try:
            context = ScopeContext.from_file(path)
        except (OSError, ValueError):
            return []
        entries = list(context.in_scope)
        if context.root_target and not os.path.isfile(context.root_target):
            if context.root_target not in entries:
                entries.insert(0, context.root_target)
        if preserve_wildcards:
            return entries
        return [value[2:] if value.startswith("*.") else value for value in entries]

    entries = []
    seen = set()
    try:
        lines = open(path, encoding="utf-8", errors="replace")
    except OSError:
        return []
    with lines:
        for raw in lines:
            value = raw.strip().strip("\ufeff").rstrip("/").lower()
            if not value or value.startswith("#"):
                continue
            if value.startswith("*.") and not preserve_wildcards:
                value = value[2:]
            if value and value not in seen:
                seen.add(value)
                entries.append(value)
    return entries


def url_belongs_to_target(url: str, target: str, *, allow_subdomains: bool = True) -> bool:
    """Return whether a URL should be treated as direct target-owned evidence.

    Discovery may keep third-party URLs as chain context, but direct finding
    queues should use this check before treating an embedded URL as evidence
    for the current target.
    """
    raw_url = (url or "").strip()
    if not raw_url:
        return True
    if raw_url.startswith("/") and not raw_url.startswith("//"):
        return True

    target_info = classify_target(canonical_target_value(target))
    if target_info["kind"] == "list":
        if str(target_info["target"]).lower().endswith(".json"):
            try:
                from tools.scope_context import ScopeContext
            except ImportError:  # pragma: no cover - direct script compatibility
                from scope_context import ScopeContext
            try:
                return ScopeContext.from_file(target_info["target"]).allows_active(raw_url)
            except (OSError, ValueError):
                return False
        for listed_target in target_list_entries(
            target_info["target"],
            preserve_wildcards=True,
        ):
            # Primary-domain lists are intentionally one level deep. A line
            # resolving to another local file is not a root target and must
            # not recurse into nested or self-referential lists.
            if classify_target(canonical_target_value(listed_target))["kind"] == "list":
                continue
            if url_belongs_to_target(
                raw_url,
                listed_target,
                allow_subdomains=allow_subdomains,
            ):
                return True
        return False

    target_value = (target or "").strip()
    target_host, target_port, target_scheme, target_wildcard = _scope_endpoint(target_value)
    inherited_scheme = target_scheme or {80: "http", 443: "https"}.get(target_port, "")
    url_host, url_port, url_scheme, _ = _scope_endpoint(
        raw_url,
        inherited_scheme=inherited_scheme,
    )
    if not url_host:
        return False

    if target_info["kind"] == "cidr":
        try:
            return ipaddress.ip_address(url_host) in ipaddress.ip_network(target_info["target"], strict=False)
        except ValueError:
            return False

    if not target_host:
        return False

    host_matches = not target_wildcard and url_host == target_host
    if (allow_subdomains or target_wildcard) and not host_matches:
        host_matches = url_host.endswith("." + target_host)
    if not host_matches:
        return False
    if target_scheme and url_scheme and url_scheme != target_scheme:
        return False
    if target_port is not None and url_port != target_port:
        return False
    return True
