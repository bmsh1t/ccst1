"""Exact historical counterevidence bundles, independent of retrieval top-k."""
from __future__ import annotations

import base64
import json
import shlex
from pathlib import Path

from tools.recall_sources import digest
from tools.target_store import StoreError, runtime_store


def _json(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _command(root, target, key):
    return shlex.join(["python3", str(Path(__file__).resolve().with_name("target_memory.py")), "version",
                       "--repo-root", str(Path(root).absolute()), "--target", target,
                       "--id", key[0], "--version", str(key[1]), "--json"])


def _context_command(root, target, key):
    return shlex.join(["python3", str(Path(__file__).resolve().with_name("experience_recall.py")), "context",
                       "--repo-root", str(Path(root).absolute()), "--target", target,
                       "--id", key[0], "--version", str(key[1]), "--json"])


def _roots(values):
    if not isinstance(values, list) or len(values) > 1000:
        raise ValueError("context roots must contain at most 1000 exact experience versions")
    keys = set()
    for value in values:
        if (not isinstance(value, dict) or set(value) != {"experience_id", "version"}
                or not isinstance(value["experience_id"], str) or not value["experience_id"].strip()
                or type(value["version"]) is not int or value["version"] < 0):
            raise ValueError("context roots require experience_id and exact non-negative version")
        keys.add((value["experience_id"], value["version"]))
    return [{"experience_id": key, "version": version} for key, version in sorted(keys)]


def _acquire(store, roots):
    """Use only public owner reads; retain unavailable references instead of dropping them."""
    binding = store.binding()
    records, items, root_refs = {}, {}, []
    artifacts = {}

    def read(key):
        if key not in records:
            try:
                records[key] = {"status": "ready", "record": store.experience_version(*key)}
            except StoreError as exc:
                records[key] = {"status": "unavailable", "reason": str(exc)}
        return records[key]

    def read_artifact(artifact_id):
        if artifact_id not in artifacts:
            try:
                artifacts[artifact_id] = {"record": store.artifact_status(artifact_id)}
            except StoreError as exc:
                artifacts[artifact_id] = {"status": "unavailable", "reason": str(exc)}
        return artifacts[artifact_id]

    def add(identity, record, relationship, parent, expansion):
        key = digest(identity)
        item = items.setdefault(key, {"identity": identity, **record, "referenced_by": [],
                                      "independent_support": False, "expand_command": expansion})
        reference = {"root": parent, **relationship}
        if reference not in item["referenced_by"]:
            item["referenced_by"].append(reference)

    for parent in roots:
        key = (parent["experience_id"], parent["version"])
        captured = read(key)
        expansion = _command(store.root, store.target, key)
        if captured["status"] != "ready":
            root_refs.append({**parent, **captured, "expand_command": expansion})
            continue
        record = captured["record"]
        root_refs.append({**parent, "content_sha256": record["content_sha256"],
                          "status": "ready", "review_state": record["review_state"],
                          "applicability": record["applicability"],
                          "source_health": record["source_health"], "expand_command": expansion})
        linked = []
        for link in record["correction_refs"] + record["dependency_refs"]:
            left = (link["experience_id"], link["experience_version"])
            right = (link["target_id"], link["target_version"])
            if key not in (left, right):
                raise StoreError("context link does not bind its retained root")
            linked.append((right if key == left else left, {"relation": link["relation"], "link": link}, None))
        for source in record["sources"]:
            if "owner" not in source:
                linked.append(((source["source_experience_id"], source["source_version"]),
                               {"relation": source["purpose"], "source": source}, source["content_sha256"]))
            else:
                identity = {"owner": source["owner"], "record_id": source["record_id"],
                            "version": source["source_version"], "content_sha256": source["content_sha256"]}
                material = {"status": source["health"], "record": source}
                if source["owner"] == "artifact":
                    identity = {"owner": "artifact", "record_id": source["record_id"]}
                    captured_artifact = read_artifact(source["record_id"])
                    if "record" in captured_artifact:
                        material["artifact"] = captured_artifact["record"]
                    else:
                        material.update(captured_artifact)
                source_expansion = expansion
                if source["owner"] == "history":
                    source_expansion = shlex.join(["python3", str(Path(__file__).resolve().with_name("target_memory.py")),
                        "history-source", "--repo-root", str(store.root), "--target", store.target,
                        "--id", source["record_id"], "--full", "--json"])
                add(identity, material,
                    {"relation": source["purpose"]}, parent, source_expansion)
        # Claim-only experience endpoints are also exact basis, not a newest-version lookup.
        for claim in record["claims"]:
            entities = [claim["subject"], claim["object"], *(claim.get("condition_bindings") or {}).values()]
            for entity in entities:
                if entity["owner"] == "experience":
                    linked.append(((entity["record_id"], entity["version"]),
                                   {"relation": "claim_basis", "claim_id": claim["id"]}, entity["content_sha256"]))
        for related, relationship, expected in linked:
            resolved = read(related)
            historical = resolved.get("record", {})
            if expected is not None and historical.get("content_sha256") != expected:
                resolved = {**resolved, "status": "unavailable", "reason": "exact source content binding mismatch"}
            identity = {"owner": "experience", "record_id": related[0], "version": related[1],
                        "content_sha256": expected or historical.get("content_sha256")}
            resolved = {**resolved, "context_command": _context_command(store.root, store.target, related)}
            add(identity, resolved, relationship, parent, _command(store.root, store.target, related))
        for health in record["source_health"]:
            if health.get("artifact_id"):
                artifact_id = health["artifact_id"]
                captured_artifact = {"status": health["status"], **read_artifact(artifact_id)}
                add({"owner": "artifact", "record_id": artifact_id}, captured_artifact,
                    {"relation": health["purpose"]}, parent, expansion)
    if store.binding() != binding:
        raise StoreError("context Store changed; retry query")
    return {"binding": binding, "roots": root_refs, "items": [items[key] for key in sorted(items)]}


def verify_context(repo_root, target, bundle):
    """Recheck exact historical peers at a composite query's final return boundary."""
    roots = [{key: row[key] for key in ("experience_id", "version")} for row in bundle["roots"]]
    if digest(_acquire(runtime_store(repo_root, target), roots)) != bundle["source_binding"]:
        raise StoreError("counterevidence source/evidence changed; retry query")


def context_page(repo_root, target, *, roots=None, cursor=None, limit=20, max_bytes=64000):
    """One direct correction/dependency/source hop, with its own bound continuation."""
    if type(limit) is not int or not 1 <= limit <= 1000 or type(max_bytes) is not int or not 1024 <= max_bytes <= 4000000:
        raise ValueError("context limit must be 1..1000 and max_bytes 1024..4000000")
    decoded, offset = None, 0
    if cursor is not None:
        try:
            if not isinstance(cursor, str) or len(cursor) > 512000:
                raise ValueError("invalid cursor size")
            decoded = json.loads(base64.b64decode(cursor, altchars=b"-_", validate=True))
            if not isinstance(decoded, dict) or type(decoded.get("offset")) is not int or decoded["offset"] < 0:
                raise ValueError("invalid offset")
            cursor_roots = _roots(decoded["roots"])
            if roots is not None and _roots(roots) != cursor_roots:
                raise ValueError("roots differ")
            roots, offset = cursor_roots, decoded["offset"]
        except (KeyError, TypeError, ValueError) as exc:
            raise ValueError("invalid context cursor; restart context read") from exc
    roots = _roots(roots)
    store = runtime_store(repo_root, target)
    acquired = _acquire(store, roots)
    signature = digest(acquired)
    if decoded is not None and decoded.get("binding") != signature:
        raise ValueError("stale context cursor; source or evidence health changed")
    if offset > len(acquired["items"]):
        raise ValueError("invalid context offset")
    selected, used, truncated = [], 0, 0
    for item in acquired["items"][offset:offset + limit]:
        size = len(_json(item).encode())
        if size > max_bytes:
            references = []
            for reference in item["referenced_by"]:
                summary = {key: value for key, value in reference.items() if key != "link"}
                if "link" in reference:
                    summary["link"] = {key: value for key, value in reference["link"].items()
                                       if key != "rationale"}
                references.append(summary)
            item = {"identity": item["identity"], "status": item["status"], "content_omitted": True,
                    "required_bytes": size, "expand_command": item["expand_command"],
                    "referenced_by": references, "independent_support": False}
            size = len(_json(item).encode())
        if used + size > max_bytes:
            if not selected:
                raise ValueError("context budget cannot fit one source reference; increase --context-max-bytes")
            break
        selected.append(item)
        used += size
        truncated += int(item.get("content_omitted", False))
    # This rechecks the historical peers too; the root's Store revision alone is insufficient.
    if acquired != _acquire(store, roots):
        raise StoreError("context source/evidence changed during read; retry")
    remaining = len(acquired["items"]) - offset - len(selected)
    continuation = base64.urlsafe_b64encode(_json({"binding": signature, "roots": roots,
        "offset": offset + len(selected)}).encode()).decode() if remaining else None
    missing = any(row["status"] == "unavailable" for row in acquired["roots"] + acquired["items"])
    incomplete = bool(remaining or truncated or missing)
    command = shlex.join(["python3", str(Path(__file__).resolve().with_name("experience_recall.py")), "context",
        "--repo-root", str(Path(repo_root).absolute()), "--target", store.target,
        "--context-limit", str(limit), "--context-max-bytes", str(max_bytes), "--cursor", continuation, "--json"]) if continuation else None
    return {"status": "partial" if incomplete else "complete", "context_incomplete": incomplete,
            "binding": acquired["binding"], "source_binding": signature, "roots": acquired["roots"],
            "items": selected, "total": len(acquired["items"]), "remaining": remaining,
            "content_omitted": truncated, "next_cursor": continuation, "next_command": command,
            "cursor_owner": "recall_context.context_page", "order": "exact-source-identity",
            "scope": "direct corrections, dependencies and basis; expand each version for further hops",
            "independent_support": False}
