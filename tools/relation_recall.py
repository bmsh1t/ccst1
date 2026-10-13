"""Source-bound relation projections; paths are hypotheses, never execution authority.

Only accepted C6 claims and explicit provenance links are projected. Free text is
inert data. Publishing and source acquisition belong to recall_index/recall_sources.
"""
from __future__ import annotations

import base64
import hashlib
import json
import time
from datetime import datetime
from pathlib import Path

from tools.experience_contract import ENTITY_FIELDS, CLAIM_PREDICATES, entity_binding, condition_bindings, validity_window
from tools.knowledge_relations import METHOD_PREDICATES, PATTERN_OWNER, pattern_binding

SCHEMA = "relation-projection-v4"
OWNER_PREDICATES = frozenset({"has_session", "owns_object", "attempted_operation",
                             "observed_artifact", "evidence_from", "depends_on"})
PREDICATES = CLAIM_PREDICATES | METHOD_PREDICATES | OWNER_PREDICATES


def _source_gaps(snapshot):
    if snapshot["binding"].get("source_partition") == "knowledge":
        return []
    if not snapshot["binding"].get("include_owner_relations"):
        return ["owner relation sources were not collected"]
    return snapshot.get("health", {}).get("target", {}).get("errors", [])


def _json(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False)


def _hash(value):
    return hashlib.sha256(_json(value).encode()).hexdigest()


def entity_key(entity, binding=None):
    """Identity uses owner version/content, never a display label or substring."""
    if isinstance(entity, dict) and entity.get("owner") == PATTERN_OWNER:
        return _hash(pattern_binding(entity))
    return _hash(entity_binding(entity, binding=binding))


def _health_available(health):
    if not isinstance(health, list) or not health or any(not isinstance(row, dict) for row in health):
        return False
    basis = [row for row in health if row.get("purpose") != "origin"]
    return bool(basis) and all(row.get("status") == "available" for row in basis)


def _project_documents(snapshot):
    """Pure closed-snapshot projection; no filesystem, Store mutation or clock."""
    binding = snapshot["binding"]
    nodes, edges, rejected = {}, {}, []
    documents = snapshot.get("documents", [])
    for document in documents:
        source_ref = document.get("source_ref")
        record = document.get("record", {})
        if document.get("source_ref", "").startswith("knowledge:"):
            rejected.extend(document.get("method_relation_errors", []))
            for relation in document.get("method_relations", []):
                try:
                    if (binding.get("source_partition") != "knowledge" or document.get("target")
                            or document.get("review_state") != "reviewed"):
                        raise ValueError("method patterns require an independent reviewed knowledge partition")
                    subject, obj = pattern_binding(relation["subject"]), pattern_binding(relation["object"])
                    if (source_ref != "knowledge:" + subject["method_id"]
                            or document["source_hash"] != subject["content_sha256"]
                            or relation["predicate"] not in METHOD_PREDICATES):
                        raise ValueError("method relation source identity or predicate mismatch")
                    start, end = entity_key(subject), entity_key(obj)
                    edge = {"subject": start, "object": end, "predicate": relation["predicate"],
                            "epistemic": "reviewed-pattern", "conditions": relation["conditions"],
                            "condition_bindings": {}, "timing": "unknown", "validity": None,
                            "observed_at": None, "rationale": relation["rationale"],
                            "source": {"source_ref": source_ref, "source_hash": document["source_hash"],
                                       "relation_id": relation["id"], "source_refs": [subject, obj],
                                       "review": record["review"], "source_health": document["source_health"]}}
                    edge["id"] = _hash(edge)
                    edges[edge["id"]] = edge
                    nodes[start], nodes[end] = subject, obj
                except (KeyError, TypeError, ValueError) as exc:
                    rejected.append({"source_ref": source_ref, "reason": str(exc)})
            continue
        if source_ref and source_ref.startswith("owner:"):
            rejected.extend(document.get("source_errors", []))
            if not _health_available(document.get("source_health")):
                if not document.get("source_errors"):
                    rejected.append({"source_ref": source_ref, "reason": "owner source unavailable"})
                continue
            for relation in document.get("owner_relations", []):
                if document.get("target") != binding["target"] or relation["predicate"] not in OWNER_PREDICATES:
                    raise ValueError("invalid owner relation partition or predicate")
                subject = entity_binding(relation["subject"], binding=binding)
                obj = entity_binding(relation["object"], binding=binding)
                start, end = entity_key(subject, binding), entity_key(obj, binding)
                edge = {"subject": start, "object": end, "predicate": relation["predicate"],
                        "epistemic": "owner-recorded", "conditions": "unknown", "condition_bindings": {},
                        "timing": "unknown", "validity": None, "observed_at": relation.get("observed_at"),
                        "source": {"source_ref": source_ref, "source_hash": document["source_hash"],
                                   "source_refs": [subject, obj], "provenance": relation["provenance"],
                                   "source_health": document["source_health"]}}
                edge["id"] = _hash(edge)
                edges[edge["id"]] = edge
                nodes[start], nodes[end] = subject, obj
            continue
        claims = document.get("claims", record.get("claims", []))
        for claim in claims:
            try:
                if not isinstance(claim, dict):
                    raise ValueError("claim must be an object")
                if not source_ref or not document.get("source_hash"):
                    raise ValueError("source binding missing")
                if document.get("target") != binding["target"]:
                    raise ValueError("foreign target document")
                if document.get("review_state") != "advisory" or claim.get("advisory") is not True:
                    raise ValueError("claim not currently accepted advisory")
                if not _health_available(document.get("source_health")):
                    raise ValueError("source unavailable or health unknown")
                if claim.get("predicate") not in CLAIM_PREDICATES or not claim.get("source_refs"):
                    raise ValueError("unsupported predicate or missing claim provenance")
                if not claim.get("conditions") or not claim.get("timing"):
                    raise ValueError("claim conditions/timing missing")
                subject, obj = claim["subject"], claim["object"]
                start, end = entity_key(subject, binding), entity_key(obj, binding)
                if any(endpoint.get("health") != "available" for endpoint in (subject, obj)):
                    raise ValueError("endpoint version changed or health unknown")
                bound_conditions = condition_bindings(claim.get("condition_bindings"), binding=binding)
                if bound_conditions and any(value.get("health") != "available" for value in claim["condition_bindings"].values()):
                    raise ValueError("condition entity version changed or health unknown")
                edge = {"subject": start, "object": end, "predicate": claim["predicate"],
                        "epistemic": "advisory", "conditions": claim["conditions"],
                        "condition_bindings": bound_conditions,
                        "timing": claim["timing"], "validity": validity_window(claim.get("validity")),
                        "observed_at": claim.get("observed_at"),
                        "source": {"source_ref": source_ref, "source_hash": document["source_hash"],
                                   "claim_id": claim["id"], "source_refs": claim["source_refs"],
                                   "source_health": document["source_health"],
                                   "correction_refs": document.get("correction_refs", []),
                                   "dependency_refs": document.get("dependency_refs", [])}}
                edge["id"] = _hash(edge)
                edges[edge["id"]] = edge
                for key, endpoint in ((start, subject), (end, obj)):
                    nodes[key] = {key: endpoint[key] for key in ENTITY_FIELDS}
            except (KeyError, TypeError, ValueError) as exc:
                rejected.append({"source_ref": source_ref, "claim_id": claim.get("id") if isinstance(claim, dict) else None,
                                 "reason": str(exc)})
    graph = {"schema": SCHEMA, "binding": binding, "nodes": nodes,
             "edges": sorted(edges.values(), key=lambda edge: edge["id"]), "rejected": rejected,
             "gaps": _source_gaps(snapshot)}
    graph["digest"] = _hash(graph)
    return graph


def _validate_projection(graph):
    if (not isinstance(graph, dict) or graph.get("schema") != SCHEMA
            or graph.get("digest") != _hash({k: v for k, v in graph.items() if k != "digest"})
            or not isinstance(graph.get("shards"), dict)):
        raise ValueError("relation format changed or corrupt; request --full-rebuild")
    for shard in graph["shards"].values():
        if (not isinstance(shard, dict) or not isinstance(shard.get("input_digest"), str)
                or not isinstance(shard.get("nodes"), dict) or not isinstance(shard.get("edges"), list)
                or not isinstance(shard.get("rejected"), list)):
            raise ValueError("corrupt relation source shard; request --full-rebuild")


def project_snapshot(snapshot, *, previous=None):
    """Reuse unchanged closed-source shards independently of source acquisition."""
    if previous is not None:
        _validate_projection(previous)
    old = previous["shards"] if previous else {}
    shards, nodes, edges, rejected = {}, {}, {}, []
    for document in sorted(snapshot["documents"], key=lambda row: row["source_ref"]):
        ref = document["source_ref"]
        if ref in shards:
            raise ValueError("duplicate relation source identity")
        source_digest = _hash(document)
        shard = old.get(ref)
        if shard is None or shard["input_digest"] != source_digest:
            projected = _project_documents({**snapshot, "documents": [document]})
            shard = {"input_digest": source_digest, **{key: projected[key] for key in ("nodes", "edges", "rejected")}}
        shards[ref] = shard
        nodes.update(shard["nodes"])
        edges.update((edge["id"], edge) for edge in shard["edges"])
        rejected.extend(shard["rejected"])
    graph = {"schema": SCHEMA, "binding": snapshot["binding"], "shards": shards, "nodes": nodes,
             "edges": sorted(edges.values(), key=lambda edge: edge["id"]), "rejected": rejected,
             "gaps": _source_gaps(snapshot)}
    graph["digest"] = _hash(graph)
    return graph


def _instant(value):
    if not isinstance(value, str):
        raise ValueError("invalid validity timestamp")
    result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if result.tzinfo is None:
        raise ValueError("validity timestamp needs timezone")
    return result.timestamp()


def _constraints(edges, known):
    """Only exact structured equality and explicit time windows are comparable."""
    values, missing, start, end = dict(known), [], None, None
    roles = set(known).union(*(set(edge.get("condition_bindings") or {}) for edge in edges))
    for edge in edges:
        conditions = edge.get("condition_bindings") or {}
        # Exact identity agreement says nothing about additional natural-language conditions.
        missing.append({"edge_id": edge["id"], "conditions": edge.get("conditions"), "reason": "text_conditions_unverified"})
        for key in sorted(roles - conditions.keys()):
            missing.append({"edge_id": edge["id"], "reason": "condition_unknown", "key": key})
        for key, value in conditions.items():
            if key in values and values[key] != value:
                return None
            values[key] = value
            if key not in known:
                missing.append({"edge_id": edge["id"], "reason": "condition_not_observed", "key": key, "value": value})
        validity = edge.get("validity")
        if not isinstance(validity, dict) or not validity.get("from") or not validity.get("until"):
            missing.append({"edge_id": edge["id"], "reason": "coexistence_unknown", "timing": edge.get("timing")})
        else:
            try:
                lower, upper = _instant(validity["from"]), _instant(validity["until"])
            except ValueError:
                missing.append({"edge_id": edge["id"], "reason": "invalid_validity"})
                continue
            start = lower if start is None else max(start, lower)
            end = upper if end is None else min(end, upper)
            if start >= end:
                return None
    return missing


def _decode_cursor(cursor):
    if not isinstance(cursor, str) or len(cursor) > 64000:
        raise ValueError("invalid relation cursor")
    try:
        decoded = json.loads(base64.b64decode(cursor.encode(), altchars=b"-_", validate=True))
    except (ValueError, UnicodeError) as exc:
        raise ValueError("invalid relation cursor") from exc
    if not isinstance(decoded, dict):
        raise ValueError("invalid relation cursor")
    return decoded


def traverse(graph, seeds, *, generation=None, direction="out", predicates=None,
             known_conditions=None, max_depth=6, min_hops=1, max_edges=1000,
             max_paths=50, max_bytes=200000, max_seconds=1.0, cursor=None):
    """Deterministic depth-first adjacency traversal with an O(depth) cursor.

    Each page resumes adjacency offsets rather than serializing a high-fanout
    frontier. Increasing max_depth starts a new query; depth-truncated results
    retain exact endpoint expansion references and never claim exhaustion.
    """
    started = time.monotonic()
    for value, upper, name in ((max_depth, 64, "max_depth"), (min_hops, 64, "min_hops"),
                                (max_edges, 100000, "max_edges"), (max_paths, 1000, "max_paths"),
                                (max_bytes, 4000000, "max_bytes")):
        if type(value) is not int or not 1 <= value <= upper:
            raise ValueError(f"invalid {name}")
    if min_hops > max_depth or not isinstance(max_seconds, (int, float)) or not 0 < max_seconds <= 30:
        raise ValueError("invalid traversal bounds")
    if direction not in {"out", "in", "both"} or not isinstance(seeds, list) or not 1 <= len(seeds) <= 100:
        raise ValueError("invalid direction or seeds")
    _validate_projection(graph)
    known_conditions = {} if known_conditions is None else known_conditions
    if not isinstance(known_conditions, dict):
        raise ValueError("known_conditions must be an object")
    if known_conditions and graph["binding"].get("source_partition") == "knowledge":
        raise ValueError("shared method patterns have no observed Store condition bindings")
    known_conditions = condition_bindings(known_conditions, binding=graph["binding"]) if known_conditions else {}
    if predicates is not None and (not isinstance(predicates, (list, tuple, set))
                                   or any(not isinstance(value, str) or value not in PREDICATES for value in predicates)):
        raise ValueError("predicates must contain supported predicate names")
    selected = sorted(set(predicates)) if predicates is not None else None
    if any(not isinstance(seed, (dict, str)) for seed in seeds):
        raise ValueError("seeds must be exact entity bindings or indexed keys")
    seed_keys = sorted(set(entity_key(seed, graph["binding"]) if isinstance(seed, dict) else seed for seed in seeds))
    unresolved = [key for key in seed_keys if key not in graph["nodes"]]
    if unresolved and not (graph["gaps"] or graph["rejected"]):
        raise ValueError("seed is not an exact indexed entity; rebuild or inspect sources")
    seed_keys = [key for key in seed_keys if key in graph["nodes"]]
    signature = _hash({"digest": graph["digest"], "generation": generation, "seeds": seed_keys,
                       "unresolved_seeds": unresolved,
                       "direction": direction, "predicates": selected, "known": known_conditions,
                       "max_depth": max_depth, "min_hops": min_hops})
    edge_map = {edge["id"]: edge for edge in graph["edges"]}
    adjacency = {key: [] for key in graph["nodes"]}
    for edge in graph["edges"]:
        if selected is not None and edge["predicate"] not in selected:
            continue
        if direction in {"out", "both"}:
            adjacency[edge["subject"]].append((edge["id"], edge["object"]))
        if direction in {"in", "both"} and edge["subject"] != edge["object"]:
            adjacency[edge["object"]].append((edge["id"], edge["subject"]))
    for rows in adjacency.values():
        rows.sort()
    state = {"signature": signature, "seed": 0, "stack": [], "depth_limited": 0}
    if cursor is not None:
        state = _decode_cursor(cursor)
        if state.get("signature") != signature:
            raise ValueError("stale relation cursor: source, generation or query changed")
        if type(state.get("seed")) is not int or not 0 <= state["seed"] <= len(seed_keys):
            raise ValueError("invalid cursor seed")
        if type(state.get("depth_limited")) is not int or state["depth_limited"] < 0:
            raise ValueError("invalid cursor depth count")
        stack = state.get("stack")
        if not isinstance(stack, list) or len(stack) > max_depth + 1:
            raise ValueError("invalid cursor stack")
        seen = set()
        for index, frame in enumerate(stack):
            if (not isinstance(frame, dict) or frame.get("node") not in adjacency or frame["node"] in seen
                    or type(frame.get("pos")) is not int or not 0 <= frame["pos"] <= len(adjacency[frame["node"]])
                    or type(frame.get("emitted")) is not bool):
                raise ValueError("invalid cursor frame")
            seen.add(frame["node"])
            if index == 0:
                if state["seed"] >= len(seed_keys) or frame["node"] != seed_keys[state["seed"]] or frame.get("via") is not None:
                    raise ValueError("invalid cursor root")
            else:
                previous = stack[index - 1]
                if previous["pos"] < 1 or adjacency[previous["node"]][previous["pos"] - 1] != (frame.get("via"), frame["node"]):
                    raise ValueError("invalid cursor adjacency")
        if _constraints([edge_map[f["via"]] for f in stack[1:]], known_conditions) is None:
            raise ValueError("invalid cursor conditions")
    paths, examined, cycles, incompatible, used = [], 0, 0, 0, 0
    reason = None
    while state["seed"] < len(seed_keys):
        stack = state["stack"]
        if not stack:
            stack.append({"node": seed_keys[state["seed"]], "pos": 0, "via": None, "emitted": True})
        frame = stack[-1]
        path_edges = [edge_map[f["via"]] for f in stack[1:]]
        if not frame["emitted"]:
            if len(path_edges) >= min_hops:
                missing = _constraints(path_edges, known_conditions)
                path = {"nodes": [graph["nodes"][f["node"]] for f in stack], "edges": path_edges,
                        "epistemic": "hypothesis", "weakest_edge": "advisory" if any(e["epistemic"] == "advisory" for e in path_edges) else "owner-recorded" if any(e["epistemic"] == "owner-recorded" for e in path_edges) else "reviewed-pattern",
                        "unverified_conditions": missing, "executable": False,
                        "expand_from": graph["nodes"][frame["node"]]}
                size = len(_json(path).encode())
                if used + size > max_bytes:
                    reason = "response_budget"
                    break
                paths.append(path)
                used += size
            frame["emitted"] = True
        if time.monotonic() - started >= max_seconds:
            reason = "time_budget"
            break
        if len(path_edges) == max_depth:
            state["depth_limited"] += int(bool(adjacency[frame["node"]]))
            stack.pop()
        elif frame["pos"] >= len(adjacency[frame["node"]]):
            stack.pop()
        else:
            if examined >= max_edges or len(paths) >= max_paths:
                reason = "edge_budget" if examined >= max_edges else "path_budget"
                break
            edge_id, destination = adjacency[frame["node"]][frame["pos"]]
            frame["pos"] += 1
            examined += 1
            if any(item["node"] == destination for item in stack):
                cycles += 1
                continue
            if _constraints(path_edges + [edge_map[edge_id]], known_conditions) is None:
                incompatible += 1
                continue
            stack.append({"node": destination, "pos": 0, "via": edge_id, "emitted": False})
        if not stack:
            state["seed"] += 1
    continuation = base64.urlsafe_b64encode(_json(state).encode()).decode() if state["seed"] < len(seed_keys) else None
    return {"status": "partial" if continuation or state["depth_limited"] or graph["rejected"] or graph["gaps"] or unresolved else "complete",
            "paths": paths, "continuation": continuation, "stop_reason": reason,
            "scope": "reviewed method patterns; instantiate only as hypotheses" if graph["binding"].get("source_partition") == "knowledge" else "accepted same-target relations; not an exploitability judgment",
            "examined_edges": examined, "cycle_edges_skipped": cycles, "incompatible_edges": incompatible,
            "depth_limited": state["depth_limited"], "remaining": "unknown" if continuation or state["depth_limited"] or graph["gaps"] or graph["rejected"] or unresolved else 0,
            "unresolved_seeds": unresolved,
            "rejected_sources": graph["rejected"][:20], "rejected_total": len(graph["rejected"]),
            "gaps": graph["gaps"], "binding": graph["binding"], "generation": generation,
            "expansion": {"seeds": seeds, "max_depth": max_depth, "increase_depth_requires_new_query": True}}


def _relation_snapshot(repo_root, target, *, shared=False, full_rebuild=False, previous_capture=None):
    from tools.recall_sources import acquire_snapshot, text_partitions
    from tools.recall_index import acquire_index_snapshot
    if shared and target is not None:
        raise ValueError("shared relations do not accept a target")
    if not shared and not target:
        raise ValueError("target is required for target relations")
    if previous_capture is not None:
        snapshot = acquire_snapshot(Path(repo_root), target, include_knowledge=False,
                                    include_owner_relations=True, previous_capture=previous_capture)
        retained = {}
    else:
        snapshot, retained = acquire_index_snapshot(repo_root, target, "relations", shared=shared,
                                                    full_rebuild=full_rebuild)
    if shared:
        return snapshot, None, retained.get("knowledge")
    return text_partitions(snapshot)["target"], snapshot, retained.get("target")


def _projection_health(snapshot, graph):
    states = [row["status"] for row in snapshot["health"].values()]
    status = "unavailable" if "unavailable" in states else "partial" if graph["gaps"] or graph["rejected"] or any(state != "ready" for state in states) else "ready"
    return {"status": status, "gaps": graph["gaps"], "rejected_total": len(graph["rejected"])}


def build_relations(repo_root: Path, target: str | None = None, *, shared=False, full_rebuild=False):
    """Explicit source-shard update using the common generation publisher."""
    from tools.recall_index import publish_generation, generation_exists
    from tools.target_store import StoreError
    name = "knowledge" if shared else "target"
    snapshot, _, retained = _relation_snapshot(repo_root, target, shared=shared, full_rebuild=full_rebuild)
    try:
        if any(row["status"] == "unavailable" for row in snapshot["health"].values()):
            raise ValueError("relation source unavailable; previous generation preserved")
        previous = None
        if not full_rebuild:
            previous = retained["payload"]
            if previous is None and generation_exists(repo_root, target, "relations", shared=shared):
                raise ValueError(f"previous relation generation unusable; request --full-rebuild: {retained['health']}")
        graph = project_snapshot(snapshot, previous=previous)
        old = previous["shards"] if previous else {}
        reused = sum(ref in old and old[ref]["input_digest"] == shard["input_digest"] for ref, shard in graph["shards"].items())
        update = {"reused_sources": reused, "updated_sources": len(graph["shards"]) - reused,
                  "removed_sources": len(old.keys() - graph["shards"].keys()),
                  "mode": "incremental" if previous else "full"}
        manifest = publish_generation(repo_root, target, "relations", snapshot, graph,
                                      shared=shared, force=full_rebuild)
        health = _projection_health(snapshot, graph)
        partition = {"manifest": manifest, "health": health, "source_health": snapshot["health"],
                     "update": update, "acquisition": snapshot.get("acquisition"), "edge_count": len(graph["edges"]), "rejected_total": len(graph["rejected"]),
                     "gaps": graph["gaps"]}
    except (OSError, ValueError, KeyError, TypeError, StoreError) as exc:
        manifest = {}
        health = {"status": "unavailable", "reason": str(exc)}
        partition = {"manifest": None, "health": health, "source_health": snapshot["health"],
                     "acquisition": snapshot.get("acquisition")}
    return {**manifest, "status": health["status"], "health": health, "partitions": {name: partition},
            **{key: partition[key] for key in ("edge_count", "rejected_total", "gaps", "update", "acquisition") if key in partition}}


def _read_relations(repo_root, target, snapshot, *, shared=False):
    from tools.recall_index import read_generation
    generation = read_generation(repo_root, target, "relations", snapshot=snapshot, shared=shared)
    if generation["payload"] is not None:
        try:
            _validate_projection(generation["payload"])
        except (ValueError, TypeError, KeyError) as exc:
            generation.update(payload=None, health={"status": "unavailable", "reason": str(exc)})
    return generation


def relation_status(repo_root: Path, target: str | None = None, *, shared=False):
    from tools.recall_sources import same_snapshot
    snapshot, _, _ = _relation_snapshot(repo_root, target, shared=shared)
    generation = _read_relations(repo_root, target, snapshot, shared=shared)
    health = (_projection_health(snapshot, generation["payload"]) if generation["payload"] is not None
              else {"status": "unavailable", "reason": generation["health"].get("reason"),
                    "index_status": generation["health"]["status"]})
    fresh, _, _ = _relation_snapshot(repo_root, target, shared=shared,
                                     previous_capture=snapshot.get("capture"))
    if not same_snapshot(fresh, snapshot):
        raise ValueError("relation sources changed during status; retry status")
    name = "knowledge" if shared else "target"
    partition = {"manifest": generation["manifest"], "health": health, "source_health": snapshot["health"],
                 "binding": snapshot["binding"], "acquisition": snapshot.get("acquisition")}
    return {**partition, "partitions": {name: partition}}


def query_relations(repo_root: Path, target: str | None = None, seeds=None, *, shared=False,
                    context_limit=20, context_max_bytes=64000, **options):
    """Shared reads never open Store; target reads retain current and exact context."""
    from tools.recall_context import context_page, verify_context
    from tools.recall_sources import same_snapshot
    from tools.target_store import StoreError
    if (not isinstance(seeds, list) or not 1 <= len(seeds) <= 100
            or any(not isinstance(seed, (dict, str)) for seed in seeds)):
        raise ValueError("relation seeds require 1..100 exact entity bindings or indexed keys")
    snapshot, current_snapshot, _ = _relation_snapshot(repo_root, target, shared=shared)
    for seed in seeds:
        if isinstance(seed, dict):
            entity_key(seed, snapshot["binding"])
    generation = _read_relations(repo_root, target, snapshot, shared=shared)
    if generation["payload"] is None:
        result = {"status": generation["health"]["status"], "paths": [],
                  "binding": snapshot["binding"], "rebuild": "relation-build --shared" if shared else "relation-build",
                  "continuation": None, "remaining": "unknown", "gaps": _source_gaps(snapshot)}
    else:
        result = traverse(generation["payload"], seeds,
                          generation=generation["manifest"].get("generation"), **options)
    if not shared:
        wanted = {edge["source"]["source_ref"] for path in result.get("paths", []) for edge in path["edges"]}
        wanted.update(row["source_ref"] for row in result.get("rejected_sources", []) if row.get("source_ref"))
        roots = [{"experience_id": doc["record"]["id"], "version": doc["record"]["version"]}
                 for doc in snapshot["documents"] if doc["source_ref"] in wanted and doc["source_ref"].startswith("experience:")]
        entities = [node for path in result.get("paths", []) for node in path["nodes"]]
        entities.extend(doc["record"] for doc in snapshot["documents"]
                        if doc["source_ref"] in wanted and doc.get("kind") == "owner_provenance")
        roots.extend({"experience_id": entity["record_id"], "version": entity["version"]}
                     for entity in entities if entity.get("owner") == "experience")
        experience_seeds = [seed for seed in seeds if isinstance(seed, dict) and seed.get("owner") == "experience"]
        roots.extend({"experience_id": seed["record_id"], "version": seed["version"]}
                     for seed in experience_seeds)
        roots = [{"experience_id": key, "version": version}
                 for key, version in sorted({(row["experience_id"], row["version"]) for row in roots})]
        counterevidence = context_page(repo_root, target, roots=roots, limit=context_limit, max_bytes=context_max_bytes)
        resolved = {(row["experience_id"], row["version"]): row["content_sha256"]
                    for row in counterevidence["roots"] if row["status"] == "ready"}
        for seed in experience_seeds:
            actual = resolved.get((seed["record_id"], seed["version"]))
            if actual is not None and actual != seed["content_sha256"]:
                raise ValueError("relation seed content binding mismatch; read the exact experience version")
    fresh, fresh_current, _ = _relation_snapshot(repo_root, target, shared=shared,
                                               previous_capture=snapshot.get("capture"))
    if not same_snapshot(fresh, snapshot) or (not shared and not same_snapshot(fresh_current, current_snapshot)):
        raise StoreError("relation sources changed during query; retry query")
    if not shared:
        verify_context(repo_root, target, counterevidence)
        result.update(current=fresh_current["current"], counterevidence=counterevidence)
    result.update(as_of=fresh["as_of"], acquisition=snapshot.get("acquisition"), health={**fresh["health"], "relations": generation["health"]})
    return result
