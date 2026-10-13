"""Explicit, target-isolated derived generations and SQLite FTS recall."""
from __future__ import annotations

import base64
import fcntl
import json
import math
import struct
import os
import re
import shutil
import sqlite3
import uuid
from contextlib import contextmanager
from pathlib import Path

from tools.artifact_io import write_json_atomic
from tools.recall_sources import acquire_snapshot, acquire_knowledge_snapshot, text_partitions, digest, validate_capture, same_snapshot
from tools.recall_models import LocalModel, LocalModelError, float32_vector, unavailable
from tools.target_paths import canonical_target_value, target_storage_key
from tools.target_store import StoreError


class RecallIndexError(ValueError):
    """A derived generation cannot be safely consumed or published."""


def _root(repo_root, target, namespace, *, shared=False):
    if namespace not in {"text", "relations"}:
        raise RecallIndexError("namespace must be text or relations")
    root = Path(repo_root).absolute()
    path = (root / ".cache" / "knowledge-recall" / namespace if shared else
            root / "state" / target_storage_key(canonical_target_value(target)) / "recall-index" / namespace)
    for item in (path, *path.parents):
        if item.is_symlink():
            raise RecallIndexError(f"symlink index path refused: {item}")
    return path


def _mkdir(path):
    missing = []
    while not path.exists():
        missing.append(path)
        path = path.parent
    for item in reversed(missing):
        item.mkdir(mode=0o700, exist_ok=True)


@contextmanager
def _lock(path, *, exclusive):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH)
        yield
    finally:
        os.close(fd)


def _sync(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _read_json(path):
    if path.is_symlink():
        raise RecallIndexError(f"symlink index file refused: {path}")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise RecallIndexError(f"index object required: {path}")
    return value


def _fresh_snapshot(repo_root, target, snapshot, *, shared=False):
    if shared:
        return acquire_knowledge_snapshot(
            Path(repo_root), parsed_capture=snapshot.get("parse_capture"))
    partition = snapshot["binding"].get("source_partition")
    fresh = acquire_snapshot(Path(repo_root), target,
                             include_knowledge=False if partition == "target" else
                             snapshot["binding"].get("include_knowledge", True),
                             include_owner_relations=snapshot["binding"].get("include_owner_relations", False),
                             previous_capture=snapshot.get("capture"),
                             knowledge_parse_capture=snapshot.get("knowledge_parse_capture"))
    return text_partitions(fresh)["target"] if partition == "target" else fresh


def _bound_capture(capture, binding, source_revision=None):
    """Validate the source owner's opaque capture and its public Store binding."""
    if type(binding.get("include_owner_relations", False)) is not bool:
        raise RecallIndexError("invalid capture relation mode; rebuild index")
    capture = validate_capture(capture, target=binding["target"],
                               include_owner_relations=binding.get("include_owner_relations", False))
    for key in ("target", "store_id", "backend", "revision", "schema_version"):
        if key == "revision" and binding.get("source_partition") == "target" and key not in binding:
            continue  # Text partitions keep the audit watermark outside semantic bindings.
        if (type(binding.get(key)) is not type(capture["binding"][key])
                or capture["binding"][key] != binding[key]):
            raise RecallIndexError("capture Store binding mismatch; rebuild index")
    if source_revision is None and binding.get("source_partition") != "target":
        source_revision = binding.get("revision")
    if (type(source_revision) is not int or source_revision < 0
            or capture["binding"]["revision"] != source_revision):
        raise RecallIndexError("capture revision mismatch; rebuild index")
    return capture


def _load_generation(root, target, namespace, *, shared=False):
    pointer = _read_json(root / "CURRENT")
    generation = pointer.get("generation")
    if not isinstance(generation, str) or not re.fullmatch(r"[0-9a-f]{32}", generation):
        raise RecallIndexError("invalid generation identity in CURRENT; rebuild index")
    directory = root / "generations" / generation
    if directory.is_symlink() or directory.parent.is_symlink():
        raise RecallIndexError("symlink generation refused")
    manifest = _read_json(directory / "manifest.json")
    payload = _read_json(directory / "payload.json")
    if not isinstance(manifest.get("binding"), dict):
        raise RecallIndexError("invalid generation binding")
    if (type(manifest.get("schema_version")) is not int or manifest["schema_version"] != 1
            or manifest.get("generation") != generation
            or manifest.get("namespace") != namespace
            or manifest["binding"].get("target") != ("" if shared else canonical_target_value(target))
            or (shared and manifest["binding"].get("source_partition") != "knowledge")
            or digest(manifest) != pointer.get("manifest_digest") or digest(payload) != manifest.get("payload_digest")):
        raise RecallIndexError("generation integrity mismatch; rebuild index")
    capture = None
    capture_path = directory / "capture.json"
    if shared:
        if "capture_digest" in manifest or capture_path.exists() or capture_path.is_symlink():
            raise RecallIndexError("shared generation must not contain a target capture")
    elif "capture_digest" in manifest:
        capture = _read_json(capture_path)
        if digest(capture) != manifest["capture_digest"]:
            raise RecallIndexError("capture integrity mismatch; rebuild index")
        if type(manifest.get("source_revision")) is not int:
            raise RecallIndexError("capture requires an exact source revision; rebuild index")
        capture = _bound_capture(capture, manifest["binding"], manifest.get("source_revision"))
    elif capture_path.exists() or capture_path.is_symlink():
        raise RecallIndexError("unbound generation capture; rebuild index")
    return manifest, payload, capture


def publish_generation(repo_root, target, namespace, snapshot, payload: dict, *, shared=False, force=False) -> dict:
    """One publisher for target/shared text/relations; unchanged input is idempotent."""
    identity = "" if shared else canonical_target_value(target)
    if snapshot["binding"]["target"] != identity or not isinstance(payload, dict):
        raise RecallIndexError("snapshot target or payload mismatch")
    if shared and (snapshot["binding"].get("source_partition") != "knowledge"
                   or snapshot.get("capture") is not None
                   or any(doc.get("target") or not doc.get("source_ref", "").startswith("knowledge:")
                          or doc.get("review_state") != "reviewed" for doc in snapshot["documents"])):
        raise RecallIndexError("shared generation requires an independent reviewed knowledge snapshot")
    capture = None if shared else _bound_capture(snapshot.get("capture"), snapshot["binding"],
                                                 snapshot.get("source_revision"))
    capture_digest = digest(capture) if capture is not None else None
    root = _root(repo_root, target, namespace, shared=shared)
    _mkdir(root)
    with _lock(root, exclusive=True):
        fresh = _fresh_snapshot(repo_root, target, snapshot, shared=shared)
        if not same_snapshot(fresh, snapshot):
            raise RecallIndexError("sources changed during build; retry explicit build")
        if not force:
            try:
                previous, old_payload, _ = _load_generation(root, target, namespace, shared=shared)
            except (OSError, ValueError, KeyError, TypeError):
                previous = None
            if (previous and previous["binding"] == snapshot["binding"] and old_payload == payload
                    and previous.get("capture_digest") == capture_digest):
                return previous
        generations = root / "generations"
        if generations.is_symlink():
            raise RecallIndexError("symlink generations refused")
        _mkdir(generations)
        generation = uuid.uuid4().hex
        directory = generations / generation
        directory.mkdir(mode=0o700)
        published = False
        try:
            write_json_atomic(directory / "payload.json", payload, sort_keys=True)
            manifest = {"schema_version": 1, "generation": generation, "namespace": namespace,
                        "binding": snapshot["binding"], "payload_digest": digest(payload),
                        "source_as_of": snapshot.get("as_of"),
                        "source_revision": capture["binding"]["revision"] if capture is not None else None,
                        "format": "whole-unit-v1"}
            if capture is not None:
                write_json_atomic(directory / "capture.json", capture, sort_keys=True)
                manifest["capture_digest"] = capture_digest
            write_json_atomic(directory / "manifest.json", manifest, sort_keys=True)
            _sync(directory)
            _sync(generations)
            if not same_snapshot(_fresh_snapshot(repo_root, target, fresh, shared=shared), snapshot):
                raise RecallIndexError("sources changed during build; retry explicit build")
            write_json_atomic(root / "CURRENT", {"generation": generation, "manifest_digest": digest(manifest)})
            published = True
            _sync(root)
            return manifest
        finally:
            if not published:
                shutil.rmtree(directory)


def read_generation(repo_root, target, namespace, *, snapshot=None, shared=False) -> dict:
    """Reader locks protect copied payloads from prune; stale data is never usable."""
    try:
        root = _root(repo_root, target, namespace, shared=shared)
        with _lock(root, exclusive=False):
            manifest, payload, capture = _load_generation(root, target, namespace, shared=shared)
            if snapshot is not None and manifest["binding"] != snapshot["binding"]:
                return {"manifest": manifest, "payload": None, "capture": capture,
                        "health": {"status": "stale", "reason": "source binding changed; explicit rebuild required"}}
            health = {"status": "ready"}
            if not shared and capture is None:
                health["capture"] = {"status": "missing", "reason": "legacy generation requires full acquisition"}
            return {"manifest": manifest, "payload": payload, "capture": capture, "health": health}
    except (OSError, ValueError, KeyError, TypeError) as exc:
        return {"manifest": None, "payload": None, "capture": None, "health": unavailable(exc)}


def generation_exists(repo_root, target, namespace, *, shared=False):
    """Distinguish a missing generation from an unusable existing pointer."""
    pointer = _root(repo_root, target, namespace, shared=shared) / "CURRENT"
    return pointer.exists() or pointer.is_symlink()


def _combined_health(rows):
    states = [row["status"] for row in rows]
    return {"status": states[0] if states and len(set(states)) == 1 else "partial"}


def acquire_index_snapshot(repo_root, target, namespace="text", *, shared=False,
                           include_knowledge=True, full_rebuild=False):
    """Load immutable capture before reading owners; ordinary reads never repair it."""
    if namespace not in {"text", "relations"}:
        raise RecallIndexError("namespace must be text or relations")
    names = (["knowledge"] if shared else
             ["target", "knowledge"] if namespace == "text" and include_knowledge else ["target"])
    generations = {name: read_generation(repo_root, target, namespace, shared=name == "knowledge")
                   for name in names} if not full_rebuild else {}
    if shared:
        previous = generations.get("knowledge", {}).get("payload") or {}
        return acquire_knowledge_snapshot(
            Path(repo_root), parsed_capture=previous.get("parse_capture")), generations
    retained = generations.get("target", {})
    capture = retained.get("capture")
    reason = ("requested_full_rebuild" if full_rebuild else
              "generation_unavailable" if retained.get("health", {}).get("status") == "unavailable" else
              "generation_capture_missing" if capture is None else None)
    snapshot = acquire_snapshot(Path(repo_root), target,
                                include_knowledge=include_knowledge if namespace == "text" else False,
                                include_owner_relations=namespace == "relations",
                                previous_capture=capture, full_acquisition_reason=reason,
                                knowledge_parse_capture=(
                                    (generations.get("knowledge", {}).get("payload") or {}).get("parse_capture")
                                    if include_knowledge and namespace == "text" else None))
    return snapshot, generations


def index_status(repo_root, target, namespace="text", *, shared=False, include_knowledge=True):
    snapshot, _ = acquire_index_snapshot(repo_root, target, namespace, shared=shared,
                                         include_knowledge=include_knowledge)
    partitions = text_partitions(snapshot)
    results = {}
    for name, part in partitions.items():
        result = read_generation(repo_root, target, namespace, snapshot=part, shared=name == "knowledge")
        results[name] = {"manifest": result["manifest"], "health": result["health"],
                         "source_health": part["health"], "binding": part["binding"],
                         "acquisition": part.get("acquisition")}
    if not same_snapshot(_fresh_snapshot(repo_root, target, snapshot, shared=shared), snapshot):
        raise RecallIndexError("sources changed during status; retry status")
    primary = results.get("target", results.get("knowledge"))
    health = _combined_health([row["health"] for row in results.values()] +
                              [health for part in partitions.values() for health in part["health"].values()])
    return {**primary, "health": health, "partitions": results}


def prune_generations(repo_root, target, namespace="text", *, shared=False):
    root = _root(repo_root, target, namespace, shared=shared)
    removed = []
    if not root.exists():
        return {"removed": removed}
    with _lock(root, exclusive=True):
        current_manifest, _, _ = _load_generation(root, target, namespace, shared=shared)
        current = current_manifest["generation"]
        generations = root / "generations"
        candidates = []
        for directory in generations.iterdir():
            if directory.name == current or not re.fullmatch(r"[0-9a-f]{32}", directory.name) or directory.is_symlink():
                continue
            manifest = _read_json(directory / "manifest.json")
            binding = manifest.get("binding")
            if (not isinstance(binding, dict) or manifest.get("namespace") != namespace
                    or binding.get("target") != ("" if shared else canonical_target_value(target))
                    or (shared and binding.get("source_partition") != "knowledge")):
                raise RecallIndexError(f"invalid or foreign generation; refusing prune; inspect {directory / 'manifest.json'}")
            candidates.append(directory)
        for directory in candidates:
            shutil.rmtree(directory)
            removed.append(directory.name)
        _sync(generations)
    return {"removed": removed}


def _document_text(doc):
    return doc["text"] + "\n" + str(doc["conditions"]) + "\n" + json.dumps(doc["record"], ensure_ascii=False, sort_keys=True)


TEXT_RANKING = "rrf60-exact-cosine-v1"
TEXT_CHUNKING = "token-windows-canonical-parent-v2"


def _text_payload(snapshot, previous, encoder):
    sources = {doc["source_ref"]: digest(doc) for doc in snapshot["documents"]}
    if len(sources) != len(snapshot["documents"]):
        raise RecallIndexError("duplicate document source identity")
    by_ref = {doc["source_ref"]: doc for doc in snapshot["documents"]}
    identity = encoder.identity if encoder is not None else None
    reusable = (previous is not None and previous.get("chunking") == TEXT_CHUNKING
                and previous.get("ranking") == TEXT_RANKING and previous.get("encoder") == identity
                and isinstance(previous.get("sources"), dict))
    old_sources = previous["sources"] if reusable else {}
    unchanged = {ref for ref, value in sources.items() if old_sources.get(ref) == value}
    changed = set(sources) - unchanged
    with sqlite3.connect(":memory:") as conn:
        if reusable:
            try:
                conn.deserialize(base64.b64decode(previous["fts"], validate=True))
                if conn.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
                    raise sqlite3.DatabaseError("invalid previous FTS")
                rows = conn.execute("SELECT source_ref,text FROM documents").fetchall()
                if (len(rows) != len(old_sources) or {ref for ref, _ in rows} != set(old_sources)
                        or any(text != _document_text(by_ref[ref]) for ref, text in rows if ref in unchanged)):
                    raise sqlite3.DatabaseError("previous FTS source binding mismatch")
                conn.executemany("DELETE FROM documents WHERE source_ref=?",
                                 [(ref,) for ref in old_sources.keys() - unchanged])
            except (sqlite3.Error, KeyError, TypeError, ValueError) as exc:
                raise RecallIndexError("previous FTS unusable; request full_rebuild") from exc
        else:
            conn.execute("CREATE VIRTUAL TABLE documents USING fts5(source_ref UNINDEXED, text, tokenize='unicode61')")
        conn.executemany("INSERT INTO documents VALUES (?,?)",
                         [(ref, _document_text(by_ref[ref])) for ref in sorted(changed)])
        conn.commit()
        payload = {"fts": base64.b64encode(conn.serialize()).decode(), "ranking": TEXT_RANKING,
                   "chunking": TEXT_CHUNKING, "sources": sources, "vectors": [], "encoder": identity}
    if encoder is not None:
        chunks = [(ref, position, text) for ref in sorted(changed)
                  for position, text in enumerate(encoder.chunks(_document_text(by_ref[ref])))]
        vectors = encoder.encode([text for _, _, text in chunks]) if chunks else []
        if len(vectors) != len(chunks):
            raise LocalModelError("encoder returned wrong row count")
        payload["vectors"] = ([row for row in previous["vectors"] if row["source_ref"] in unchanged]
                              if reusable else [])
        # A hash-consistent old generation may still have an obsolete payload shape.
        retained_chunks = {ref: [] for ref in unchanged}
        for row in payload["vectors"]:
            _vector_values(row, identity["dimension"])
            if type(row["chunk"]) is not int or row["chunk"] < 0:
                raise RecallIndexError("invalid retained chunk; request full_rebuild")
            retained_chunks[row["source_ref"]].append(row["chunk"])
        if any(not positions or sorted(positions) != list(range(len(positions)))
               for positions in retained_chunks.values()):
            raise RecallIndexError("incomplete retained vectors; request full_rebuild")
        for (ref, position, _), vector in zip(chunks, vectors):
            vector = float32_vector(vector, identity["dimension"])
            payload["vectors"].append({"source_ref": ref, "chunk": position,
                "float32": base64.b64encode(struct.pack(f"<{len(vector)}f", *vector)).decode()})
        payload["vectors"].sort(key=lambda row: (row["source_ref"], row["chunk"]))
    return payload, {"reused_sources": len(unchanged), "updated_sources": len(changed),
                     "removed_sources": len(old_sources.keys() - sources.keys()),
                     "mode": "incremental" if reusable else "full"}


def build_text_index(repo_root, target, *, encoder_path=None, reranker_path=None,
                     include_knowledge=True, shared=False, full_rebuild=False):
    """Explicitly build independent partitions; a partial commit is never overall ready."""
    if reranker_path is not None:
        raise RecallIndexError("reranker_path applies to query, not index-build")
    snapshot, generations = acquire_index_snapshot(repo_root, target, "text", shared=shared,
                                                    include_knowledge=include_knowledge,
                                                    full_rebuild=full_rebuild)
    partitions = text_partitions(snapshot)
    try:
        encoder = LocalModel(encoder_path, "encoder")
        provider = {"status": "ready", "model": encoder.identity}
    except (LocalModelError, OSError, ValueError) as exc:
        encoder, provider = None, unavailable(exc)
    results = {}
    for name, part in partitions.items():
        public = name == "knowledge"
        try:
            if encoder_path is not None and encoder is None:
                raise RecallIndexError(f"requested encoder unavailable; previous generation preserved: {provider['reason']}")
            if any(row["status"] != "ready" for row in part["health"].values()):
                raise RecallIndexError("source health is not ready; previous generation preserved")
            previous = None
            if not full_rebuild:
                old = generations[name]
                previous = old["payload"]
                pointer = _root(repo_root, target, "text", shared=public) / "CURRENT"
                if previous is None and (pointer.exists() or pointer.is_symlink()):
                    raise RecallIndexError(f"previous generation unusable; request --full-rebuild: {old['health']}")
            payload, update = _text_payload(part, previous, encoder)
            if public and part.get("parse_capture") is not None:
                # Public Markdown/frontmatter parse results are reusable; review
                # receipts and blind artifacts remain outside the generation.
                payload["parse_capture"] = part["parse_capture"]
            payload["provider"] = provider
            payload["reranker"] = {"status": "not_requested", "reason": "explicit reranker_path applies at query time"}
            manifest = publish_generation(repo_root, target, "text", part, payload,
                                          shared=public, force=full_rebuild)
            health = _combined_health(list(part["health"].values()))
            results[name] = {"manifest": manifest, "health": health, "provider": provider,
                             "source_health": part["health"], "update": update,
                             "acquisition": part.get("acquisition")}
        except (OSError, ValueError, TypeError, KeyError, sqlite3.Error, StoreError) as exc:
            results[name] = {"manifest": None, "health": unavailable(exc), "provider": provider,
                             "source_health": part["health"], "acquisition": part.get("acquisition")}
    primary = results.get("target", results.get("knowledge"))
    return {**(primary["manifest"] or {}), "health": _combined_health([row["health"] for row in results.values()]),
            "acquisition": snapshot.get("acquisition"), "partitions": results}


def _vector_values(row, size):
    raw = base64.b64decode(row["float32"], validate=True)
    if len(raw) != size * 4:
        raise LocalModelError("persisted vector dimension mismatch")
    return float32_vector(struct.unpack(f"<{size}f", raw), size)


def _semantic_rank(payload, query, encoder_path):
    encoder = LocalModel(encoder_path, "encoder")
    if payload.get("encoder") != encoder.identity:
        raise LocalModelError("encoder identity differs from index; explicit rebuild required")
    queries = encoder.chunks(query)
    if len(queries) != 1:
        raise LocalModelError("query exceeds encoder token budget; original query not truncated")
    vector = encoder.encode([query])[0]
    size = encoder.identity["dimension"]
    norm = math.sqrt(sum(value * value for value in vector))
    scores = {}
    for row in payload["vectors"]:
        values = _vector_values(row, size)
        score = sum(a * b for a, b in zip(vector, values)) / (norm * math.sqrt(sum(value * value for value in values)))
        scores[row["source_ref"]] = max(scores.get(row["source_ref"], -math.inf), score)
    return sorted(scores, key=lambda ref: (-scores[ref], ref)), scores, encoder.identity


def _query_partition(repo_root, target, snapshot, query, *, limit=5, offset=0, encoder_path=None, reranker_path=None, shared=False):
    if (not isinstance(query, str) or len(query) > 512
            or (limit is not None and (type(limit) is not int or limit < 1))
            or type(offset) is not int or offset < 0):
        raise RecallIndexError("query must be <=512 characters, offset >=0 and limit positive or None")
    generation = read_generation(repo_root, target, "text", snapshot=snapshot, shared=shared)
    by_ref = {doc["source_ref"]: doc for doc in snapshot["documents"]}
    tokens = re.findall(r"\w+", query, re.UNICODE)
    ranked, channel = [], "source-order"
    health = generation["health"]
    payload = generation["payload"]
    if query and tokens and payload is not None:
        try:
            with sqlite3.connect(":memory:") as conn:
                conn.deserialize(base64.b64decode(payload["fts"], validate=True))
                conn.execute("PRAGMA query_only=ON")
                expression = " OR ".join('"' + token.replace('"', '""') + '"' for token in tokens)
                ranked = [row[0] for row in conn.execute("SELECT source_ref FROM documents WHERE documents MATCH ? ORDER BY bm25(documents),source_ref", (expression,))]
            channel = "fts5-bm25"
        except (sqlite3.Error, ValueError, KeyError, TypeError) as exc:
            health = unavailable(exc)
    if channel != "fts5-bm25":
        ranked = [ref for ref, doc in by_ref.items() if not query or any(token.casefold() in _document_text(doc).casefold() for token in tokens)]
        channel = "fresh-source-lexical" if query else "source-order"
    ranked = [ref for ref in ranked if ref in by_ref]
    lexical_ranks = {ref: index for index, ref in enumerate(ranked, 1)}
    semantic, reranker = unavailable("no explicit local encoder"), unavailable("no explicit local reranker")
    semantic_scores, rerank_scores, fused = {}, {}, {}
    model_binding = {}
    if not query:
        semantic = reranker = {"status": "not_requested", "reason": "empty query uses source order"}
    elif encoder_path is not None:
        if payload is None or not isinstance(payload.get("provider"), dict) or payload["provider"].get("status") != "ready":
            semantic = unavailable("current index has no usable vectors; explicit model-bound build required")
        else:
            try:
                semantic_refs, semantic_scores, identity = _semantic_rank(payload, query, encoder_path)
                for refs in (ranked, semantic_refs):
                    for position, ref in enumerate(refs, 1):
                        if ref in by_ref:
                            fused[ref] = fused.get(ref, 0.0) + 1.0 / (60 + position)
                ranked = sorted(fused, key=lambda ref: (-fused[ref], ref))
                semantic = {"status": "ready", "model": identity}
                model_binding["encoder"] = identity
                channel = "rrf60-fts5-exact-cosine"
            except (LocalModelError, OSError, ValueError, KeyError, TypeError) as exc:
                semantic = unavailable(exc)
    if query and reranker_path is not None:
        try:
            model = LocalModel(reranker_path, "reranker")
            chunks = [(ref, text) for ref in ranked for text in model.chunks(_document_text(by_ref[ref]), query=query)]
            values = model.score(query, [text for _, text in chunks]) if chunks else []
            for (ref, _), value in zip(chunks, values):
                rerank_scores[ref] = max(rerank_scores.get(ref, -math.inf), value)
            prior = {ref: position for position, ref in enumerate(ranked)}
            ranked.sort(key=lambda ref: (-rerank_scores[ref], prior[ref], ref))
            reranker = {"status": "ready", "model": model.identity}
            model_binding["reranker"] = model.identity
            channel += "+cross-encoder"
        except (LocalModelError, OSError, ValueError, TypeError) as exc:
            reranker = unavailable(exc)
    end = None if limit is None else offset + limit
    selected = ranked[offset:end]
    items = [{**by_ref[ref], "match": {"channel": channel, "lexical_rank": lexical_ranks.get(ref),
              "cosine": semantic_scores.get(ref), "rrf": fused.get(ref), "reranker": rerank_scores.get(ref)},
              "expand_ref": ref} for ref in selected]
    ranking_binding = digest({"query": query, "order": channel, "models": model_binding,
                              "semantic": semantic, "reranker": reranker, "ranked": ranked})
    return {"items": items, "health": {"lexical": health, "semantic": semantic, "reranker": reranker},
            "pagination": {"total": len(ranked), "remaining": max(0, len(ranked)-offset-len(items)),
                "offset": offset, "next_offset": offset+len(items) if offset+len(items)<len(ranked) else None,
                "order": channel, "ranking_binding": ranking_binding,
                "generation": (generation["manifest"] or {}).get("generation"),
                "expansion": "query_text(offset=next_offset, limit=...); source_ref"}}


def query_text(repo_root, target, snapshot, query, *, limit=5, offset=0,
               encoder_path=None, reranker_path=None, include_knowledge=True):
    """Fuse independent partitions; missing/stale indexes use current lexical originals."""
    if (not isinstance(query, str) or len(query) > 512
            or (limit is not None and (type(limit) is not int or limit < 1))
            or type(offset) is not int or offset < 0):
        raise RecallIndexError("query must be <=512 characters, offset >=0 and limit positive or None")
    if snapshot["binding"].get("source_partition") != "knowledge":
        if snapshot["binding"]["target"] != canonical_target_value(target):
            raise RecallIndexError("query snapshot belongs to another target")
    partitions = text_partitions(snapshot)
    if not include_knowledge:
        partitions.pop("knowledge", None)
    results, candidates, ranks = {}, {}, {}
    for name, part in partitions.items():
        result = _query_partition(repo_root, target, part, query, limit=None,
                                  encoder_path=encoder_path, reranker_path=reranker_path,
                                  shared=name == "knowledge")
        results[name] = {"health": result["health"], "pagination": result["pagination"],
                         "source_health": part["health"]}
        for position, item in enumerate(result["items"], 1):
            ref = item["source_ref"]
            candidates[ref] = {**item, "match": {**item["match"], "partition": name}}
            ranks[ref] = 1.0 / (60 + position)
    ranked = sorted(candidates, key=lambda ref: (-ranks[ref], ref)) if query else list(candidates)
    end = None if limit is None else offset + limit
    items = [candidates[ref] for ref in ranked[offset:end]]
    health = {channel: _combined_health([row["health"][channel] for row in results.values()])
              for channel in ("lexical", "semantic", "reranker")}
    if not query:
        health["semantic"] = health["reranker"] = {"status": "not_requested"}
    health["lexical"] = _combined_health([health["lexical"]] +
                         [value for row in results.values() for value in row["source_health"].values()])
    health["partitions"] = results
    generations = {name: row["pagination"]["generation"] for name, row in results.items()}
    return {"items": items, "health": health,
            "pagination": {"total": len(ranked), "remaining": max(0, len(ranked)-offset-len(items)),
                           "offset": offset, "next_offset": offset+len(items) if offset+len(items)<len(ranked) else None,
                           "order": "partition-rrf60" if query else "source-order",
                           "ranking_binding": digest({"query": query, "partitions": results, "ranked": ranked}),
                           "generation": generations.get("target"), "generations": generations,
                           "expansion": "query_text(offset=next_offset, limit=...); source_ref"}}
