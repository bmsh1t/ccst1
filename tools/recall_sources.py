"""Read-only acquisition shared by text and relation recall projections.

Capture v1 is a disposable JSON projection: binding (including Store schema),
include_owner_relations, complete target documents, experience_dependencies
(ID -> external REF list), owner_groups (key/source_refs/dependencies), and
probes (ref/fingerprint). Groups retain empty results. Only public projection
DTOs are stored; current facts, private bytes and shared knowledge are excluded.
Dependencies and fingerprints invalidate consumers, never interpret health.
Ephemeral source_fences bind file identities within one acquisition/use cycle;
they are not semantic fingerprints and never enter a persisted capture.
"""
from __future__ import annotations

import hashlib
import json
import fcntl
import os
from datetime import date, datetime, timezone
from pathlib import Path

from tools.knowledge_registry import KnowledgeRegistryError, load_registry, parse_knowledge_document
from tools.knowledge_review import knowledge_path, read_published_review
from tools.knowledge_relations import method_descriptor, parse_method_relations
from tools.scope_context import read_scope_source
from tools.target_paths import canonical_target_value
from tools.target_store import StoreError, runtime_store


def digest(value) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()).hexdigest()


def same_snapshot(left, right):
    """Compare closed inputs and per-call fences, excluding time and read statistics."""
    return (left["binding"] == right["binding"]
            and left.get("capture") == right.get("capture")
            and left.get("source_fences") == right.get("source_fences"))


def _metadata_scalar(value):
    if isinstance(value, date):
        return value.isoformat()
    raise ValueError(f"knowledge metadata cannot be represented in recall JSON: {type(value).__name__}")


def _parse_entry_digest(body, metadata):
    """Bind the reusable DTO to its normalized parse output, not only source bytes."""
    return digest({"body": body, "metadata": metadata})


def acquire_current(repo_root: Path, target: str, *, limit: int = 20) -> dict:
    """Read bounded owner pages, rejecting mixed revisions rather than merging them."""
    store = runtime_store(repo_root, canonical_target_value(target))
    before = store.binding()
    scope = read_scope_source(repo_root, store.target)
    memory = store.memory_context(limit=limit)
    actions = store.action_page(statuses=("ready", "claimed", "blocked"), limit=limit)
    findings = store.finding_page(limit=limit)
    after = store.binding()
    if scope != read_scope_source(repo_root, store.target):
        raise StoreError("recall Scope changed; retry query")
    if before != after or any(page["revision"] != before["revision"] or page["store_id"] != before["store_id"]
                              for page in (memory, actions, findings)):
        raise StoreError("recall current snapshot changed; retry query")
    return {"binding": before, "memory": memory, "active_actions": actions,
            "findings": findings, "scope": {"status": "ready", **scope},
            "adjudications": {"owner": "TargetStore.finding_page", "page_ref": "current.findings",
                               "fields": ["disposition", "assessment", "deliveries"], "authority": "recorded decisions; recheck before execution"},
            "expansion": {"actions": "TargetStore.action_page(statuses=('ready','claimed','blocked'), cursor=...)",
                          "findings": "TargetStore.finding_page(cursor=...)"}}


def acquire_knowledge(repo_root: Path, *, parsed_capture=None,
                      return_parse_capture: bool = False):
    """Read reviewed knowledge while optionally reusing a validated parse capture.

    The capture contains only public Markdown/frontmatter parse results. Registry,
    published review, raw-byte, maturity, and relation checks still run on every
    acquisition. The extended return form is private plumbing for shared index
    generations; the legacy two-value form remains unchanged.
    """
    try:
        descriptor = os.open(Path(repo_root) / "knowledge", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    except OSError as exc:
        result = ([], {"status": "unavailable", "reason": str(exc)[:240]}, None,
                  {"mode": "unavailable", "parsed_sources": 0, "reused_sources": 0})
        return result if return_parse_capture else result[:2]
    try:
        fcntl.flock(descriptor, fcntl.LOCK_SH)
        result = _acquire_knowledge(Path(repo_root), parsed_capture=parsed_capture)
        return result if return_parse_capture else result[:2]
    finally:
        os.close(descriptor)


def _acquire_knowledge(repo_root: Path, *, parsed_capture=None):
    repo_root = repo_root.absolute()
    documents, errors, excluded, observed = [], [], [], {}
    parse_entries, parsed_sources, reused_sources = {}, 0, 0

    def read_review_bytes(path: Path) -> bytes:
        ref = str(path.relative_to(repo_root))
        try:
            raw = path.read_bytes()
        except FileNotFoundError:
            if ref in observed and observed[ref] is not None:
                raise StoreError("knowledge source disappeared during acquisition; retry")
            observed[ref] = None
            raise
        fingerprint = hashlib.sha256(raw).hexdigest()
        if ref in observed and observed[ref] != fingerprint:
            raise StoreError("knowledge review changed during acquisition; retry")
        observed[ref] = fingerprint
        return raw

    methods = {}
    try:
        registry_path = repo_root / "knowledge" / "capabilities.yaml"
        if registry_path.is_symlink() or registry_path.parent.is_symlink():
            raise KnowledgeRegistryError("symlink knowledge registry refused")
        registry_before = registry_path.read_bytes()
        registry = load_registry(repo_root)
        registry_hash = hashlib.sha256(registry_before).hexdigest()
        if registry.path.read_bytes() != registry_before:
            raise KnowledgeRegistryError("knowledge registry changed during acquisition")
        entries = registry.method_entries()
    except (KnowledgeRegistryError, OSError, UnicodeError) as exc:
        return ([], {"status": "unavailable", "reason": str(exc)[:240]}, None,
                {"mode": "unavailable", "parsed_sources": 0, "reused_sources": 0})

    cache = {}
    if isinstance(parsed_capture, dict) and parsed_capture.get("schema_version") == 1 \
            and parsed_capture.get("registry_hash") == registry_hash \
            and isinstance(parsed_capture.get("entries"), dict):
        cache = parsed_capture["entries"]
    for entry in entries:
        methods[entry["id"]] = {"status": "unavailable", "reason": "method is not active"}
        if entry.get("status", "active") != "active":
            continue
        ref = entry.get("file")
        try:
            if not isinstance(ref, str) or not ref.startswith(("knowledge/cards/", "knowledge/playbooks/", "knowledge/payloads/")) or ".." in Path(ref).parts:
                raise ValueError("invalid registered knowledge path")
            path = repo_root / ref
            if any(part.is_symlink() for part in (path, *path.parents) if part != repo_root.parent):
                raise ValueError("knowledge path contains symlink")
            if not path.resolve().is_relative_to((repo_root / "knowledge").resolve()):
                raise ValueError("knowledge escapes root")
            raw = read_review_bytes(path)
            source_hash = hashlib.sha256(raw).hexdigest()
            observed[ref] = source_hash
            text = raw.decode("utf-8")
            cached = cache.get(ref)
            if (isinstance(cached, dict) and cached.get("id") == entry.get("id")
                    and cached.get("file") == ref and cached.get("source_hash") == source_hash
                    and isinstance(cached.get("text"), str) and cached["text"] == text
                    and isinstance(cached.get("body"), str)
                    and isinstance(cached.get("metadata"), dict)
                    and cached.get("parse_digest") == _parse_entry_digest(cached["body"], cached["metadata"])):
                body, metadata = cached["body"], cached["metadata"]
                reused_sources += 1
            else:
                parsed = parse_knowledge_document(text)
                parsed_sources += 1
                if parsed.frontmatter_error:
                    raise ValueError(parsed.frontmatter_error)
                body, metadata = parsed.body, parsed.metadata or {}
            try:
                metadata = json.loads(json.dumps(metadata, default=_metadata_scalar, allow_nan=False))
            except TypeError as exc:
                raise ValueError("knowledge metadata is not JSON-compatible") from exc
            for label, maturity in (("frontmatter", metadata.get("maturity")),
                                    ("registry", entry.get("maturity", metadata.get("maturity")))):
                if maturity is not None and not isinstance(maturity, str):
                    raise ValueError(f"{label} maturity must be a string")
            tags = metadata.get("trigger_tags", [])
            if not isinstance(tags, list) or any(not isinstance(tag, str) for tag in tags):
                raise ValueError("knowledge trigger_tags must be a list of strings")
            if (metadata.get("status", "active") != "active"
                    or metadata.get("maturity") not in {"tested", "proven"}
                    or entry.get("maturity", metadata.get("maturity")) not in {"tested", "proven"}):
                methods[entry["id"]]["reason"] = "draft/unreviewed: requires active tested/proven maturity"
                excluded.append({"ref": ref, "reason": methods[entry["id"]]["reason"]})
                parse_entries[ref] = {"id": entry["id"], "file": ref,
                                     "source_hash": source_hash, "text": text,
                                     "body": body, "metadata": metadata,
                                     "parse_digest": _parse_entry_digest(body, metadata)}
                continue
            if metadata.get("id") != entry.get("id"):
                raise ValueError("knowledge identity differs from registry")
            parse_entries[ref] = {"id": entry["id"], "file": ref,
                                 "source_hash": source_hash, "text": text,
                                 "body": body, "metadata": metadata,
                                 "parse_digest": _parse_entry_digest(body, metadata)}
            review = read_published_review(repo_root, entry, raw, read_bytes=read_review_bytes)
            methods[entry["id"]] = method_descriptor(entry, metadata, body, source_hash, review)
            if review["status"] != "ready":
                errors.append({"ref": ref, "status": "review-unverified", "review": review,
                               "reason": review.get("reason"), "expansion": ref})
                continue
            documents.append({"source_ref": f"knowledge:{entry['id']}", "source_hash": observed[ref],
                              "text": text, "conditions": metadata.get("conditions", ""),
                              "target": "", "kind": "knowledge_card", "review_state": "reviewed",
                              "claims": [], "source_health": [{"status": "ready", "ref": ref}],
                              "correction_refs": [], "dependency_refs": [],
                              "record": {"id": entry["id"], "file": ref, "kind": entry["kind"],
                                         "metadata": metadata, "review": review}, "expansion": ref})
        except (OSError, UnicodeError, ValueError) as exc:
            methods[entry["id"]] = {"status": "unavailable", "reason": str(exc)[:240]}
            errors.append({"ref": ref, "reason": str(exc)[:240]})
    for document in documents:
        record = document["record"]
        document["method_relations"], document["method_relation_errors"] = [], []
        try:
            document["method_relations"] = parse_method_relations(
                record["metadata"], method_id=record["id"], methods=methods)
        except ValueError as exc:
            error = {"source_ref": document["source_ref"], "ref": record["file"], "reason": str(exc)}
            document["method_relation_errors"].append(error)
            errors.append(error)
    if knowledge_path(repo_root, "knowledge/capabilities.yaml").read_bytes() != registry_before:
        raise StoreError("knowledge registry changed; retry acquisition")
    for ref, value in observed.items():
        path = knowledge_path(repo_root, ref)
        try:
            current = hashlib.sha256(path.read_bytes()).hexdigest()
        except FileNotFoundError:
            current = None
        if current != value:
            raise StoreError("knowledge source bytes changed; retry acquisition")
    health = {"status": "partial" if errors else "ready", "errors": errors, "excluded": excluded,
              "registry_hash": registry_hash, "count": len(documents)}
    parse_capture = {"schema_version": 1, "registry_hash": registry_hash,
                     "entries": parse_entries}
    parse_stats = {"mode": "incremental" if reused_sources else "full",
                   "parsed_sources": parsed_sources, "reused_sources": reused_sources}
    return documents, health, parse_capture, parse_stats


_PROBE_OWNERS = {"artifact", "assessment", "operation", "session", "object", "knowledge", "history", "case"}
_BINDING_FIELDS = {"target", "store_id", "backend", "revision", "schema_version"}


def _ref_key(ref):
    return ref["owner"], ref["record_id"]


def _refs(values):
    return [{"owner": owner, "record_id": record_id}
            for owner, record_id in sorted({_ref_key(value) for value in values})]


def validate_capture(capture, *, target, include_owner_relations):
    """Reject unusable derived data without opening any canonical owner."""
    def require(condition, message):
        if not condition:
            raise ValueError("invalid recall capture: " + message)

    def ref(value, owners):
        require(isinstance(value, dict) and set(value) == {"owner", "record_id"}, "reference shape")
        require(isinstance(value["owner"], str) and value["owner"] in owners
                and isinstance(value["record_id"], str) and bool(value["record_id"])
                and value["record_id"] == value["record_id"].strip()
                and "\x00" not in value["record_id"], "reference identity")
        require(value["owner"] != "case" or value["record_id"] == "context", "case identity")
        return _ref_key(value)

    def ref_list(values):
        require(isinstance(values, list), "dependency list")
        keys = [ref(value, _PROBE_OWNERS) for value in values]
        require(len(keys) == len(set(keys)), "duplicate dependency")
        return set(keys)

    def sha(value):
        return isinstance(value, str) and len(value) == 64 and all(c in "0123456789abcdef" for c in value)

    require(isinstance(capture, dict) and set(capture) == {
        "schema_version", "binding", "include_owner_relations", "documents",
        "experience_dependencies", "owner_groups", "probes"}, "shape")
    require(type(capture["schema_version"]) is int and capture["schema_version"] == 1, "schema")
    require(type(capture["include_owner_relations"]) is bool
            and capture["include_owner_relations"] == include_owner_relations, "owner relation mode")
    binding = capture["binding"]
    require(isinstance(binding, dict) and set(binding) == _BINDING_FIELDS, "Store binding")
    require(binding["target"] == canonical_target_value(target)
            and all(isinstance(binding[key], str) and binding[key] for key in ("target", "store_id", "backend"))
            and type(binding["revision"]) is int and binding["revision"] >= 0
            and type(binding["schema_version"]) is int and binding["schema_version"] > 0, "Store identity")
    try:
        json.dumps(capture, allow_nan=False)
    except (TypeError, ValueError, OverflowError, RecursionError) as exc:
        raise ValueError("invalid recall capture: non-JSON data") from exc
    require(isinstance(capture["documents"], list), "documents")
    experiences, owners, seen = {}, {}, set()
    for doc in capture["documents"]:
        require(isinstance(doc, dict) and doc.get("target") == binding["target"], "document target")
        source = doc.get("source_ref")
        require(isinstance(source, str) and source not in seen, "document identity")
        seen.add(source)
        require(isinstance(doc.get("record"), dict) and sha(doc.get("source_hash")), "document record")
        record = doc["record"]
        if source.startswith("experience:"):
            identifier = record.get("id")
            require(isinstance(identifier, str) and source == "experience:" + identifier
                    and bool(identifier) and isinstance(record.get("created_at"), str)
                    and type(record.get("version")) is int and record["version"] >= 0,
                    "experience identity")
            require(all(isinstance(record.get(key), str) for key in ("statement", "conditions", "kind")), "experience fields")
            require(isinstance(record.get("evidence"), list) and all(
                isinstance(item, dict) and isinstance(item.get("operation_id"), str) and bool(item["operation_id"])
                and type(item.get("step")) is int and item["step"] >= 0 for item in record["evidence"]), "experience evidence")
            require(doc == _experience_document(record, binding["target"]), "experience projection")
            experiences[identifier] = doc
        else:
            require(set(doc) == {"source_ref", "target", "kind", "record", "owner_relations",
                                 "source_health", "source_errors", "source_hash"}, "owner document shape")
            require(include_owner_relations and source.startswith("owner:")
                    and doc.get("kind") == "owner_provenance"
                    and all(isinstance(doc.get(key), list) for key in ("owner_relations", "source_health", "source_errors")),
                    "owner document")
            require(doc["source_hash"] == digest({key: value for key, value in doc.items() if key != "source_hash"}),
                    "owner document digest")
            owners[source] = doc
    dependencies = capture["experience_dependencies"]
    require(isinstance(dependencies, dict) and set(dependencies) == set(experiences), "experience dependencies")
    required_probes = set()
    for values in dependencies.values():
        required_probes.update(ref_list(values))
    require(isinstance(capture["owner_groups"], list), "owner groups")
    group_keys, grouped = set(), set()
    for group in capture["owner_groups"]:
        require(isinstance(group, dict) and set(group) == {"key", "source_refs", "dependencies"}, "owner group shape")
        key = ref(group["key"], {"case", "operation", "experience"})
        require(include_owner_relations and key not in group_keys, "owner group identity")
        group_keys.add(key)
        require(key[0] != "experience" or key[1] in experiences, "group experience missing")
        sources = group["source_refs"]
        require(isinstance(sources, list) and all(isinstance(value, str) for value in sources), "group sources")
        for source in sources:
            require(source in owners and source not in grouped, "group document missing/duplicate")
            if key[0] == "experience":
                require(source == f"owner:experience:{key[1]}:{experiences[key[1]]['record']['version']}", "group version")
            elif key[0] == "operation":
                require(source == "owner:operation:" + key[1], "group operation")
            else:
                require(source == "owner:case" or source.startswith("owner:case:"), "group case")
            grouped.add(source)
        refs = ref_list(group["dependencies"])
        if key[0] in {"case", "operation"}:
            require(key in refs, "group probe missing")
        else:
            require(ref_list(dependencies[key[1]]) <= refs, "group dependencies incomplete")
            require({("operation", item["operation_id"]) for item in experiences[key[1]]["record"]["evidence"]} <= refs,
                    "group operation dependencies incomplete")
        required_probes.update(refs)
    require(grouped == set(owners), "ungrouped owner document")
    if include_owner_relations:
        require(("case", "context") in group_keys
                and {("experience", key) for key in experiences} <= group_keys, "owner groups incomplete")
    require(isinstance(capture["probes"], list), "probes")
    probed = set()
    for probe in capture["probes"]:
        require(isinstance(probe, dict) and set(probe) == {"ref", "fingerprint"}, "probe shape")
        key = ref(probe["ref"], _PROBE_OWNERS)
        require(key not in probed and sha(probe["fingerprint"]), "probe fingerprint")
        probed.add(key)
    require(probed == required_probes, "probe coverage")
    return capture


def acquire_snapshot(repo_root: Path, target: str, *, include_knowledge: bool = True,
                     include_owner_relations: bool = False, previous_capture=None,
                     full_acquisition_reason=None,
                     knowledge_parse_capture=None) -> dict:
    """Acquire a closed owner-derived view, re-reading only invalidated groups."""
    repo_root = Path(repo_root).absolute()
    target = canonical_target_value(target)
    store = runtime_store(repo_root, target)
    current = acquire_current(repo_root, target)
    previous, reason = previous_capture, full_acquisition_reason
    if reason is not None and (not isinstance(reason, str) or not reason):
        raise ValueError("full_acquisition_reason must be a non-empty string")
    if reason is not None:
        previous = None
    elif previous is None:
        reason = "capture_missing"
    else:
        try:
            validate_capture(previous, target=target, include_owner_relations=include_owner_relations)
        except ValueError:
            previous, reason = None, "capture_invalid_or_incompatible"
    delta = store.recall_delta(previous["binding"] if previous is not None else None,
                               include_owner_relations=include_owner_relations)
    binding = delta["binding"]
    if any(binding[key] != value for key, value in current["binding"].items()):
        raise StoreError("recall source revision changed; retry acquisition")
    if delta["full_acquisition_reason"] is not None:
        previous, reason = None, reason or delta["full_acquisition_reason"]
    stats = {"mode": "incremental" if previous is not None else "full",
             "full_acquisition_reason": reason, "experience_rows_read": 0,
             "owner_groups_read": 0, "reused_experiences": 0, "external_probes": 0,
             "knowledge_acquisition": "full_owner_audit" if include_knowledge else "not_requested"}
    documents = {doc["source_ref"]: doc for doc in previous["documents"]} if previous else {}
    dependencies = dict(previous["experience_dependencies"]) if previous else {}
    groups = {_ref_key(group["key"]): group for group in previous["owner_groups"]} if previous else {}
    fingerprints, fences = {}, {}

    def accept_probes(items, source_fences):
        stats["external_probes"] += len(items)
        if {_ref_key(item["ref"]) for item in items} != {_ref_key(item["ref"]) for item in source_fences}:
            raise StoreError("recall source fence coverage is incomplete")
        for values, retained in ((items, fingerprints), (source_fences, fences)):
            for item in values:
                key, value = _ref_key(item["ref"]), item["fingerprint"]
                if key in retained and retained[key] != value:
                    raise StoreError("recall external source changed; retry acquisition")
                retained[key] = value

    def probe(refs):
        refs = _refs(refs)
        for offset in range(0, max(1, len(refs)), 1000):
            result = store.recall_probe(refs[offset:offset + 1000], expected_binding=binding)
            if result["binding"] != binding:
                raise StoreError("recall probe revision changed; retry acquisition")
            accept_probes(result["items"], result["fences"])

    pending = set(delta["experience_ids"])
    owner_keys = {_ref_key(key) for key in delta["owner_keys"]}
    if previous is not None:
        probe([item["ref"] for item in previous["probes"]])
        changed = {_ref_key(item["ref"]) for item in previous["probes"]
                   if fingerprints[_ref_key(item["ref"])] != item["fingerprint"]}
        pending.update(identifier for identifier, refs in dependencies.items()
                       if any(_ref_key(ref) in changed for ref in refs))
        owner_keys.update(key for key, group in groups.items()
                          if any(_ref_key(ref) in changed for ref in group["dependencies"]))
    pending.update(identifier for owner, identifier in owner_keys if owner == "experience")
    identifiers = sorted(pending)
    for offset in range(0, len(identifiers), 1000):
        wanted = identifiers[offset:offset + 1000]
        result = store.recall_rows(wanted, expected_binding=binding)
        if result["binding"] != binding or {row["id"] for row in result["items"]} != set(wanted):
            raise StoreError("recall rows changed or incomplete; retry acquisition")
        accept_probes(result["probes"], result["fences"])
        stats["experience_rows_read"] += len(result["items"])
        for row in result["items"]:
            documents["experience:" + row["id"]] = _experience_document(row, target)
            dependencies[row["id"]] = _refs(result["dependencies"][row["id"]])
    experiences = {doc["record"]["id"]: doc for doc in documents.values()
                   if doc["source_ref"].startswith("experience:")}
    if include_owner_relations:
        owner_keys.update(("experience", identifier) for identifier in pending)
        for key, group_documents, refs in _owner_groups(store, binding, owner_keys, experiences, dependencies, probe):
            for source in groups.get(key, {}).get("source_refs", []):
                documents.pop(source)
            documents.update((doc["source_ref"], doc) for doc in group_documents)
            groups[key] = {"key": {"owner": key[0], "record_id": key[1]},
                           "source_refs": [doc["source_ref"] for doc in group_documents], "dependencies": refs}
            stats["owner_groups_read"] += 1
    stats["reused_experiences"] = len(experiences) - len(pending)
    ordered_experiences = sorted(experiences.values(), key=lambda doc: (doc["record"]["created_at"], doc["record"]["id"]), reverse=True)
    ranks = {doc["record"]["id"]: rank for rank, doc in enumerate(ordered_experiences)}
    ordered_groups = sorted(groups.values(), key=lambda group: (
        {"case": 0, "operation": 1, "experience": 2}[group["key"]["owner"]],
        ranks[group["key"]["record_id"]] if group["key"]["owner"] == "experience" else group["key"]["record_id"]))
    owners = [documents[source] for group in ordered_groups for source in group["source_refs"]]
    target_documents = ordered_experiences + owners
    errors = [error for doc in owners for error in doc["source_errors"]]
    owner_health = ({"status": "partial" if errors else "ready", "errors": errors, "owner_sources": len(owners)}
                    if include_owner_relations else {"status": "ready"})
    all_refs = _refs([ref for refs in dependencies.values() for ref in refs]
                     + [ref for group in ordered_groups for ref in group["dependencies"]])
    if include_knowledge:
        knowledge, knowledge_health, parse_capture, parse_stats = acquire_knowledge(
            repo_root, parsed_capture=knowledge_parse_capture, return_parse_capture=True)
        stats["knowledge_parse"] = {"mode": "incremental" if knowledge_parse_capture else "full",
                                    "parse": parse_stats, "verification": "all-source-byte-fence"}
    else:
        knowledge, knowledge_health, parse_capture = [], {"status": "not_requested"}, None
        stats["knowledge_parse"] = {"mode": "not_requested"}
    probe(all_refs)
    if current != acquire_current(repo_root, target) or store.binding() != current["binding"]:
        raise StoreError("current source health or revision changed; retry acquisition")
    probes = [{"ref": ref, "fingerprint": fingerprints[_ref_key(ref)]} for ref in all_refs]
    capture = {"schema_version": 1, "binding": binding, "include_owner_relations": include_owner_relations,
               "documents": target_documents, "experience_dependencies": dependencies,
               "owner_groups": ordered_groups, "probes": probes}
    validate_capture(capture, target=target, include_owner_relations=include_owner_relations)
    return {"binding": {**binding, "source_digest": digest([target_documents + knowledge, knowledge_health, owner_health, probes]),
                         "scope_sha256": current["scope"]["sha256"], "current_digest": digest(current),
                         "include_knowledge": include_knowledge, "include_owner_relations": include_owner_relations},
            "current": current, "documents": target_documents + knowledge,
            "health": {"target": owner_health, "knowledge": knowledge_health},
            "source_fences": [{"ref": ref, "fingerprint": fences[_ref_key(ref)]} for ref in all_refs],
            "capture": capture, "acquisition": stats,
            "knowledge_parse_capture": parse_capture,
            "as_of": datetime.now(timezone.utc).isoformat()}


def knowledge_snapshot(documents, health, *, as_of=None, parse_capture=None,
                       acquisition=None):
    """Bind reviewed public methods without any target/private snapshot fields."""
    if any(doc.get("target") or not doc.get("source_ref", "").startswith("knowledge:")
           or doc.get("review_state") != "reviewed" for doc in documents):
        raise ValueError("shared recall accepts reviewed knowledge only")
    result = {"binding": {"target": "", "source_partition": "knowledge",
                        "registry_hash": health.get("registry_hash"),
                        "source_digest": digest([documents, health])},
            "documents": documents, "health": {"knowledge": health},
            "as_of": as_of or datetime.now(timezone.utc).isoformat()}
    if parse_capture is not None:
        result["parse_capture"] = parse_capture
    if acquisition is not None:
        result["acquisition"] = acquisition
    return result


def acquire_knowledge_snapshot(repo_root: Path, *, parsed_capture=None) -> dict:
    """Acquire an independent shared snapshot; never open a target Store."""
    documents, health, parse_capture, parse_stats = acquire_knowledge(
        Path(repo_root), parsed_capture=parsed_capture, return_parse_capture=True)
    return knowledge_snapshot(documents, health, parse_capture=parse_capture,
                              acquisition={"mode": "incremental" if parsed_capture else "full",
                                           "parse": parse_stats,
                                           "verification": "all-source-byte-fence"})


def text_partitions(snapshot: dict) -> dict:
    """Derive two text inputs from one already closed snapshot, without I/O."""
    if snapshot["binding"].get("source_partition") == "knowledge":
        return {"knowledge": snapshot}
    if snapshot["binding"].get("source_partition") == "target":
        return {"target": snapshot}
    target = snapshot["binding"]["target"]
    documents, knowledge = [], []
    for document in snapshot["documents"]:
        if document["source_ref"].startswith("knowledge:"):
            knowledge.append(document)
        elif document.get("target") == target and (document["source_ref"].startswith("experience:")
                or snapshot["binding"].get("include_owner_relations") and document["source_ref"].startswith("owner:")):
            documents.append(document)
        else:
            raise ValueError("foreign source in target recall snapshot")
    target_health = snapshot["health"]["target"]
    result = {"target": {"binding": {"target": target, "store_id": snapshot["binding"]["store_id"],
                                      "source_partition": "target",
                                      "source_digest": digest([documents, target_health, (snapshot.get("capture") or {}).get("probes", [])]),
                                      "backend": snapshot["binding"].get("backend"),
                                      "schema_version": snapshot["binding"].get("schema_version")},
                         "documents": documents, "health": {"target": target_health},
                         "as_of": snapshot.get("as_of"),
                         "source_revision": snapshot["binding"].get("revision"),
                         "source_fences": snapshot.get("source_fences"),
                         "capture": snapshot.get("capture"), "acquisition": snapshot.get("acquisition")}}
    if snapshot["binding"].get("include_owner_relations"):
        result["target"]["binding"].update(include_owner_relations=True,
                                           revision=snapshot["binding"]["revision"])
    if snapshot["binding"].get("include_knowledge", True):
        knowledge_acquisition = None
        acquisition = snapshot.get("acquisition")
        if isinstance(acquisition, dict) and "knowledge_parse" in acquisition:
            knowledge_acquisition = {"knowledge_parse": acquisition["knowledge_parse"]}
        result["knowledge"] = knowledge_snapshot(
            knowledge, snapshot["health"]["knowledge"], as_of=snapshot.get("as_of"),
            parse_capture=snapshot.get("knowledge_parse_capture"),
            acquisition=knowledge_acquisition)
    return result


def _experience_document(row, target):
    doc = {key: row.get(key, []) for key in ("claims", "source_health", "correction_refs", "dependency_refs", "applicability")}
    doc.update(source_ref=f"experience:{row['id']}", text=row["statement"], conditions=row["conditions"],
               review_state=row.get("review_state", "advisory"), kind=row["kind"], target=target, record=row)
    doc["source_hash"] = digest(row)
    return doc


def _owner_groups(store, binding, keys, experiences, dependencies, probe):
    """Read only named owner groups and directly referenced exact executions."""
    entities, executions, versions = {}, {}, {}

    def entity(owner, record_id):
        key = (owner, record_id)
        if key not in entities:
            entities[key] = store.experience_entity(owner, record_id)
        return entities[key]

    def document(ref, record, relations, health=None):
        health = health if health is not None else [{"status": "available", "source_ref": ref}]
        failures = [{"source_ref": ref, **row} for row in health if row["status"] != "available"]
        value = {"source_ref": ref, "target": store.target, "kind": "owner_provenance",
                 "record": record, "owner_relations": relations, "source_health": health,
                 "source_errors": failures}
        value["source_hash"] = digest(value)
        return value

    def relation(subject, predicate, obj, provenance, observed_at=None):
        return {"subject": subject, "predicate": predicate, "object": obj,
                "provenance": provenance, "observed_at": observed_at}

    def execution(operation_id):
        if operation_id in executions:
            return executions[operation_id]
        probe([{"owner": "operation", "record_id": operation_id}])
        record = store.execution(operation_id)
        operation = entity("operation", operation_id)
        attempt = record["attempt"]
        if attempt["id"] != record["attempt_id"]:
            raise StoreError("operation attempt binding is corrupt")
        provenance = {"operation_id": operation_id, "attempt_id": attempt["id"]}
        links, health = [], []
        for observation in record["observations"]:
            for artifact in observation["artifacts"]:
                status = store.artifact_status(artifact["id"])
                health.append({"status": "available" if status["authorized"] else "unavailable",
                               "artifact_id": artifact["id"], "artifact": status})
                links.append(relation(operation, "observed_artifact", entity("artifact", artifact["id"]),
                                      {**provenance, "step": observation["step"], "artifact": artifact},
                                      observation.get("observed_at")))
        if not health or all(item["status"] == "available" for item in health):
            health.append({"status": "available", "verification": store.verify_operation(operation_id)})
        if attempt["action_id"]:
            links.append(relation(entity("action", attempt["action_id"]), "attempted_operation", operation,
                                  {**provenance, "action_id": attempt["action_id"], "started_at": attempt["started_at"]}))
        value = document(f"owner:operation:{operation_id}", {"operation": operation, "attempt": attempt}, links, health)
        executions[operation_id] = record, health, value
        return executions[operation_id]

    def retained(experience_id, version):
        key = experience_id, version
        if key not in versions:
            row = store.experience_version(experience_id, version)
            identity = {name: row[name] for name in ("target", "store_id", "version", "content_sha256")}
            identity.update(owner="experience", record_id=row["experience_id"])
            versions[key] = identity, row
        return versions[key]

    for key in sorted(keys):
        owner, identifier = key
        if owner == "case":
            refs = [{"owner": "case", "record_id": "context"}]
            probe(refs)
            documents = []
            try:
                case = store.case_context()
            except StoreError as exc:
                if not str(exc).startswith(("private case material", "private_ref")):
                    raise
                documents.append(document("owner:case", {}, [], [{"status": "unavailable", "reason": str(exc)}]))
            else:
                if any(case[name] != binding[name] for name in ("store_id", "revision")):
                    raise StoreError("Case relation snapshot changed; retry acquisition")
                for collection, endpoint_owner, id_key, actor_key, predicate in (
                        ("sessions", "session", "id", "actor", "has_session"),
                        ("objects", "object", "ref", "owner_actor", "owns_object")):
                    for row in case[collection]:
                        endpoint = entity(endpoint_owner, row[id_key])
                        links = []
                        if row[actor_key]:
                            links.append(relation(entity("actor", row[actor_key]), predicate, endpoint,
                                                  {"owner": "case_context", "field": actor_key, "record_id": row[id_key]}))
                        documents.append(document(f"owner:case:{endpoint_owner}:{row[id_key]}", endpoint, links))
        elif owner == "operation":
            refs = [{"owner": "operation", "record_id": identifier}]
            documents = [execution(identifier)[2]]
        elif owner == "experience":
            current = experiences[identifier]["record"]
            refs = _refs(dependencies[identifier] + [{"owner": "operation", "record_id": item["operation_id"]}
                                                     for item in current["evidence"]])
            probe(refs)
            subject, version = retained(identifier, current["version"])
            links, health = [], list(version["source_health"])
            for evidence in version["snapshot"].get("evidence", []):
                operation_id, step = evidence["operation_id"], evidence["step"]
                record, operation_health, _ = execution(operation_id)
                if not any(item["step"] == step for item in record["observations"]):
                    raise StoreError("experience observation foreign key is missing")
                refs = _refs(refs + [{"owner": "operation", "record_id": operation_id}])
                health.extend(operation_health)
                links.append(relation(subject, "evidence_from", entity("operation", operation_id),
                                      {"experience_id": identifier, "experience_version": current["version"],
                                       "operation_id": operation_id, "attempt_id": record["attempt_id"], "step": step}))
            for source in version["sources"]:
                if source["purpose"] != "basis":
                    continue
                if "source_experience_id" in source:
                    endpoint, dependency = retained(source["source_experience_id"], source["source_version"])
                    if endpoint["content_sha256"] != source["content_sha256"]:
                        raise StoreError("experience dependency content binding is corrupt")
                    health.extend(dependency["source_health"])
                elif source.get("owner") in {"artifact", "assessment"}:
                    endpoint = entity(source["owner"], source["record_id"])
                    if (endpoint["version"], endpoint["content_sha256"]) != (source["source_version"], source["content_sha256"]):
                        health.append({"status": "version_changed", "source": source})
                        continue
                else:
                    continue
                links.append(relation(subject, "depends_on", endpoint, source))
            for link in version["dependency_refs"]:
                if (link["experience_id"], link["experience_version"]) != (identifier, current["version"]):
                    continue
                endpoint, dependency = retained(link["target_id"], link["target_version"])
                health.extend(dependency["source_health"])
                links.append(relation(subject, "depends_on", endpoint, link))
            documents = [document(f"owner:experience:{identifier}:{current['version']}", subject, links, health)] if links else []
        else:
            raise StoreError("unknown recall owner group")
        yield key, documents, refs
