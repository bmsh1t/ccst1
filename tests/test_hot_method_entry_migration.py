"""Local synthetic owners: never copy real journal identities or publish a target."""

import copy
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys

import pytest

from tools import hot_method as hm
from tools.skill_reference_contract import CORE_SKILL_PATH, LEGACY_SKILL_READ_PATHS


def _hash(raw):
    return hashlib.sha256(raw).hexdigest()


def _write(root, path, raw):
    destination = root / path
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(raw)
    return path


def _manifest(root):
    raw = (root / hm.MANIFEST_RELATIVE).read_bytes()
    return json.loads(raw), _hash(raw)


def _review(manifest):
    return {
        "reviewer": {"kind": "main_session", "session_id": "synthetic-test-only"},
        "reason": "Synthetic entry governance test, not a method efficacy or human review claim",
        "three_questions": ["navigation only", "exact version and consumers", "no source repair"],
        "admission": [{"path": "rules.md", "sha256": _hash(b"Synthetic admission\n")}],
        "sources": [{"kind": "origin", "id": "S01", "sha256": manifest["origins"][0]["origin_sha256"]}],
    }


@pytest.fixture
def owner(tmp_path):
    root = tmp_path / "owner"
    bodies = {
        "README.md": b"Use repository `skills/src-hunting/SKILL.md`\n",
        "skills/src-hunter/SKILL.md": "仓库根 `skills/src-hunting/SKILL.md`\n".encode(),
        "skills/src-hunter/知识库/README.md": "仓库根 `skills/src-hunting/SKILL.md`\n".encode(),
        "references/researcher-blackbox-whitebox.md": b"source_incomplete; skills/whitebox-audit/SKILL.md\n",
        "method.md": b"Complete synthetic method\n", "rules.md": b"Synthetic admission\n",
    }
    entries = []
    for path, raw in bodies.items():
        _write(root, hm.METHOD_ROOT + "/" + path, raw)
        entries.append({"path": path, "role": "method", "sha256": _hash(raw)})
    old = {"schema": hm.MANIFEST_SCHEMA, "source_id": "synthetic-test-only",
           "bundled_root": hm.METHOD_ROOT, "root_env": "CCST_CLOWN_SNAPSHOT",
           "entries": entries, "context_files": []}
    _write(root, hm.MANIFEST_RELATIVE, hm._json_bytes(old))
    new = copy.deepcopy(old)
    new.update(schema=hm.MANIFEST_V2, revision_ref=".history/receipts/bootstrap.json", origins=[])
    materials = []
    for number in range(1, 63):
        identity = f"S{number:02}"
        raw = f"Synthetic origin {identity}\n".encode()
        path = _write(root, f"inputs/{identity}", raw)
        materials.append({"id": identity, "content_path": path})
        source_path = "rules/" + hm.RULE_ORIGINALS[identity] if identity in hm.RULE_ORIGINALS else f"{identity}.md"
        new["origins"].append({"id": identity, "source_path": source_path,
                               "origin_sha256": _hash(raw), "archive_path": ".history/blobs/" + _hash(raw),
                               "disposition": "synthetic origin", "defects": ["missing Phase 0"] if number == 52 else [],
                               "consumers": [hm.METHOD_ROOT + "/method.md"]})
    new["origins"][0].update(consumers=[hm.METHOD_ROOT + "/skills/src-hunter/SKILL.md"],
        disposition="keep full source reference under methods; root skills/src-hunting remains sole native entry; repair only host/path instructions")
    new["origins"][55].update(consumers=["skills/src-hunting/SKILL.md"], disposition="native src-hunting")
    new["origins"][60].update(consumers=["skills/report-writing/SKILL.md"], disposition="skills/report-writing/SKILL.md")
    for entry in new["entries"]:
        entry.update(id=entry["path"], origin_refs=["S01"], maintenance_scope=(
            "entry_reference" if entry["path"] in hm.ENTRY_MIGRATION_FILES else "method"))
    for name, path in LEGACY_SKILL_READ_PATHS.items():
        _write(root, f"skills/{name}/SKILL.md", f"Old {name}\n".encode())
        _write(root, path, f"New {name}\n".encode())
    body = b"Complete synthetic method, bootstrapped\n"
    path = _write(root, "inputs/bootstrap-method", body)
    next(x for x in new["entries"] if x["path"] == "method.md")["sha256"] = _hash(body)
    update = {"schema_version": 1, "transaction_id": "bootstrap", "expected_manifest": _manifest(root)[1],
              "manifest": new, "origin_materials": materials, "review": _review(new),
              "files": [{"path": "method.md", "before_sha256": _hash(bodies["method.md"]),
                         "after_sha256": _hash(body), "content_path": path}]}
    hm.apply_update(root, update, bootstrap=True, environ={})
    return root


def _migration(root, identity="forward", direction="forward"):
    old, digest = _manifest(root)
    new = copy.deepcopy(old)
    new["revision_ref"] = f".history/receipts/{identity}.json"
    source = hm.METHOD_ROOT + "/skills/src-hunter/SKILL.md"
    old_disposition = "keep full source reference under methods; root skills/src-hunting remains sole native entry; repair only host/path instructions"
    new_disposition = "S01 is the source of root skills/src-hunter/SKILL.md; keep full source reference under methods; nine specialist methods are internal modules"
    new["origins"][0].update(consumers=[source, CORE_SKILL_PATH] if direction == "forward" else [source],
                               disposition=new_disposition if direction == "forward" else old_disposition)
    replacements = {f"skills/{name}/SKILL.md": path for name, path in LEGACY_SKILL_READ_PATHS.items()}
    if direction == "reverse":
        replacements = {b: a for a, b in replacements.items()}
    for origin in (new["origins"][55], new["origins"][60]):
        origin["consumers"] = [replacements.get(p, p) for p in origin["consumers"]]
        for a, b in replacements.items():
            origin["disposition"] = origin["disposition"].replace(a, b)
    new["origins"][55]["disposition"] = "native src-hunter" if direction == "forward" else "native src-hunting"
    changed = []
    for path in hm.ENTRY_MIGRATION_FILES:
        before = (root / hm.METHOD_ROOT / path).read_bytes()
        body = before.decode()
        for a, b in replacements.items():
            body = body.replace(a, b)
        body = body.encode()
        transport = _write(root, f"inputs/{identity}/{path}", body)
        changed.append({"path": path, "before_sha256": _hash(before), "after_sha256": _hash(body), "content_path": transport})
        next(x for x in new["entries"] if x["path"] == path)["sha256"] = _hash(body)
    update = {"schema_version": 1, "transaction_id": identity, "expected_manifest": digest,
              "manifest": new, "files": changed, "origin_materials": [], "review": _review(new)}
    marker = {"schema_version": 1, "profile": "src-hunter-single-entry", "direction": direction}
    native = set(LEGACY_SKILL_READ_PATHS.values()) if direction == "forward" else set(replacements.values())
    approval = {**marker, "authorization": "Synthetic user approval declaration only", "expected_manifest": digest,
                "after_manifest": _hash(hm._json_bytes(new)),
                "files": [{k: item[k] for k in ("path", "before_sha256", "after_sha256")} for item in changed],
                "native_assets": {p: _hash((root / p).read_bytes()) for p in sorted(native)}}
    raw = hm._json_bytes(approval)
    marker["approval"] = {"sha256": _hash(raw), "content_path": _write(root, f"inputs/{identity}-approval", raw)}
    return update, marker


def _apply(root, pair):
    update, marker = pair
    return hm.migrate_entry(root, update, entry_migration=marker, environ={})


def test_entry_migration_preserves_history_and_captured_reads(owner, tmp_path):
    before, _ = _manifest(owner)
    historical = {p: p.read_bytes() for p in (owner / hm.HISTORY).rglob("*") if p.is_file()}
    pair = _migration(owner)
    result = _apply(owner, pair)
    assert result["status"] == "accepted"
    after, digest = _manifest(owner)
    for old, new in zip(before["origins"], after["origins"]):
        assert {k: v for k, v in old.items() if k not in {"consumers", "disposition"}} == {k: v for k, v in new.items() if k not in {"consumers", "disposition"}}
    assert all(p.read_bytes() == raw for p, raw in historical.items())
    for name in LEGACY_SKILL_READ_PATHS:
        (owner / f"skills/{name}/SKILL.md").unlink()
    shutil.rmtree(owner / "inputs")
    assert _apply(owner, pair)["receipt"] == result["receipt"]
    cli = subprocess.run([sys.executable, str(Path(hm.__file__)), "--repo-root", str(owner),
                          "--read", "README.md", "--expected-manifest", digest, "--json"],
                         capture_output=True, text=True, timeout=10)
    assert cli.returncode == 0, cli.stdout + cli.stderr
    assert CORE_SKILL_PATH in cli.stdout
    checkout = tmp_path / "new-checkout"
    shutil.copytree(owner, checkout)
    assert hm.read_methods(checkout, ["README.md"], expected_manifest=digest, environ={})["status"] == "ready"
    with pytest.raises(hm.HotMethodError):
        hm.recover_update(checkout, "forward", mode="complete", environ={})


def test_entry_migration_is_separate_from_ordinary_a_and_reverses_with_new_receipt(owner):
    pair = _migration(owner)
    with pytest.raises(hm.HotMethodError, match="ordinary maintenance"):
        hm.apply_update(owner, pair[0], environ={})
    forward = _apply(owner, pair)
    reverse = _apply(owner, _migration(owner, "reverse", "reverse"))
    assert reverse["status"] == "accepted"
    assert reverse["receipt"]["request_sha256"] != forward["receipt"]["request_sha256"]
    assert _manifest(owner)[0]["origins"][0]["consumers"] == [hm.METHOD_ROOT + "/skills/src-hunter/SKILL.md"]
    with pytest.raises(hm.HotMethodError, match="terminal_applied"):
        hm.recover_update(owner, "forward", mode="restore", environ={})


@pytest.mark.parametrize("fault", ["prose", "defects", "metadata", "extra_file", "approval", "consumer", "incomplete_source"])
def test_entry_migration_rejects_out_of_profile_before_publication(owner, fault):
    update, marker = _migration(owner)
    before = (owner / hm.MANIFEST_RELATIVE).read_bytes()
    if fault == "prose":
        item = update["files"][0]
        body = b"Rewrite all governance\n"
        (owner / item["content_path"]).write_bytes(body)
        item["after_sha256"] = _hash(body)
        update["manifest"]["entries"][0]["sha256"] = _hash(body)
    elif fault == "defects":
        update["manifest"]["origins"][51]["defects"] = []
    elif fault == "metadata":
        update["manifest"]["entries"][0]["maintenance_scope"] = "method"
    elif fault == "extra_file":
        update["files"][0]["path"] = "method.md"
    elif fault == "approval":
        marker["approval"]["sha256"] = "0" * 64
    elif fault == "consumer":
        (owner / CORE_SKILL_PATH).unlink()
    else:
        source = update["manifest"]["origins"][51]
        update["review"]["sources"] = [{"kind": "origin", "id": "S52", "sha256": source["origin_sha256"]}]
    with pytest.raises((hm.HotMethodError, OSError)):
        hm.migrate_entry(owner, update, entry_migration=marker, environ={})
    assert (owner / hm.MANIFEST_RELATIVE).read_bytes() == before
    assert not (owner / hm.HISTORY / "pending.json").exists()
    assert not (owner / hm.HISTORY / "transactions/forward.json").exists()


@pytest.mark.parametrize("mode", ["complete", "restore"])
@pytest.mark.parametrize("stage", ["body", "manifest"])
def test_entry_migration_pending_recovery(owner, monkeypatch, mode, stage):
    pair = _migration(owner)
    before = (owner / hm.MANIFEST_RELATIVE).read_bytes()
    publish = hm._publish_item
    fired = False
    def interrupted(files, item, desired):
        nonlocal fired
        publish(files, item, desired)
        if not fired and (stage == "body" or item["path"] == str(hm.MANIFEST_RELATIVE)):
            fired = True
            raise OSError("synthetic process interruption")
    with monkeypatch.context() as patch:
        patch.setattr(hm, "_publish_item", interrupted)
        with pytest.raises(OSError):
            _apply(owner, pair)
    assert fired
    assert hm.build_hot_method_projection(owner, environ={})["status"] == "pending_update"
    result = hm.recover_update(owner, "forward", mode=mode, environ={})
    assert result["status"] == ("accepted" if mode == "complete" else "restored")
    if mode == "restore":
        assert (owner / hm.MANIFEST_RELATIVE).read_bytes() == before
    with pytest.raises(hm.HotMethodError, match="terminal_"):
        hm.recover_update(owner, "forward", mode="restore" if mode == "complete" else "complete", environ={})


@pytest.mark.parametrize("stage", ["decisions", "receipts"])
def test_entry_migration_decision_and_receipt_interruptions(owner, monkeypatch, stage):
    create = hm._MethodFiles.create
    def interrupted(files, path, *args, **kwargs):
        value = create(files, path, *args, **kwargs)
        if path == f"{hm.HISTORY}/{stage}/forward.json":
            raise OSError("synthetic journal interruption")
        return value
    pair = _migration(owner)
    with monkeypatch.context() as patch:
        patch.setattr(hm._MethodFiles, "create", interrupted)
        with pytest.raises(OSError):
            _apply(owner, pair)
    with pytest.raises(hm.HotMethodError):
        hm.recover_update(owner, "forward", mode="restore", environ={})
    assert hm.recover_update(owner, "forward", mode="complete", environ={})["status"] == "accepted"
    assert not (owner / hm.HISTORY / "pending.json").exists()


def test_entry_migration_two_process_writers_cas(owner):
    def invoke(identity):
        update, marker = _migration(owner, identity)
        payload = _write(owner, f"inputs/{identity}.json", hm._json_bytes({"entry_migration": marker, "update": update}))
        return [sys.executable, str(Path(hm.__file__)), "--repo-root", str(owner), "--migrate-entry",
                str(owner / payload), "--expected-manifest", update["expected_manifest"], "--json"]
    commands = [invoke("writer-one"), invoke("writer-two")]
    with ThreadPoolExecutor(2) as pool:
        results = list(pool.map(lambda command: subprocess.run(command, capture_output=True, text=True, timeout=15), commands))
    assert sorted(r.returncode for r in results) == [0, 2], [r.stdout + r.stderr for r in results]
    assert "manifest CAS conflict" in next(r.stdout for r in results if r.returncode == 2)
    assert not (owner / hm.HISTORY / "pending.json").exists()


def test_entry_migration_sync_failure_before_pending_and_exact_retry(owner, monkeypatch):
    pair = _migration(owner)
    before = (owner / hm.MANIFEST_RELATIVE).read_bytes()
    sync = hm._MethodFiles.sync
    fired = False
    def fail_sync(files, path):
        nonlocal fired
        if "/blobs/" in path:
            fired = True
            raise OSError("synthetic durability failure")
        return sync(files, path)
    with monkeypatch.context() as patch:
        patch.setattr(hm._MethodFiles, "sync", fail_sync)
        with pytest.raises(OSError):
            _apply(owner, pair)
    assert fired
    assert (owner / hm.MANIFEST_RELATIVE).read_bytes() == before
    assert not (owner / hm.HISTORY / "pending.json").exists()
    assert _apply(owner, pair)["status"] == "accepted"
    pair[0]["review"]["reason"] += " changed declaration"
    with pytest.raises(hm.HotMethodError, match="ID material conflict"):
        _apply(owner, pair)


def test_entry_migration_rejects_local_identity_drift(owner):
    pair = _migration(owner)
    path = owner / hm.MANIFEST_RELATIVE
    path.chmod(0o600 if path.stat().st_mode & 0o777 != 0o600 else 0o644)
    with pytest.raises(hm.HotMethodError, match="witness conflict"):
        _apply(owner, pair)
    assert not (owner / hm.HISTORY / "pending.json").exists()


def test_ordinary_a_after_entry_migration_keeps_governance_closed(owner):
    _apply(owner, _migration(owner))
    manifest, digest = _manifest(owner)
    body = b"A reviewed synthetic method difference\n"
    entry = next(x for x in manifest["entries"] if x["path"] == "method.md")
    before = entry["sha256"]
    entry["sha256"] = _hash(body)
    manifest["revision_ref"] = ".history/receipts/ordinary.json"
    update = {"schema_version": 1, "transaction_id": "ordinary", "expected_manifest": digest,
              "manifest": manifest, "files": [{"path": "method.md", "before_sha256": before,
              "after_sha256": _hash(body), "content_path": _write(owner, "inputs/ordinary", body)}],
              "review": _review(manifest)}
    assert hm.apply_update(owner, update, environ={})["status"] == "accepted"
    governance, _ = _migration(owner, "reverse", "reverse")
    with pytest.raises(hm.HotMethodError, match="ordinary maintenance"):
        hm.apply_update(owner, governance, environ={})


def _rules_import(root):
    before, digest = _manifest(root)
    candidate = copy.deepcopy(before)
    candidate['revision_ref'] = '.history/receipts/rules.json'
    entries = {e['path']: e for e in candidate['entries'] + candidate['context_files']}
    changed = []

    def body(path, raw):
        old = root / hm.METHOD_ROOT / path
        item = {'path': path, 'before_sha256': _hash(old.read_bytes()) if old.exists() else None,
                'after_sha256': _hash(raw), 'content_path': _write(root, 'inputs/rules/' + path, raw)}
        if not old.exists():
            info = root.stat()
            item.update(mode=0o644, uid=info.st_uid, gid=info.st_gid)
        changed.append(item)
        entries[path]['sha256'] = _hash(raw)

    for origin in candidate['origins']:
        if origin['id'] not in hm.RULE_ORIGINALS:
            continue
        path = 'references/' + hm.RULE_ORIGINALS[origin['id']]
        if path not in entries:
            entry = {'id': origin['id'], 'path': path, 'role': 'method',
                     'source_path': origin['source_path'], 'origin_refs': [origin['id']],
                     'maintenance_scope': 'governance_reference'}
            candidate['entries'].append(entry)
            entries[path] = entry
        body(path, (root / hm.METHOD_ROOT / origin['archive_path']).read_bytes())
        origin['consumers'] = list(dict.fromkeys([hm.METHOD_ROOT + '/' + path, *origin['consumers'], 'rules/README.md']))
        origin['disposition'] = ('Complete original rule is active; environment and engineering interfaces are owned by '
                                 + hm.RULE_ADAPTER + '; ordinary A cannot edit governance.')
    adapter = {'id': 'ccst-rules-runtime-adapter', 'path': hm.RULE_ADAPTER,
               'origin_refs': list(hm.RULE_ORIGINALS), 'maintenance_scope': 'governance_reference'}
    candidate['context_files'].append(adapter)
    entries[hm.RULE_ADAPTER] = adapter
    body(hm.RULE_ADAPTER, b'Synthetic explicit runtime adapter\n')
    body('README.md', b'Synthetic complete rule loading guide\n')
    for path in hm.RULE_RUNTIME_ASSETS:
        if not (root / path).exists():
            _write(root, path, b'Synthetic current runtime consumer\n')
    marker = {'schema_version': 1, 'profile': '6k-rules-originals', 'direction': 'forward'}
    approval = {**marker, 'authorization': 'Synthetic rules import declaration',
                'expected_manifest': digest, 'after_manifest': _hash(hm._json_bytes(candidate)),
                'files': [{k: item[k] for k in ('path', 'before_sha256', 'after_sha256')} for item in changed],
                'runtime_assets': {p: _hash((root / p).read_bytes()) for p in sorted(hm.RULE_RUNTIME_ASSETS)}}
    raw = hm._json_bytes(approval)
    marker['approval'] = {'content_path': _write(root, 'inputs/rules-approval', raw), 'sha256': _hash(raw)}
    update = {'schema_version': 1, 'transaction_id': 'rules', 'expected_manifest': digest,
              'manifest': candidate, 'files': changed, 'review': _review(candidate)}
    return update, marker


def test_rules_import_preserves_originals_history_and_cli_reads(owner):
    update, marker = _rules_import(owner)
    historical = {p: p.read_bytes() for p in (owner / hm.HISTORY).rglob('*') if p.is_file()}
    before = _manifest(owner)[0]
    with pytest.raises(hm.HotMethodError, match='ordinary maintenance'):
        hm.apply_update(owner, update, environ={})
    result = hm.import_rules(owner, update, rules_migration=marker, environ={})
    assert result['status'] == 'accepted'
    assert all(p.read_bytes() == raw for p, raw in historical.items())
    after, digest = _manifest(owner)
    for old, new in zip(before['origins'], after['origins']):
        assert {k: v for k, v in old.items() if k not in {'consumers', 'disposition'}} == {
            k: v for k, v in new.items() if k not in {'consumers', 'disposition'}}
    paths = ['references/' + name for name in hm.RULE_ORIGINALS.values()]
    cli = subprocess.run([sys.executable, hm.__file__, '--repo-root', str(owner),
                          *[a for p in paths for a in ('--read', p)], '--expected-manifest', digest, '--json'],
                         capture_output=True, text=True, timeout=10)
    assert cli.returncode == 0, cli.stdout + cli.stderr
    captured = {f['path']: f for f in json.loads(cli.stdout)['files']}
    for origin in after['origins']:
        if origin['id'] in hm.RULE_ORIGINALS:
            assert captured['references/' + hm.RULE_ORIGINALS[origin['id']]]['content'].encode() == (
                owner / hm.METHOD_ROOT / origin['archive_path']).read_bytes()
    assert captured[hm.RULE_ADAPTER]['content'] == 'Synthetic explicit runtime adapter\n'
    shutil.rmtree(owner / 'inputs')
    assert hm.import_rules(owner, update, rules_migration=marker, environ={})['receipt'] == result['receipt']


@pytest.mark.parametrize('fault', ['original', 'defects', 'runtime', 'entry_profile'])
def test_rules_import_rejects_out_of_scope_without_publication(owner, fault):
    update, marker = _rules_import(owner)
    before = (owner / hm.MANIFEST_RELATIVE).read_bytes()
    if fault == 'original':
        item = next(x for x in update['files'] if x['path'] == 'references/vuln-report-format.md')
        raw = b'Rewrite source report policy\n'
        (owner / item['content_path']).write_bytes(raw)
        item['after_sha256'] = _hash(raw)
        next(e for e in update['manifest']['entries'] if e['path'] == item['path'])['sha256'] = _hash(raw)
    elif fault == 'defects':
        update['manifest']['origins'][51]['defects'] = []
    elif fault == 'runtime':
        (owner / CORE_SKILL_PATH).write_bytes(b'Concurrent changed consumer\n')
    else:
        with pytest.raises(hm.HotMethodError):
            hm.migrate_entry(owner, update, entry_migration=marker, environ={})
        return
    with pytest.raises(hm.HotMethodError):
        hm.import_rules(owner, update, rules_migration=marker, environ={})
    assert (owner / hm.MANIFEST_RELATIVE).read_bytes() == before
    assert not (owner / hm.HISTORY / 'pending.json').exists()
    assert not (owner / hm.HISTORY / 'transactions/rules.json').exists()


@pytest.mark.parametrize('mode', ['complete', 'restore'])
@pytest.mark.parametrize('runtime_drift', [False, True])
def test_rules_import_interruption_uses_existing_recovery(owner, monkeypatch, mode, runtime_drift):
    update, marker = _rules_import(owner)
    before = (owner / hm.MANIFEST_RELATIVE).read_bytes()
    publish = hm._publish_item
    fired = False

    def interrupt(files, item, desired):
        nonlocal fired
        publish(files, item, desired)
        if not fired and item['before'] is None:
            fired = True
            raise OSError('Synthetic new-rule publication interruption')

    with monkeypatch.context() as patch:
        patch.setattr(hm, '_publish_item', interrupt)
        with pytest.raises(OSError):
            hm.import_rules(owner, update, rules_migration=marker, environ={})
    assert fired
    if runtime_drift:
        runtime = owner / CORE_SKILL_PATH
        original = runtime.read_bytes()
        runtime.write_bytes(b'Concurrent runtime changed after interruption\n')
        if mode == 'complete':
            with pytest.raises(hm.HotMethodError, match='runtime consumer changed'):
                hm.recover_update(owner, 'rules', mode=mode, environ={})
            assert (owner / hm.HISTORY / 'pending.json').exists()
            runtime.write_bytes(original)
    assert hm.recover_update(owner, 'rules', mode=mode, environ={})['status'] == (
        'accepted' if mode == 'complete' else 'restored')
    if mode == 'restore':
        assert (owner / hm.MANIFEST_RELATIVE).read_bytes() == before
        assert not (owner / hm.METHOD_ROOT / 'references/vuln-report-format.md').exists()
