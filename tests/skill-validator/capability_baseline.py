#!/usr/bin/env python3
"""Offline, explicit-allowlist source snapshots; never copy live target state."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import stat
import sys
from datetime import datetime, timezone


class BaselineError(ValueError):
    """An input or snapshot failed its integrity contract."""


SOURCE_ROOTS = frozenset({
    'tools', 'tests', 'docs', 'rules', 'skills', 'knowledge', 'scripts',
    'agents', 'commands', 'mcp', 'templates', 'web3', 'wordlists', 'hooks',
    '.github', 'memory', 'plan',
})
ROOT_FILES = frozenset({
    'AGENTS.md', 'CLAUDE.md', 'README.md', 'FAQ.md', 'CHANGELOG.md', 'LICENSE',
    'TERMS.md', '.gitignore', '.gitattributes', '.env.example',
    'config.example.json', 'conftest.py', 'requirements.txt',
    'requirements-dev.txt', 'requirements-ci.lock', 'install.sh',
    'install_tools.sh', 'logo.png',
})
FORBIDDEN_PARTS = frozenset({
    '.git', '.private', 'state', 'recon', 'findings', 'reports', 'hunt-memory',
    '.claude', '.codex', '.agents', '__pycache__', '.pytest_cache', '.cache',
    '.env', 'config.json',
})
FORBIDDEN_PREFIXES = (
    'tests/skill-validator/runs/', 'knowledge/distill-digests/',
    'knowledge/candidates/', 'knowledge/archive/', 'memory/goals/',
)


def _canonical(value: object) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + '\n').encode()


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _path(value: object) -> str:
    if not isinstance(value, str) or not value or '\\' in value or '\x00' in value:
        raise BaselineError('allowlist paths must be nonempty canonical relative strings')
    parts = value.split('/')
    if any(p in ('', '.', '..') or any(ord(c) < 32 for c in p) for p in parts):
        raise BaselineError(f'noncanonical path: {value!r}')
    if PurePosixPath(value).is_absolute() or ':' in parts[0]:
        raise BaselineError(f'absolute path: {value}')
    if any(p in FORBIDDEN_PARTS or p.startswith('.env.') and p != '.env.example' for p in parts):
        raise BaselineError(f'private/runtime path forbidden: {value}')
    if value.startswith(FORBIDDEN_PREFIXES) or value == 'knowledge/pull-log.jsonl':
        raise BaselineError(f'runtime path forbidden: {value}')
    if not (parts[0] in SOURCE_ROOTS or value in ROOT_FILES
            or value.startswith('.trellis/spec/') or value == '.trellis/workflow.md'):
        raise BaselineError(f'path outside reviewed source roots: {value}')
    if parts[0] == 'memory' and not value.endswith('.py'):
        raise BaselineError(f'non-source memory path: {value}')
    return value


def _absolute(value: str | Path, *, exists: bool) -> Path:
    if not isinstance(value, (str, Path)):
        raise BaselineError('root/output must be a path string')
    raw = Path(value)
    if not raw.is_absolute() or '..' in raw.parts:
        raise BaselineError('root/output paths must be explicit absolute canonical paths')
    for p in reversed((raw, *raw.parents)):
        if p.is_symlink():
            raise BaselineError(f'symlink forbidden: {p}')
    if exists and not raw.is_dir():
        raise BaselineError(f'missing directory: {raw}')
    return raw


def _member(root: Path, name: str) -> Path:
    p = root
    for part in name.split('/'):
        p = p / part
        if p.is_symlink():
            raise BaselineError(f'symlink forbidden: {p}')
    return p


def _disjoint(a: Path, b: Path) -> None:
    if a == b or a in b.parents or b in a.parents:
        raise BaselineError('source and destination must not overlap')


def _allowlist(value: object) -> tuple[list[str], list[str]]:
    if not isinstance(value, dict) or set(value) != {'files', 'deleted'}:
        raise BaselineError('allowlist must contain only files and deleted arrays')
    groups = []
    for key in ('files', 'deleted'):
        if not isinstance(value[key], list):
            raise BaselineError(f'{key} must be an array')
        groups.append([_path(p) for p in value[key]])
    all_paths = groups[0] + groups[1]
    if not all_paths or len(set(all_paths)) != len(all_paths):
        raise BaselineError('allowlist is empty or contains duplicate paths')
    paths = set(all_paths)
    if any(str(parent) in paths for p in paths for parent in PurePosixPath(p).parents):
        raise BaselineError('allowlist contains file/parent conflicts')
    return sorted(groups[0]), sorted(groups[1])


def _read(root: Path, name: str) -> tuple[bytes, int]:
    path = _member(root, name)
    # Anchor every component by descriptor, including root ancestors, so a
    # concurrent parent-symlink replacement cannot redirect the read.
    parent_fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        for component in path.parts[1:-1]:
            next_fd = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                              dir_fd=parent_fd)
            os.close(parent_fd)
            parent_fd = next_fd
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                     dir_fd=parent_fd)
    finally:
        os.close(parent_fd)
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode):
            raise BaselineError(f'not a regular file: {name}')
        data = stream.read()
        after = os.fstat(stream.fileno())
    if (before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
            after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns):
        raise BaselineError(f'source changed during read: {name}')
    return data, stat.S_IMODE(before.st_mode)


def _record(root: Path, name: str) -> tuple[dict, bytes]:
    data, mode = _read(root, name)
    return {'path': name, 'sha256': _digest(data), 'size': len(data), 'mode': mode}, data


def _write(root: Path, name: str, data: bytes, mode: int) -> None:
    path = _member(root, name)
    parent_fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        for component in path.parts[1:-1]:
            try:
                os.mkdir(component, dir_fd=parent_fd)
            except FileExistsError:
                pass
            next_fd = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                              dir_fd=parent_fd)
            os.close(parent_fd)
            parent_fd = next_fd
        fd = os.open(path.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                     0o600, dir_fd=parent_fd)
    finally:
        os.close(parent_fd)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(data)
        stream.flush()
        os.fchmod(stream.fileno(), mode)
        os.fsync(stream.fileno())


def _inventory(root: Path) -> set[str]:
    result = set()
    for parent, dirs, files in os.walk(root, followlinks=False):
        for name in dirs + files:
            path = Path(parent) / name
            if path.is_symlink():
                raise BaselineError(f'symlink forbidden: {path}')
        result.update((Path(parent) / f).relative_to(root).as_posix() for f in files)
    return result


def _check_tree(root: Path, manifest: dict, *, sealed: bool) -> None:
    expected = {entry['path'] for entry in manifest['files']}
    if _inventory(root) != expected:
        raise BaselineError('file inventory differs from manifest')
    for entry in manifest['files']:
        actual, _ = _record(root, entry['path'])
        wanted = dict(entry)
        if sealed:
            wanted['mode'] &= ~0o222
        if actual != wanted:
            raise BaselineError(f'content/mode/size mismatch: {entry["path"]}')
    for name in manifest['deleted']:
        if _member(root, name).exists():
            raise BaselineError(f'deleted path reappeared: {name}')


def capture(root: str | Path, output: str | Path, allowlist: object,
            *, provenance: dict | None = None) -> dict:
    """Create once; on failure retain a diagnostic partial directory, no manifest."""
    source = _absolute(root, exists=True)
    dest = _absolute(output, exists=False)
    _disjoint(source, dest)
    files, deleted = _allowlist(allowlist)
    if provenance is not None and not isinstance(provenance, dict):
        raise BaselineError('provenance must be a JSON object')
    if provenance and 'source_root' in provenance:
        _absolute(provenance['source_root'], exists=False)
    for name in deleted:
        if _member(source, name).exists():
            raise BaselineError(f'declared deletion exists: {name}')
    # Reserve the destination exclusively; existing/partial outputs are never reused.
    dest.mkdir()
    tree = dest / 'source'
    tree.mkdir()
    entries = []
    for name in files:
        entry, data = _record(source, name)
        _write(tree, name, data, entry['mode'] & ~0o222)
        entries.append(entry)
    manifest = {
        'schema': 'capability-baseline/v1', 'source_root': str(source),
        'captured_at': datetime.now(timezone.utc).isoformat(),
        'files': entries, 'deleted': deleted, 'provenance': provenance or {},
        'interpreter': {'executable': sys.executable, 'version': sys.version},
        'dependencies': [e for e in entries if e['path'] in {
            'requirements.txt', 'requirements-dev.txt', 'requirements-ci.lock'}],
        'model': {'status': 'pending', 'reason': 'no model execution authorized or measured'},
        'platform_permissions': {'status': 'pending', 'reason': 'not measured by source capture'},
    }
    _check_tree(tree, manifest, sealed=True)
    for entry in entries:
        actual, _ = _record(source, entry['path'])
        if actual != entry:
            raise BaselineError(f'source changed during capture: {entry["path"]}')
    for name in deleted:
        if _member(source, name).exists():
            raise BaselineError(f'deletion changed during capture: {name}')
    data = _canonical(manifest)
    # Only the final durable file is the publication marker.
    _write(dest, 'manifest.pending', data, 0o444)
    for parent, dirs, _ in os.walk(dest, topdown=False):
        for name in dirs:
            (Path(parent) / name).chmod(0o555)
    os.rename(dest / 'manifest.pending', dest / 'manifest.json')
    return {'snapshot': str(dest), 'manifest_sha256': _digest(data), 'files': len(entries)}


def verify(snapshot: str | Path, expected_sha256: str) -> dict:
    root = _absolute(snapshot, exists=True)
    if not isinstance(expected_sha256, str) or len(expected_sha256) != 64 or any(
            c not in '0123456789abcdef' for c in expected_sha256):
        raise BaselineError('a pinned lowercase SHA256 is required')
    data, mode = _read(root, 'manifest.json')
    if mode != 0o444:
        raise BaselineError('manifest is not sealed read-only')
    if _digest(data) != expected_sha256:
        raise BaselineError('manifest hash mismatch')
    try:
        manifest = json.loads(data)
    except (ValueError, UnicodeError) as exc:
        raise BaselineError('invalid manifest JSON') from exc
    if not isinstance(manifest, dict) or manifest.get('schema') != 'capability-baseline/v1':
        raise BaselineError('unsupported manifest schema')
    _absolute(manifest.get('source_root'), exists=False)
    if not isinstance(manifest.get('provenance'), dict):
        raise BaselineError('invalid manifest provenance')
    if 'source_root' in manifest['provenance']:
        _absolute(manifest['provenance']['source_root'], exists=False)
    entries = manifest.get('files')
    if not isinstance(entries, list) or any(not isinstance(e, dict) for e in entries):
        raise BaselineError('invalid manifest file records')
    for entry in entries:
        if set(entry) != {'path', 'size', 'mode', 'sha256'}:
            raise BaselineError('invalid manifest file fields')
        if (type(entry['size']) is not int or entry['size'] < 0
                or type(entry['mode']) is not int or not 0 <= entry['mode'] <= 0o7777
                or not isinstance(entry['sha256'], str) or len(entry['sha256']) != 64):
            raise BaselineError('invalid manifest hash/size/mode')
    _allowlist({'files': [e['path'] for e in entries], 'deleted': manifest.get('deleted')})
    if set(p.name for p in root.iterdir()) != {'manifest.json', 'source'}:
        raise BaselineError('partial or unexpected snapshot entries')
    tree = _absolute(root / 'source', exists=True)
    _check_tree(tree, manifest, sealed=True)
    return manifest


def verify_restored(snapshot: str | Path, root: str | Path, expected_sha256: str) -> dict:
    manifest = verify(snapshot, expected_sha256)
    target = _absolute(root, exists=True)
    _disjoint(_absolute(snapshot, exists=True), target)
    _check_tree(target, manifest, sealed=False)
    return {'root': str(target), 'files': len(manifest['files']), 'status': 'verified'}


def restore(snapshot: str | Path, output: str | Path, expected_sha256: str) -> dict:
    manifest = verify(snapshot, expected_sha256)
    source = _absolute(snapshot, exists=True)
    dest = _absolute(output, exists=False)
    _disjoint(source, dest)
    original = _absolute(manifest['source_root'], exists=False)
    _disjoint(original, dest)
    recorded_source = manifest.get('provenance', {}).get('source_root')
    if recorded_source is not None:
        _disjoint(_absolute(recorded_source, exists=False), dest)
    dest.mkdir()
    for entry in manifest['files']:
        data, _ = _read(source / 'source', entry['path'])
        if _digest(data) != entry['sha256'] or len(data) != entry['size']:
            raise BaselineError(f'snapshot changed during restore: {entry["path"]}')
        _write(dest, entry['path'], data, entry['mode'])
    return verify_restored(snapshot, dest, expected_sha256)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    capture_parser = commands.add_parser('capture')
    capture_parser.add_argument('--root', required=True)
    capture_parser.add_argument('--output', required=True)
    capture_parser.add_argument('--allowlist', required=True)
    capture_parser.add_argument('--provenance')
    for name in ('verify', 'restore', 'verify-restored'):
        command = commands.add_parser(name)
        command.add_argument('--snapshot', required=True)
        command.add_argument('--sha256', required=True)
        if name != 'verify':
            command.add_argument('--output', required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == 'capture':
            allowlist = json.loads(Path(args.allowlist).read_bytes())
            provenance = json.loads(Path(args.provenance).read_bytes()) if args.provenance else None
            result = capture(args.root, args.output, allowlist, provenance=provenance)
        elif args.command == 'restore':
            result = restore(args.snapshot, args.output, args.sha256)
        elif args.command == 'verify-restored':
            result = verify_restored(args.snapshot, args.output, args.sha256)
        else:
            manifest = verify(args.snapshot, args.sha256)
            result = {'status': 'verified', 'files': len(manifest['files'])}
    except (OSError, ValueError) as exc:
        print(json.dumps({'error': str(exc)}), file=sys.stderr)
        return 2
    print(json.dumps(result, ensure_ascii=False))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
