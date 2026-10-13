"""Strict, read-only migration bindings shared by importers and history readers."""
from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
import stat
from contextlib import contextmanager
from pathlib import Path

try:
    from tools.target_paths import canonical_target_value, target_storage_key
except ImportError:  # pragma: no cover - direct tools/ execution
    from target_paths import canonical_target_value, target_storage_key

LEGACY_METADATA_PATHS = (
    ("state/{key}/action_queue.json", "state/action_queue.json"),
    ("state/{key}/case_state.json", "state/case_state.json"),
    ("state/{key}/unsafe_skipped_reviews.json", "state/unsafe_skipped_reviews.json"),
    ("findings/{key}/findings.json", "findings/findings.json"),
    ("findings/{key}/mutation-events.jsonl", "findings/mutation-events.jsonl"),
    ("memory/evidence/{key}/ledger.jsonl", "memory/evidence/ledger.jsonl"),
    ("memory/goals/targets/{key}.json", "memory/goals/targets.json"),
)


def canonical_relative(value):
    if (not isinstance(value, str) or not value or '\x00' in value or '\\' in value
            or any(part in ('', '.', '..') for part in value.split('/'))
            or Path(value).is_absolute()):
        raise ValueError('migration binding contains a noncanonical relative path')
    return value


def _digest(value):
    return hashlib.sha256(json.dumps(value, ensure_ascii=True, sort_keys=True,
                                     separators=(',', ':')).encode('utf-8')).hexdigest()


def _hash(value):
    if not isinstance(value, str) or re.fullmatch(r'[0-9a-f]{64}', value) is None:
        raise ValueError('migration binding requires a SHA256 digest')
    return value


def _files(value):
    if not isinstance(value, list):
        raise ValueError('migration file manifest must be a list')
    seen = set()
    for item in value:
        if not isinstance(item, dict):
            raise ValueError('migration file binding must be an object')
        relative = canonical_relative(item.get('path'))
        if relative in seen:
            raise ValueError('migration file manifest has duplicate paths')
        seen.add(relative)
        if type(item.get('size')) is not int or item['size'] < 0:
            raise ValueError('migration file size must be a nonnegative integer')
        _hash(item.get('sha256'))
    return value


def _identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_size,
            info.st_mtime_ns, info.st_ctime_ns)


@contextmanager
def directory_handle(path):
    """Pin every directory component without following links or creating files."""
    path = Path(os.path.abspath(path))
    fd = os.open(path.anchor, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    identities = []
    current = Path(path.anchor)
    try:
        for part in path.parts[1:]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
            current /= part
            info = os.fstat(fd)
            identities.append((current, info.st_dev, info.st_ino))
        yield fd
        for component, device, inode in identities:
            info = component.lstat()
            if not stat.S_ISDIR(info.st_mode) or (info.st_dev, info.st_ino) != (device, inode):
                raise ValueError('migration directory identity changed during access')
    finally:
        os.close(fd)


def read_file(path, *, read_bytes=None):
    """Read a regular file while checking descriptor and pathname identities."""
    path = Path(path)
    with directory_handle(path.parent) as parent:
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        with os.fdopen(fd, 'rb') as handle:
            before = os.fstat(handle.fileno())
            if not stat.S_ISREG(before.st_mode):
                raise ValueError('migration source must be a regular file')
            raw = read_bytes(path) if read_bytes is not None else handle.read()
            after = os.fstat(handle.fileno())
            current = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
            if (not isinstance(raw, bytes) or len(raw) != before.st_size
                    or _identity(before) != _identity(after)
                    or _identity(before) != _identity(current)):
                raise ValueError('migration source changed during read')
            return raw


def read_bound_file(root, relative, *, size, sha256, read_bytes=None):
    relative = canonical_relative(relative)
    if type(size) is not int or size < 0:
        raise ValueError('migration file size must be a nonnegative integer')
    _hash(sha256)
    raw = read_file(Path(root) / relative, read_bytes=read_bytes)
    if len(raw) != size or hashlib.sha256(raw).hexdigest() != sha256:
        raise ValueError('migration source bytes differ from the receipt binding')
    return raw


def _object(path, read_bytes):
    value = json.loads(read_file(path, read_bytes=read_bytes))
    if not isinstance(value, dict):
        raise ValueError('migration receipt must be a JSON object')
    return value


def _receipt_identity(value, *, target, store_id, kind):
    if (type(value.get('schema_version')) is not int or value['schema_version'] != 1
            or value.get('kind') != kind or value.get('target') != target
            or value.get('store_id') != store_id or not isinstance(store_id, str) or not store_id):
        raise ValueError('migration receipt identity or schema does not match')


def _active(value, *, target, store_id, kind):
    _receipt_identity(value, target=target, store_id=store_id, kind=kind)
    if value.get('activation_status') != 'active':
        raise ValueError('migration receipt activation does not match')


def _manifest(receipt, target):
    manifest = receipt.get('source_manifest')
    if (not isinstance(manifest, dict) or type(manifest.get('schema_version')) is not int
            or manifest['schema_version'] != 1 or manifest.get('target') != target):
        raise ValueError('migration source manifest identity does not match')
    digest = _digest(_files(manifest.get('files')))
    if digest != manifest.get('sha256') or digest != receipt.get('source_manifest_sha256'):
        raise ValueError('migration source manifest digest does not match')
    return manifest, digest


def read_migration_receipt(path, *, target, store_id, read_bytes=None):
    """Validate an import; a missing Store identity needs a prepared restore."""
    target = canonical_target_value(target)
    path = Path(path)
    if path.name != 'migration-receipt.json' or path.parent.name != target_storage_key(target) or path.parent.parent.name != 'state':
        raise ValueError('migration receipt is not at its canonical target location')
    receipt = _object(path, read_bytes)
    if store_id is None:
        if receipt.get('legacy_restore_status') != 'prepared':
            raise ValueError('missing Store identity requires a prepared legacy restore')
        store_id = receipt.get('store_id')
    _receipt_identity(receipt, target=target, store_id=store_id, kind='target_migration_receipt')
    if (receipt.get('backend') not in ('preview', 'primary')
            or receipt.get('status') not in ('complete', 'partial')
            or receipt.get('activation_status') not in (None, 'active')):
        raise ValueError('migration receipt is not a completed import')
    restore_status = receipt.get('legacy_restore_status')
    if (restore_status not in (None, 'prepared')
            or (restore_status == 'prepared'
                and (receipt['backend'] != 'preview' or receipt.get('activation_status') is not None))):
        raise ValueError('migration receipt legacy restore state is invalid')
    manifest, digest = _manifest(receipt, target)
    return receipt, manifest, digest


def read_active_receipt(path, *, target, store_id, read_bytes=None):
    receipt, manifest, digest = read_migration_receipt(
        path, target=target, store_id=store_id, read_bytes=read_bytes)
    _active(receipt, target=canonical_target_value(target), store_id=store_id, kind='target_migration_receipt')
    if receipt['backend'] != 'primary':
        raise ValueError('migration receipt is not an active completed import')
    return receipt, manifest, digest


def read_legacy_archive(root, receipt, *, target, store_id, read_bytes=None, allow_pending=False):
    """Read exact archive bindings; only explicit cutover may admit pending state."""
    if type(allow_pending) is not bool:
        raise ValueError('legacy archive allow_pending must be boolean')
    target = canonical_target_value(target)
    if allow_pending:
        _receipt_identity(receipt, target=target, store_id=store_id, kind='target_migration_receipt')
    else:
        _active(receipt, target=target, store_id=store_id, kind='target_migration_receipt')
    key = target_storage_key(target)
    relative = f'state/{key}/legacy-archive.json'
    locator = receipt.get('legacy_archive_path')
    if locator != relative and not (allow_pending and locator is None):
        raise ValueError('migration receipt has no canonical legacy archive locator')
    archive = _object(Path(root) / relative, read_bytes)
    _receipt_identity(archive, target=target, store_id=store_id, kind='legacy_metadata_archive')
    statuses = ('pending', 'active') if allow_pending else ('active',)
    if archive.get('activation_status') not in statuses:
        raise ValueError('legacy archive activation does not match')
    manifest, digest = _manifest(receipt, target)
    if archive.get('source_manifest_sha256') != digest:
        raise ValueError('legacy archive manifest identity does not match')
    bindings = {item['path']: item for item in manifest['files']}
    allowed = {source.format(key=key): f'state/{key}/legacy-archive/{digest}/{destination}'
               for source, destination in LEGACY_METADATA_PATHS}
    for item in _files(archive.get('files')):
        source = bindings.get(item['path'])
        if (source is None or item.get('archive_path') != allowed.get(item['path'])
                or item['size'] != source['size'] or item['sha256'] != source['sha256']):
            raise ValueError('legacy archive locator or file binding does not match')
        canonical_relative(item['archive_path'])
    if {item['path'] for item in archive['files']} != bindings.keys() & allowed.keys():
        raise ValueError('legacy archive file set does not match the source manifest')
    return archive


def pattern_archive_relative(target, source_files):
    files = _files(source_files)
    allowed = {f'hunt-memory/patterns.jsonl{suffix}' for suffix in ('', '.1', '.2', '.3')}
    if not files or any(item['path'] not in allowed for item in files):
        raise ValueError('PatternDB source manifest contains an unexpected file')
    return f'state/{target_storage_key(canonical_target_value(target))}/pattern-archive/{_digest(files)}'


@contextmanager
def receipt_lock(root, target, *, exclusive=False):
    if type(exclusive) is not bool:
        raise ValueError('receipt lock exclusive must be boolean')
    path = Path(root) / 'state' / target_storage_key(canonical_target_value(target))
    with directory_handle(path) as fd:
        fcntl.flock(fd, fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH)
        try:
            yield path / 'migration-receipt.json'
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
