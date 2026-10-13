"""Baseline tests use synthetic files only; no model or target state."""
import importlib.util
import json
from pathlib import Path
import subprocess
import sys

import pytest

MODULE = Path(__file__).parent / 'skill-validator' / 'capability_baseline.py'
spec = importlib.util.spec_from_file_location('capability_baseline', MODULE)
baseline = importlib.util.module_from_spec(spec)
spec.loader.exec_module(baseline)


@pytest.fixture
def source(tmp_path):
    root = tmp_path / 'repo'
    (root / 'tools').mkdir(parents=True)
    (root / 'tools/changed.py').write_bytes(b'actual dirty bytes\x00\xff')
    (root / 'tools/changed.py').chmod(0o755)
    (root / 'tools/untracked.py').write_bytes(b'new source')
    return root


def allowlist():
    return {'files': ['tools/changed.py', 'tools/untracked.py'],
            'deleted': ['plan/removed.md']}


def captured(source, tmp_path):
    output = tmp_path / 'snapshot'
    result = baseline.capture(source, output, allowlist())
    return output, result['manifest_sha256']


def test_bytes_deletions_untracked_modes_and_original_unchanged(source, tmp_path):
    before = {p.name: (p.read_bytes(), p.stat().st_mtime_ns, p.stat().st_mode)
              for p in source.glob('tools/*')}
    output, digest = captured(source, tmp_path)
    manifest = baseline.verify(output, digest)
    assert manifest['deleted'] == ['plan/removed.md']
    assert manifest['model']['status'] == 'pending'
    target = tmp_path / 'restore'
    assert baseline.restore(output, target, digest)['status'] == 'verified'
    assert not (target / 'plan/removed.md').exists()
    assert (target / 'tools/changed.py').stat().st_mode & 0o777 == 0o755
    assert {p.name: (p.read_bytes(), p.stat().st_mtime_ns, p.stat().st_mode)
            for p in source.glob('tools/*')} == before
    assert (target / 'tools/untracked.py').read_bytes() == b'new source'


@pytest.mark.parametrize('bad', ['', '../tools/x', '/tools/x', 'tools//x', './tools/x',
    'tools/../x', 'C:/tools/x', 'tools\\x', '.env', 'config.json',
    'state/x', 'tests/skill-validator/runs/x', 'knowledge/pull-log.jsonl',
    'knowledge/distill-digests/x', 'memory/goals/x', '.claude/settings.json'])
def test_path_rejections_before_publication(source, tmp_path, bad):
    output = tmp_path / 'bad'
    with pytest.raises(baseline.BaselineError):
        baseline.capture(source, output, {'files': [bad], 'deleted': []})
    assert not output.exists()


@pytest.mark.parametrize('value', [None, [], {}, {'files': [], 'deleted': []},
    {'files': ['tools/changed.py'] * 2, 'deleted': []},
    {'files': ['tools/changed.py'], 'deleted': ['tools/changed.py']},
    {'files': ['tools', 'tools/changed.py'], 'deleted': []},
    {'files': 'tools/changed.py', 'deleted': []}])
def test_malformed_allowlist(source, tmp_path, value):
    with pytest.raises(baseline.BaselineError):
        baseline.capture(source, tmp_path / 'bad', value)


def test_symlink_source_parent_root_output_and_overlap(source, tmp_path):
    (source / 'tools/link.py').symlink_to(source / 'tools/changed.py')
    with pytest.raises(baseline.BaselineError):
        baseline.capture(source, tmp_path / 'bad', {'files': ['tools/link.py'], 'deleted': []})
    alias = tmp_path / 'alias'
    alias.symlink_to(source, target_is_directory=True)
    with pytest.raises(baseline.BaselineError):
        baseline.capture(alias, tmp_path / 'bad2', allowlist())
    with pytest.raises(baseline.BaselineError):
        baseline.capture(source, alias / 'nested', allowlist())
    with pytest.raises(baseline.BaselineError):
        baseline.capture(source, source / 'snapshot', allowlist())
    (source / 'tests').symlink_to(source / 'tools', target_is_directory=True)
    with pytest.raises(baseline.BaselineError):
        baseline.capture(source, tmp_path / 'bad3', {'files': ['tests/changed.py'], 'deleted': []})


def test_partial_output_and_failed_copy_never_publish(source, tmp_path, monkeypatch):
    output = tmp_path / 'partial'
    output.mkdir()
    (output / 'keep').write_text('retained')
    with pytest.raises(FileExistsError):
        baseline.capture(source, output, allowlist())
    assert (output / 'keep').read_text() == 'retained'
    real_write = baseline._write
    def fail(root, name, data, mode):
        if name.endswith('untracked.py'):
            raise OSError('injected write failure')
        real_write(root, name, data, mode)
    monkeypatch.setattr(baseline, '_write', fail)
    with pytest.raises(OSError, match='injected'):
        baseline.capture(source, tmp_path / 'failed', allowlist())
    assert not (tmp_path / 'failed/manifest.json').exists()
    assert (source / 'tools/untracked.py').read_bytes() == b'new source'


@pytest.mark.parametrize('damage', ['bytes', 'mode', 'manifest', 'extra', 'symlink'])
def test_snapshot_corruption_rejected(source, tmp_path, damage):
    output, digest = captured(source, tmp_path)
    file = output / 'source/tools/changed.py'
    if damage == 'bytes':
        file.chmod(0o755); file.write_bytes(b'damaged')
    elif damage == 'mode':
        file.chmod(0o644)
    elif damage == 'manifest':
        path = output / 'manifest.json'; path.chmod(0o644); path.write_text('{}')
    elif damage == 'extra':
        (output / 'source').chmod(0o755); (output / 'source/extra').write_text('x')
    else:
        file.parent.chmod(0o755); file.unlink(); file.symlink_to(source / 'tools/changed.py')
    with pytest.raises(baseline.BaselineError):
        baseline.restore(output, tmp_path / 'badrestore', digest)
    assert not (tmp_path / 'badrestore').exists()


def test_restore_corruption_and_existing_output(source, tmp_path):
    output, digest = captured(source, tmp_path)
    target = tmp_path / 'restored'
    baseline.restore(output, target, digest)
    with pytest.raises(FileExistsError):
        baseline.restore(output, target, digest)
    (target / 'tools/changed.py').write_bytes(b'corrupted')
    with pytest.raises(baseline.BaselineError):
        baseline.verify_restored(output, target, digest)


def test_missing_not_silently_deletion_and_false_deletion(source, tmp_path):
    with pytest.raises(FileNotFoundError):
        baseline.capture(source, tmp_path / 'bad', {'files': ['tools/missing.py'], 'deleted': []})
    assert not (tmp_path / 'bad/manifest.json').exists()
    with pytest.raises(baseline.BaselineError):
        baseline.capture(source, tmp_path / 'bad2', {'files': [], 'deleted': ['tools/changed.py']})


def test_cli_capture_verify_restore_and_error(source, tmp_path):
    allow = tmp_path / 'allow.json'; allow.write_text(json.dumps(allowlist()))
    output = tmp_path / 'cli'
    def run(*args):
        return subprocess.run([sys.executable, str(MODULE), *args], capture_output=True, text=True)
    result = run('capture', '--root', str(source), '--output', str(output), '--allowlist', str(allow))
    assert result.returncode == 0, result.stderr
    digest = json.loads(result.stdout)['manifest_sha256']
    for command in ('verify', 'restore', 'verify-restored'):
        args = [command, '--snapshot', str(output), '--sha256', digest]
        if command != 'verify':
            args += ['--output', str(tmp_path / 'cli-restore')]
        checked = run(*args)
        assert checked.returncode == 0, checked.stderr
    failed = run('verify', '--snapshot', str(output), '--sha256', '0' * 64)
    assert failed.returncode == 2 and json.loads(failed.stderr)['error']


def test_source_drift_refuses_publication(source, tmp_path, monkeypatch):
    real_write = baseline._write
    def mutate(root, name, data, mode):
        real_write(root, name, data, mode)
        if name.endswith('untracked.py'):
            (source / 'tools/changed.py').write_bytes(b'concurrent writer')
    monkeypatch.setattr(baseline, '_write', mutate)
    with pytest.raises(baseline.BaselineError, match='source changed'):
        baseline.capture(source, tmp_path / 'drift', allowlist())
    assert not (tmp_path / 'drift/manifest.json').exists()


def test_restore_failure_keeps_source_and_partial_destination(source, tmp_path, monkeypatch):
    output, digest = captured(source, tmp_path)
    real_write = baseline._write
    def fail(root, name, data, mode):
        if name.endswith('untracked.py'):
            raise OSError('restore interrupted')
        real_write(root, name, data, mode)
    monkeypatch.setattr(baseline, '_write', fail)
    target = tmp_path / 'interrupted'
    with pytest.raises(OSError, match='interrupted'):
        baseline.restore(output, target, digest)
    baseline.verify(output, digest)
    with pytest.raises(baseline.BaselineError):
        baseline.verify_restored(output, target, digest)
    assert (source / 'tools/untracked.py').read_bytes() == b'new source'


@pytest.mark.parametrize('path', ['mcp/client/config.json', 'tools/nested/.env',
    'templates/private/.env.local', 'tests/fixtures/config.json'])
def test_nested_private_paths_rejected_before_any_read(source, tmp_path, monkeypatch, path):
    def forbidden_read(*args):
        pytest.fail('a private allowlist entry reached source reading')
    monkeypatch.setattr(baseline, '_read', forbidden_read)
    output = tmp_path / 'private-output'
    with pytest.raises(baseline.BaselineError, match='private/runtime'):
        baseline.capture(source, output, {'files': ['tools/changed.py', path], 'deleted': []})
    assert not output.exists()


def test_parent_symlink_swap_between_check_and_open_is_rejected(source, tmp_path, monkeypatch):
    outside = tmp_path / 'outside'; outside.mkdir()
    (outside / 'changed.py').write_bytes(b'must not read outside')
    real_member = baseline._member
    def swap(root, name):
        result = real_member(root, name)
        if root == source and name == 'tools/changed.py':
            (source / 'tools').rename(source / 'old-tools')
            (source / 'tools').symlink_to(outside, target_is_directory=True)
        return result
    monkeypatch.setattr(baseline, '_member', swap)
    with pytest.raises(OSError):
        baseline.capture(source, tmp_path / 'raced', {'files': ['tools/changed.py'], 'deleted': []})
    assert not (tmp_path / 'raced/source/tools/changed.py').exists()


def test_malformed_source_provenance_fails_before_output(source, tmp_path):
    with pytest.raises(baseline.BaselineError):
        baseline.capture(source, tmp_path / 'bad-meta', allowlist(), provenance={'source_root': 7})
    assert not (tmp_path / 'bad-meta').exists()


def test_destination_parent_swap_cannot_write_outside(source, tmp_path, monkeypatch):
    output = tmp_path / 'restore'
    output.mkdir()
    (output / 'tools').mkdir()
    outside = tmp_path / 'outside'
    outside.mkdir()
    real_member = baseline._member
    def swap(root, name):
        path = real_member(root, name)
        (output / 'tools').rmdir()
        (output / 'tools').symlink_to(outside, target_is_directory=True)
        return path
    monkeypatch.setattr(baseline, '_member', swap)
    with pytest.raises(OSError):
        baseline._write(output, 'tools/new.py', b'must stay inside', 0o644)
    assert not (outside / 'new.py').exists()
