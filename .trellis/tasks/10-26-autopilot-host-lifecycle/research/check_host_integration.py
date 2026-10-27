#!/usr/bin/env python3
"""Focused, isolated assertions for host transport, ownership and current review."""

from __future__ import annotations

import argparse
from copy import deepcopy
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from unittest.mock import patch


def fixture(root: Path) -> None:
    for directory in ("commands", "agents", "skills/src-hunter", "tools"):
        (root / directory).mkdir(parents=True, exist_ok=True)
    manifest = {"schema_version": 4, "host_hooks": True, "paths": [
        {"kind": "commands", "relative_path": "autopilot.md"},
        {"kind": "skills", "relative_path": "src-hunter/SKILL.md"}], "mcp_contracts": []}
    (root / "commands/autopilot.md").write_text(
        "<!-- AUTOPILOT_CRITICAL_RUNTIME_MANIFEST\n" + json.dumps(manifest)
        + "\nAUTOPILOT_CRITICAL_RUNTIME_MANIFEST -->\n## Shared Automation\nContinue with current owners.\n")
    (root / "commands/autopilot-round.md").write_text("## Prepare And Terminal Precheck\nClaim before execution.\n")
    (root / "skills/runtime-protocol.md").write_text("# Memory\nRestore, recall, register evidence.\n")
    (root / "skills/src-hunter/SKILL.md").write_bytes((
        "---\r\nname: src-hunter\r\n---\r\nFIRST\r\n" + ("中🙂\\\"\t\n" * 1400) + "LAST\r\n").encode())
    for name in ("autopilot_host.py", "claude_hook_contract.py"):
        shutil.copyfile(Path('/probe/project/tools') / name, root / 'tools' / name)


def check() -> None:
    sys.path.insert(0, '/probe/project')
    from tools import runtime_doctor as doctor
    from tools import autopilot_host as host
    from tools import autopilot_bootstrap as bootstrap
    from tools import autopilot_state as state_owner
    from tools import checkpoint
    from tools.autopilot_gate import build_control_projection
    from tools.claude_hook_contract import (HOOK_OWNER, capture_context, context_chunks, hook_context,
                                            host_hooks, host_source_digest, managed_hook_groups, replace_managed_hooks)
    from tools.artifact_io import write_json_atomic
    from tools.target_store import initialize_target_store, runtime_store
    from tools.runtime_state import RuntimePhaseBusy, runtime_phase_lock, update_runtime_state
    from tools.action_queue import claim_next_action
    from tools.autopilot_args import parse_autopilot_args
    root, runtime = Path('/probe/source'), Path('/probe/runtime')
    fixture(root)
    runtime.mkdir()
    checks = []
    original = {"env": {"SYNTHETIC_USER_VALUE": "preserve"}, "permissions": {"allow": ["Read"]},
                "hooks": {"Stop": [{"hooks": [{"type": "command", "command": "true"}]}], "Notification": []}}
    write_json_atomic(runtime / 'settings.json', original)
    installed = doctor.sync_runtime(root, runtime, prune=True)
    assert installed['status'] == 'complete', installed
    assert doctor.compare_runtime(root, runtime)['critical_clean']
    settings = json.loads((runtime / 'settings.json').read_text())
    assert replace_managed_hooks(settings, {}) == original | {'hooks': original['hooks'] | {
        event: [] for event in host_hooks(root, runtime) if event not in original['hooks']}}
    assert settings['hooks']['Stop'][0] == original['hooks']['Stop'][0]
    assert json.loads((runtime / '.ccst-installed.json').read_text())[HOOK_OWNER]['groups'] == managed_hook_groups(settings)
    checks.append('fresh install preserves user settings and records only owned hook groups')

    (root / 'commands/autopilot.md').write_text((root / 'commands/autopilot.md').read_text() + 'Updated source.\n')
    altered = deepcopy(settings)
    altered['hooks']['Stop'][-1]['hooks'][0]['timeout'] = 19
    write_json_atomic(runtime / 'settings.json', altered)
    command_before = (runtime / 'commands/autopilot.md').read_bytes()
    receipt_before = (runtime / '.ccst-installed.json').read_bytes()
    rejected = doctor.sync_runtime(root, runtime, prune=True)
    assert rejected['status'] == 'rejected' and rejected['conflicts']
    assert (runtime / 'commands/autopilot.md').read_bytes() == command_before
    assert (runtime / '.ccst-installed.json').read_bytes() == receipt_before
    assert json.loads((runtime / 'settings.json').read_text()) == altered
    checks.append('modified groups reject whole batch before payload/receipt writes')

    write_json_atomic(runtime / 'settings.json', settings)
    publish = doctor.write_text_atomic
    def interrupt_receipt(path, text):
        if Path(path).name == '.ccst-installed.json':
            raise OSError('synthetic interrupted receipt publication')
        return publish(path, text)
    with patch.object(doctor, 'write_text_atomic', interrupt_receipt):
        interrupted = doctor.sync_runtime(root, runtime, prune=True)
    assert interrupted['status'] == 'partial', interrupted
    assert (runtime / doctor.ENTRY_MIGRATION_RECORD).exists()
    assert not doctor.compare_runtime(root, runtime)['critical_clean']
    concurrent = json.loads((runtime / 'settings.json').read_text())
    concurrent['env']['ADDED_DURING_INTERRUPTION'] = 'preserve too'
    write_json_atomic(runtime / 'settings.json', concurrent)
    recovered = doctor.sync_runtime(root, runtime, prune=True)
    assert recovered['status'] == 'complete', recovered
    assert not (runtime / doctor.ENTRY_MIGRATION_RECORD).exists()
    assert json.loads((runtime / 'settings.json').read_text()) == concurrent
    assert doctor.compare_runtime(root, runtime)['critical_clean']
    checks.append('same-source receipt recovery preserves unrelated settings edited during interruption')

    disabled = deepcopy(concurrent) | {'disableAllHooks': True}
    write_json_atomic(runtime / 'settings.json', disabled)
    assert not doctor.compare_runtime(root, runtime)['critical_clean']
    assert doctor.sync_runtime(root, runtime, prune=True)['status'] == 'rejected'
    write_json_atomic(runtime / 'settings.json', concurrent)
    unowned = Path('/probe/unowned')
    unowned.mkdir()
    write_json_atomic(unowned / 'settings.json', {'hooks': host_hooks(root, unowned)})
    assert doctor.sync_runtime(root, unowned, prune=True)['status'] == 'rejected'
    checks.append('disabled hooks and identical unowned groups remain operator-owned conflicts')

    receipt_path = runtime / '.ccst-installed.json'
    current_receipt = receipt_path.read_text()
    legacy = json.loads(current_receipt)
    legacy['commands/old.md'] = {'kind': 'commands'}
    write_json_atomic(receipt_path, legacy)
    assert doctor.compare_runtime(root, runtime)['critical_clean']
    receipt_path.write_text(current_receipt)
    assert doctor.sync_runtime(root, runtime, kinds=['commands'])['status'] == 'complete'
    command_path = root / 'commands/autopilot.md'
    active_source = command_path.read_bytes()
    command_path.write_bytes(active_source + b'New source for interrupted hook update.\n')
    assert '--kind commands,agents,skills' in doctor.format_report(doctor.compare_runtime(root, runtime, kinds=['commands']))
    try:
        doctor.sync_runtime(root, runtime, kinds=['commands'], prune=True)
    except ValueError:
        pass
    else:
        raise AssertionError('partial-kind hook update admitted')
    hook_publish = doctor._publish_hooks
    def interrupt_hooks(*args, **kwargs):
        hook_publish(*args, **kwargs)
        raise OSError('synthetic interruption after hook payload')
    with patch.object(doctor, '_publish_hooks', interrupt_hooks):
        interrupted = doctor.sync_runtime(root, runtime, prune=True)
    assert interrupted['status'] == 'partial'
    assert json.loads((runtime / doctor.ENTRY_MIGRATION_RECORD).read_text())['phase'] == 'payload'
    command_path.write_bytes(active_source + b'Different source cannot recover.\n')
    try:
        doctor.sync_runtime(root, runtime, prune=True)
    except ValueError:
        pass
    else:
        raise AssertionError('changed-source recovery admitted')
    command_path.write_bytes(active_source + b'New source for interrupted hook update.\n')
    assert doctor.sync_runtime(root, runtime, prune=True)['status'] == 'complete'
    enabled_source = command_path.read_bytes()
    command_path.write_bytes(enabled_source.replace(b'"host_hooks": true', b'"host_hooks": false'))
    assert doctor.sync_runtime(root, runtime, prune=True)['status'] == 'complete'
    remaining = json.loads((runtime / 'settings.json').read_text())
    assert not managed_hook_groups(remaining)
    assert remaining['hooks']['Stop'] == original['hooks']['Stop']
    assert remaining['env'] == concurrent['env']
    assert HOOK_OWNER not in json.loads(receipt_path.read_text())
    command_path.write_bytes(enabled_source)
    assert doctor.sync_runtime(root, runtime, prune=True)['status'] == 'complete'
    checks.append('legacy read receipts/partial sync preserved; hook payload retry is source-bound; retirement preserves user settings')

    source = capture_context(root, round_mode=True)
    assert ''.join(source['chunks']) == source['text']
    body = (root / 'skills/src-hunter/SKILL.md').read_bytes().decode().split('---\r\n', 2)[2]
    assert body in source['sections'][0]
    for part in source['chunks']:
        hook_context('SessionStart', part)
    try:
        context_chunks('x' * 56001)
    except ValueError:
        pass
    else:
        raise AssertionError('oversize context silently truncated')
    checks.append('CRLF/Chinese/astral/control characters preserved with bounded escaped hook outputs')

    empty = {'target': 'lab.test', 'has_recon': False, 'has_memory': False}
    assert build_control_projection(empty)['next_action'] == 'run_recon'
    assert build_control_projection(empty | {'has_recon': True})['next_action'] == 'continue_investigation'
    assert build_control_projection(empty | {'recon_in_progress': True})['next_action'] == 'wait_recon'
    for phase in ('recon', 'scan'):
        running = empty | {phase + '_in_progress': True}
        assert not build_control_projection(running)['hard_gate']
        independent = build_control_projection(running | {
            'action_queue_next': {'id': 'saved-evidence-review', 'action': 'Review existing capture'},
            'structured_findings': {'next_validation': {'id': 'finding-1'}},
        })
        assert not independent['hard_gate'] and independent['selection_mode'] == 'ai_priority'
        assert {v['owner'] for v in independent['owner_continuations']} == {'action_queue', 'finding'}
        assert build_control_projection(running | {'checkpoint_health': {'status': 'invalid'}})['hard_gate']['action'] == 'repair_checkpoint'
    matrix = {'endpoints': [{'endpoint': '/x', 'cells': {'sqli': {'status': 'untested'}}}]}
    old = state_owner.build_closure_projection({'target': 'lab.test', 'next_action': 'handoff'}, matrix)
    new = state_owner.build_closure_projection({'target': 'lab.test', 'next_action': 'continue_investigation'}, matrix)
    assert old == new
    checks.append('fresh Recon default retained; running phase keeps independent owners visible and does not bypass a damaged checkpoint')

    ref = root / 'evidence/lab.test/review.txt'
    ref.parent.mkdir(parents=True)
    ref.write_text('Synthetic current review evidence')
    review = {'status': 'complete', 'snapshot_digest': 'a' * 64, 'evidence_refs': ['evidence/lab.test/review.txt'],
              'decision': 'Synthetic review', 'residual_unknowns': [], 'cross_source_links': [], 'next_action': ''}
    termination = {'reason': 'no_worthwhile_work', 'session_id': 'session-1', 'invocation_id': 'invocation-1',
                   'boundary': 'Reviewed current evidence and remaining conditions'}
    checked = state_owner.validate_global_review(root, 'lab.test', review | {'termination': termination}, {}, expected_digest='a' * 64)
    assert checked['status'] == 'valid', checked
    assert checked['review']['termination'] == termination
    assert state_owner.validate_global_review(root, 'lab.test', review, {}, expected_digest='a' * 64)['status'] == 'valid'
    for invalid in (None, {}, termination | {'reason': []}, termination | {'session_id': '../bad'}, termination | {'boundary': ''}):
        assert state_owner.validate_global_review(root, 'lab.test', review | {'termination': invalid}, {}, expected_digest='a' * 64)['status'] == 'invalid'
    binding = {'session_id': 'session-1', 'invocation_id': 'invocation-1'}
    closure = {'global_review': checked['review'], 'snapshot_components': {}, 'owner_continuations': []}
    assert host.stop_check(binding, {}, closure, {})['allow']
    assert not host.stop_check(binding, {}, {'global_review': review}, {})['allow']
    assert not host.stop_check(binding | {'invocation_id': 'invocation-2'}, {}, closure, {})['allow']
    assert not host.stop_check(binding, {'recon_in_progress': True}, closure, {})['allow']
    pending = {'owner_continuations': [{'owner': 'finding', 'id': 'candidate', 'action': 'validate', 'runnable': True}]}
    assert not host.stop_check(binding, pending, closure, {})['allow']
    assert not host.stop_check(binding, {}, closure | pending, {})['allow']
    checks.append('current review retains termination; invalid/stale/cross-invocation/pending-owner stops rejected')

    assert parse_autopilot_args(['lab.test'])['max_seconds'] is None
    for round_mode in (False, True):
        parsed = parse_autopilot_args(['lab.test', '--normal', '--max-seconds=720'], round_defaults=round_mode)
        assert parsed['valid'] and parsed['max_seconds'] == 720 and parsed['max_lanes'] is None
        assert parsed['recon_flags'] == (['--deep'] if round_mode else [])
    for value in ('', '0', '-1', '1.5', 'true', '７２０', '1000000000000'):
        assert not parse_autopilot_args(['lab.test', '--max-seconds=' + value])['valid'], value
    assert not parse_autopilot_args(['lab.test', '--max-seconds=720', '--max-seconds=60'])['valid']
    timed = termination | {'reason': 'explicit_limit', 'limit': {'elapsed_seconds': 720}}
    timed_review = state_owner.validate_global_review(root, 'lab.test', review | {'termination': timed}, {}, expected_digest='a' * 64)
    assert timed_review['status'] == 'valid', timed_review
    timed_closure = closure | {'global_review': timed_review['review']}
    for invalid_limit in (None, {}, {'elapsed_seconds': True}, {'elapsed_seconds': -1},
                          {'elapsed_seconds': 720.0}, {'cost_usd': 12}, {'round_id': '../old'},
                          {'elapsed_seconds': 720, 'round_id': 'round-1'}):
        checked_limit = state_owner.validate_global_review(root, 'lab.test',
            review | {'termination': timed | {'limit': invalid_limit}}, {}, expected_digest='a' * 64)
        assert checked_limit['status'] == 'invalid', invalid_limit
    assert state_owner.validate_global_review(root, 'lab.test',
        review | {'termination': termination | {'reason': 'explicit_limit'}}, {}, expected_digest='a' * 64)['status'] == 'invalid'
    clocked = binding | {'started_at': 1000.0, 'max_seconds': 720}
    with patch.object(host.time, 'time', return_value=1505.0):
        # Reproduce the live run: 505 seconds cannot consume a 720-second allowance.
        rejected = host.stop_check(clocked, {}, timed_closure, {})
        assert not rejected['allow'] and 'not been reached' in rejected['reason']
        assert not host.stop_check(binding, {}, timed_closure, {})['allow']
        shortened = timed_closure | {'global_review': timed_review['review'] | {
            'termination': timed | {'limit': {'elapsed_seconds': 60}}}}
        assert not host.stop_check(clocked, {}, shortened, {})['allow']
    with patch.object(host.time, 'time', return_value=1719.999):
        assert not host.stop_check(clocked, {}, timed_closure, {})['allow']
    with patch.object(host.time, 'time', return_value=1720.0):
        assert host.stop_check(clocked, {}, timed_closure, {})['allow']
        assert not host.stop_check(clocked, {'scan_in_progress': True}, timed_closure, {})['allow']
        assert not host.stop_check(clocked | {'max_seconds': None}, {}, timed_closure, {})['allow']
    capped = closure | {'global_review': checked['review'] | {'termination': timed | {'limit': {'round_id': 'round-1'}}}}
    progress = {'status': 'completed', 'round_id': 'round-1', 'max_lanes': 2, 'budget_reached': True}
    round_binding = binding | {'round_limit': {'max_lanes': 2, 'round_id': 'round-1', 'previous_round_id': ''}}
    assert host.stop_check(round_binding, {'round_progress': progress}, capped, {})['allow']
    assert not host.stop_check(binding, {'round_progress': progress}, capped, {})['allow']
    for change in ({'round_id': 'round-old'}, {'max_lanes': None}, {'budget_reached': False}, {'status': 'active'}):
        assert not host.stop_check(round_binding, {'round_progress': progress | change}, capped, {})['allow']
    for admitted in ({'max_lanes': None, 'round_id': 'round-1'}, {'max_lanes': 3, 'round_id': 'round-1'},
                     {'max_lanes': 2, 'round_id': '', 'previous_round_id': 'round-1'}):
        assert not host.stop_check(binding | {'round_limit': admitted}, {'round_progress': progress}, capped, {})['allow']
    assert host.stop_check(binding | {'round_limit': {'max_lanes': 2, 'round_id': '', 'previous_round_id': 'old'}},
                           {'round_progress': progress}, capped, {})['allow']
    checks.append('optional entry limits stay unset by default; Stop rejects shortened time, 505/720s, unmeasured cost and prior completed Round')

    partial_state = {'target': 'lab.test', 'next_action': 'continue_investigation',
        'recon_artifacts': {'phase_gates': {'latest': {'dns': {
            'status': 'partial', 'evidence_refs': ['evidence/lab.test/review.txt'],
            'bounded': {'input_total': 2, 'selected': 1, 'remaining': 1, 'closure_blocking': False},
        }}}}}
    residual_review = {'status': 'valid', 'review': timed_review['review'] | {
        'residual_unknowns': ['DNS collection partial; reopen when passive source is available.']}}
    partial_closure = state_owner.build_closure_projection(partial_state, matrix, global_review=residual_review)
    assert partial_closure['global_review']['status'] == 'form_insufficient'
    assert partial_closure['global_review']['termination'] == timed
    assert partial_closure['global_review']['missing_tokens'] == ['recon:dns:remaining=1']
    assert not partial_closure['can_claim_exhausted']
    with patch.object(host.time, 'time', return_value=1505.0):
        assert not host.stop_check(clocked, partial_state, partial_closure, {})['allow']
    with patch.object(host.time, 'time', return_value=1720.0):
        released = host.stop_check(clocked, partial_state, partial_closure, {})
        assert released['allow'] and not released['exhausted']
        assert not host.stop_check(clocked, partial_state, partial_closure | {'snapshot_stale': True}, {})['allow']
        incomplete_claim = state_owner.build_closure_projection(partial_state, matrix, global_review={
            'status': 'valid', 'review': residual_review['review'] | {'termination': termination}})
        assert not host.stop_check(clocked, partial_state, incomplete_claim, {})['allow']
        stale_review = state_owner.build_closure_projection(partial_state, matrix, global_review={
            'status': 'stale', 'reason': 'global_review_stale', 'review': residual_review['review']})
        assert not host.stop_check(clocked, partial_state, stale_review, {})['allow']
    checks.append('missing residual tokens cannot erase a valid explicit stop or authorize exhaustion; stale and no-worthwhile-work claims still rejected')

    initialize_target_store(root, 'lab.test')
    live_state = state_owner.build_autopilot_state(str(root), 'lab.test', bounded=True)
    live_closure = state_owner.load_closure_projection(str(root), live_state)
    invocation_termination = termination | {'reason': 'scope_boundary', 'boundary': 'Host-only fixture; no target I/O.'}
    cli = [sys.executable, '/probe/project/tools/checkpoint.py', '--repo-root', str(root), '--target', 'lab.test',
           '--record-global-review', '--review-status', 'complete', '--snapshot-digest', live_closure['snapshot_digest'],
           '--decision', 'End synthetic host-only probe, retaining all untested work.',
           '--evidence-refs-json', json.dumps(['evidence/lab.test/review.txt']),
           '--residual-unknowns-json', json.dumps(['Untested target; reopen under authorized lab scope.']), '--json',
           '--termination-json', json.dumps(invocation_termination)]
    completed = subprocess.run(cli, text=True, capture_output=True)
    assert completed.returncode == 0, completed.stderr
    witness = json.loads(completed.stdout)
    witness_bytes = Path(witness['path']).read_bytes()
    live_closure = state_owner.load_closure_projection(str(root), state_owner.build_autopilot_state(str(root), 'lab.test', bounded=True))
    assert live_closure['global_review']['termination'] == invocation_termination
    assert host.stop_check(binding, live_state, live_closure, {})['allow']
    invalid_cli = subprocess.run(cli[:-1] + ['null'], text=True, capture_output=True)
    assert invalid_cli.returncode == 2 and Path(witness['path']).read_bytes() == witness_bytes
    drifted = subprocess.run(cli[:cli.index('--snapshot-digest') + 1] + ['0' * 64]
                             + cli[cli.index('--snapshot-digest') + 2:], text=True, capture_output=True)
    assert drifted.returncode == 2 and Path(witness['path']).read_bytes() == witness_bytes
    store = runtime_store(root, 'lab.test')
    store.create_action(command_id='host-review-work', action_id='host-review-work', intent='Review synthetic missing evidence',
                        execution_key='host-review-work', actor='host-probe', kind='work', subject={'target':'lab.test'})
    with runtime_phase_lock(root, 'lab.test', 'recon'):
        update_runtime_state(root, 'lab.test', last_executed_workflow='run_recon_started', mode='recon_running')
        claim_next_action(root, 'lab.test', action_id='host-review-work', actor='host-probe')
        current = state_owner.build_autopilot_state(str(root), 'lab.test', bounded=True)
        assert current['recon_in_progress'] and not current['hard_gate']
        assert any(v['id'] == 'host-review-work' for v in current['owner_continuations'])
        current_checkpoint = checkpoint.build_checkpoint(root, target='lab.test', refresh_coverage=False)
        assert current_checkpoint['recommended_executable_action']['id'] == 'host-review-work'
        assert current_checkpoint['decision'] == 'continue'
        try:
            with runtime_phase_lock(root, 'lab.test', 'recon'):
                raise AssertionError('duplicate Recon lock was acquired')
        except RuntimePhaseBusy:
            pass
    changed = state_owner.load_closure_projection(str(root), state_owner.build_autopilot_state(str(root), 'lab.test', bounded=True))
    assert not host.stop_check(binding, live_state, changed, {})['allow']
    ref.write_text('')
    missing = state_owner.load_closure_projection(str(root), state_owner.build_autopilot_state(str(root), 'lab.test', bounded=True))
    assert not host.stop_check(binding, live_state, missing, {})['allow']
    checks.append('real Checkpoint/Queue under Recon lock keeps independent claims visible and rejects duplicate Recon; invalid or stale review cannot stop')

    event = {'hook_event_name': 'UserPromptSubmit', 'cwd': str(root), 'session_id': 'session-1', 'prompt': '/autopilot lab.test'}
    digest = host_source_digest(root)
    bootstrap_payload = {'action': 'continue', 'arguments': {'target': 'lab.test', 'max_seconds': 720, 'max_lanes': 2},
                         'state': {'target_memory': {'fresh': True}, 'round_progress': {
                             'status': 'completed', 'round_id': 'previous-round', 'max_lanes': 1}}}
    with patch.object(host, 'REPO_ROOT', root), patch.object(bootstrap, 'build_autopilot_bootstrap', return_value=bootstrap_payload) as build:
        host.hook(runtime, event, part=None, contract_sha256=digest)
        entry_chunks = context_chunks('\n\n'.join(capture_context(root)['sections'][:2]))
        before_entry = [host.body(runtime, 'session-1', part, round_mode=False) for part in range(len(entry_chunks))]
        assert all(value.endswith(chunk + '\nCCST_ENTRY_END') for value,chunk in zip(before_entry, entry_chunks))
        assert build.call_count == 0
        entry = host.start(runtime, 'session-1', ['lab.test', '--max-seconds=720', '--deep', '--max-lanes=2'], round_mode=False)
        assert json.loads(entry)['action'] == 'continue'
        assert before_entry == [host.body(runtime, 'session-1', part, round_mode=False) for part in range(len(entry_chunks))]
        assert build.call_count == 1
        assert all(value.startswith('CCST_ENTRY ' + json.loads(entry)['host']['source_sha256']) for value in before_entry)
        with host.session_binding(runtime, 'session-1') as (saved, _, __):
            invocation = saved['invocation_id']
            old_prompt = saved['prompt_id']
            started_at = saved['started_at']
        assert json.loads(entry)['host']['started_at'] == started_at
        assert json.loads(entry)['host']['elapsed_seconds'] >= 0
        assert json.loads(entry)['host']['max_seconds'] == 720
        assert json.loads(entry)['host']['round_limit'] == {'max_lanes': 2, 'round_id': '', 'previous_round_id': 'previous-round'}
        notification = ('<task-notification>\n<task-id>b-native</task-id>\n<tool-use-id>toolu_native</tool-use-id>\n'
                        '<output-file>/tmp/claude/tasks/b-native.output</output-file>\n<status>completed</status>\n'
                        '<summary>Background Recon completed (exit code 0)</summary>\n</task-notification>')
        with host.session_binding(runtime, 'session-1') as (_, saved_path, __):
            before_notice = saved_path.read_bytes()
        assert host.hook(runtime, event | {'prompt': notification}, part=None, contract_sha256=digest) == {}
        assert saved_path.read_bytes() == before_notice
        notice = host.hook(runtime, event | {'prompt': 'An unrelated ordinary task'}, part=None, contract_sha256=digest)
        assert 'suspended' in notice['hookSpecificOutput']['additionalContext']
        assert host.hook(runtime, event | {'prompt': notification}, part=None, contract_sha256=digest) == {}
        with host.session_binding(runtime, 'session-1') as (saved, _, __):
            assert saved['status'] == 'suspended'
        assert host.hook(runtime, event | {'hook_event_name': 'Stop'}, part=None, contract_sha256=digest) == {}
        try:
            host.resume(runtime, 'session-1', invocation, old_prompt)
        except ValueError:
            pass
        else:
            raise AssertionError('stale prompt rearms earlier invocation')
        with host.session_binding(runtime, 'session-1') as (saved, _, __):
            prompt = saved['prompt_id']
        resumed = json.loads(host.resume(runtime, 'session-1', invocation, prompt))
        assert resumed['host']['invocation_id'] == invocation
        assert resumed['host']['started_at'] == started_at
        assert resumed['host']['max_seconds'] == 720
        assert resumed['host']['round_limit'] == json.loads(entry)['host']['round_limit']
        assert resumed['state']['target_memory']['fresh']
        with host.session_binding(runtime, 'session-1') as (saved, saved_path, _):
            saved['last_stop_basis'] = 'same-owner-facts'
            write_json_atomic(saved_path, saved)
        host.resume(runtime, 'session-1', invocation, prompt)
        with host.session_binding(runtime, 'session-1') as (saved, _, __):
            assert saved['last_stop_basis'] == 'same-owner-facts'
        outside = event | {'cwd': '/probe', 'prompt': '普通新任务'}
        host.hook(runtime, outside, part=None, contract_sha256=digest)
        assert host.hook(runtime, outside | {'hook_event_name': 'Stop'}, part=None, contract_sha256=digest) == {}
        dormant = host.hook(runtime, outside | {'hook_event_name':'SessionStart', 'source':'compact'}, part=0, contract_sha256=digest)
        assert dormant['hookSpecificOutput']['additionalContext'].startswith('Retained prior Autopilot context only.')
        assert 'unless the current user request continues' in dormant['hookSpecificOutput']['additionalContext']
        host.hook(runtime, event, part=None, contract_sha256=digest)
        host.start(runtime, 'session-1', ['lab.test'], round_mode=False)
        compact = event | {'hook_event_name': 'SessionStart', 'source': 'compact'}
        host.hook(runtime, compact, part=None, contract_sha256=digest)
        received = [host.hook(runtime, compact, part=i, contract_sha256=digest) for i in range(len(capture_context(root)['chunks']))]
        assert all('CCST_RECOVERY' in item['hookSpecificOutput']['additionalContext'] for item in received)
        with host.session_binding(runtime, 'session-1') as (saved, _, context_path):
            damaged = json.loads(context_path.read_text())
            damaged['sections'][0] += 'CORRUPTION'
            write_json_atomic(context_path, damaged)
        try:
            host.hook(runtime, compact, part=0, contract_sha256=digest)
        except ValueError:
            pass
        else:
            raise AssertionError('damaged body accepted by hash labels')
        with host.session_binding(runtime, 'session-1') as (saved, _, __):
            assert saved['status'] == 'suspended'
        host.hook(runtime, event, part=None, contract_sha256=digest)
        host.start(runtime, 'session-1', ['lab.test'], round_mode=False)
        original_source = command_path.read_bytes()
        command_path.write_bytes(original_source + b'Source changed during invocation.\n')
        try:
            host.hook(runtime, compact, part=None, contract_sha256=digest)
        except ValueError:
            pass
        else:
            raise AssertionError('changed source accepted during recovery')
        with host.session_binding(runtime, 'session-1') as (saved, _, __):
            assert saved['status'] == 'suspended'
        command_path.write_bytes(original_source)
        bootstrap_payload['state']['round_progress'] = {'status': 'active', 'round_id': 'inherited-round', 'max_lanes': 3}
        inherited_entry = json.loads(host.start(runtime, 'session-1', ['lab.test'], round_mode=False))
        assert inherited_entry['host']['round_limit'] == {'max_lanes': 3, 'round_id': 'inherited-round', 'previous_round_id': ''}
        bootstrap_payload['arguments']['max_seconds'] = None
        bootstrap_payload['state']['round_progress']['max_lanes'] = None
        unbounded_entry = json.loads(host.start(runtime, 'session-1', ['lab.test'], round_mode=False))
        assert unbounded_entry['host']['max_seconds'] is None and unbounded_entry['host']['round_limit']['max_lanes'] is None
    checks.append('static parts precede admission safely with matching sources and exactly one Bootstrap; resume keeps invocation; corrupt recovery rejected')

    targets = root / 'batch.txt'
    targets.write_text('lab.test\nsecond.test\n')
    batch_state = state_owner.build_autopilot_state(str(root), str(targets), bounded=True)
    assert batch_state['target_kind'] == 'list' and batch_state['next_action'] == 'run_batch_recon'
    with patch.object(host, 'REPO_ROOT', root), patch.object(bootstrap, 'build_autopilot_bootstrap',
            return_value={'action':'continue', 'arguments':{'target':str(targets)}}):
        host.hook(runtime, event, part=None, contract_sha256=digest)
        host.start(runtime, 'session-1', [str(targets)], round_mode=False)
        with patch.object(state_owner, 'load_closure_projection', side_effect=AssertionError('list is not a Store')):
            blocked = host.hook(runtime, event | {'hook_event_name':'Stop'}, part=None, contract_sha256=digest)
            assert blocked['decision'] == 'block' and 'batch' in blocked['reason'].lower()
            suspended = host.hook(runtime, event | {'hook_event_name':'Stop', 'stop_hook_active':True}, part=None, contract_sha256=digest)
            assert suspended['continue'] is False
    checks.append('batch input uses existing continuation without loading a list Store or inventing a list review')
    result = {'status': 'passed', 'checks': checks, 'scope': 'synthetic owner/transport/install assertions; not live model behavior'}
    write_json_atomic('/probe/acceptance.json', result)
    print(json.dumps(result, ensure_ascii=False))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('--inside', action='store_true')
    args = parser.parse_args()
    if args.inside:
        check()
        return 0
    repo = Path(__file__).resolve().parents[4]
    run = Path(tempfile.mkdtemp(prefix='ccst-host-contract-'))
    (run / 'home').mkdir()
    for directory in ('tools', 'memory'):
        for source in (repo / directory).rglob('*.py'):
            destination = run / 'project' / source.relative_to(repo)
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, destination)
    (run / 'project/knowledge').mkdir()
    shutil.copyfile(repo / 'knowledge/capabilities.yaml', run / 'project/knowledge/capabilities.yaml')
    shutil.copyfile(__file__, run / 'check.py')
    for directory, dirs, files in os.walk(run):
        for path in [Path(directory), *(Path(directory) / name for name in files)]:
            os.chown(path, 65534, 65534)
    sandbox = ['bwrap', '--die-with-parent', '--unshare-net', '--unshare-pid', '--unshare-ipc', '--unshare-uts',
               '--ro-bind', '/usr', '/usr', '--symlink', 'usr/bin', '/bin', '--symlink', 'usr/lib', '/lib',
               '--symlink', 'usr/lib64', '/lib64', '--proc', '/proc', '--dev', '/dev', '--perms', '1777',
               '--tmpfs', '/tmp', '--dir', '/etc', '--bind', str(run), '/probe', '--bind', str(run / 'home'), '/root',
               '--chdir', '/probe/project', '--', '/usr/bin/setpriv', '--reuid=65534', '--regid=65534',
               '--clear-groups', '--no-new-privs', '--bounding-set=-all', '--inh-caps=-all', '--ambient-caps=-all',
               '/usr/bin/python3', '/probe/check.py', '--inside']
    print('isolated run: ' + str(run), flush=True)
    return subprocess.run(sandbox, env={'PATH': '/usr/bin:/bin', 'HOME': '/root', 'LANG': 'C.UTF-8',
                       'PYTHONDONTWRITEBYTECODE': '1', 'PYTHONNOUSERSITE': '1'}, timeout=60).returncode


if __name__ == '__main__':
    raise SystemExit(main())
