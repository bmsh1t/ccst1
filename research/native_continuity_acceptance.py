"""Real Claude CLI/hooks with scripted loopback responses; no paid inference.

Run: python3 -I research/native_continuity_acceptance.py
Adapted from the isolated native_large_output acceptance harness. This verifies
transport and lifecycle mechanics, not autonomous model intent or investigation.
"""

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import hashlib
import json
import os
import queue
import shlex
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
import uuid

ROOT, PROJECT, RUNTIME = Path('/probe'), Path('/probe/project'), Path('/root/.claude')
TARGET = 'native-continuity.test'


def require_isolation():
    assert os.getuid() == 65534 and Path('/root/isolation-marker').read_text() == ROOT.name
    assert not Path('/root/.codex').exists()
    sys.path.insert(0, str(PROJECT))


def read_binding(sid):
    return json.loads((RUNTIME / '.ccst-autopilot' / sid / 'binding.json').read_text())


def write_review(sid, reason):
    require_isolation()
    from tools.autopilot_state import build_autopilot_state, load_closure_projection
    from tools.checkpoint import record_global_review
    from tools.target_paths import target_storage_key
    binding = read_binding(sid)
    state = build_autopilot_state(str(PROJECT), TARGET, bounded=True)
    closure = load_closure_projection(str(PROJECT), state)
    evidence = f'evidence/{target_storage_key(TARGET)}/local-phase.txt'
    result = record_global_review(PROJECT, TARGET, status='complete',
        snapshot_digest=closure['snapshot_digest'], evidence_refs=[evidence],
        residual_unknowns=['Pending local comparison requires the next explicit fixture step.',
            *[item['review_token'] for item in closure.get('bounded_residuals', []) if item.get('review_token')]],
        decision='Local read-only phase reached its fixture boundary; pending work is retained.',
        termination={'reason': reason, 'session_id': sid, 'invocation_id': binding['invocation_id'],
                     'boundary': 'This scripted phase permits local metadata reads only; remaining work is outside this phase.'})
    print(json.dumps({'review_recorded': result['global_review']['termination']}, ensure_ascii=False))


def strings(value):
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for child in value.values():
            yield from strings(child)
    elif isinstance(value, list):
        for child in value:
            yield from strings(child)


def decoded_objects(value):
    decoder = json.JSONDecoder()
    for text in strings(value):
        for position, char in enumerate(text):
            if char != '{':
                continue
            try:
                decoded, _ = decoder.raw_decode(text, position)
            except ValueError:
                continue
            if isinstance(decoded, dict):
                yield decoded


def tool_results(value, tool_id):
    if isinstance(value, dict):
        if value.get('type') == 'tool_result' and value.get('tool_use_id') == tool_id:
            yield value.get('content')
        for child in value.values():
            yield from tool_results(child, tool_id)
    elif isinstance(value, list):
        for child in value:
            yield from tool_results(child, tool_id)


def check_rejection(reason, binding, phase):
    expected = ('Known runnable owner work remains' if phase == 'entry'
                else 'termination_mismatch:')
    explanation, marker, host = reason.partition('\nHost binding: ')
    assert expected in explanation and marker, 'expected current Stop rejection missing'
    host = json.loads(host)
    for key in ('session_id', 'invocation_id', 'target'):
        assert host[key] == binding[key], f'Stop rejection has stale {key}'
    assert host['status'] == 'active'
    return explanation


def inside():
    require_isolation()
    from tools.autopilot_host import _state_command
    from tools.claude_hook_contract import capture_context, context_chunks
    from tools.runtime_doctor import sync_runtime
    from tools.target_store import initialize_target_store, runtime_store
    from tools.target_paths import target_storage_key
    assert not RUNTIME.exists()
    current = capture_context(PROJECT)
    for part, chunk in enumerate(current['chunks']):
        output = subprocess.check_output([sys.executable, '-B', str(PROJECT / 'tools/autopilot_host.py'),
            'body', '--part', str(part)], cwd=PROJECT, text=True, timeout=10)
        assert output == (f'CCST_ENTRY {current["sha256"]} PART {part + 1}/{len(current["chunks"])}\n'
                          f'{chunk}\nCCST_ENTRY_END\n'), 'body requires no runtime or lifecycle event'
    assert not RUNTIME.exists(), 'body created a runtime'
    assert sync_runtime(PROJECT, RUNTIME, prune=True)['status'] == 'complete'
    initialize_target_store(PROJECT, TARGET)
    store = runtime_store(PROJECT, TARGET)
    store.set_active_goal(command_id='local-goal', goal='Review the supplied local fixture', actor='acceptance')
    handoff = 'BEGIN-LOCAL-HANDOFF\n' + 'Pending local revision comparison; conditions remain explicit.\n' * 8 + 'END-LOCAL-HANDOFF'
    store.remember(command_id='initial-handoff', kind='handoff', statement=handoff,
        conditions='local fixture revision A', reopen_when='revision B is supplied',
        next_intent='Compare local fixture revision B', evidence=[], actor='acceptance')
    for number in range(6):
        store.remember(command_id=f'local-note-{number}', kind='note', statement=f'Local note {number}',
            conditions='local fixture', reopen_when='', next_intent='', evidence=[], actor='acceptance')
    store.create_action(command_id='pending-local', action_id='pending-local-review',
        intent='Compare local fixture revision B', execution_key='local-only', actor='acceptance',
        kind='work', subject={'target': TARGET})
    evidence = PROJECT / 'evidence' / target_storage_key(TARGET) / 'local-phase.txt'
    evidence.parent.mkdir(parents=True, exist_ok=True)
    evidence.write_text('Synthetic local phase boundary; no target network activity is authorized.\n')
    sid, owner = str(uuid.uuid4()), store.binding()
    state = {'phase': '', 'steps': {}, 'requests': 0, 'tools': {}, 'error': ''}
    boundaries, timeline, source_updates = [], [], []
    started = time.monotonic()

    def log(kind, **fields):
        timeline.append({'t_rel': round(time.monotonic() - started, 3), 'kind': kind, **fields})
        (ROOT / 'timeline.json').write_text(json.dumps(timeline, ensure_ascii=False, indent=2))

    def update_source(phase):
        protocol = PROJECT / 'skills/runtime-protocol.md'
        protocol.write_text(protocol.read_text() + f'\n<!-- Local source fixture {phase}: {uuid.uuid4().hex} -->\n')
        state['source'] = capture_context(PROJECT)
        update = {'phase': phase, 'sha256': state['source']['sha256'],
                  'protocol_sha256': hashlib.sha256(protocol.read_bytes()).hexdigest()}
        source_updates.append(update)
        log('source_updated', **update)

    def check_bodies(data, marker):
        current = state['source']
        rendered = '\n'.join(strings([data.get('messages'), data.get('system')]))
        chunks = context_chunks(current['text'])
        for index, chunk in enumerate(chunks):
            assert f'{marker} {current["sha256"]} PART {index + 1}/{len(chunks)}\n{chunk}' in rendered, 'current body part missing'
        log('source_bodies_received', phase=state['phase'], sha256=current['sha256'], parts=len(chunks))

    def check_memory(memory):
        assert memory['active_goal'] == 'Review the supplied local fixture'
        assert memory['current_handoff']['text'] == handoff
        assert memory['current_handoff']['entry_id'] == 'initial-handoff'
        assert memory['next_actions'][0]['text'] == 'Compare local fixture revision B'
        for key, expected in (('conditions', 'local fixture revision A'),
                              ('reopen_when', 'revision B is supplied'),
                              ('next_intent', 'Compare local fixture revision B')):
            assert memory['current_handoff']['structured'][key] == expected
            assert memory['next_actions'][0]['structured'][key] == expected
        assert memory['source_binding'] == owner
        assert len(memory['recent_entries']) == 5 and memory['experience_window']['has_more']
        assert all(item['entry_id'] != 'initial-handoff' for item in memory['recent_entries'])

    def script_response(data):
        phase = state['phase']
        step = state['steps'].get(phase, 0)
        state['requests'] += 1
        assert step < 10 and state['requests'] < 70, 'scripted protocol did not progress'
        messages = data.get('messages', [])
        rendered = '\n'.join(strings(messages))
        returned = list(tool_results(messages, state.get('pending_tool')))
        if phase == 'compact':
            return None, '<summary>Continue the same local fixture only on explicit user request. Retain the Store goal, pending-local-review and current handoff.</summary>'
        if phase == 'question_restart' or (phase == 'after_compact' and step == 0):
            check_bodies(data, f'CCST_RECOVERY {read_binding(sid)["invocation_id"]}')
        if phase.startswith('question'):
            return None, 'The prior local fixture result is retained. This answer performs no further work.'
        command = None
        if step == 0:
            before = read_binding(sid)
            state['before'] = before
            if phase == 'entry':
                check_bodies(data, 'CCST_ENTRY')
                payload = next(item for item in decoded_objects(messages)
                               if item.get('action') == 'continue' and item.get('host', {}).get('session_id') == sid)
                check_memory(payload['state']['target_memory'])
                assert 'pending-local-review' in json.dumps(payload)
            else:
                assert before['status'] == 'completed'
            command = _state_command(RUNTIME, before)
            assert command in rendered, 'current hook state command missing from actual request'
            log('current_command_delivered', phase=phase, status=before['status'])
        elif step == 1:
            payload = state.get('source_payload')
            if payload is None:
                payload = next(item for item in decoded_objects(returned)
                               if item.get('action') == 'continue' and item.get('host', {}).get('session_id') == sid
                               and item.get('kind') == 'autopilot_loop_check_projection')
                state['source_part'] = 0
            else:
                index = state['source_part'] - 1
                chunks = state['source']['chunks']
                expected = f'CCST_ENTRY {state["source"]["sha256"]} PART {index + 1}/{len(chunks)}\n{chunks[index]}\nCCST_ENTRY_END'
                assert expected in '\n'.join(strings(returned)), 'current recovery body was truncated'
            delivery = payload.get('recovery', {}).get('source_context')
            if delivery:
                assert delivery['sha256'] == state['source']['sha256']
                assert len(delivery['commands']) == len(state['source']['chunks'])
                if state['source_part'] < len(delivery['commands']):
                    command = delivery['commands'][state['source_part']]
                    state['source_part'] += 1
                    state['source_payload'] = payload
                    state['tools'][phase] = state['tools'].get(phase, 0) + 1
                    return command, ''
                state.pop('source_payload', None)
                log('refresh_bodies_received', phase=phase, sha256=delivery['sha256'], parts=state['source_part'])
            current, before = read_binding(sid), state['before']
            assert payload['host']['invocation_id'] == current['invocation_id']
            assert payload['active_goal'] == 'Review the supplied local fixture'
            assert 'pending-local-review' in json.dumps(payload['control'])
            for key in ('started_at', 'max_seconds', 'round_limit', 'arguments', 'target'):
                assert current[key] == before[key], key
            if phase != 'entry':
                check_memory(payload['recovery']['state']['target_memory'])
                assert delivery and state['source_part'] == len(delivery['commands'])
                assert current['source_sha256'] == state['source']['sha256']
                assert current['invocation_id'] != before['invocation_id']
            else:
                assert current['invocation_id'] == before['invocation_id']
            log('refresh_received', phase=phase, old_invocation=before['invocation_id'],
                invocation=current['invocation_id'], owner=store.binding(), goal=payload['active_goal'])
            assert store.binding() == owner
            if phase == 'entry':
                command = shlex.join(['python3', '/probe/probe.py', '--review', sid, 'no_worthwhile_work'])
            else:
                state['steps'][phase] = 3
                return None, 'Attempt to finish with the preceding invocation review.'
        elif step == 2:
            assert any(item.get('review_recorded', {}).get('reason') == 'no_worthwhile_work'
                       for item in decoded_objects(returned))
            return_text = 'Attempt to finish while the known local work remains.'
            state['steps'][phase] = 3
            return None, return_text
        elif step == 3:
            current = read_binding(sid)
            feedback = next((text for text in strings(messages[-1].get('content'))
                             if text.startswith('Stop hook blocking error from command: ')), '')
            assert feedback, 'current API Stop feedback missing'
            reason = check_rejection(feedback, current, phase)
            assert current['status'] == 'active'
            log('stop_feedback_received', phase=phase, reason=reason, invocation=current['invocation_id'])
            command = shlex.join(['python3', '/probe/probe.py', '--review', sid, 'scope_boundary'])
        elif step == 4:
            assert any(item.get('review_recorded', {}).get('reason') == 'scope_boundary'
                       for item in decoded_objects(returned))
            state['steps'][phase] = 5
            return None, 'Local phase boundary recorded; remaining work is preserved.'
        else:
            raise AssertionError('fresh scope-bound review failed to release the real Stop hook')
        state['steps'][phase] = step + 1
        state['tools'][phase] = state['tools'].get(phase, 0) + 1
        return command, ''

    class API(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_POST(self):
            data = json.loads(self.rfile.read(int(self.headers.get('Content-Length', '0'))))
            if 'count_tokens' in self.path:
                wire, media = b'{"input_tokens":5000}', 'application/json'
            elif self.path.startswith('/v1/messages'):
                try:
                    command, text = script_response(data)
                except Exception as exc:
                    state['error'] = f'{type(exc).__name__}: {exc}'
                    log('fixture_error', phase=state['phase'], error=state['error'])
                    self.send_error(500, state['error'])
                    return
                tool = command is not None
                content = ({'type': 'tool_use', 'id': 'toolu_' + uuid.uuid4().hex, 'name': 'Bash',
                            'input': {'command': command, 'description': 'Check local lifecycle fixture'}}
                           if tool else {'type': 'text', 'text': text})
                if tool:
                    state['pending_tool'] = content['id']
                message = {'id': 'msg_' + uuid.uuid4().hex, 'type': 'message', 'role': 'assistant',
                    'model': data.get('model'), 'content': [content], 'stop_reason': 'tool_use' if tool else 'end_turn',
                    'stop_sequence': None, 'usage': {'input_tokens': 5000, 'output_tokens': 20}}
                if data.get('stream'):
                    events = [('message_start', {'type': 'message_start', 'message': {**message, 'content': [], 'stop_reason': None}}),
                        ('content_block_start', {'type': 'content_block_start', 'index': 0,
                            'content_block': {**content, 'input': {}} if tool else {'type': 'text', 'text': ''}}),
                        ('content_block_delta', {'type': 'content_block_delta', 'index': 0,
                            'delta': {'type': 'input_json_delta', 'partial_json': json.dumps(content['input'])}
                            if tool else {'type': 'text_delta', 'text': content['text']}}),
                        ('content_block_stop', {'type': 'content_block_stop', 'index': 0}),
                        ('message_delta', {'type': 'message_delta', 'delta': {'stop_reason': message['stop_reason'], 'stop_sequence': None}, 'usage': {'output_tokens': 20}}),
                        ('message_stop', {'type': 'message_stop'})]
                    wire = ''.join('event: ' + name + '\ndata: ' + json.dumps(item) + '\n\n' for name, item in events).encode()
                    media = 'text/event-stream'
                else:
                    wire, media = json.dumps(message).encode(), 'application/json'
            else:
                self.send_error(404)
                return
            self.send_response(200)
            self.send_header('Content-Type', media)
            self.send_header('Content-Length', str(len(wire)))
            self.end_headers()
            self.wfile.write(wire)

    server = ThreadingHTTPServer(('127.0.0.1', 0), API)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    env = {'HOME': '/root', 'CLAUDE_CONFIG_DIR': str(RUNTIME), 'CCST_RUNTIME_ROOT': str(RUNTIME),
        'HUNT_MEMORY_DIR': str(PROJECT / 'hunt-memory'), 'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8',
        'SHELL': '/bin/bash', 'ANTHROPIC_API_KEY': 'synthetic-only',
        'ANTHROPIC_BASE_URL': f'http://127.0.0.1:{server.server_port}', 'PYTHONDONTWRITEBYTECODE': '1',
        'PYTHONNOUSERSITE': '1', 'DISABLE_AUTOUPDATER': '1', 'CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC': '1'}
    argv = ['/opt/claude', '-p', '--model', 'claude-opus-4-8', '--input-format', 'stream-json',
        '--output-format', 'stream-json', '--verbose', '--include-hook-events', '--setting-sources', 'user,project',
        '--settings', str(RUNTIME / 'settings.json'), '--strict-mcp-config', '--mcp-config', '{"mcpServers":{}}',
        '--no-chrome', '--dangerously-skip-permissions', '--permission-prompts', 'none',
        '--tools', 'Bash,Read,Skill', '--session-id', sid]

    def run(command, phases):
        with (ROOT / 'stderr.txt').open('a') as errors:
            process = subprocess.Popen(command, env=env, cwd=PROJECT, text=True, stdin=subprocess.PIPE,
                stdout=subprocess.PIPE, stderr=errors, start_new_session=True)
            messages = queue.Queue()
            def read():
                for line in process.stdout:
                    row = json.loads(line)
                    with (ROOT / 'visible.jsonl').open('a') as output:
                        output.write(line)
                    if row.get('subtype') == 'compact_boundary':
                        boundaries.append(row)
                    messages.put(row)
                messages.put({'type': 'eof'})
            threading.Thread(target=read, daemon=True).start()
            try:
                for phase, prompt in phases:
                    state['phase'] = phase
                    if phase in {'continue', 'compact', 'continue_restart'}:
                        update_source(phase)
                    stops = []
                    before = read_binding(sid) if phase != 'entry' else None
                    log('user_prompt', phase=phase, prompt=prompt)
                    process.stdin.write(json.dumps({'type': 'user', 'message': {'role': 'user', 'content': prompt}}) + '\n')
                    process.stdin.flush()
                    while True:
                        row = messages.get(timeout=30)
                        assert not state['error'], state['error']
                        assert row['type'] != 'eof', 'CLI exited before result'
                        if row.get('subtype') == 'hook_response' and row.get('hook_event') == 'Stop':
                            assert row['session_id'] == sid and row['exit_code'] == 0, row
                            response = json.loads(row['stdout'])
                            stops.append({'hook_id': row['hook_id'], 'response': response})
                            log('stop_hook', phase=phase, **stops[-1])
                        if row['type'] == 'result':
                            assert row['subtype'] == 'success' and not row.get('is_error'), row
                            current = read_binding(sid)
                            assert current['status'] == 'completed', current
                            if phase.startswith('question') or phase == 'compact':
                                assert state['tools'].get(phase, 0) == 0
                                for key in ('invocation_id', 'started_at', 'max_seconds', 'round_limit', 'arguments', 'target'):
                                    assert current[key] == before[key], key
                                assert [item['response'] for item in stops] == ([] if phase == 'compact' else [{}])
                            else:
                                assert state['steps'].get(phase) == 5, 'phase stopped before fresh review and release'
                                assert len(stops) == 2 and stops[0]['hook_id'] != stops[1]['hook_id'], stops
                                assert stops[0]['response'].get('decision') == 'block', stops
                                check_rejection(stops[0]['response']['reason'], current, phase)
                                assert stops[1]['response'] == {}, stops
                            assert store.binding() == owner
                            log('result', phase=phase, subtype=row['subtype'], binding=current, owner=owner,
                                steps=state['steps'].get(phase, 0), tools=state['tools'].get(phase, 0))
                            print(json.dumps({'phase': phase, 'status': 'passed'}), flush=True)
                            break
                process.stdin.close()
                assert process.wait(timeout=8) == 0, 'CLI failed on exit'
            finally:
                if process.poll() is None:
                    os.killpg(process.pid, signal.SIGTERM)
                    process.wait(timeout=5)

    try:
        update_source('entry')
        run(argv, [('entry', f'/autopilot {TARGET} --normal --max-seconds=600'),
                   ('question', '解释刚才的本地记录，不要继续执行'),
                   ('continue', '继续同一个本地夹具核验'), ('compact', '/compact'),
                   ('after_compact', '继续同一个本地夹具核验')])
        argv[argv.index('--session-id')] = '--resume'
        update_source('restart')
        run(argv, [('question_restart', '解释上次的本地记录，不要继续执行'),
                   ('continue_restart', '继续同一个本地夹具核验')])
        assert boundaries, 'no real compact boundary'
        assert not list((RUNTIME / '.ccst-autopilot').rglob('context*.json')), 'host wrote a body snapshot'
        result = {'status': 'passed', 'session_id': sid, 'owner_unchanged': store.binding() == owner,
            'elapsed_seconds': round(time.monotonic() - started, 3), 'compact_boundaries': boundaries,
            'requests': state['requests'], 'tool_calls': state['tools'], 'inference': False,
            'phase_steps': state['steps'], 'body_without_runtime': True, 'context_snapshots': 0,
            'source_updates': source_updates,
            'provider_charge_usd': 0, 'usage': 'scripted; CLI token/cost estimates are not model billing',
            'cli': subprocess.check_output(['/opt/claude', '--version'], env=env, text=True).strip()}
        (ROOT / 'result.json').write_text(json.dumps(result, ensure_ascii=False, indent=2))
        print(json.dumps(result, ensure_ascii=False))
    finally:
        server.shutdown()
        server.server_close()


def main():
    if sys.argv[1:] == ['--inside']:
        inside()
        return
    if sys.argv[1:2] == ['--review']:
        write_review(*sys.argv[2:])
        return
    source = Path(__file__).resolve().parents[1]
    stage = Path(tempfile.mkdtemp(prefix='ccst-native-continuity-'))
    source_head = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=source, text=True).strip()
    names = subprocess.check_output(['git', 'ls-files', '-z', '--', 'tools', 'memory', 'commands',
        'agents', 'skills', 'rules', 'docs', 'knowledge', 'CLAUDE.md'], cwd=source).decode().split('\0')
    manifest = {}
    for name in names:
        relative = Path(name)
        if not name or relative.suffix not in {'.py', '.sh', '.md', '.json', '.yaml', '.yml'}:
            continue
        if {'tests', 'goals', '.private', '.history', '__pycache__', 'clown'} & set(relative.parts) or relative.name == 'connection.py':
            continue
        original = source / relative
        assert not any(path.is_symlink() for path in (original, *original.parents)), name
        destination = stage / 'project' / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(original, destination)
        destination.chmod(original.stat().st_mode & 0o777)
        manifest[name] = hashlib.sha256(destination.read_bytes()).hexdigest()
    (stage / 'source-manifest.json').write_text(json.dumps(manifest, ensure_ascii=False, indent=2))
    (stage / 'home').mkdir()
    (stage / 'home/isolation-marker').write_text('probe')
    shutil.copyfile(__file__, stage / 'probe.py')
    shutil.copyfile(stage / 'project/skills/runtime-protocol.md', stage / 'runtime-protocol.md')
    provenance = {'kind': 'tracked_worktree', 'git_head': source_head, 'source_files': len(manifest),
        'manifest_sha256': hashlib.sha256((stage / 'source-manifest.json').read_bytes()).hexdigest(),
        'harness_sha256': hashlib.sha256((stage / 'probe.py').read_bytes()).hexdigest()}
    (stage / 'source-provenance.json').write_text(json.dumps(provenance, ensure_ascii=False, indent=2))
    for current, dirs, files in os.walk(stage):
        for path in (Path(current), *(Path(current) / name for name in files)):
            os.chown(path, 65534, 65534)
    argv = ['bwrap', '--die-with-parent', '--unshare-net', '--unshare-pid', '--unshare-ipc',
        '--ro-bind', '/usr', '/usr', '--symlink', 'usr/bin', '/bin', '--symlink', 'usr/lib', '/lib',
        '--symlink', 'usr/lib64', '/lib64', '--proc', '/proc', '--dev', '/dev', '--perms', '1777', '--tmpfs', '/tmp',
        '--tmpfs', '/run', '--dir', '/etc', '--dir', '/opt', '--bind', str(stage), '/probe',
        '--bind', str(stage / 'home'), '/root', '--ro-bind', str(Path(shutil.which('claude')).resolve()), '/opt/claude']
    for directory in ('tools', 'memory', 'commands', 'agents', 'skills', 'rules', 'docs', 'knowledge'):
        argv.extend(['--ro-bind', str(stage / 'project' / directory), '/probe/project/' + directory])
    argv.extend(['--bind', str(stage / 'runtime-protocol.md'), '/probe/project/skills/runtime-protocol.md'])
    for name in ('/etc/nsswitch.conf', '/etc/passwd', '/etc/group', '/etc/alternatives'):
        argv.extend(['--ro-bind', name, name])
    argv.extend(['--chdir', '/probe', '--', '/usr/bin/setpriv', '--reuid=65534', '--regid=65534',
        '--clear-groups', '--no-new-privs', '--bounding-set=-all', '/usr/bin/python3', '-B', '/probe/probe.py', '--inside'])
    print(json.dumps({'run': str(stage), 'source_files': len(manifest), 'inference': False}), flush=True)
    result = subprocess.run(argv, env={'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8'}, timeout=240)
    if result.returncode == 0:
        assert all(hashlib.sha256((stage / 'project' / name).read_bytes()).hexdigest() == digest
                   for name, digest in manifest.items()), 'staged source changed'
        assert hashlib.sha256((stage / 'probe.py').read_bytes()).hexdigest() == provenance['harness_sha256'], 'harness changed'
        report = json.loads((stage / 'result.json').read_text())
        assert hashlib.sha256((stage / 'runtime-protocol.md').read_bytes()).hexdigest() == report['source_updates'][-1]['protocol_sha256']
        report.update(source=provenance, staged_source_unchanged=True)
        (stage / 'result.json').write_text(json.dumps(report, ensure_ascii=False, indent=2))
        print(json.dumps({'source_verified': True, 'result': str(stage / 'result.json')}), flush=True)
    raise SystemExit(result.returncode)


if __name__ == '__main__':
    main()
