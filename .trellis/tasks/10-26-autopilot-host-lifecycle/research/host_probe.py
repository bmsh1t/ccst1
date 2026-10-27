#!/usr/bin/env python3
"""Probe the real Claude host with inert input and a never-forwarding local API."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import queue
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


FIXTURE = '''import json,sys
from pathlib import Path
p=Path('/probe')
body=p.joinpath('body.txt').read_text()
if sys.argv[1]=='activate':
    p.joinpath('active.json').write_text(json.dumps({'session_id':sys.argv[2]}))
    p.joinpath('released').unlink(missing_ok=True)
    print('BODY_BEGIN\\n'+body+'\\nBODY_END')
    raise SystemExit()
d=json.load(sys.stdin)
event=d['hook_event_name']
record={k:d[k] for k in ('hook_event_name','source','stop_hook_active','prompt','session_id') if k in d}
record['phase']=p.joinpath('phase.txt').read_text() if p.joinpath('phase.txt').exists() else 'startup'
with p.joinpath('hook-events.jsonl').open('a') as f:f.write(json.dumps(record)+'\\n')
if event=='UserPromptSubmit':
    prompt=d.get('prompt','')
    if not prompt.startswith(('/host-probe','/compact')):
        p.joinpath('active.json').unlink(missing_ok=True)
if event=='SessionStart' and p.joinpath('active.json').exists():
    part=int(sys.argv[2]) if len(sys.argv)>2 else None
    label='RECOVERY_'+d.get('source','unknown')
    if part is not None:
        label+='_PART_'+str(part)
        body=body[part*7000:(part+1)*7000]
    print(json.dumps({'hookSpecificOutput':{'hookEventName':event,'additionalContext':label+'_BEGIN\\n'+body+'\\nRECOVERY_END'}},ensure_ascii=False))
elif event=='Stop' and p.joinpath('active.json').exists() and not p.joinpath('released').exists():
    print(json.dumps({'decision':'block','reason':'STOP_PROBE_REQUIRED: write /probe/released with receipt before completing this synthetic task.'}))
'''

PRODUCT_FINISH = '''import json,sys,time
from pathlib import Path
sys.path.insert(0, '/probe/project')
from tools.autopilot_state import build_autopilot_state,load_closure_projection
from tools.checkpoint import record_global_review
from tools.recon_gate import append_recon_record
from tools.target_paths import target_storage_key
root=Path('/probe/project')
binding=json.loads(Path('/root/.claude/.ccst-autopilot',sys.argv[1],'binding.json').read_text())
if sys.argv[2:]==['wait']:
    time.sleep(max(0,binding['started_at']+binding['max_seconds']-time.time()+0.05))
    print(json.dumps({'elapsed_seconds':time.time()-binding['started_at']}))
    raise SystemExit()
target=binding['target']
ref='evidence/'+target_storage_key(target)+'/host-review.txt'
path=root/ref
path.parent.mkdir(parents=True,exist_ok=True)
path.write_text('Synthetic host-only acceptance. No target I/O is authorized in this probe.')
(root/'recon'/target_storage_key(target)).mkdir(parents=True,exist_ok=True)
append_recon_record(root,target=target,mode='deep',phase='host_partial',status='partial',artifact=ref,count=1)
state=build_autopilot_state(str(root),target,bounded=True)
closure=load_closure_projection(str(root),state)
termination={'reason':'scope_boundary','session_id':binding['session_id'],'invocation_id':binding['invocation_id'],
    'boundary':'Synthetic host-only probe authorizes no target I/O; there is no claim of exhaustion.'}
if binding.get('max_seconds') is not None:
    termination.update(reason='explicit_limit',limit={'elapsed_seconds':binding['max_seconds']})
result=record_global_review(root,target,status='complete',snapshot_digest=closure['snapshot_digest'],
    evidence_refs=[ref],decision='End synthetic host-only probe; investigation remains untested.',
    residual_unknowns=['All target investigation remains untested: host-only probe Scope. Reopen in authorized lab acceptance.'],
    termination=termination)
current=load_closure_projection(str(root),build_autopilot_state(str(root),target,bounded=True))
assert current['global_review']['status']=='form_insufficient'
assert current['global_review']['termination']['invocation_id']==binding['invocation_id']
assert not current['can_claim_exhausted']
with Path('/probe/stop-reviews.jsonl').open('a') as out:
    out.write(json.dumps({'invocation_id':binding['invocation_id'],'review_status':current['global_review']['status'],
                         'can_claim_exhausted':current['can_claim_exhausted']})+'\\n')
print(json.dumps(result))
'''


def save(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + '\n')


def verify(run: Path) -> dict:
    """Assert host effects, never infer instruction use from a successful exit."""
    options = json.loads(run.joinpath('options.json').read_text())
    result = json.loads(run.joinpath('result.json').read_text())
    command = json.loads(run.joinpath('command.json').read_text())
    assert command['isolated_uid'] == 65534
    requests, hooks = result['requests'], result['hooks']
    checks = ['isolated real CLI with synthetic API']
    if options.get('product_background'):
        notices = [r for r in requests if r.get('task_notification_present')]
        assert notices and all(r['binding_status'] in {'active', 'completed'} for r in notices), notices
        assert notices[0]['binding_status'] == 'active'
        phases = {r['phase']: r for r in result['phase_bindings']}
        assert phases['background']['status'] == 'completed', phases
        assert phases['ordinary']['status'] == 'completed', phases
        assert len([r for r in requests if r['phase'] == 'ordinary']) == 1
        assert any(r.get('product_entry_complete') for r in requests)
        checks += ['native background task notification preserves active invocation and normal Stop enforcement',
                   'ordinary conversation after completion remains released']
    elif options.get('product_host'):
        entry_request = requests[1] if options.get('product_entry') == 'skill' else requests[0]
        assert entry_request['phase'] == 'initial' and entry_request['product_entry_complete'], 'product entry failed to deliver complete source'
        assert result['compact_boundary_seen']
        assert result['result_messages'] == 9
        for phase in ('after_compact', 'resume'):
            first = next(r for r in requests if r['phase'] == phase)
            assert first['product_recovery_complete'], 'product recovery incomplete: ' + phase
            finished = next(r for r in result['phase_bindings'] if r['phase'] == phase)
            assert finished['status'] == 'completed', finished
            assert finished['invocation_id'] == first['invocation_id'], 'resume created another invocation'
        first = next(r for r in result['phase_bindings'] if r['phase'] == 'initial')
        assert first['status'] == 'completed'
        reviews = [json.loads(line) for line in (run / 'stop-reviews.jsonl').read_text().splitlines()]
        assert len(reviews) == 3 and all(r['review_status'] == 'form_insufficient' and not r['can_claim_exhausted'] for r in reviews)
        for phase in ('reactivate', 'before_restart'):
            stopped = next(r for r in result['phase_bindings'] if r['phase'] == phase)
            assert stopped['status'] == 'suspended', stopped
        interrupt = [h for h in hooks if h['phase'] == 'interrupt' and h['hook_event_name'] == 'Stop']
        assert not interrupt
        assert any(r['response'].get('subtype') == 'success' for r in result['interrupt_ack'])
        for phase in ('ordinary', 'after_interrupt'):
            assert len([r for r in requests if r['phase'] == phase]) == 1
        assert 'CCST_AUTOPILOT_INCOMPLETE' in run.joinpath('visible.jsonl').read_text()
        checks += ['product command delivers complete original Skill', 'real Checkpoint review releases normal Stop',
                   'unchanged repeated Stop suspends as incomplete', 'complete product compact/resume bodies delivered',
                   'current resume keeps original invocation and reaches normal release',
                   'valid boundary Stop releases with residual tokens missing while exhaustion remains false',
                   'native interrupt bypasses Stop; ordinary next messages do not rearm']
        if options.get('product_entry') == 'skill':
            assert len([h for h in hooks if h['phase'] == 'initial' and h['hook_event_name'] == 'UserPromptSubmit']) == 1
            checks.append('native Skill tool entry needs no additional UserPromptSubmit and delivers complete bodies')
        if options.get('product_entry') == 'round':
            checks.append('Round entry and recovery deliver shared and round source bodies')
        if options.get('product_limit'):
            assert any(r.get('early_limit_feedback') for r in requests), 'no native Stop rejection before the time limit'
            by_phase = {r['phase']: r for r in result['phase_bindings']}
            for phase in ('initial', 'after_compact', 'resume'):
                bound = by_phase[phase]
                assert bound['max_seconds'] == options['product_limit']
                assert bound['elapsed_seconds'] >= bound['max_seconds']
            for before, after in (('reactivate', 'after_compact'), ('before_restart', 'resume')):
                for key in ('invocation_id', 'started_at', 'max_seconds'):
                    assert by_phase[before][key] == by_phase[after][key], (before, after, key)
            checks.append('native time limit rejects early Stop, survives compact/restart, and releases after the bound deadline')
    elif options.get('missing_body'):
        assert not requests, 'missing dynamic body reached model API'
        visible = run.joinpath('visible.jsonl').read_text()
        assert '<local-command-stderr>' in visible and 'body.txt' in visible
        checks.append('missing source rejected before model API')
    else:
        assert requests[0]['phase'] == 'initial' and requests[0]['body_complete']
        assert result['compact_boundary_seen'], 'no native compact boundary'
        assert result['result_messages'] == (9 if options['interrupt'] else 7)
        initial_stops = [h for h in hooks if h['phase'] == 'initial' and h['hook_event_name'] == 'Stop']
        assert [h['stop_hook_active'] for h in initial_stops] == [False, True]
        assert any(r['stop_feedback_present'] for r in requests if r['phase'] == 'initial')
        checks += ['complete dynamic entry', 'normal Stop block then release', 'native compact completion']
        if run.joinpath('settings-hooks').exists():
            for source in ('startup', 'compact', 'resume'):
                assert any(h.get('source') == source for h in hooks if h['hook_event_name'] == 'SessionStart')
            if options['split_recovery']:
                for phase, key in (('after_compact', 'split_compact_complete'), ('resume', 'split_resume_complete')):
                    phase_requests = [r for r in requests if r['phase'] == phase]
                    assert phase_requests and phase_requests[0][key], 'incomplete recovery: ' + phase
                checks.append('every original recovery chunk reaches first compact/resume request')
            elif result['body_characters'] > 10000:
                after = next(r for r in requests if r['phase'] == 'after_compact')
                assert not after['recovery_complete'], 'oversize boundary changed; reassess integration'
                checks.append('oversize single hook is not complete delivery')
        else:
            assert not any(h['hook_event_name'] == 'SessionStart' for h in hooks)
            checks.append('command frontmatter does not provide SessionStart recovery')
        if options['interrupt']:
            assert any(r['response'].get('subtype') == 'success' and
                       r['response'].get('request_id') == 'host-probe-interrupt' for r in result['interrupt_ack'])
            assert not any(h['phase'] == 'interrupt' and h['hook_event_name'] == 'Stop' for h in hooks)
            later = [h for h in hooks if h['phase'] == 'after_interrupt' and h['hook_event_name'] == 'Stop']
            assert len(later) == 1 and later[0]['stop_hook_active'] is False
            checks += ['native interrupt acknowledged without Stop', 'ordinary post-interrupt turn released']
    accepted = {'status': 'passed', 'cli_version': command['cli_version'], 'checks': checks,
                'limits': ['synthetic API: no model method-use or lab capability claim',
                           'manual compact only; automatic context pressure not exercised']}
    save(run / 'acceptance.json', accepted)
    return accepted


def run_inside() -> int:
    root = Path('/probe')
    project = root / 'project'
    commands = project / '.claude/commands'
    commands.mkdir(parents=True)
    Path('/root/.claude').mkdir(parents=True, exist_ok=True)
    subprocess.run(['git', 'init', '-q', str(project)], check=True)
    root.joinpath('fixture.py').write_text(FIXTURE)
    options = json.loads(root.joinpath('options.json').read_text())
    product = options.get('product_host', False)
    body = 'SYNTHETIC_METHOD_FIRST\n' + ('inert method guidance only\n' * options['body_lines']) + 'SYNTHETIC_METHOD_LAST'
    root.joinpath('body.txt').write_text(body)
    events = ('SessionStart', 'UserPromptSubmit', 'Stop', 'SessionEnd', 'PreCompact', 'PostCompact')
    hooks = {event: [{'hooks': [{'type': 'command', 'command': 'python3 /probe/fixture.py hook'}]}] for event in events}
    # JSON values are valid YAML, avoiding a fixture-only YAML dependency.
    settings_hooks = root.joinpath('settings-hooks').exists()
    command = ('---\ndescription: Inert native host contract probe\n'
               'allowed-tools: Bash(python3 *) Write Read\n'
               + ('hooks: ' + json.dumps(hooks) + '\n' if not settings_hooks else '') + '---\n'
               'Synthetic host probe; no target requests.\n'
               '!`python3 /probe/fixture.py activate "${CLAUDE_SESSION_ID}"`\n')
    commands.joinpath('host-probe.md').write_text(command)
    settings = {'permissions': {'allow': ['Bash(python3 *)', 'Read', 'Write', 'Skill']}, 'disableAutoMemory': True}
    if settings_hooks:
        settings['hooks'] = hooks
        if options['split_recovery']:
            settings['hooks']['SessionStart'] = [{'hooks': [
                {'type': 'command', 'command': 'python3 /probe/fixture.py hook '+str(part)}
                for part in range((len(body)+6999)//7000)]}]
    save(root / 'settings.json', settings)
    if product:
        sys.path.insert(0, str(project))
        from tools.runtime_doctor import sync_runtime
        from tools.claude_hook_contract import capture_context, context_chunks, _body
        from tools.autopilot_host import _resume_command
        commands.joinpath('host-probe.md').unlink()
        runtime = Path('/root/.claude')
        save(runtime / 'settings.json', settings | {'hooks': {}})
        installed = sync_runtime(project, runtime, prune=True)
        if installed['status'] != 'complete':
            raise RuntimeError('product fixture runtime install: ' + json.dumps(installed))
        body = _body((project / 'skills/src-hunter/SKILL.md').read_bytes().decode())
        root.joinpath('product_finish.py').write_text(PRODUCT_FINISH)
    if options.get('missing_body'):
        root.joinpath('body.txt').unlink()
    state = {'phase': 'initial', 'requests': [], 'interrupt_started': threading.Event(),
             'interrupt_release': threading.Event()}
    phase_bindings, native_hooks, finish_issued, skill_issued, limit_wait_issued = [], [], set(), set(), set()

    def current_binding():
        path = Path('/root/.claude/.ccst-autopilot') / session_id / 'binding.json'
        return json.loads(path.read_text()) if path.exists() else {}

    def texts(value):
        if isinstance(value, str):
            return [value]
        if isinstance(value, dict):
            return [s for child in value.values() for s in texts(child)]
        if isinstance(value, list):
            return [s for child in value for s in texts(child)]
        return []

    class API(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_POST(self):
            data = json.loads(self.rfile.read(int(self.headers.get('Content-Length', '0'))))
            if 'count_tokens' in self.path:
                payload = b'{"input_tokens":5000}'
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)
                return
            if not self.path.startswith('/v1/messages'):
                self.send_error(404)
                return
            rendered = json.dumps(data, ensure_ascii=False)
            phase = str(state['phase'])
            record = {'phase': phase, 'path': self.path, 'body': data}
            state['requests'].append(record)
            with root.joinpath('requests.jsonl').open('a') as out:
                out.write(json.dumps(record, ensure_ascii=False) + '\n')
            strings = texts(data.get('messages', [])) + texts(data.get('system', []))
            summary = {'phase': phase, 'body_complete': any(body in s for s in strings),
                       'recovery_complete': any(('RECOVERY_compact_BEGIN\n'+body+'\nRECOVERY_END') in s for s in strings),
                       'recovery_present': 'RECOVERY_compact_BEGIN' in rendered,
                       'split_compact_complete': all(any(('RECOVERY_compact_PART_'+str(part)+'_BEGIN\n'+
                            body[part*7000:(part+1)*7000]+'\nRECOVERY_END') in s for s in strings)
                            for part in range((len(body)+6999)//7000)),
                       'split_resume_complete': all(any(('RECOVERY_resume_PART_'+str(part)+'_BEGIN\n'+
                            body[part*7000:(part+1)*7000]+'\nRECOVERY_END') in s for s in strings)
                            for part in range((len(body)+6999)//7000)),
                       'stop_feedback_present': 'STOP_PROBE_REQUIRED' in rendered,
                       'early_limit_feedback': any('The submitted explicit limit has not been reached' in s
                           for s in texts(data.get('messages', [])[-1:]))}
            binding = current_binding() if product else {}
            summary['binding_status'] = binding.get('status')
            summary['task_notification_present'] = any('<task-notification>' in s
                for s in texts(data.get('messages', [])))
            if product:
                round_mode = binding.get('round_mode', False)
                context = capture_context(project, round_mode=round_mode)
                entry_chunks = context_chunks('\n\n'.join(context['sections'][:3 if round_mode else 2]))
                summary.update(invocation_id=binding.get('invocation_id'),
                    product_entry_complete=binding.get('source_sha256') == context['sha256'] and all(any((f"CCST_ENTRY {context['sha256']} "
                      f"PART {part+1}/{len(entry_chunks)}\n"+chunk) in s for s in strings)
                      for part,chunk in enumerate(entry_chunks)),
                    product_recovery_complete=all(any((f"CCST_RECOVERY {binding.get('invocation_id')} {context['sha256']} "
                      f"PART {part+1}/{len(context['chunks'])}\n"+chunk) in s for s in strings)
                      for part,chunk in enumerate(context['chunks'])))
            with root.joinpath('request-summary.jsonl').open('a') as out:
                out.write(json.dumps(summary) + '\n')
            if phase == 'interrupt':
                state['interrupt_started'].set()
                state['interrupt_release'].wait(10)
            tool = 'STOP_PROBE_REQUIRED' in rendered and not root.joinpath('released').exists()
            content = ({'type': 'tool_use', 'id': 'toolu_' + uuid.uuid4().hex, 'name': 'Write',
                        'input': {'file_path': '/probe/released', 'content': 'synthetic receipt\n'}}
                       if tool else {'type': 'text', 'text': '<summary>Inert host probe. Resume the synthetic task.</summary>'
                                    if phase == 'compact' else 'Synthetic host response complete.'})
            if product:
                tool = False
                command = None
                if phase in {'after_compact', 'resume'} and (binding.get('status') == 'suspended' or binding.get('needs_refresh')):
                    command = _resume_command(Path('/root/.claude'), binding)
                elif (phase in {'initial', 'after_compact', 'resume'} and binding.get('status') == 'active'
                        and binding.get('last_stop_basis') and binding.get('invocation_id') not in finish_issued):
                    command = 'python3 /probe/product_finish.py ' + session_id
                    finish_issued.add(binding['invocation_id'])
                elif (options.get('product_limit') and summary['early_limit_feedback']
                        and binding.get('status') == 'active' and binding['invocation_id'] not in limit_wait_issued):
                    command = 'python3 /probe/product_finish.py ' + session_id + ' wait'
                    limit_wait_issued.add(binding['invocation_id'])
                if command:
                    tool = True
                    content = {'type': 'tool_use', 'id': 'toolu_' + uuid.uuid4().hex, 'name': 'Bash',
                               'input': {'command': command, 'description': 'Synthetic host acceptance owner operation'}}
                else:
                    content = {'type': 'text', 'text': '<summary>Synthetic Autopilot remains suspended until user resumes.</summary>'
                               if phase == 'compact' else 'Synthetic host response complete.'}
                if (options.get('product_entry') == 'skill' and phase in {'initial', 'reactivate', 'interrupt', 'before_restart'}
                        and phase not in skill_issued):
                    skill_issued.add(phase)
                    tool = True
                    content = {'type': 'tool_use', 'id': 'toolu_' + uuid.uuid4().hex, 'name': 'Skill',
                               'input': {'skill': 'autopilot', 'args': 'lab.test --normal --deep' +
                                   (f" --max-seconds={options['product_limit']}" if options.get('product_limit') else '')}}
                if options.get('product_background') and phase == 'background':
                    step = state.get('background_step', 0)
                    if step < 2:
                        state['background_step'] = step + 1
                        tool = True
                        content = {'type': 'tool_use', 'id': 'toolu_' + uuid.uuid4().hex, 'name': 'Bash',
                            'input': {'command': "python3 -c 'import time; time.sleep(" + ('2' if step == 0 else '5') + "); print(123)'",
                                      'run_in_background': step == 0}}
                    elif binding.get('status') == 'active' and binding.get('last_stop_basis') and binding['invocation_id'] not in finish_issued:
                        finish_issued.add(binding['invocation_id'])
                        tool = True
                        content = {'type': 'tool_use', 'id': 'toolu_' + uuid.uuid4().hex, 'name': 'Bash',
                            'input': {'command': 'python3 /probe/product_finish.py ' + session_id}}
            if not data.get('stream'):
                payload = json.dumps({'id': 'msg_' + uuid.uuid4().hex, 'type': 'message', 'role': 'assistant',
                                      'model': data.get('model'), 'content': [content], 'stop_reason': 'tool_use' if tool else 'end_turn',
                                      'stop_sequence': None, 'usage': {'input_tokens': 5000, 'output_tokens': 20}}).encode()
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)
                return
            sequence = [
                ('message_start', {'type': 'message_start', 'message': {'id': 'msg_' + uuid.uuid4().hex,
                    'type': 'message', 'role': 'assistant', 'model': data.get('model'), 'content': [],
                    'stop_reason': None, 'stop_sequence': None, 'usage': {'input_tokens': 5000, 'output_tokens': 0}}}),
                ('content_block_start', {'type': 'content_block_start', 'index': 0, 'content_block':
                    {**content, 'input': {}} if tool else {'type': 'text', 'text': ''}}),
                ('content_block_delta', {'type': 'content_block_delta', 'index': 0, 'delta':
                    {'type': 'input_json_delta', 'partial_json': json.dumps(content['input'])} if tool
                    else {'type': 'text_delta', 'text': content['text']}}),
                ('content_block_stop', {'type': 'content_block_stop', 'index': 0}),
                ('message_delta', {'type': 'message_delta', 'delta': {'stop_reason': 'tool_use' if tool else 'end_turn',
                    'stop_sequence': None}, 'usage': {'output_tokens': 20}}),
                ('message_stop', {'type': 'message_stop'}),
            ]
            wire = ''.join('event: ' + event + '\ndata: ' + json.dumps(value) + '\n\n' for event, value in sequence).encode()
            try:
                self.send_response(200)
                self.send_header('Content-Type', 'text/event-stream')
                self.send_header('Content-Length', str(len(wire)))
                self.end_headers()
                self.wfile.write(wire)
            except (BrokenPipeError, ConnectionResetError):
                if phase != 'interrupt':
                    raise
                pass

    server = ThreadingHTTPServer(('127.0.0.1', 0), API)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    env = {'HOME': '/root', 'CLAUDE_CONFIG_DIR': '/root/.claude', 'PATH': '/usr/bin:/bin',
           'SHELL': '/bin/bash', 'LANG': 'C.UTF-8', 'ANTHROPIC_API_KEY': 'synthetic-dummy-key',
           'ANTHROPIC_BASE_URL': f'http://127.0.0.1:{server.server_port}',
           'DISABLE_AUTOUPDATER': '1', 'CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC': '1',
           'DISABLE_TELEMETRY': '1', 'DISABLE_ERROR_REPORTING': '1', 'GIT_CONFIG_NOSYSTEM': '1',
           'PYTHONNOUSERSITE': '1', 'PYTHONDONTWRITEBYTECODE': '1'}
    session_id = str(uuid.uuid4())
    phase_results = []
    argv = ['/opt/claude', '-p', '--model', 'claude-opus-4-8', '--input-format', 'stream-json',
            '--output-format', 'stream-json', '--verbose', '--include-hook-events',
            '--setting-sources', 'project', '--settings', '/probe/settings.json',
            '--strict-mcp-config', '--mcp-config', '{"mcpServers":{}}', '--no-chrome',
            '--permission-mode', 'dontAsk', '--tools', 'Bash,Read,Write,Skill',
            '--session-id', session_id]
    if product:
        argv[argv.index('--setting-sources') + 1] = 'user,project'
        argv[argv.index('/probe/settings.json')] = '/root/.claude/settings.json'
    save(root / 'command.json', {'argv': argv, 'session_id': session_id, 'isolated_uid': os.getuid(),
                                 'cli_version': subprocess.check_output(['/opt/claude', '--version'], env=env, text=True).strip()})

    def session(command: list[str], phases: list[tuple[str, str]]) -> list[dict]:
        process = subprocess.Popen(command, env=env, cwd=project, stdin=subprocess.PIPE,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, start_new_session=True)
        messages: queue.Queue = queue.Queue()
        captured: list[dict] = []

        def reader():
            for line in process.stdout:
                with root.joinpath('visible.jsonl').open('a') as out:
                    out.write(line)
                try:
                    row = json.loads(line)
                    captured.append(row)
                    if product and row.get('subtype') == 'hook_started':
                        native_hooks.append({'phase': state['phase'], 'hook_event_name': row.get('hook_event'),
                                             'hook_name': row.get('hook_name')})
                    messages.put(row)
                except json.JSONDecodeError:
                    messages.put({'type': 'unparsed', 'text': line})
            messages.put({'type': 'eof'})

        def errors():
            with root.joinpath('stderr.txt').open('a') as out:
                for line in process.stderr:
                    out.write(line)

        threading.Thread(target=reader, daemon=True).start()
        threading.Thread(target=errors, daemon=True).start()
        try:
            for phase, prompt in phases:
                state['phase'] = phase
                root.joinpath('phase.txt').write_text(phase)
                process.stdin.write(json.dumps({'type': 'user', 'message': {'role': 'user', 'content': prompt}}) + '\n')
                process.stdin.flush()
                if phase == 'interrupt':
                    if not state['interrupt_started'].wait(10):
                        raise RuntimeError('interrupt phase did not reach local API')
                    process.stdin.write(json.dumps({'type': 'control_request', 'request_id': 'host-probe-interrupt',
                                                    'request': {'subtype': 'interrupt'}}) + '\n')
                    process.stdin.flush()
                    state['interrupt_release'].set()
                deadline = time.monotonic() + 25 + options.get('product_limit', 0)
                while True:
                    row = messages.get(timeout=max(.01, deadline - time.monotonic()))
                    if row.get('type') == 'result':
                        if product:
                            b = current_binding()
                            phase_bindings.append({'phase':phase, 'status':b.get('status'), 'invocation_id':b.get('invocation_id'),
                                'started_at':b.get('started_at'), 'max_seconds':b.get('max_seconds'),
                                'elapsed_seconds':time.time()-b['started_at'] if b.get('started_at') else None})
                        phase_results.append({'phase': phase, 'subtype': row.get('subtype'),
                                              'is_error': row.get('is_error', False)})
                        print(json.dumps({'phase': phase, 'event': row.get('subtype') or row['type'],
                                          'is_error': row.get('is_error', False)}), flush=True)
                        break
                    if row.get('type') == 'eof':
                        raise RuntimeError('Claude exited before phase ' + phase)
            process.stdin.close()
            process.wait(timeout=8)
            if process.returncode and not options.get('missing_body'):
                raise RuntimeError('Claude exit ' + str(process.returncode))
        finally:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGTERM)
                process.wait(timeout=5)
        return captured

    try:
        phases = [('initial', '/host-probe'), ('ordinary', 'Ordinary synthetic conversation.'),
                  ('reactivate', '/host-probe'), ('compact', '/compact'),
                  ('after_compact', 'Check recovered synthetic context.')]
        if options['interrupt']:
            phases += [('interrupt', '/host-probe'), ('after_interrupt', 'New ordinary task after interruption.')]
        phases += [('before_restart', '/host-probe')]
        if product:
            entry_prompt = ('Run this synthetic investigation using the autopilot Skill.' if options.get('product_entry') == 'skill'
                            else '/autopilot-round lab.test --normal --deep' if options.get('product_entry') == 'round'
                            else '/autopilot lab.test --normal --deep')
            if options.get('product_limit') and options.get('product_entry') != 'skill':
                entry_prompt += f" --max-seconds={options['product_limit']}"
            phases = [(phase, entry_prompt if prompt == '/host-probe'
                       else '继续' if phase == 'after_compact' else prompt) for phase, prompt in phases]
            if options.get('product_background'):
                phases = [('background', entry_prompt), ('ordinary', 'Ordinary synthetic conversation.')]
        first = session(argv, [('missing', '/host-probe')] if options.get('missing_body') else phases)
        second = []
        if not options.get('missing_body') and not options.get('product_background'):
            resumed = list(argv)
            resumed[resumed.index('--session-id')] = '--resume'
            second = session(resumed, [('resume', '继续' if product else 'Inspect resumed synthetic context.')])
        def records(name):
            path = root / name
            return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []
        hooks_seen = records('hook-events.jsonl')
        if product:
            hooks_seen = native_hooks
        requests = records('request-summary.jsonl')
        result = {'status': 'observed', 'body_characters': len(body), 'body_sha256': hashlib.sha256(body.encode()).hexdigest(),
                  'hooks': hooks_seen, 'requests': requests,
                  'compact_boundary_seen': any(row.get('subtype') == 'compact_boundary' for row in first),
                  'interrupt_ack': [row for row in first if row.get('type') == 'control_response'],
                  'phase_results': phase_results,
                  'phase_bindings': phase_bindings,
                  'phases': sorted({row['phase'] for row in requests}), 'result_messages':
                  sum(row.get('type') == 'result' for row in first + second)}
        save(root / 'result.json', result)
        print(json.dumps(verify(root)), flush=True)
        return 0
    finally:
        server.shutdown()
        server.server_close()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('--inside', action='store_true')
    parser.add_argument('--settings-hooks', action='store_true')
    parser.add_argument('--body-lines', type=int, default=160)
    parser.add_argument('--interrupt', action='store_true')
    parser.add_argument('--split-recovery', action='store_true')
    parser.add_argument('--missing-body', action='store_true')
    parser.add_argument('--verify-run', type=Path)
    parser.add_argument('--product-host', action='store_true')
    parser.add_argument('--product-entry', choices=('command', 'skill', 'round'), default='command')
    parser.add_argument('--product-limit', type=int, default=0)
    parser.add_argument('--product-background', action='store_true')
    args = parser.parse_args()
    if args.verify_run:
        print(json.dumps(verify(args.verify_run), ensure_ascii=False))
        return 0
    if args.inside:
        return run_inside()
    run = Path(tempfile.mkdtemp(prefix='ccst-host-mechanics-'))
    run.joinpath('home').mkdir()
    if args.settings_hooks:
        run.joinpath('settings-hooks').touch()
    save(run/'options.json', {'body_lines': args.body_lines, 'interrupt': args.interrupt,
                              'split_recovery': args.split_recovery, 'missing_body': args.missing_body,
                              'product_host': args.product_host, 'product_entry': args.product_entry,
                              'product_limit': args.product_limit, 'product_background': args.product_background})
    if args.product_host:
        repo = Path(__file__).resolve().parents[4]
        for directory in ('tools', 'memory'):
            for path in (repo / directory).rglob('*.py'):
                destination = run / 'project' / path.relative_to(repo)
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(path, destination)
        for directory in ('commands', 'agents', 'skills'):
            shutil.copytree(repo / directory, run / 'project' / directory)
        (run / 'project/knowledge').mkdir()
        shutil.copyfile(repo / 'knowledge/capabilities.yaml', run / 'project/knowledge/capabilities.yaml')
    shutil.copyfile(__file__, run / 'host_probe.py')
    for path in (run, run / 'home', run / 'host_probe.py'):
        os.chown(path, 65534, 65534)
    if args.product_host:
        for directory, dirs, files in os.walk(run / 'project'):
            for path in [Path(directory), *(Path(directory) / name for name in files)]:
                os.chown(path, 65534, 65534)
    binary = str(Path(shutil.which('claude')).resolve())
    sandbox = ['bwrap', '--die-with-parent', '--unshare-net', '--unshare-pid', '--unshare-ipc', '--unshare-uts',
               '--ro-bind', '/usr', '/usr', '--symlink', 'usr/bin', '/bin', '--symlink', 'usr/sbin', '/sbin',
               '--symlink', 'usr/lib', '/lib', '--symlink', 'usr/lib64', '/lib64', '--proc', '/proc',
               '--dev', '/dev', '--perms', '1777', '--tmpfs', '/tmp', '--tmpfs', '/run', '--dir', '/etc', '--dir', '/opt',
               '--bind', str(run), '/probe', '--bind', str(run / 'home'), '/root', '--ro-bind', binary, '/opt/claude']
    for path in ('/etc/hosts', '/etc/nsswitch.conf', '/etc/passwd', '/etc/group', '/etc/alternatives'):
        if Path(path).exists():
            sandbox += ['--ro-bind', path, path]
    sandbox += ['--chdir', '/probe', '--', '/usr/bin/setpriv', '--reuid=65534', '--regid=65534',
                '--clear-groups', '--no-new-privs', '--bounding-set=-all', '--inh-caps=-all', '--ambient-caps=-all',
                '/usr/bin/python3', '/probe/host_probe.py', '--inside']
    print(json.dumps({'run': str(run), 'api': 'loopback fake; no forwarding', 'claude': binary}), flush=True)
    child_env = {'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'HOME': '/root', 'SHELL': '/bin/bash', 'PYTHONDONTWRITEBYTECODE': '1'}
    return subprocess.run(sandbox, env=child_env, timeout=150).returncode


if __name__ == '__main__':
    raise SystemExit(main())
