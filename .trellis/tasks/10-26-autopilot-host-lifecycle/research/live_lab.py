"""Bounded native Claude acceptance against isolated, disposable local labs."""
from __future__ import annotations

import hashlib
import fcntl
import http.client
import importlib.util
import json
import os
from pathlib import Path
import queue
import selectors
import shutil
import signal
import socket
import socketserver
import sqlite3
import subprocess
import sys
import threading
import time
import urllib.parse
import uuid

ROOT = Path('/root/tool/ccst(rename-_Ya66f2)/ccst3/ccst')
RUN = Path(__file__).resolve().parent
TARGET = 'ccst-fresh.test'
MODEL = 'claude-opus-4-8'
CAP = 12


def save(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + '\n')


def module(path):
    spec = importlib.util.spec_from_file_location('existing_lab_gateway', path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def clean_env():
    env = {key: os.environ[key] for key in ('HOME', 'LANG') if key in os.environ}
    env.update(PATH='/opt/ccst-bin:/usr/local/bin:/usr/bin:/bin', LANG='C.UTF-8', SHELL='/bin/bash',
               PYTHONDONTWRITEBYTECODE='1', PYTHONNOUSERSITE='1', GIT_CONFIG_NOSYSTEM='1',
               DISABLE_AUTOUPDATER='1', CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC='1',
               DISABLE_ERROR_REPORTING='1', DISABLE_TELEMETRY='1')
    return env


def prepare(recovery=False):
    target = 'ccst-lab.test' if recovery else TARGET
    project, session = RUN / 'project', RUN / 'session'
    project.mkdir()
    runtime = session / 'home/.claude'
    runtime.mkdir(parents=True)
    selected = ['CLAUDE.md', 'tools', 'memory', 'commands', 'agents', 'skills', 'rules',
                'docs', 'knowledge', 'templates', 'schemas', 'wordlists']
    names = subprocess.check_output(['git', 'ls-files', '--cached', '--others', '--exclude-standard',
                                     '-z', '--', *selected], cwd=ROOT).decode().split('\0')
    hashes = {}
    for name in sorted(set(names)):
        parts = Path(name).parts
        if (not parts or 'tests' in parts or '.history' in parts
                or parts[:3] == ('knowledge', 'methods', 'clown') or name == 'knowledge/clown-hot-method-manifest.json'):
            continue
        if parts[0] == 'memory' and not name.endswith('.py'):
            continue
        source = ROOT / name
        assert source.is_file() and not source.is_symlink(), name
        data = source.read_bytes()
        dest = project / name
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(data)
        dest.chmod(source.stat().st_mode & 0o777)
        hashes[name] = hashlib.sha256(data).hexdigest()
    save(RUN / 'source-sha256.json', hashes)
    save(project / 'config.json', {'ctf_mode': True, 'resin': {'enabled': False}})
    save(runtime / 'settings.json', {'permissions': {'defaultMode': 'bypassPermissions'}})
    save(runtime / '.claude.json', {'hasCompletedOnboarding': True, 'lastOnboardingVersion': '2.1.304'})
    (session / 'home/isolation-marker').write_text(RUN.name)
    env = clean_env()
    subprocess.run(['git', 'init', '-q', str(project)], env=env, check=True, timeout=10)
    result = subprocess.run([sys.executable, '-B', str(project / 'tools/runtime_doctor.py'),
                             '--repo-root', str(project), '--runtime-root', str(runtime),
                             '--kind', 'commands,agents,skills', '--sync', '--prune',
                             '--fail-on-critical-drift', '--json'],
                            env=env, cwd=project, capture_output=True, text=True, timeout=60)
    (RUN / 'runtime-sync.json').write_text(result.stdout)
    assert result.returncode == 0, 'isolated runtime sync failed'
    save(session / 'mcp.json', {'mcpServers': {'Playwright': {
        'command': '/opt/ccst-bin/node', 'args': ['/opt/playwright/node_modules/@playwright/mcp/cli.js',
            '--headless', '--isolated', '--no-sandbox', '--executable-path', '/usr/lib/chromium/chromium',
            '--save-session', '--output-dir', str(project / '.private/browser' / target),
            '--timeout-navigation', '15000']}}})
    hosts = [target, *(['www.' + target, 'app.' + target, 'billing.' + target] if recovery else [])]
    (RUN / 'hosts').write_text('127.0.0.1 localhost ' + ' '.join(hosts) + '\n::1 localhost\n')
    (RUN / 'resolv.conf').write_text('nameserver 127.0.0.1\noptions attempts:1 timeout:1\n')
    (RUN / 'hosts').chmod(0o644)
    (RUN / 'resolv.conf').chmod(0o644)
    for top in (project, session):
        for path in [top, *top.rglob('*')]:
            assert not path.is_symlink(), str(path)
            os.chown(path, 65534, 65534)
            if path.is_dir():
                path.chmod(0o755 if path == top else 0o700)
    save(RUN / 'run.json', {'model': MODEL, 'budget_usd': CAP, 'target': target, 'recovery': recovery,
        'session_id': str(uuid.uuid4()), 'claude': str(Path(shutil.which('claude')).resolve()),
        'node': str(Path(shutil.which('node')).resolve()),
        'mcp_modules': '/root/.npm/_npx/9833c18b2d85bc59/node_modules',
        'tool_paths': {name: str(Path(shutil.which(name)).resolve()) for name in ('httpx', 'katana', 'ffuf', 'rg')},
        'prompt': f'/autopilot {target} --deep --normal --max-seconds=720', 'hard_wall_seconds': 900,
        'constraints': (
            f'这是本地隔离靶场验收，当前项目为 {project}。本次范围为 {target}'
            + ('及其子域名的 HTTP 服务，' if recovery else '的 HTTP 服务，') +
            '域名由靶场环境解析，全部账号、订单和业务数据均为测试数据。允许低速、可逆的安全测试和正常注册测试账号。'
            '目标直连，模型代理仅供模型调用；不能访问范围外服务，不能修改产品源码、方法、规则或安装配置，'
            '不能读取个人配置、凭据、/proc环境或外层验收材料。本请求运行现有产品，不是开发任务。'
            f'本阶段从收到本请求起预算12分钟，保留最后2分钟登记与交接；全会话模型费用上限${CAP}，'
            '压缩和后续恢复共享该总费用。只使用会话实际可用的工具；外网被动资产服务不可用时如实保留未测。'
            '阶段边界保存进度，不声称范围穷尽。')})
    print(json.dumps({'prepared': str(RUN), 'source_files': len(hashes)}), flush=True)


def inside():
    meta = json.loads((RUN / 'run.json').read_text())
    target = meta['target']
    gateway = module(RUN / 'gateway_impl.py')

    def relay(port, name):
        class Handler(socketserver.BaseRequestHandler):
            def handle(self):
                with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as remote:
                    remote.connect(str(RUN / name))
                    gateway.pipe(self.request, remote)
        server = socketserver.ThreadingTCPServer(('127.0.0.1', port), Handler)
        server.daemon_threads = True
        threading.Thread(target=server.serve_forever, daemon=True).start()
        return server

    model_relay = relay(0, 'gateway.sock')
    lab_relay = gateway.start_lab(RUN) if meta.get('recovery') else relay(80, 'lab.sock')
    proxy = f'http://127.0.0.1:{model_relay.server_address[1]}'
    project, session = RUN / 'project', RUN / 'session'
    runtime = session / 'home/.claude'
    env = clean_env()
    env.update(CLAUDE_CONFIG_DIR=str(runtime), CCST_RUNTIME_ROOT=str(runtime),
        HTTP_PROXY=proxy, HTTPS_PROXY=proxy, http_proxy=proxy, https_proxy=proxy,
        NO_PROXY=f'localhost,127.0.0.1,::1,{target},.{target}',
        no_proxy=f'localhost,127.0.0.1,::1,{target},.{target}',
        BBHUNT_ENABLE_AMASS='0', BBHUNT_ENABLE_UNWAF='0', BBHUNT_SKIP_UNWAF='1',
        BB_THREADS='2', BB_RATE_LIMIT='8', KATANA_CONCURRENCY='1', KATANA_PARALLELISM='1',
        BBHUNT_FFUF_HOST_CONCURRENCY='1', BBHUNT_DIR_FUZZ_HARD_BUDGET_SECONDS='30')
    for key in ('ANTHROPIC_AUTH_TOKEN', 'ANTHROPIC_API_KEY', 'ANTHROPIC_BASE_URL', 'CLAUDE_CODE_DISABLE_EXPERIMENTAL_BETAS'):
        if os.environ.get(key):
            env[key] = os.environ[key]
    for key in ('ANTHROPIC_MODEL', 'ANTHROPIC_DEFAULT_OPUS_MODEL', 'ANTHROPIC_DEFAULT_SONNET_MODEL', 'ANTHROPIC_DEFAULT_HAIKU_MODEL'):
        env[key] = MODEL
    secret_values = [env[key] for key in ('ANTHROPIC_AUTH_TOKEN', 'ANTHROPIC_API_KEY', 'ANTHROPIC_BASE_URL') if env.get(key)]

    def scrub(value):
        for secret in secret_values:
            value = value.replace(secret, '[redacted]')
        return value

    sandbox = ['bwrap', '--die-with-parent', '--unshare-pid', '--unshare-ipc', '--unshare-uts',
        '--ro-bind', '/usr', '/usr', '--symlink', 'usr/bin', '/bin', '--symlink', 'usr/sbin', '/sbin',
        '--symlink', 'usr/lib', '/lib', '--symlink', 'usr/lib64', '/lib64', '--proc', '/proc',
        '--dev', '/dev', '--perms', '1777', '--tmpfs', '/tmp', '--tmpfs', '/run',
        '--bind', str(session / 'home'), '/root', '--perms', '0755', '--dir', '/etc']
    for path in ('/etc/hosts', '/etc/resolv.conf', '/etc/nsswitch.conf', '/etc/passwd', '/etc/group',
                 '/etc/ssl', '/etc/alternatives', '/etc/localtime', '/etc/fonts'):
        if Path(path).exists():
            sandbox.extend(['--ro-bind', path, path])
    sandbox.extend(['--perms', '0755', '--dir', str(RUN), '--perms', '0755', '--dir', '/opt',
                    '--perms', '0755', '--dir', '/opt/ccst-bin',
                    '--perms', '0755', '--dir', '/opt/playwright',
                    '--bind', str(project), str(project), '--bind', str(session), str(session),
                    '--ro-bind', meta['claude'], '/opt/ccst-bin/claude', '--ro-bind', meta['node'], '/opt/ccst-bin/node',
                    '--ro-bind', meta['mcp_modules'], '/opt/playwright/node_modules'])
    for name, path in meta['tool_paths'].items():
        sandbox.extend(['--ro-bind', path, '/opt/ccst-bin/' + name])
    for part in ('tools', 'commands', 'agents', 'skills', 'rules', 'knowledge', 'docs', 'templates', 'schemas', 'wordlists', '.git'):
        if (project / part).exists():
            sandbox.extend(['--ro-bind', str(project / part), str(project / part)])
    for path in [*(project / 'memory').rglob('*.py'), project / 'CLAUDE.md', project / 'config.json', session / 'mcp.json']:
        sandbox.extend(['--ro-bind', str(path), str(path)])
    for part in ('commands', 'skills', 'agents', 'settings.json', '.ccst-installed.json'):
        sandbox.extend(['--ro-bind', str(runtime / part), str(runtime / part)])
    sandbox.extend(['--chdir', str(project), '--', '/usr/bin/setpriv', '--reuid=65534',
                    '--regid=65534', '--clear-groups', '--no-new-privs', '--bounding-set=-all',
                    '--inh-caps=-all', '--ambient-caps=-all'])
    check = "from pathlib import Path; import os,socket; assert os.getuid()==65534; assert Path('/root/isolation-marker').read_text()==" + repr(RUN.name) + "; assert not Path('/root/.codex').exists(); assert not Path(" + repr(str(ROOT)) + ").exists(); assert not Path('tests').exists(); assert Path(" + repr(str(runtime / 'settings.json')) + ").read_text(); s=socket.socket(); s.settimeout(1); assert s.connect_ex(('127.0.0.1',3000))!=0; assert s.connect_ex(('192.0.2.1',80))!=0"
    checked = subprocess.run([*sandbox, '/usr/bin/python3', '-c', check], env=env, capture_output=True, timeout=10)
    save(RUN / 'filesystem-preflight.json', {'exit': checked.returncode, 'stderr': scrub(checked.stderr.decode())})
    assert checked.returncode == 0, 'isolation preflight failed'
    mcp_check = r'''import subprocess,json
p=subprocess.Popen(['/opt/ccst-bin/node','/opt/playwright/node_modules/@playwright/mcp/cli.js','--headless','--isolated','--no-sandbox','--executable-path','/usr/lib/chromium/chromium'],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
def send(v):p.stdin.write(json.dumps(v)+'\n');p.stdin.flush()
def read(i):
 while True:
  line=p.stdout.readline()
  if not line:raise RuntimeError(p.stderr.read()[:2000])
  v=json.loads(line)
  if v.get('id')==i:return v
send({'jsonrpc':'2.0','id':1,'method':'initialize','params':{'protocolVersion':'2024-11-05','capabilities':{},'clientInfo':{'name':'lab-preflight','version':'1'}}})
assert 'result' in read(1)
send({'jsonrpc':'2.0','method':'notifications/initialized'})
send({'jsonrpc':'2.0','id':2,'method':'tools/call','params':{'name':'browser_tabs','arguments':{'action':'list'}}})
v=read(2);assert not v.get('error') and not v.get('result',{}).get('isError'),v
print(json.dumps({'mcp_tools_call':'browser_tabs','result':v}))
send({'jsonrpc':'2.0','id':3,'method':'tools/call','params':{'name':'browser_close','arguments':{}}});read(3)
p.stdin.close();p.wait(timeout=10)
'''
    checked = subprocess.run([*sandbox, '/usr/bin/python3', '-c', mcp_check], env=env,
                             capture_output=True, timeout=40)
    save(RUN / 'mcp-preflight.json', {'exit': checked.returncode,
        'stdout': scrub(checked.stdout.decode()), 'stderr': scrub(checked.stderr.decode())})
    assert checked.returncode == 0, 'MCP tool preflight failed'
    client = http.client.HTTPConnection('127.0.0.1', model_relay.server_address[1], timeout=5)
    client.request('POST', f'http://{target}/boundary-check', body='{}')
    assert client.getresponse().status == 403
    client.close()
    save(RUN / 'isolation.json', {'unshare_net': True, 'uid': 65534, 'outside_target_denied': True})
    argv = [*sandbox, '/opt/ccst-bin/claude', '-p', '--model', MODEL,
        '--tools', 'default',
        '--dangerously-skip-permissions', '--permission-prompts', 'none',
        '--setting-sources', 'user,project,local', '--settings', str(runtime / 'settings.json'),
        '--strict-mcp-config', '--mcp-config', str(session / 'mcp.json'), '--no-chrome',
        '--session-id', meta['session_id'], '--max-budget-usd', str(CAP),
        '--input-format', 'stream-json', '--output-format', 'stream-json', '--verbose',
        '--include-hook-events',
        '--append-system-prompt', meta['constraints']]
    started, results, process = time.monotonic(), [], None
    compact_seen = False
    first_cost = 0
    binding_path = runtime / '.ccst-autopilot' / meta['session_id'] / 'binding.json'

    def snapshot(label):
        counts = {}
        for path in (project / 'state').glob('*/metadata.sqlite3'):
            with sqlite3.connect(f'file:{path}?mode=ro', uri=True) as source:
                counts[path.parent.name] = {table: source.execute('SELECT count(*) FROM ' + table).fetchone()[0]
                    for table in ('operations', 'observations', 'findings', 'assessments', 'reports', 'experiences')}
                with sqlite3.connect(RUN / f'{label}-{path.parent.name}.sqlite3') as dest:
                    source.backup(dest)
        value = {'at': time.time(), 'counts': counts,
                 'binding': json.loads(binding_path.read_text()) if binding_path.exists() else {}}
        save(RUN / (label + '.json'), value)
        return value

    def held_locks():
        for path in (project / 'state').rglob('*.lock'):
            try:
                with path.open('rb') as handle:
                    try:
                        fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                    except BlockingIOError:
                        return True
                    fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
            except OSError:
                return True
        return False

    try:
        for generation in range(2 if meta.get('recovery') else 1):
            command = list(argv)
            stage = 'resume' if generation else 'initial'
            if generation:
                command[command.index('--session-id')] = '--resume'
                assert 0 <= first_cost < CAP, 'no remaining research model allowance'
                # CLI 2.1.304 restores cumulative session cost; keep the same total ceiling.
                snapshot('before-restart')
            (RUN / 'phase.txt').write_text(stage)
            process = subprocess.Popen(command, env=env, cwd=project, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                       stderr=subprocess.PIPE, text=True, start_new_session=True)
            save(RUN / f'process-{generation}.json', {'pid': process.pid, 'model': MODEL, 'session_id': meta['session_id'],
                'max_budget_usd': command[command.index('--max-budget-usd') + 1]})
            messages = queue.Queue()

            def reader(child, output):
                for line in child.stdout:
                    output.put(json.loads(line))
                output.put({'type': 'eof'})

            def errors(child):
                with (RUN / 'stderr.txt').open('a') as out:
                    for line in child.stderr:
                        out.write(scrub(line))

            threading.Thread(target=reader, args=(process, messages), daemon=True).start()
            threading.Thread(target=errors, args=(process,), daemon=True).start()

            def send(value):
                process.stdin.write(json.dumps(value) + '\n')
                process.stdin.flush()

            def user(value):
                send({'type': 'user', 'message': {'role': 'user', 'content': value}})

            user('继续' if generation else meta['prompt'])
            print(json.dumps({'started': str(RUN), 'stage': stage, 'model': MODEL}), flush=True)
            last_activity, last_probe = time.monotonic(), time.monotonic()
            result_seen, interrupted, input_closed = False, False, False
            pending_tasks = set()
            with (RUN / 'visible.jsonl').open('a') as visible:
                while True:
                    try:
                        event = messages.get(timeout=1)
                    except queue.Empty:
                        event = {}
                    now = time.monotonic()
                    if event.get('type') == 'eof':
                        break
                    if event:
                        last_activity = now
                    if event.get('type') == 'system' and event.get('subtype') == 'init':
                        save(RUN / f'host-{generation}.json', {key: event.get(key) for key in ('model', 'tools', 'mcp_servers', 'permissionMode', 'claude_code_version', 'skills', 'slash_commands')})
                    if event.get('subtype') == 'task_started':
                        pending_tasks.add(str(event.get('task_id') or ''))
                    if event.get('subtype') == 'task_notification':
                        pending_tasks.discard(str(event.get('task_id') or ''))
                    if event.get('type') in {'system', 'control_response'}:
                        with (RUN / 'system-events.jsonl').open('a') as out:
                            out.write(scrub(json.dumps({'stage': stage, 'at': time.time(), **event}, ensure_ascii=False)) + '\n')
                    if event.get('subtype') == 'compact_boundary':
                        compact_seen = True
                        save(RUN / 'compact-boundary.json', {'stage': stage, 'metadata': event.get('compact_metadata')})
                    blocks = (event.get('message') or {}).get('content', [])
                    for block in blocks if isinstance(blocks, list) else []:
                        if isinstance(block, dict) and block.get('type') in ('text', 'tool_use', 'tool_result'):
                            visible.write(scrub(json.dumps({'stage': stage, 'role': event.get('type'), 'elapsed_seconds': round(now-started, 2), **block}, ensure_ascii=False)) + '\n')
                            visible.flush()
                    if event.get('type') == 'result':
                        result_seen = True
                        result = {'stage': stage, **{key: event.get(key) for key in ('subtype', 'is_error', 'duration_ms', 'num_turns', 'result', 'total_cost_usd', 'usage', 'modelUsage', 'permission_denials', 'errors')}}
                        results.append(result)
                        (RUN / f'result-event-{len(results)-1}.json').write_text(scrub(json.dumps(result, ensure_ascii=False, indent=2)) + '\n')
                        snapshot(f'result-{len(results)-1}')
                        if generation == 0 and type(result['total_cost_usd']) in (int, float):
                            first_cost = max(first_cost, result['total_cost_usd'])
                        print(json.dumps({'stage': stage, 'subtype': result['subtype'], 'turns': result['num_turns'], 'cost_usd': result['total_cost_usd']}), flush=True)
                        if stage == 'interrupt':
                            stage = 'compact'
                            (RUN / 'phase.txt').write_text(stage)
                            result_seen = False
                            user('/compact')
                        elif stage == 'compact':
                            assert compact_seen and not result['is_error'], 'native compact did not complete'
                            assert type(result['total_cost_usd']) in (int, float), 'missing first-process cost receipt'
                            process.stdin.close()
                            input_closed = True
                    if (meta.get('recovery') and stage == 'initial' and not result_seen and not interrupted
                            and now-started >= 120 and now-last_probe >= 10):
                        last_probe = now
                        if not pending_tasks and not held_locks() and binding_path.exists():
                            operations = 0
                            for path in (project / 'state').glob('*/metadata.sqlite3'):
                                with sqlite3.connect(f'file:{path}?mode=ro', uri=True) as source:
                                    operations += source.execute('SELECT count(*) FROM operations').fetchone()[0]
                            if operations >= 2:
                                snapshot('before-interrupt')
                                stage, interrupted = 'interrupt', True
                                (RUN / 'phase.txt').write_text(stage)
                                send({'type': 'control_request', 'request_id': 'lab-native-interrupt', 'request': {'subtype': 'interrupt'}})
                                print(json.dumps({'stage': stage, 'operations_before': operations}), flush=True)
                    if result_seen and not input_closed and now-last_activity >= 90 and not pending_tasks and not held_locks():
                        save(RUN / 'input-closed.json', {'reason': '90s idle after result, no task or held target lock', 'seconds': round(now-started, 2)})
                        process.stdin.close()
                        input_closed = True
            process.wait(timeout=10)
            if process.returncode or (generation == 0 and stage != 'compact'):
                break
    finally:
        if process and process.poll() is None:
            os.killpg(process.pid, signal.SIGTERM)
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()
        save(RUN / 'exit.json', {'exit_code': process.returncode if process else None, 'seconds': round(time.monotonic()-started, 2),
            'compact_boundary_seen': compact_seen, 'result_count': len(results)})
        model_relay.shutdown()
        lab_relay.shutdown()
    return process.returncode


def run():
    meta = json.loads((RUN / 'run.json').read_text())
    base = urllib.parse.urlsplit(os.environ.get('ANTHROPIC_BASE_URL', ''))
    assert base.scheme == 'http' and base.hostname, 'configured model transport incompatible'
    assert any(os.environ.get(k) for k in ('ANTHROPIC_AUTH_TOKEN', 'ANTHROPIC_API_KEY')), 'model auth unavailable'
    name = 'ccst-lab-' + RUN.name.rsplit('-', 1)[-1]
    network = name + '-net'
    gateway = module(ROOT / '.trellis/tasks/10-23-autopilot-convergence/research/p0_host.py')
    shutil.copyfile(ROOT / '.trellis/tasks/10-23-autopilot-convergence/research/p0_host.py', RUN / 'gateway_impl.py')
    save(RUN / 'gateway-authorities.json', {'authorities': [[base.scheme, base.hostname, base.port or 80]]})
    made_network = made_container = False
    servers = []
    process = None
    try:
        if meta.get('recovery'):
            save(RUN / 'lab.json', {'kind': 'synthetic-multiasset', 'target': meta['target'],
                'hosts': ['ccst-lab.test', 'www.ccst-lab.test', 'app.ccst-lab.test', 'billing.ccst-lab.test'],
                'unshare_net': True, 'listener': '127.0.0.1:80'})
        else:
            subprocess.run(['docker', 'network', 'create', '--internal', network], check=True, capture_output=True, timeout=15)
            made_network = True
            subprocess.run(['docker', 'run', '-d', '--name', name, '--network', network,
                '--memory', '768m', '--cpus', '2', '--pids-limit', '256',
                'bkimminich/juice-shop:latest'], check=True, capture_output=True, timeout=30)
            made_container = True
            address = subprocess.check_output(['docker', 'inspect', '--format',
                '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}', name], text=True).strip()
            assert address and address != '127.0.0.1'
            port = 3000
            ready = False
            for _ in range(30):
                client = http.client.HTTPConnection(address, port, timeout=2)
                try:
                    client.request('GET', '/')
                    response = client.getresponse()
                    if response.status == 200:
                        ready = True
                        break
                except (OSError, http.client.HTTPException):
                    time.sleep(1)
                finally:
                    client.close()
            assert ready, 'Juice Shop did not become ready'
            save(RUN / 'lab.json', {'container': name, 'network': network, 'bridge_address': address, 'container_port': port,
                'image_id': 'sha256:9f0f27a4451494f6442351e8f3cd8eca7b00ddb6d473fa7ab28c7373f255c2a4',
                'target': TARGET, 'internal_network': True})
        raw_dir = RUN / 'transport'
        raw_dir.mkdir(mode=0o700, exist_ok=True)
        class Lab(socketserver.BaseRequestHandler):
            def handle(self):
                ident = str(time.time_ns())
                with socket.create_connection((address, port), timeout=15) as remote, selectors.DefaultSelector() as sel, \
                        (raw_dir / (ident + '.request')).open('wb') as req, (raw_dir / (ident + '.response')).open('wb') as resp:
                    sel.register(self.request, selectors.EVENT_READ, (remote, req))
                    sel.register(remote, selectors.EVENT_READ, (self.request, resp))
                    while True:
                        events = sel.select(timeout=30)
                        if not events:
                            return
                        for key, _ in events:
                            data = key.fileobj.recv(65536)
                            if not data:
                                return
                            dest, log = key.data
                            log.write(data)
                            log.flush()
                            dest.sendall(data)
        class Server(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
            daemon_threads = True
            def handle_error(self, *_):
                pass
        if not meta.get('recovery'):
            lab = Server(str(RUN / 'lab.sock'), Lab)
            servers.append(lab)
            threading.Thread(target=lab.serve_forever, daemon=True).start()
        original = http.client.HTTPConnection
        sys.path.insert(0, str(RUN / 'project'))
        from tools.claude_hook_contract import capture_context, context_chunks
        context = capture_context(RUN / 'project')
        entry_chunks = context_chunks('\n\n'.join(context['sections'][:2]))
        class ObservedModel(original):
            def request(self, method, url, body=None, headers={}, **kwargs):
                if method == 'POST' and isinstance(body, (str, bytes)):
                    data = body.decode() if isinstance(body, bytes) else body
                    try:
                        payload = json.loads(data)
                    except ValueError:
                        payload = {}
                    if 'messages' in payload:
                        row = {'at': time.time(), 'model': payload.get('model'), 'request_bytes': len(data),
                            'stage': (RUN / 'phase.txt').read_text() if (RUN / 'phase.txt').exists() else 'startup',
                            'native_tool_names': [item.get('name') for item in payload.get('tools', [])],
                            'full_skill_body_present': False, 'expanded_bootstrap': []}
                        def text_blocks(content):
                            if isinstance(content, str):
                                yield content
                            elif isinstance(content, list):
                                for block in content:
                                    if isinstance(block, dict):
                                        if block.get('type') == 'text':
                                            yield block.get('text', '')
                                        elif block.get('type') == 'tool_result':
                                            yield from text_blocks(block.get('content'))
                        received_texts = []
                        for message in payload['messages']:
                            for body_text in text_blocks(message.get('content')):
                                received_texts.append(body_text)
                                marker = 'Authoritative bootstrap contract (do not reinterpret):'
                                if marker not in body_text:
                                    continue
                                tail = body_text.split(marker, 1)[1].lstrip()
                                try:
                                    expanded, _ = json.JSONDecoder().raw_decode(tail)
                                except ValueError:
                                    row.setdefault('unparsed_bootstrap_prefix', tail[:300])
                                    continue
                                if isinstance(expanded, dict) and 'action' in expanded and 'repo_root' in expanded:
                                    state = expanded.get('state') or {}
                                    row['expanded_bootstrap'].append({'action':expanded['action'],
                                        'repo_root':expanded['repo_root'], 'target':(expanded.get('arguments') or {}).get('target'),
                                        'next_action':state.get('next_action'), 'next_step':state.get('next_step'),
                                        'lane_contract':(state.get('lane_contract') or {}).get('id'), 'host':expanded.get('host')})
                        row['full_skill_body_present'] = all(any(
                            f"CCST_ENTRY {context['sha256']} PART {part+1}/{len(entry_chunks)}\n" + chunk + '\nCCST_ENTRY_END' in text
                            for text in received_texts) for part,chunk in enumerate(entry_chunks))
                        path = RUN / 'session/home/.claude/.ccst-autopilot' / meta['session_id'] / 'binding.json'
                        binding = json.loads(path.read_text()) if path.exists() else {}
                        row['invocation_id'] = binding.get('invocation_id')
                        row['full_recovery_body_present'] = all(any(
                            f"CCST_RECOVERY {binding.get('invocation_id')} {context['sha256']} PART {part+1}/{len(context['chunks'])}\n" + chunk in text
                            for text in received_texts) for part, chunk in enumerate(context['chunks']))
                        with (RUN / 'model-requests.jsonl').open('a') as out:
                            out.write(json.dumps(row, ensure_ascii=False) + '\n')
                return super().request(method, url, body, headers, **kwargs)
        http.client.HTTPConnection = ObservedModel
        servers.append(gateway.gateway(RUN))
        argv = ['bwrap', '--die-with-parent', '--unshare-net', '--unshare-pid', '--ro-bind', '/', '/',
            '--proc', '/proc', '--dev', '/dev', '--tmpfs', '/tmp', '--bind', str(RUN), str(RUN),
            '--ro-bind', str(RUN / 'hosts'), '/etc/hosts', '--ro-bind', str(RUN / 'resolv.conf'), '/etc/resolv.conf',
            '--', sys.executable, '-B', str(Path(__file__).resolve()), '--inside']
        process = subprocess.Popen(argv, start_new_session=True)
        reason = 'completed'
        try:
            process.wait(timeout=meta['hard_wall_seconds'])
        except subprocess.TimeoutExpired:
            reason = 'hard_wall_timeout'
        save(RUN / 'supervisor-exit.json', {'exit_code': process.poll(), 'reason': reason})
    finally:
        if process and process.poll() is None:
            os.killpg(process.pid, signal.SIGTERM)
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()
        for server in servers:
            server.shutdown()
            server.server_close()
        if made_container:
            logs = subprocess.run(['docker', 'logs', name], capture_output=True, timeout=10)
            (RUN / 'container.log').write_bytes(logs.stdout + logs.stderr)
            subprocess.run(['docker', 'rm', '-f', name], check=True, capture_output=True, timeout=15)
        if made_network:
            subprocess.run(['docker', 'network', 'rm', network], check=True, capture_output=True, timeout=15)
        for path in (RUN / 'lab.sock', RUN / 'gateway.sock'):
            path.unlink(missing_ok=True)
        save(RUN / 'cleanup.json', {'own_container_removed': made_container, 'own_network_removed': made_network})
    print(json.dumps({'finished': str(RUN)}), flush=True)


if __name__ == '__main__':
    os.umask(0o077)
    if sys.argv[1:] == ['--prepare']:
        prepare()
    elif sys.argv[1:] == ['--prepare-recovery']:
        prepare(recovery=True)
    elif sys.argv[1:] == ['--inside']:
        raise SystemExit(inside())
    elif sys.argv[1:] == ['--run']:
        run()
    elif sys.argv[1:] == ['--launch']:
        with (RUN / 'supervisor.log').open('ab') as output:
            subprocess.Popen([sys.executable, '-B', str(Path(__file__).resolve()), '--run'],
                cwd=RUN, stdout=output, stderr=output, stdin=subprocess.DEVNULL, start_new_session=True)
        print('CCST isolated lab supervisor started.')
    else:
        raise SystemExit('choose --prepare or --run')
