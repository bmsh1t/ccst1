"""Isolated behavioral checks; never imports or reads the repository tests directory."""
from pathlib import Path
import ast
import concurrent.futures
import hashlib
import http.server
import json
import os
import re
import shutil
import socket
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time

SOURCE = Path(__file__).resolve().parents[4]
GIT = ['git', '-c', f'safe.directory={SOURCE}']
START = time.monotonic()
ROOT = Path(tempfile.mkdtemp(prefix='ccst-depth-fix-check-'))
os.chmod(ROOT, 0o700)
PROJECT = ROOT / 'project'
PROJECT.mkdir(mode=0o700)
paths = subprocess.run([*GIT, 'ls-files', '-z', '--', 'tools', 'memory', 'commands', 'rules', 'skills', 'docs', 'knowledge/capabilities.yaml', 'config.json', 'CLAUDE.md'], cwd=SOURCE, capture_output=True, check=True).stdout.decode().split('\0')
for name in filter(None, paths):
    path = SOURCE / name
    if not path.is_file() or 'tests' in Path(name).parts:
        continue
    target = PROJECT / name
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(path, target)
HOME_DIR = ROOT / 'home'
HOME_DIR.mkdir(mode=0o700)
ENV = {'PATH': os.environ['PATH'], 'HOME': str(HOME_DIR), 'LANG': 'C.UTF-8', 'PYTHONPATH': str(PROJECT), 'PYTHONDONTWRITEBYTECODE': '1'}
os.environ.clear()
os.environ.update(ENV)
os.chdir(PROJECT)
sys.path.insert(0, str(PROJECT))
sys.path.insert(0, str(PROJECT / 'tools'))
sys.dont_write_bytecode = True
from tools.target_store import TargetStore, StoreError, ConflictError, initialize_target_store
from tools import validation_runner, validate, resume_read, structured_findings, coverage_matrix, runtime_state, surface, context_pack, autopilot_state, recall_sources

COUNT = 0

def check(value, label):
    global COUNT
    assert value, label
    COUNT += 1

def rejects(call, label):
    before = store.binding()
    try:
        call()
    except (StoreError, ValueError):
        check(store.binding() == before, label + ' atomic')
    else:
        raise AssertionError(label + ' accepted')

def cli(script, args, code=0):
    out = subprocess.run([sys.executable, str(PROJECT / 'tools' / script), *args], cwd=PROJECT, env=ENV, capture_output=True, text=True, timeout=12)
    check(out.returncode == code, f'{script} expected {code}: {out.stderr[-1800:]} {out.stdout[-500:]}')
    return out

TARGET = 'depth-check.invalid'
initialize_target_store(PROJECT, TARGET)
store = TargetStore(PROJECT, TARGET)

def create(fid):
    return store.create_finding(command_id='create:' + fid, finding_id=fid, endpoint=f'https://{TARGET}/{fid}?q=original', method='GET', family='sqli', title=fid, claim=f'Claim {fid}', actor='operator')

def dispose(fid, cid, status='withdrawn', previous=None, replacement=None):
    return store.dispose_finding(command_id=cid, finding_id=fid, status=status, reason='Correct mistaken unbound claim', actor='operator', expected_disposition=previous, replacement_id=replacement)

for fid in ['a-mistake', 'b-retained', 'c-retained']:
    create(fid)
initial = store.finding('a-mistake')
old_cursor = store.finding_state_page(limit=1)['next_cursor']
recall_binding = store.recall_delta(None)['binding']
receipt = dispose('a-mistake', 'withdraw:a', replacement='b-retained')
check(not receipt['replayed'], 'first withdrawal')
check(dispose('a-mistake', 'withdraw:a', replacement='b-retained')['replayed'], 'exact idempotence')
a = store.finding('a-mistake')
check(all(a[k] == initial[k] for k in ['id', 'endpoint', 'method', 'family', 'title', 'claim', 'created_at']), 'claim bytes preserved')
check(a['assessment'] is None and not a['evidence'] and not a['reports'], 'withdrawal creates no verdict or evidence')
check(a['disposition']['replacement_id'] == 'b-retained' and len(a['disposition_history']) == 1, 'retained disposition')
snapshot = store.finding_summary(limit=1)
check(snapshot['counts']['total'] == 3 and snapshot['counts']['active'] == 2 and snapshot['counts']['withdrawn'] == 1, 'separate counts')
check(snapshot['counts']['pending_validation'] == 2 and snapshot['next_validation']['id'] == 'b-retained', 'next valid candidate')
check(snapshot['total'] == 2 and snapshot['items'][0]['id'] == 'b-retained' and snapshot['remaining'] == 1, 'filter precedes page')
check(store.finding_state_page(limit=1, cursor=snapshot['next_cursor'], status='active')['items'][0]['id'] == 'c-retained', 'active continuation cursor')
check(store.page('findings', status='withdrawn')['total'] == 1 and store.finding_page()['total'] == 3, 'history and filtered raw page')
check(store.candidates()['total'] == 2, 'candidate active page')
rejects(lambda: store.finding_state_page(cursor=old_cursor), 'stale cursor')
rejects(lambda: store.finding_state_page(cursor=snapshot['next_cursor'], status='withdrawn'), 'filter changed cursor')
rejects(lambda: dispose('a-mistake', 'withdraw:a', replacement=None), 'same id changed content')
rejects(lambda: dispose('a-mistake', 'reopen:a', 'active'), 'missing predecessor')
rejects(lambda: dispose('b-retained', 'bad:self', replacement='b-retained'), 'self replacement')
rejects(lambda: dispose('b-retained', 'bad:missing', replacement='not-present'), 'missing replacement')
rejects(lambda: dispose('b-retained', 'bad:withdrawn', replacement='a-mistake'), 'withdrawn replacement')
rejects(lambda: store.create_finding(command_id='new:create:a', finding_id='a-mistake', endpoint=initial['endpoint'], method='GET', family='sqli', title='a-mistake', claim=initial['claim'], actor='operator'), 'create cannot revive')
rejects(lambda: store.create_action(command_id='work:a', action_id='work:a', intent='Review', execution_key='work:a', kind='work', subject={'finding_id':'a-mistake'}, actor='operator'), 'new action cannot revive')
rejects(lambda: validate.load_finding_prefill(str(PROJECT/'findings'/TARGET), 'a-mistake', repo_root=PROJECT, target=TARGET), 'validation preflight withdrawn')
rejects(lambda: validation_runner.record_native_evidence(repo_root=PROJECT, target=TARGET, finding_id='a-mistake', evidence={'schema_version':1}), 'native preflight withdrawn')
check(store.recall_delta(recall_binding)['full_acquisition_reason'] is None, 'recognized audit keeps incremental acquisition')

pool = PROJECT / 'evidence' / TARGET / 'validation' / 'failed-registration'
pool.mkdir(parents=True)
(pool/'summary.json').write_text(json.dumps({'schema_version':1, 'finding_id':'a-mistake', 'lane':'native_evidence', 'result':'candidate', 'candidate_ready':True, 'attempt_id':'failed-original', 'runs':[]}))
check(structured_findings.load_validation_runner_candidate_pool(PROJECT, TARGET) == [], 'runner material cannot revive withdrawn candidate')
check({x['id'] for x in runtime_state._primary_finding_rows(PROJECT, TARGET)} == {'b-retained','c-retained'}, 'runtime active list')
check({x['id'] for x in surface._primary_scanner_findings(store)} == {'b-retained','c-retained'}, 'Surface active claims')
check(context_pack._load_findings(PROJECT, TARGET)['counts']['withdrawn'] == 1, 'Pack preserves counts')
for full in (False, True):
    resume = resume_read.load_resume_summary(ROOT/'memory', TARGET, repo_root=PROJECT, full_domain_context=full)
    check(resume['structured_findings']['withdrawn'] == 1 and resume['domain_windows']['findings']['total'] == 2, 'resume count '+str(full))
    check(all(x['id'] != 'a-mistake' for x in resume['findings']), 'resume active rows '+str(full))
state = autopilot_state.build_autopilot_state(str(PROJECT), TARGET, memory_dir=str(ROOT/'memory'), bounded=True)
check(state['structured_findings']['next_validation']['id'] != 'a-mistake', 'real Autopilot followup')
current = recall_sources.acquire_current(PROJECT, TARGET)
check(any(x['id']=='a-mistake' and x['disposition']['status']=='withdrawn' for x in current['findings']['items']), 'current recall keeps labeled history')
mat = coverage_matrix.read_matrix(TARGET, PROJECT, current_only=True)
check('a-mistake' not in json.dumps(mat), 'withdrawn unobserved endpoint absent from Coverage')

out = cli('target_store.py', ['dispose-finding','--target',TARGET,'--finding-id','a-mistake','--status','active','--expected-disposition','withdraw:a','--reason','Reopen original claim','--command-id','reopen:a'])
check(json.loads(out.stdout)['command']=='dispose_finding', 'actual reopen CLI')
check(store.finding('a-mistake')['disposition']['replacement_id'] is None, 'reopen clears current replacement')
check(len(structured_findings.load_validation_runner_candidate_pool(PROJECT,TARGET))==1, 'reopen restores raw candidate')
check(store.finding_summary()['counts']['pending_validation']==3, 'reopen restores pending')
check(len(store.finding('a-mistake')['disposition_history'])==2, 'reopen append history')
check(dispose('a-mistake','withdraw:a',replacement='b-retained')['replayed'] and store.finding('a-mistake')['disposition']['status']=='active', 'historical replay does not reclose')
rejects(lambda: dispose('a-mistake','stale:close',previous='withdraw:a'), 'stale writer')

create('d-action')
store.create_action(command_id='work:d', action_id='work:d', intent='Review', execution_key='work:d', kind='work', subject={'finding_id':'d-action'}, actor='operator')
rejects(lambda: dispose('d-action','withdraw:d'), 'linked Action refusal')
create('e-coverage')
candidate={k:store.finding('e-coverage')[k] for k in ['id','endpoint','method','family','title','claim']}
store.record_coverage_review(command_id='coverage:e', endpoint=candidate['endpoint'], kind='cell_status', value='tested_finding', family='sqli', reason='Authored claim only', candidate=candidate, actor='operator')
rejects(lambda: dispose('e-coverage','withdraw:e'), 'linked Coverage refusal')

raw=PROJECT/'evidence'/TARGET/'synthetic-response.txt';raw.write_text('synthetic response')
obs={'endpoint':initial['endpoint'],'method':'GET','family':'sqli','observed_at':'2026-10-21T00:00:01Z','description':'Synthetic captured control', 'actor':'anonymous','state_changing':False,'artifacts':{'response':str(raw)}}
store.start_attempt(attempt_id='evidence:a', source='synthetic', started_at='2026-10-21T00:00:00Z', actor='operator')
operation=store.record_execution(attempt_id='evidence:a',outcome='complete',observations=[obs],finding_id='a-mistake',actor='operator')
rejects(lambda: dispose('a-mistake','withdraw:bound',previous='reopen:a'), 'linked evidence refusal')
store.assess(command_id='assess:a', finding_id='a-mistake', verdict='confirmed', reason='Synthetic permission demonstration', boundary=initial['endpoint'], impact='Synthetic read only', evidence=[{'operation_id':operation['entity_id'],'step':0}], actor='operator', expected_assessment=None)
rejects(lambda: dispose('a-mistake','withdraw:assessed',previous='reopen:a'), 'assessment preserved')
check(store.finding('a-mistake')['assessment']['verdict']=='confirmed', 'technical result unchanged')

create('f-race')
def race(cid):
    try:
        dispose('f-race',cid)
        return 'ok'
    except ConflictError:
        return 'conflict'
with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
    results=list(executor.map(race,['race:1','race:2']))
check(sorted(results)==['conflict','ok'], 'concurrent withdrawal one writer')

create('g-rollback')
with sqlite3.connect(store.path) as conn:
    conn.execute("CREATE TRIGGER deny_disposition BEFORE INSERT ON finding_dispositions WHEN NEW.finding_id='g-rollback' BEGIN SELECT RAISE(ABORT,'synthetic write failure'); END")
rejects(lambda: dispose('g-rollback','withdraw:g'), 'write fault rollback')
check(store.finding('g-rollback')['disposition']['status']=='active', 'failed disposition retains state')
with sqlite3.connect(store.path) as conn:
    conn.execute('DROP TRIGGER deny_disposition')
check(not dispose('g-rollback','withdraw:g')['replayed'], 'retry after fault writes once')
rejects(lambda: store.record_execution(attempt_id='unstarted', outcome='complete', observations=[obs], finding_id='g-rollback',actor='operator'), 'Store direct registration guard')

old_module=PROJECT/'old_target_store.py'
old_module.write_bytes(subprocess.run([*GIT,'show','73e0113:tools/target_store.py'],cwd=SOURCE,capture_output=True,check=True).stdout)
subprocess.run([sys.executable,'-c',"from old_target_store import initialize_target_store,TargetStore; from pathlib import Path; r=Path.cwd(); initialize_target_store(r,'upgrade-check.invalid'); s=TargetStore(r,'upgrade-check.invalid'); s.create_finding(command_id='old',finding_id='old',endpoint='https://upgrade-check.invalid/a',method='GET',family='sqli',title='old',claim='old',actor='operator')"],cwd=PROJECT,env=ENV,check=True,capture_output=True,text=True,timeout=10)
old=TargetStore(PROJECT,'upgrade-check.invalid')
check(old.finding_summary()['counts']['active']==1 and old.finding('old')['disposition_history']==[], 'real v17 read compatibility')
cli('target_store.py',['dispose-finding','--target','upgrade-check.invalid','--finding-id','old','--status','withdrawn','--reason','mistake','--command-id','old:close'],code=2)
backup=ROOT/'backup.sqlite3'
upgraded=cli('target_store.py',['upgrade-schema','--target','upgrade-check.invalid','--backup',str(backup)])
check(json.loads(upgraded.stdout)['status']=='upgraded', 'actual upgrade CLI')
with sqlite3.connect(backup) as conn:
    check(conn.execute('SELECT schema_version FROM store').fetchone()[0]==17, 'private backup original schema')
check(backup.stat().st_mode&0o077==0, 'backup private')
check(old.finding('old')['claim']=='old', 'upgrade retains claim')
cli('target_store.py',['dispose-finding','--target','upgrade-check.invalid','--finding-id','old','--status','withdrawn','--reason','mistake','--command-id','old:close'])
check(old.finding_summary()['next_validation'] is None, 'upgraded closure no stale pending')
check(old.upgrade_schema(ROOT/'unused-backup.sqlite3')['status']=='already_current', 'upgrade idempotence')

class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body=b'captured localhost response'
        self.send_response(200)
        self.send_header('Content-Length',str(len(body)))
        self.end_headers(); self.wfile.write(body)
    def log_message(self,*args):
        pass
server=http.server.ThreadingHTTPServer(('127.0.0.1',0),Handler)
thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
try:
    document=(PROJECT/'docs/evidence-runners.md').read_text()
    snippet=document.split('```bash\numask 077\n',1)[1].split('```',1)[0]
    capture=ROOT/'capture'
    shell_env={**ENV,'capture_dir':str(capture),'request_url':f'http://127.0.0.1:{server.server_port}/capture?q=exact'}
    run=subprocess.run(['bash','-eu','-c','umask 077\n'+snippet],cwd=PROJECT,env=shell_env,capture_output=True,text=True,timeout=10)
    check(run.returncode==0 and (capture/'exit-code.txt').read_text().strip()=='0', 'documented capture real success')
    check((capture/'response.body').read_bytes()==b'captured localhost response', 'captured body exact')
    trace = (capture/'request-response.trace').read_text()
    sent_header = trace.split('=> Send header,',1)[1].split('== Info:',1)[0]
    request = bytes.fromhex(''.join(re.findall(r'(?m)^[0-9a-f]+: ((?:[0-9a-f]{2} ){1,16})', sent_header)))
    check(request.startswith(b'GET /capture?q=exact HTTP/1.1\r\n'), 'trace actual request target')
finally:
    server.shutdown();server.server_close();thread.join(timeout=3)
failed=ROOT/'capture-failed'
run=subprocess.run(['bash','-eu','-c','umask 077\n'+snippet],cwd=PROJECT,env={**shell_env,'capture_dir':str(failed)},capture_output=True,text=True,timeout=10)
check(run.returncode==0 and int((failed/'exit-code.txt').read_text())!=0 and (failed/'finished_at.txt').is_file(), 'capture preserves failed request exit even under errexit')

for s in (store,old):
    with sqlite3.connect(s.path) as conn:
        check(conn.execute('PRAGMA integrity_check').fetchone()[0]=='ok' and not conn.execute('PRAGMA foreign_key_check').fetchall(), 'final SQLite integrity')
for name in subprocess.run([*GIT,'diff','--name-only','--','tools'],cwd=SOURCE,capture_output=True,text=True,check=True).stdout.splitlines():
    ast.parse((SOURCE/name).read_text(),filename=name)
check(True,'changed Python syntax')
result={'status':'passed','assertions':COUNT,'seconds':round(time.monotonic()-START,3),'root':str(ROOT),'project_tests_read_or_run':False}
(ROOT/'result.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n')
print(json.dumps(result,ensure_ascii=False))
