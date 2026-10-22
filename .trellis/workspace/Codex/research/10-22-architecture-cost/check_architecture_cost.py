"""Isolated regression checks for architecture/cost optimizations; no project tests."""
from __future__ import annotations
import ast, base64, collections, contextlib, copy, hashlib, io, json, os
from pathlib import Path
import sqlite3, subprocess, sys, tarfile, tempfile, time, types, traceback
from unittest.mock import patch
sys.dont_write_bytecode = True
os.umask(0o077)
origin = next(path for path in Path(__file__).resolve().parents if (path / '.git').exists())
commit = 'd8a91a1eaf0eb71758565279c385b000de2761e9'
names = subprocess.check_output(['git','-c','core.quotePath=false','ls-tree','-r','--name-only',commit,'--','tools','memory'],cwd=origin,text=True).splitlines()
names = [name for name in names if name.endswith('.py') and 'tests' not in Path(name).parts]
archive = subprocess.check_output(['git','archive',commit,'--',*names],cwd=origin)
root = Path(tempfile.mkdtemp(prefix='ccst-arch-cost-optimized-'))
repo = root/'source';repo.mkdir()
with tarfile.open(fileobj=io.BytesIO(archive)) as bundle:
    for member in bundle.getmembers():
        if member.isfile():
            path=repo/member.name
            assert path.resolve().is_relative_to(repo)
            path.parent.mkdir(parents=True,exist_ok=True)
            path.write_bytes(bundle.extractfile(member).read())
overlays = ['tools/coverage_matrix.py', 'tools/surface_index.py', 'tools/surface_projection.py', 'tools/target_store.py', 'tools/recall_index.py', 'tools/experience_recall.py', 'tools/relation_recall.py']
source_hashes = {}
baseline_sources = {}
for name in overlays:
    baseline_sources[name] = (repo/name).read_bytes()
    raw = (origin/name).read_bytes()
    (repo/name).write_bytes(raw)
    source_hashes[name] = hashlib.sha256(raw).hexdigest()
(repo/'knowledge').mkdir()
(repo/'knowledge/capabilities.yaml').write_text('capabilities: []\ncontracts: {}\n')
keep={name:os.environ[name] for name in ('PATH','LANG','LC_ALL','TZ') if name in os.environ}
os.environ.clear();os.environ.update(keep)
os.environ.update(PYTHONDONTWRITEBYTECODE='1',PYTHONNOUSERSITE='1',HUNT_MEMORY_DIR=str(repo/'hunt-memory'),CCST_RUNTIME_ROOT=str(root/'private-runtime'))
os.chdir(repo);sys.path[:0]=[str(repo),str(repo/'tools')]
def guard(event,args):
    if event in ('socket.connect','socket.connect_ex','socket.getaddrinfo'):
        raise RuntimeError('audit forbids network')
    if event=='open' and isinstance(args[0],(str,bytes,os.PathLike)):
        p=Path(os.fsdecode(args[0])).absolute()
        if origin==p or origin in p.parents or 'tests' in p.parts:
            raise RuntimeError('audit forbids original checkout and tests')
        if any(v==p or v in p.parents for v in (Path('/root/.claude'),Path('/root/.codex'))):
            raise RuntimeError('audit forbids personal config')
sys.addaudithook(guard)
results={'commit':commit,'fixture':str(root),'source_files':len(names),'source_hashes':source_hashes,'checks':{}}
def section(name,call):
    start=time.monotonic()
    try: result=call()
    except Exception as exc:
        result={'failed':str(type(exc).__name__)+': '+str(exc),'trace':traceback.format_exc(limit=5)}
    result['seconds']=round(time.monotonic()-start,4)
    results['checks'][name]=result
    print(json.dumps({name:result},ensure_ascii=False),flush=True)
def profile(call, wanted):
    counts=collections.Counter()
    def counter(frame,event,arg):
        if event=='call' and frame.f_code.co_name in wanted:
            counts[frame.f_code.co_name]+=1
    sys.setprofile(counter)
    start=time.monotonic()
    try: value=call()
    finally: sys.setprofile(None)
    return value,dict(counts),round(time.monotonic()-start,4)
from tools.target_store import TargetStore
from tools import coverage_matrix as cm, surface_index as si, surface_projection as sp
from tools import recall_index as ri, relation_recall as rr
owner=TargetStore(repo,'audit-cost.invalid');owner.initialize()
baselines = {}
for name in ('target_store', 'recall_index', 'coverage_matrix'):
    module = types.ModuleType('cost_baseline_' + name)
    module.__file__ = str(repo / 'tools' / (name + '.py'))
    exec(compile(baseline_sources['tools/' + name + '.py'], module.__file__, 'exec'), module.__dict__)
    baselines[name] = module

def put_urls(count):
    p=repo/'recon/audit-cost.invalid/urls/all_filtered.txt';p.parent.mkdir(parents=True,exist_ok=True)
    p.write_text(''.join(f'https://audit-cost.invalid/item-{i}\n' for i in range(count)))
def coverage_read():
    put_urls(40);si.build_surface_index(repo,owner.target)
    assert si.load_surface_index_status(repo,owner.target)['status']=='valid'
    matrix,counts,elapsed=profile(lambda:cm.read_matrix(owner.target,repo),{'build_surface_index_input_manifest','coverage_source_fingerprint','_rebuild_matrix_unlocked','current_cell_projection'})
    assert len(matrix['endpoints'])==40
    assert counts['coverage_source_fingerprint']==2 and counts['build_surface_index_input_manifest']==3
    return {'url_count':40,'endpoint_count':len(matrix['endpoints']),'calls':counts,'profiled_read_seconds':elapsed}
section('coverage_duplicate_work',coverage_read)
def stale_surface():
    sp.write_surface_projection(repo,owner.target,{'available':True,'target':owner.target})
    owner.remember(command_id='handoff-audit',kind='handoff',statement='Synthetic audit handoff',conditions='synthetic',reopen_when='',next_intent='continue audit',evidence=[],actor='audit')
    value,counts,elapsed=profile(lambda:sp.load_surface_projection(repo,owner.target),{'build_surface_input_manifest','current_cell_projection','closure_records'})
    assert value['status']=='stale' and value['reason']=='store-revision-mismatch'
    assert counts.get('build_surface_input_manifest',0)==0 and counts.get('current_cell_projection',0)==0
    return {'status':value['status'],'reason':value['reason'],'calls_before_stale_return':counts}
section('known_stale_surface_checks',stale_surface)
def handoff_repeat():
    value,counts,elapsed=profile(lambda:owner.memory_context(limit=5),{'_experience_page_conn','_experience_health'})
    assert value['current_handoff']['id']=='handoff-audit'
    assert len(value['experiences']['items'])==1
    assert counts['_experience_health']==1
    return {'history_rows':1,'handoff_already_in_history':True,'calls':counts}
section('handoff_repeated_expansion',handoff_repeat)
def lexical_repeat():
    n=250;t=12
    docs=[{'source_ref':f'experience:{i}','text':'plain synthetic record','conditions':'synthetic','record':{'statement':'x'*4096}} for i in range(n)]
    db=sqlite3.connect(':memory:');db.execute('CREATE VIRTUAL TABLE documents USING fts5(source_ref UNINDEXED, body)')
    db.executemany('INSERT INTO documents VALUES(?,?)',[(d['source_ref'],ri._document_text(d)) for d in docs]);db.commit()
    payload={'fts':base64.b64encode(db.serialize()).decode()};db.close()
    old=ri.read_generation;ri.read_generation=lambda *a,**k:{'health':{'status':'ready'},'payload':payload,'manifest':{'generation':'synthetic'}}
    try:
        value,counts,elapsed=profile(lambda:ri._query_partition(repo,owner.target,{'documents':docs},' '.join(f'absentword{i}' for i in range(t)),limit=5),{'_document_text'})
    finally:ri.read_generation=old
    assert counts['_document_text']==n and not value['items']
    return {'documents':n,'query_terms':t,'record_bytes':4096,'document_serializations':counts['_document_text'],'fts_channel':value['pagination']['order'],'local_seconds':elapsed,'boundary':'generation validation stub only; actual FTS deserialize/match and lexical function executed'}
section('lexical_serialization',lexical_repeat)
def dependency_chain():
    db=sqlite3.connect(':memory:');db.row_factory=sqlite3.Row
    db.executescript('''CREATE TABLE experience_versions(experience_id TEXT,version INTEGER,snapshot_json TEXT,content_sha256 TEXT);
CREATE TABLE experience_sources(experience_id TEXT,experience_version INTEGER,source_experience_id TEXT,source_version INTEGER,content_sha256 TEXT);
CREATE TABLE experience_links(experience_id TEXT,experience_version INTEGER,target_id TEXT,target_version INTEGER,relation TEXT);
CREATE TABLE experience_material_sources(experience_id TEXT,experience_version INTEGER,owner TEXT,record_id TEXT);
CREATE TABLE experience_external_sources(experience_id TEXT,experience_version INTEGER,owner TEXT,record_id TEXT);
CREATE TABLE experience_claims(id TEXT,experience_id TEXT,experience_version INTEGER);
CREATE TABLE experience_claim_endpoints(claim_id TEXT,owner TEXT,record_id TEXT,version INTEGER);
CREATE TABLE experience_claim_conditions(claim_id TEXT,owner TEXT,record_id TEXT,version INTEGER);
CREATE TABLE store(schema_version INTEGER);INSERT INTO store VALUES(18);''')
    from tools.target_store import _digest
    n=120;snap={'evidence':[]};sha=_digest(snap)
    db.executemany('INSERT INTO experience_versions VALUES(?,?,?,?)',[(str(i),1,json.dumps(snap),sha) for i in range(n)])
    db.executemany('INSERT INTO experience_sources VALUES(?,?,?,?,?)',[(str(i),1,str(i-1),1,sha) for i in range(1,n)])
    count=0
    def trace(sql):
        nonlocal count
        if sql.startswith('SELECT * FROM experience_versions'):count+=1
    db.set_trace_callback(trace)
    start=time.monotonic()
    nodes={}
    for i in range(n):TargetStore._recall_dependencies(owner,db,str(i),nodes=nodes)
    assert count==n
    elapsed=time.monotonic()-start;db.close()
    return {'chain_nodes':n,'retained_version_reads':count,'unique_versions':n,'local_seconds':round(elapsed,4),'boundary':'exact production dependency walker on minimal synthetic in-memory schema; not end-to-end Store benchmark'}
section('dependency_closure_rewalk',dependency_chain)
def relation_zero_progress():
    graph={'schema':rr.SCHEMA,'binding':{'target':owner.target,'store_id':'synthetic'},'shards':{},'nodes':{'a':{'label':'a'},'b':{'label':'b'}},'edges':[{'id':'e','subject':'a','object':'b','predicate':'depends_on','epistemic':'advisory','conditions':'synthetic'}],'rejected':[],'gaps':[]}
    graph['digest']=rr._hash(graph)
    good=rr.traverse(graph,['a'])
    assert good['examined_edges']==1 and good['paths']
    actual=rr.time
    def page(cursor=None):
        ticks=iter((0.0,))
        rr.time=types.SimpleNamespace(monotonic=lambda:next(ticks,1.01))
        return rr.traverse(graph,['a'],cursor=cursor)
    try:first=page();second=page(first['continuation'])
    finally:rr.time=actual
    assert first['stop_reason']==second['stop_reason']=='time_budget'
    assert first['examined_edges']==1 and first['paths']
    assert first['continuation']!=second['continuation']
    return {'normal_paths':len(good['paths']),'simulated_preparation_seconds':1.01,'default_budget_seconds':1,'first_examined':first['examined_edges'],'second_examined':second['examined_edges'],'same_cursor':False,'boundary':'controlled monotonic clock reproduces preparation overrunning budget; no actual large-graph threshold claimed'}
section('relation_paging_no_progress',relation_zero_progress)
def help_navigation():
    from tools.experience_recall import main
    output=io.StringIO()
    with contextlib.redirect_stdout(output):
        try:main(['--help'])
        except SystemExit as exc:assert exc.code==0
    text=output.getvalue()
    assert 'relation-query' in text and 'index-build' in text and 'history' in text
    return {'current_commands_in_top_help':True,'current_command_count_hidden':0}
section('recall_help_navigation',help_navigation)
def rejects(call, exception, message):
    try:
        call()
    except exception as exc:
        assert message in str(exc), str(exc)
        return str(exc)
    raise AssertionError('expected rejection: ' + message)


def coverage_integrity():
    from tools.target_store import StoreError
    legacy = baselines['coverage_matrix']
    put_urls(40)
    si.build_surface_index(repo, owner.target)
    fixed = '2026-10-22T00:00:00+00:00'
    before = owner.binding()
    assert cm.coverage_source_fingerprint(owner.target, repo) == legacy.coverage_source_fingerprint(owner.target, repo)
    old = legacy.read_matrix(owner.target, repo, as_of=fixed)
    new = cm.read_matrix(owner.target, repo, as_of=fixed)
    assert new == old
    calls = []
    real_iterator = cm.iter_surface_index
    def iterator(*args, **kwargs):
        calls.append(kwargs.get('_status'))
        yield from real_iterator(*args, **kwargs)
    with patch.object(cm, 'iter_surface_index', iterator):
        rebuilt = cm.rebuild_matrix(owner.target, repo)
    assert rebuilt['source_fingerprint'] == cm.coverage_source_fingerprint(owner.target, repo)
    assert calls == [None]
    urls = repo / 'recon' / owner.key / 'urls/all_filtered.txt'
    real_route = cm.load_route_kind_observations
    def change_urls(*args, **kwargs):
        value = real_route(*args, **kwargs)
        urls.write_text(urls.read_text() + 'https://audit-cost.invalid/new-race\n')
        return value
    with patch.object(cm, 'load_route_kind_observations', change_urls):
        rejects(lambda: cm.read_matrix(owner.target, repo), StoreError, 'inputs changed')
    si.build_surface_index(repo, owner.target)
    with patch.object(cm, 'load_route_kind_observations', change_urls):
        rejects(lambda: cm.rebuild_matrix(owner.target, repo), si.SurfaceIndexError, 'surface index unavailable')
    si.build_surface_index(repo, owner.target)
    changed = False
    def change_store(*args, **kwargs):
        nonlocal changed
        value = real_route(*args, **kwargs)
        if not changed:
            changed = True
            owner.remember(command_id='coverage-race', kind='note', statement='synthetic race', conditions='synthetic',
                           reopen_when='', next_intent='', evidence=[], actor='fixture')
        return value
    with patch.object(cm, 'load_route_kind_observations', change_store):
        rejects(lambda: cm.read_matrix(owner.target, repo), StoreError, 'inputs changed')
    assert owner.binding()['revision'] == before['revision'] + 1
    return {'equal_fixed_time_projection': True, 'standalone_rebuild_checks_index': True,
            'file_and_store_races_rejected': True}


section('coverage_integrity_and_races', coverage_integrity)


def surface_byte_freshness():
    target = TargetStore(repo, 'surface-bytes.invalid')
    target.initialize()
    raw = repo / 'evidence' / target.key / 'surface-bytes.txt'
    raw.parent.mkdir(parents=True, exist_ok=True)
    raw.write_text('SYNTHETIC raw bytes\n')
    target.start_attempt(attempt_id='surface-attempt', source='synthetic', started_at='2026-10-22T00:00:00+00:00', actor='fixture')
    target.record_execution(attempt_id='surface-attempt', outcome='complete', actor='fixture', observations=[{
        'endpoint': 'https://surface-bytes.invalid/item', 'method': 'GET', 'family': 'synthetic',
        'observed_at': '2026-10-22T00:00:00+00:00', 'description': 'synthetic byte fixture',
        'artifacts': {'response': raw.relative_to(repo).as_posix()}, 'state_changing': False}])
    sp.write_surface_projection(repo, target.target, {'available': True, 'target': target.target})
    assert sp.load_surface_projection(repo, target.target)['status'] == 'valid'
    binding = target.binding()
    raw.write_text('TAMPERED raw bytes\n')
    value, calls, _ = profile(lambda: sp.load_surface_projection(repo, target.target),
                             {'build_surface_input_manifest', 'closure_records'})
    assert value['status'] == 'stale' and value['reason'] == 'input-manifest-mismatch'
    assert calls['build_surface_input_manifest'] == calls['closure_records'] == 1
    assert target.binding() == binding
    return {'same_revision_changed_bytes_rejected': True, 'calls': calls}


section('surface_same_revision_bytes', surface_byte_freshness)


def lexical_equivalence():
    docs = [
        {'source_ref': 'experience:a', 'text': 'Unauthenticated invoice', 'conditions': 'synthetic', 'record': {'statement': 'alpha'}},
        {'source_ref': 'experience:b', 'text': '匿名访问财务导出被拒绝', 'conditions': 'synthetic', 'record': {'statement': '中文'}},
        {'source_ref': 'experience:c', 'text': 'Unauthenticated 匿名导出', 'conditions': 'synthetic', 'record': {'statement': 'other'}},
        {'source_ref': 'experience:d', 'text': 'STRASSE details', 'conditions': 'tenant', 'record': {'statement': 'metadata field'}},
    ]
    db = sqlite3.connect(':memory:')
    db.execute('CREATE VIRTUAL TABLE documents USING fts5(source_ref UNINDEXED, body)')
    db.executemany('INSERT INTO documents VALUES(?,?)', [(d['source_ref'], ri._document_text(d)) for d in docs])
    db.commit()
    payload = {'fts': base64.b64encode(db.serialize()).decode()}
    db.close()
    snapshot = {'binding': {'target': owner.target}, 'documents': docs}
    baseline = baselines['recall_index']
    count = 0
    for selected in (payload, None, {'fts': 'damaged'}):
        generation = {'health': {'status': 'ready' if selected is not None else 'unavailable'},
                      'payload': selected, 'manifest': {'generation': 'synthetic', 'binding': snapshot['binding']}, 'capture': None}
        for query in ('', ' ', '!!!', 'Unauthenticated 匿名', '匿名', 'STRASSE', 'straße', 'metadata', 'absent one two three'):
            with patch.object(baseline, 'read_generation', lambda *a, **k: generation), patch.object(ri, 'read_generation', lambda *a, **k: generation):
                expected = baseline._query_partition(repo, owner.target, snapshot, query, limit=None)
                actual, calls, _ = profile(lambda: ri._query_partition(repo, owner.target, snapshot, query, limit=None), {'_document_text'})
            assert actual == expected, (selected is None, query)
            assert calls.get('_document_text', 0) <= len(docs)
            if query in ('', ' ', '!!!'):
                assert calls.get('_document_text', 0) == 0
            count += 1
    return {'baseline_equal_cases': count, 'includes_fts_missing_corrupt_chinese_empty_punctuation': True}


section('lexical_behavior_equivalence', lexical_equivalence)


def generation_reuse():
    from tools import experience_recall as er, recall_sources as rs
    target = TargetStore(repo, 'reuse-generation.invalid')
    target.initialize()
    for identity in ('item-one', 'item-two'):
        target.remember(command_id=identity, kind='note', statement='needle ' + identity, conditions='synthetic',
                        reopen_when='', next_intent='', evidence=[], actor='fixture')
    assert ri.build_text_index(repo, target.target)['health']['status'] == 'ready'
    before = target.binding()
    result, calls, _ = profile(lambda: er.query_recall(repo, target=target.target, query='needle', limit=1), {'read_generation'})
    assert len(result['recalled']) == 1 and calls['read_generation'] == 2
    assert result['pagination']['next_cursor'] and target.binding() == before
    parsed = []
    real_acquire = rs.acquire_snapshot
    def capture_parse(*args, **kwargs):
        parsed.append(kwargs.get('knowledge_parse_capture'))
        return real_acquire(*args, **kwargs)
    with patch.object(rs, 'acquire_snapshot', capture_parse):
        er.query_recall(repo, target=target.target, query='needle')
    assert len(parsed) == 1 and parsed[0] is not None
    snapshot, generations = ri.acquire_index_snapshot(repo, target.target)
    parts = rs.text_partitions(snapshot)
    target_gen = generations['target']
    stale_part = copy.deepcopy(parts['target'])
    stale_part['binding']['source_digest'] = 'changed'
    bound = ri._bind_generation(target_gen, stale_part)
    assert bound['payload'] is None and bound['health']['status'] == 'stale'
    assert target_gen['payload'] is not None
    missing = {'manifest': None, 'payload': None, 'capture': None, 'health': {'status': 'unavailable'}}
    assert ri._bind_generation(missing, parts['target']) == missing
    with patch.object(ri, 'read_generation', side_effect=AssertionError('generation reread')):
        cached = ri.query_text(repo, target.target, snapshot, 'needle', generations=generations)
    assert len(cached['items']) == 2
    target.remember(command_id='item-three', kind='note', statement='needle new', conditions='synthetic',
                    reopen_when='', next_intent='', evidence=[], actor='fixture')
    fresh = rs.acquire_snapshot(repo, target.target)
    with patch.object(ri, 'read_generation', side_effect=AssertionError('generation reread')):
        stale = ri.query_text(repo, target.target, fresh, 'needle', generations=generations)
    assert len(stale['items']) == 3
    assert stale['health']['partitions']['target']['health']['lexical']['status'] == 'stale'
    rejects(lambda: er.query_recall(repo, target=target.target, query='needle', limit=1,
            cursor=result['pagination']['next_cursor']), ValueError, 'stale recall cursor')
    return {'generation_reads_for_two_partitions': calls['read_generation'], 'parse_capture_forwarded': True,
            'stale_binding_uses_fresh_lexical': True, 'old_cursor_rejected': True}


section('generation_and_parse_reuse', generation_reuse)


def dependency_graphs():
    from tools.target_store import StoreError, _digest
    db = sqlite3.connect(':memory:')
    db.row_factory = sqlite3.Row
    db.executescript('''
CREATE TABLE experience_versions(experience_id TEXT,version INTEGER,snapshot_json TEXT,content_sha256 TEXT);
CREATE TABLE experience_sources(experience_id TEXT,experience_version INTEGER,source_experience_id TEXT,source_version INTEGER,content_sha256 TEXT,purpose TEXT);
CREATE TABLE experience_links(experience_id TEXT,experience_version INTEGER,target_id TEXT,target_version INTEGER,relation TEXT);
CREATE TABLE experience_material_sources(experience_id TEXT,experience_version INTEGER,owner TEXT,record_id TEXT);
CREATE TABLE experience_external_sources(experience_id TEXT,experience_version INTEGER,owner TEXT,record_id TEXT);
CREATE TABLE experience_claims(id TEXT,experience_id TEXT,experience_version INTEGER);
CREATE TABLE experience_claim_endpoints(claim_id TEXT,owner TEXT,record_id TEXT,version INTEGER);
CREATE TABLE experience_claim_conditions(claim_id TEXT,owner TEXT,record_id TEXT,version INTEGER);
CREATE TABLE store(schema_version INTEGER); INSERT INTO store VALUES(18);
CREATE TABLE observation_artifacts(operation_id TEXT,step INTEGER,artifact_id TEXT);
CREATE TABLE assessment_observations(assessment_id TEXT,operation_id TEXT);
CREATE TABLE observations(operation_id TEXT,step INTEGER);
''')
    plain = {'evidence': []}
    evidence = {'evidence': [{'operation_id': 'obs-one', 'step': 0}]}
    for identity, version, snapshot in [('a', 1, plain), ('b', 1, plain), ('c', 1, plain), ('d', 1, evidence), ('d', 2, plain)]:
        db.execute('INSERT INTO experience_versions VALUES(?,?,?,?)', (identity, version, json.dumps(snapshot), _digest(snapshot)))
    for start, end, sha in [('a', 'b', _digest(plain)), ('a', 'c', _digest(plain)), ('b', 'd', _digest(evidence)),
                            ('c', 'd', _digest(evidence)), ('d', 'a', _digest(plain))]:
        db.execute('INSERT INTO experience_sources VALUES(?,?,?,?,?,?)', (start, 1, end, 1, sha, 'origin'))
    db.executemany('INSERT INTO experience_external_sources VALUES(?,?,?,?)', [('b', 1, 'knowledge', 'missing-card'), ('c', 1, 'history', 'missing-history'), ('d', 2, 'knowledge', 'new-version-card')])
    db.execute('INSERT INTO experience_material_sources VALUES(?,?,?,?)', ('d', 1, 'assessment', 'assessment-one'))
    db.execute('INSERT INTO assessment_observations VALUES(?,?)', ('assessment-one', 'obs-two'))
    db.execute('INSERT INTO observations VALUES(?,?)', ('obs-one', 0))
    db.execute('INSERT INTO observation_artifacts VALUES(?,?,?)', ('obs-one', 0, 'raw-one'))
    db.execute('INSERT INTO experience_claims VALUES(?,?,?)', ('claim-one', 'b', 1))
    db.execute('INSERT INTO experience_claim_endpoints VALUES(?,?,?,?)', ('claim-one', 'experience', 'd', 1))
    db.execute('INSERT INTO experience_claim_conditions VALUES(?,?,?,?)', ('claim-one', 'session', 'session-one', 1))
    old = baselines['target_store'].TargetStore._recall_dependencies
    cached = {}
    values = {}
    for identity in ('a', 'b', 'c', 'd'):
        expected = old(owner, db, identity)
        actual = owner._recall_dependencies(db, identity, nodes=cached)
        assert actual == expected
        values[identity] = actual
    refs = {(ref['owner'], ref['record_id']) for ref in values['a']}
    assert {('knowledge', 'missing-card'), ('history', 'missing-history'), ('artifact', 'raw-one'),
            ('operation', 'obs-one'), ('operation', 'obs-two'), ('session', 'session-one')} <= refs
    assert ('knowledge', 'new-version-card') not in refs
    assert values['d'] == [{'owner': 'knowledge', 'record_id': 'new-version-card'}]
    db.execute("UPDATE experience_sources SET content_sha256='bad' WHERE experience_id='c'")
    rejects(lambda: owner._recall_dependencies(db, 'a', nodes={}), StoreError, 'retained binding is corrupt')
    db.execute('UPDATE experience_sources SET content_sha256=? WHERE experience_id=?', (_digest(evidence), 'c'))
    db.execute("UPDATE experience_versions SET snapshot_json='{}' WHERE experience_id='d' AND version=1")
    rejects(lambda: owner._recall_dependencies(db, 'a', nodes={}), StoreError, 'retained version is corrupt')
    db.execute("DELETE FROM experience_versions WHERE experience_id='d' AND version=1")
    rejects(lambda: owner._recall_dependencies(db, 'a', nodes={}), StoreError, 'retained binding is corrupt')
    db.close()
    return {'cycle_diamond_exact_version_external_refs_equal': True, 'per_edge_hash_corruption_rejected': True,
            'retained_content_and_missing_version_rejected': True}


section('dependency_cache_integrity', dependency_graphs)


def health_graphs():
    from tools.target_store import _digest
    target = TargetStore(repo, 'health-graph.invalid')
    target.initialize()
    base = baselines['target_store'].TargetStore._experience_health
    with sqlite3.connect(target.path) as db:
        db.row_factory = sqlite3.Row
        plain = {'evidence': [], 'conditions': 'synthetic'}
        sha = _digest(plain)
        n = 120
        for i in range(n):
            value = '{} corrupted' if i == 0 else json.dumps(plain)
            db.execute('INSERT INTO experience_versions VALUES(?,?,?,?,?)', (f'n{i}', 1, sha, value, 'synthetic'))
            if i:
                db.execute('INSERT INTO experience_sources VALUES(?,?,?,?,?,?)', (f'n{i}', 1, f'n{i-1}', 1, 'basis', sha))
        for identity in ('origin-only', 'diamond', 'cycle-a', 'cycle-b'):
            db.execute('INSERT INTO experience_versions VALUES(?,?,?,?,?)', (identity, 1, sha, json.dumps(plain), 'synthetic'))
        edges = [('origin-only', 'n0', 'origin'), ('diamond', 'n80', 'basis'), ('diamond', 'n50', 'basis'),
                 ('cycle-a', 'cycle-b', 'basis'), ('cycle-b', 'cycle-a', 'basis')]
        db.executemany('INSERT INTO experience_sources VALUES(?,?,?,?,?,?)', [(a, 1, b, 1, purpose, sha) for a, b, purpose in edges])
        roots = [('n119', 1), ('origin-only', 1), ('diamond', 1), ('cycle-a', 1)]
        expected = base(target, db, roots)
        actual = target._experience_health(db, roots)
        assert actual == expected
        assert actual[('n119', 1)]['unhealthy'] and actual[('diamond', 1)]['unhealthy']
        assert not actual[('origin-only', 1)]['unhealthy']
        assert not actual[('cycle-a', 1)]['unhealthy'] and not actual[('cycle-b', 1)]['unhealthy']
        db.execute('INSERT INTO experience_sources VALUES(?,?,?,?,?,?)', ('cycle-b', 1, 'n0', 1, 'basis', sha))
        actual = target._experience_health(db, roots)
        assert actual == base(target, db, roots)
        assert actual[('cycle-a', 1)]['unhealthy'] and actual[('cycle-b', 1)]['unhealthy']
    return {'nodes': n + 4, 'full_health_dto_matches_baseline': True,
            'origin_is_advisory_and_bad_basis_propagates_through_cycles': True}


section('health_chain_cycle_diamond', health_graphs)


def handoff_and_claims():
    target = TargetStore(repo, 'handoff-claims.invalid')
    target.initialize()
    def remember(identity, kind='note', **kwargs):
        target.remember(command_id=identity, kind=kind, statement=identity, conditions='synthetic',
                        reopen_when='', next_intent='', evidence=[], actor='fixture', **kwargs)
    remember('handoff-old', 'handoff')
    for i in range(6):
        remember(f'new-note-{i}')
    with sqlite3.connect(target.path) as db:
        db.execute("UPDATE experiences SET created_at='2000-01-01' WHERE id='handoff-old'")
        from tools.target_store import _digest
        row = db.execute("SELECT snapshot_json FROM experience_versions WHERE experience_id='handoff-old'").fetchone()
        value = json.loads(row[0]); value['created_at'] = '2000-01-01'
        db.execute("UPDATE experience_versions SET snapshot_json=?,content_sha256=? WHERE experience_id='handoff-old'", (json.dumps(value), _digest(value)))
    context, calls, _ = profile(lambda: target.memory_context(limit=5), {'_experience_health'})
    assert context['current_handoff']['id'] == 'handoff-old' and calls['_experience_health'] == 2
    assert 'handoff-old' not in {r['id'] for r in context['experiences']['items']}
    full = target.memory_context(limit=20)
    saved = next(row for row in full['experiences']['items'] if row['id'] == 'handoff-old')
    full['current_handoff']['source_health'].append({'mutation': 'isolated'})
    assert {'mutation': 'isolated'} not in saved['source_health']
    first = target.experience_entity('experience', 'new-note-0')
    second = target.experience_entity('experience', 'new-note-1')
    source = {'target': target.target, 'store_id': first['store_id'], 'experience_id': first['record_id'],
              'version': first['version'], 'content_sha256': first['content_sha256'], 'purpose': 'basis'}
    claim = {'subject': first, 'predicate': 'requires', 'object': second, 'conditions': 'synthetic',
             'timing': 'synthetic', 'source_refs': [{'source': 0}], 'condition_bindings': {'premise': second}}
    remember('claim-holder', sources=[source], claims=[claim])
    retained, calls, _ = profile(lambda: target.experience_version('claim-holder'), {'_experience_health'})
    assert calls['_experience_health'] == 1
    assert retained['claims'][0]['subject']['health'] == 'available'
    old_store = baselines['target_store'].TargetStore(repo, target.target)
    assert retained == old_store.experience_version('claim-holder')
    with sqlite3.connect(target.path) as db:
        db.execute("UPDATE experience_versions SET snapshot_json='corrupt' WHERE experience_id='new-note-1'")
    retained = target.experience_version('claim-holder')
    assert retained == old_store.experience_version('claim-holder')
    assert retained['claims'][0]['object']['health'] == retained['claims'][0]['condition_bindings']['premise']['health'] == 'needs_review'
    return {'outside_window_handoff_retained': True, 'handoff_mutation_does_not_alias_history': True,
            'claim_health_calls': calls['_experience_health'], 'claim_dto_equal_when_healthy_and_corrupt': True}


section('handoff_and_claim_health_reuse', handoff_and_claims)


def relation_progress_edges():
    def make_graph(edges, nodes=('a', 'b', 'c', 'd')):
        graph = {'schema': rr.SCHEMA, 'binding': {'target': owner.target, 'store_id': 'synthetic'}, 'shards': {},
                 'nodes': {key: {'label': key} for key in nodes}, 'edges': [], 'rejected': [], 'gaps': []}
        for i, (a, b, conditions) in enumerate(edges):
            graph['edges'].append({'id': f'e{i}', 'subject': a, 'object': b, 'predicate': 'depends_on',
                                   'epistemic': 'advisory', 'conditions': 'synthetic', 'condition_bindings': conditions})
        graph['digest'] = rr._hash(graph)
        return graph
    graph = make_graph([('a', 'b', {'role': 'one'}), ('b', 'a', {'role': 'one'}),
                        ('b', 'c', {'role': 'two'}), ('b', 'd', {'role': 'one'})])
    all_paths = rr.traverse(graph, ['a'])['paths']
    cursors, paths, cursor, steps = set(), [], None, 0
    while True:
        ticks = iter((0.0,))
        with patch.object(rr, 'time', types.SimpleNamespace(monotonic=lambda: next(ticks, 1.01))):
            page = rr.traverse(graph, ['a'], cursor=cursor, max_edges=1, max_paths=1)
        paths.extend(page['paths']); steps += 1
        cursor = page['continuation']
        if cursor is None:
            break
        assert cursor not in cursors
        cursors.add(cursor)
        assert steps < 30
    assert paths == all_paths and len(paths) == 2
    empty = make_graph([], nodes=('a', 'b', 'c'))
    ticks = iter((0.0,))
    with patch.object(rr, 'time', types.SimpleNamespace(monotonic=lambda: next(ticks, 1.01))):
        page = rr.traverse(empty, ['a', 'b', 'c'])
    assert page['continuation'] and rr._decode_cursor(page['continuation'])['seed'] == 1
    rejects(lambda: rr.traverse(graph, ['a'], max_bytes=1), ValueError, 'requires max_bytes')
    size = len(rr._json(all_paths[0]).encode())
    page = rr.traverse(graph, ['a'], max_bytes=size)
    assert len(page['paths']) == 1 and page['stop_reason'] == 'response_budget'
    more = rr.traverse(graph, ['a'], cursor=page['continuation'], max_bytes=10000)
    assert page['paths'] + more['paths'] == all_paths
    changed = make_graph([('a', 'c', {})])
    rejects(lambda: rr.traverse(changed, ['a'], cursor=page['continuation']), ValueError, 'stale relation cursor')
    bad = copy.deepcopy(graph); bad['digest'] = 'bad'
    rejects(lambda: rr.traverse(bad, ['a']), ValueError, 'format changed or corrupt')
    return {'bounded_pages_complete_without_repeated_cursor': steps, 'cycle_and_condition_conflict_skipped': True,
            'empty_seeds_advance': True, 'insufficient_bytes_explicit_error': True, 'changed_graph_rejected': True}


section('relation_progress_and_budgets', relation_progress_edges)


def legacy_help():
    from tools.experience_recall import main
    for argv, marker in [(['--help'], 'relation-query'), (['-h'], 'index-build'),
                         (['query', '--help'], '--source-ref'), (['--target', owner.target, '--help'], '--kind')]:
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            try:
                main(argv)
            except SystemExit as exc:
                assert exc.code == 0
        assert marker in output.getvalue()
    return {'top_and_command_help_discoverable': True, 'legacy_help_retained': True}


section('legacy_cli_help_compatibility', legacy_help)

results['isolation']={'source_read_only':True,'project_tests_read_or_run':False,'network':False,'original_data':False,'new_model_calls':False}
(root/'result.json').write_text(json.dumps(results,ensure_ascii=False,indent=2)+'\n')
Path('/tmp/ccst-architecture-cost-optimized-result.json').write_text(json.dumps(results,ensure_ascii=False,indent=2)+'\n')
print(json.dumps({'result':'/tmp/ccst-architecture-cost-optimized-result.json','failed_checks':[k for k,v in results['checks'].items() if 'failed' in v]},ensure_ascii=False))

raise SystemExit(int(any("failed" in value for value in results["checks"].values())))
