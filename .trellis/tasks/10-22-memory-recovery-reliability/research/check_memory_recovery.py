"""Committed-source, synthetic-only memory/iteration acceptance; no project tests."""
from __future__ import annotations

import hashlib
import io
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tarfile
import tempfile
import time
import traceback

sys.dont_write_bytecode = True
ORIGIN = Path('/root/tool/ccst(rename-_Ya66f2)/ccst3/ccst')
COMMIT = '9d0675a'
ONLY = set(sys.argv[1:])
RESULT = Path('/tmp/ccst-memory-recovery-check-20261022' + ('-retry' if ONLY else '') + '-result.json')
START = time.monotonic()
CHECKS = 0
SECTIONS, ISSUES, FACTS = [], [], {}


def check(condition, label):
    global CHECKS
    if not condition:
        raise AssertionError(label)
    CHECKS += 1


def iter_trace(tb):
    while tb is not None:
        yield tb
        tb = tb.tb_next


def section(name, function):
    if ONLY and function.__name__ not in ONLY:
        return
    started, before = time.monotonic(), CHECKS
    try:
        function()
    except Exception as exc:
        SECTIONS.append({'name': name, 'status': 'failed',
                         'error': f'{type(exc).__name__}: {exc}',
                         'trace': [{'file': f.tb_frame.f_code.co_filename, 'line': f.tb_lineno} for f in iter_trace(exc.__traceback__)]})
    else:
        SECTIONS.append({'name': name, 'status': 'passed', 'assertions': CHECKS - before})
    SECTIONS[-1]['seconds'] = round(time.monotonic() - started, 3)
    print(json.dumps(SECTIONS[-1], ensure_ascii=False), flush=True)


def rejected(function, exception, label, owner=None):
    revision = owner.binding()['revision'] if owner else None
    try:
        function()
    except exception as exc:
        check(True, label)
        if owner:
            check(owner.binding()['revision'] == revision, label + ': no Store write')
        return str(exc)
    raise AssertionError(label)


def put(path, data):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.write_bytes(data if isinstance(data, bytes) else data.encode('utf-8'))
    path.chmod(0o600)
    return path


GUARD = '''import os, runpy, sys
from pathlib import Path
sys.dont_write_bytecode = True
origin = Path(os.environ['CCST_AUDIT_ORIGIN'])
def guard(event, args):
    if event in {'socket.connect', 'socket.connect_ex', 'socket.getaddrinfo'}:
        raise RuntimeError('audit forbids network access')
    if event == 'open' and isinstance(args[0], (str, bytes, os.PathLike)):
        path = Path(os.fsdecode(args[0])).absolute()
        if path == origin or origin in path.parents:
            raise RuntimeError('audit forbids original checkout reads')
        if 'tests' in path.parts:
            raise RuntimeError('audit forbids project tests')
        if any(root == path or root in path.parents for root in (Path('/root/.claude'), Path('/root/.codex'))):
            raise RuntimeError('audit forbids personal runtime/config')
sys.addaudithook(guard)
script = Path(sys.argv[1]).resolve()
sys.argv = [str(script), *sys.argv[2:]]
sys.path[:0] = [str(script.parent.parent), str(script.parent)]
runpy.run_path(str(script), run_name='__main__')
'''


with tempfile.TemporaryDirectory(prefix='ccst-memory-acceptance-') as temporary:
    fixture = Path(temporary)
    runtime = fixture / 'checkout'
    runtime.mkdir(mode=0o700)
    names = subprocess.check_output([
        'git', 'ls-tree', '-r', '--name-only', COMMIT, '--', 'tools', 'memory',
    ], cwd=ORIGIN, text=True).splitlines()
    selected = [name for name in names if Path(name).suffix == '.py' and 'tests' not in Path(name).parts]
    archive = subprocess.check_output(['git', 'archive', COMMIT, '--', *selected], cwd=ORIGIN)
    with tarfile.open(fileobj=io.BytesIO(archive)) as bundle:
        for member in bundle.getmembers():
            if member.isfile():
                destination = runtime / member.name
                if not destination.resolve().is_relative_to(runtime):
                    raise AssertionError('unsafe archive path')
                put(destination, bundle.extractfile(member).read())
    overlay = ('tools/autopilot_bootstrap.py', 'tools/context_pack.py', 'tools/resume.py',
               'tools/recall_index.py', 'tools/target_store.py', 'tools/distill_target.py')
    for name in overlay:
        put(runtime / name, (ORIGIN / name).read_bytes())
    FACTS['source_overlay'] = {name: hashlib.sha256((runtime / name).read_bytes()).hexdigest() for name in overlay}
    put(runtime / 'knowledge/capabilities.yaml', 'capabilities: []\ncontracts: {}\n')
    guard_path = put(fixture / 'guard.py', GUARD)
    env = {name: os.environ[name] for name in ('PATH', 'LANG', 'LC_ALL', 'TZ') if name in os.environ}
    env.update(PYTHONDONTWRITEBYTECODE='1', PYTHONNOUSERSITE='1', PYTHONPATH=str(runtime),
               HUNT_MEMORY_DIR=str(runtime / 'hunt-memory'),
               CCST_RUNTIME_ROOT=str(fixture / 'host-runtime'), CCST_AUDIT_ORIGIN=str(ORIGIN))
    os.environ.clear()
    os.environ.update(env)
    os.chdir(runtime)
    sys.path[:0] = [str(runtime), str(runtime / 'tools')]
    exec(GUARD.split('script = Path(sys.argv[1])')[0], {'__name__': 'memory_audit_guard'})

    from tools.target_store import TargetStore, StoreError
    from tools.experience_recall import query_recall
    from tools.recall_index import build_text_index, index_status
    from tools.relation_recall import build_relations, query_relations, relation_status
    from tools.distill_target import build_evidence_view
    from tools.knowledge_review import publication_receipt, publication_ref, read_published_review, sha256
    from tools.experience_knowledge import capture_source
    from tools.recall_sources import acquire_knowledge
    from tools.surface_advisory import build_surface_advisory

    def cli(script, *args, expected=0):
        result = subprocess.run([sys.executable, '-B', str(guard_path), str(runtime / script),
                                 *map(str, args)], cwd=runtime, env=env, capture_output=True,
                                text=True, timeout=15)
        check(result.returncode == expected,
              f'{script}: exit={result.returncode} expected={expected}; {result.stderr[-1200:]} {result.stdout[-1200:]}')
        return result

    def new_store(name):
        owner = TargetStore(runtime, name + '.invalid')
        owner.initialize()
        return owner

    def snapshot(owner):
        files = {}
        for path in runtime.rglob('*'):
            if (not path.is_file() or 'locks' in path.parts
                    or path.name.endswith(('.lock', '-wal', '-shm')) or path.name == 'metadata.sqlite3'):
                continue
            files[path.relative_to(runtime).as_posix()] = sha256(path.read_bytes())
        with sqlite3.connect(f'file:{owner.path}?mode=ro', uri=True) as connection:
            logical = sha256('\n'.join(connection.iterdump()).encode())
        return {'files': files, 'logical_store': logical, 'binding': owner.binding()}

    def evidence(owner, identity='observation'):
        raw = put(runtime / 'evidence' / owner.key / (identity + '.txt'), b'SYNTHETIC raw only\n')
        stamp = '2026-10-21T00:00:00+00:00'
        attempt = 'attempt:' + identity
        owner.start_attempt(attempt_id=attempt, source='synthetic', started_at=stamp, actor='fixture')
        op = owner.record_execution(attempt_id=attempt, outcome='complete', actor='fixture', observations=[{
            'endpoint': f'https://{owner.target}/synthetic', 'method': 'GET', 'family': 'synthetic',
            'observed_at': stamp, 'description': 'Offline synthetic observation only',
            'artifacts': {'response': raw.relative_to(runtime).as_posix()}, 'state_changing': False,
        }])['entity_id']
        return [{'operation_id': op, 'step': 0}], raw

    def remember(owner, identity, kind='note', conditions='tenant=A; release=1', refs=None, sources=None):
        return owner.remember(command_id=identity, kind=kind, statement=identity, conditions=conditions,
                              reopen_when='release changes' if kind == 'negative' else '', next_intent='',
                              evidence=refs or [], sources=sources or [], actor='fixture')

    def source(owner, identity, purpose='basis', version=None):
        retained = owner.experience_version(identity, version)
        return {**{key: retained[key] for key in ('target', 'store_id', 'experience_id', 'version', 'content_sha256')},
                'purpose': purpose}

    def link(owner, identity, start, end, relation='refutes', conditions='tenant=A; release=1'):
        return owner.link_experience(command_id=identity, experience_id=start, target_id=end,
                                     relation=relation, conditions=conditions, rationale='Synthetic correction',
                                     expected_revision=owner.binding()['revision'], actor='fixture')

    def memory_corrections():
        owner = new_store('memory-corrections')
        refs, raw = evidence(owner)
        remember(owner, 'negative', 'negative', refs=refs)
        remember(owner, 'primitive', 'primitive', refs=refs)
        remember(owner, 'derived', sources=[source(owner, 'negative')])
        check(owner.experience_version('negative')['review_state'] == 'advisory', 'Evidence-backed negative accepted')
        check(owner.experience_version('primitive')['review_state'] == 'advisory', 'Evidence-backed primitive accepted')
        rejected(lambda: remember(owner, 'no-evidence', 'negative'), StoreError, 'No-evidence negative rejected', owner)
        rejected(lambda: remember(owner, 'false-step', 'primitive', refs=[{'operation_id': refs[0]['operation_id'], 'step': True}]),
                 StoreError, 'Bool observation step rejected', owner)
        rejected(lambda: remember(owner, 'missing-operation', 'primitive', refs=[{'operation_id': 'foreign:operation', 'step': 0}]),
                 StoreError, 'Unknown operation rejected', owner)
        old_source = source(owner, 'negative')
        for field, value in [('target', 'foreign.invalid'), ('store_id', 'foreign-store'), ('content_sha256', '0' * 64)]:
            rejected(lambda field=field, value=value: remember(owner, 'invalid-' + field,
                     sources=[{**old_source, field: value}]), StoreError, 'Invalid source ' + field, owner)
        remember(owner, 'other-scope', conditions='tenant=B; release=1')
        link(owner, 'conditional', 'other-scope', 'negative', conditions='tenant=B; release=1')
        before = owner.experience_version('negative')
        check(before['review_state'] == 'advisory'
              and before['correction_refs'][0]['applicability']['effect'] == 'conditional',
              'Different conditions retain original applicability')
        remember(owner, 'correction')
        link(owner, 'refutation', 'correction', 'negative')
        check(owner.experience_version('negative')['review_state'] == 'disputed', 'Same-scope refutation challenges old record')
        check(owner.experience_version('derived')['review_state'] == 'needs_review', 'Challenged basis propagates')
        rejected(lambda: remember(owner, 'new-derived', sources=[source(owner, 'negative')]), StoreError,
                 'New reliance on challenged basis rejected', owner)
        remember(owner, 'origin-only', sources=[source(owner, 'negative', 'origin')])
        check(owner.experience_version('origin-only')['review_state'] == 'advisory', 'Origin preserves history without a basis claim')
        owner.retract_experience_link(command_id='withdraw-refutation', link_id='refutation', reason='Synthetic reconsideration',
                                      expected_revision=owner.binding()['revision'], actor='fixture')
        disputed = owner.experience_version('negative')
        check(disputed['review_state'] == 'disputed', 'Withdrawal does not resurrect old advice')
        check(any(item.get('retraction_id') == 'withdraw-refutation' for item in disputed['correction_refs'])
              and any(item.get('withdrawn') for item in disputed['applicability']['corrections']),
              'Withdrawal receipt and applicability marker remain visible')
        remembered = query_recall(runtime, target=owner.target, source_ref='experience:negative', include_knowledge=False)
        check(remembered['recalled'][0]['review_state'] == 'disputed', 'Exact recall retains correction state')
        check('refutation' in json.dumps(remembered['counterevidence']), 'Recall includes exact counterevidence')

        remember(owner, 'replace-old')
        remember(owner, 'replace-new')
        link(owner, 'replacement', 'replace-new', 'replace-old', 'supersedes')
        check(owner.experience_version('replace-old')['review_state'] == 'superseded', 'Same-scope supersession recorded')
        remember(owner, 'dependency')
        remember(owner, 'dependent')
        link(owner, 'dependency-link', 'dependent', 'dependency', 'depends_on')
        rejected(lambda: link(owner, 'cycle', 'dependency', 'dependent', 'depends_on'), StoreError,
                 'Dependency cycle rejected', owner)
        owner.retract_experience_link(command_id='withdraw-dependency', link_id='dependency-link', reason='Synthetic withdrawal',
                                      expected_revision=owner.binding()['revision'], actor='fixture')
        check(owner.experience_version('dependent')['review_state'] == 'needs_review', 'Withdrawn dependency becomes needs_review')

        artifact = owner.execution(refs[0]['operation_id'])['observations'][0]['artifacts'][0]['id']
        owner.record_artifact_event(command_id='revoke', artifact_id=artifact, dimension='provenance',
                                    state='revoked', reason='Synthetic revocation', actor='fixture')
        check(owner.experience_version('primitive')['review_state'] == 'needs_review', 'Revoked evidence invalidates reliance')
        rejected(lambda: remember(owner, 'invalid-new-primitive', 'primitive', refs=refs), StoreError,
                 'New experience cannot cite revoked evidence', owner)
        binding = owner.binding()
        check(remember(owner, 'negative', 'negative', refs=refs)['replayed'], 'Original command still replays idempotently')
        check(owner.binding() == binding, 'Replay does not change state')
        check(owner.experience_version('negative')['review_state'] == 'disputed', 'Replay does not revalidate bad advice')

    def retained_versions():
        owner = new_store('memory-versions')
        owner.remember_hypothesis(command_id='hyp-open', hypothesis_id='hypothesis', vuln_class='synthetic',
                                  why_now='conditional hypothesis', status='open', actor='fixture')
        original = owner.experience_version('hypothesis')
        old_source = source(owner, 'hypothesis')
        remember(owner, 'derived-from-version', sources=[old_source])
        owner.remember_hypothesis(command_id='hyp-closed', hypothesis_id='hypothesis', vuln_class='synthetic',
                                  why_now='conditional hypothesis', status='closed', actor='fixture')
        current = owner.experience_version('hypothesis')
        retained = owner.experience_version('hypothesis', original['version'])
        check(current['version'] > original['version'], 'Hypothesis change creates retained version')
        check(retained['snapshot']['case_context'][0]['status'] == 'open'
              and current['snapshot']['case_context'][0]['status'] == 'closed', 'Old and current hypothesis statuses remain distinct')
        check(retained['content_sha256'] == original['content_sha256'], 'Old bytes remain bound')
        derived = owner.experience_version('derived-from-version')
        check(derived['review_state'] == 'needs_review'
              and any(item['status'] == 'version_changed' for item in derived['source_health']), 'Version change invalidates fixed old basis')
        rejected(lambda: remember(owner, 'stale-basis', sources=[old_source]), StoreError, 'Stale basis cannot be newly admitted', owner)
        remember(owner, 'old-origin', sources=[{**old_source, 'purpose': 'origin'}])
        check(owner.experience_version('old-origin')['review_state'] == 'advisory', 'Old origin may be retained')

    def text_recall():
        owner = new_store('memory-text')
        remember(owner, 'alphafixture-one')
        remember(owner, 'alphafixture-two')
        before = snapshot(owner)
        first = query_recall(runtime, target=owner.target, query='alphafixture', limit=1, include_knowledge=False)
        check(first['pagination']['remaining'] == 1 and first['pagination']['next_cursor'], 'Text recall has exact bounded continuation')
        check(first['recalled'][0]['match']['channel'] == 'fresh-source-lexical', 'Missing index uses source lexical')
        check(first['health']['partitions']['target']['health']['lexical']['status'] == 'unavailable', 'Missing index stays visible')
        check(first['health']['semantic']['status'] == 'unavailable', 'Missing model is not semantic success')
        second = query_recall(runtime, target=owner.target, query='alphafixture', limit=1,
                              cursor=first['pagination']['next_cursor'], include_knowledge=False)
        check(second['recalled'][0]['source_ref'] != first['recalled'][0]['source_ref'], 'Continuation avoids duplicate candidate')
        empty_query = query_recall(runtime, target=owner.target, include_knowledge=False)
        check(empty_query['health']['semantic']['status'] == 'not_requested'
              and empty_query['pagination']['order'] == 'source-order', 'Default empty query uses source order')
        check(before == snapshot(owner), 'Query without index is read-only')
        check(not (runtime / 'state' / owner.key / 'recall-index').exists(), 'Query does not create index directory')

        built = build_text_index(runtime, owner.target, include_knowledge=False)
        check(built['health']['status'] == 'ready', 'Explicit no-model FTS build succeeds')
        check(built['partitions']['target']['provider']['status'] == 'unavailable', 'FTS readiness does not claim model availability')
        before = snapshot(owner)
        ranked = query_recall(runtime, target=owner.target, query='alphafixture', limit=1, include_knowledge=False)
        check(ranked['recalled'][0]['match']['channel'] == 'fts5-bm25', 'Built FTS index is actually used')
        check(index_status(runtime, owner.target, include_knowledge=False)['health']['status'] == 'ready', 'Index status is ready')
        check(before == snapshot(owner), 'Indexed query and status are read-only')
        rejected(lambda: query_recall(runtime, target=owner.target, query='alphafixture',
                 cursor=first['pagination']['next_cursor'], include_knowledge=False), ValueError, 'Generation change rejects old query cursor')

        pointer = runtime / 'state' / owner.key / 'recall-index/text/CURRENT'
        previous = pointer.read_bytes()
        remember(owner, 'betafixture-new')
        stale = query_recall(runtime, target=owner.target, query='betafixture', include_knowledge=False)
        check(stale['recalled'][0]['source_ref'] == 'experience:betafixture-new', 'New record is found despite stale index')
        check(stale['health']['partitions']['target']['health']['lexical']['status'] == 'stale'
              and stale['recalled'][0]['match']['channel'] == 'fresh-source-lexical', 'Stale index explicitly falls back to fresh source')
        check(pointer.read_bytes() == previous, 'Stale query does not rebuild')
        rejected(lambda: query_recall(runtime, target=owner.target, query='alphafixture',
                 cursor=ranked['pagination']['next_cursor'], include_knowledge=False), ValueError, 'Source change rejects old query cursor')
        build = build_text_index(runtime, owner.target, include_knowledge=False)
        check(build['health']['status'] == 'ready', 'Explicit incremental rebuild restores FTS')
        previous = pointer.read_bytes()
        missing_model = str(fixture / 'nonexistent-encoder')
        declined = build_text_index(runtime, owner.target, include_knowledge=False, encoder_path=missing_model)
        check(declined['health']['status'] == 'unavailable' and pointer.read_bytes() == previous,
              'Unavailable requested encoder cannot publish over working index')
        degraded = query_recall(runtime, target=owner.target, query='betafixture', include_knowledge=False, encoder_path=missing_model)
        check(degraded['health']['semantic']['status'] == 'unavailable' and degraded['recalled'],
              'Unavailable semantic query preserves lexical result and explicit health')
        shown = json.loads(cli('tools/target_memory.py', 'show', owner.target, '--repo-root', runtime, '--json').stdout)
        check(shown['target']['target'] == owner.target, 'Documented trailing global CLI options are accepted')
        FACTS['text_recall'] = {'no_index': first['health']['partitions']['target']['health'],
                                'indexed_match': ranked['recalled'][0]['match'],
                                'stale_match': stale['recalled'][0]['match'],
                                'failed_model_build': declined['health']}

    def relations():
        owner = new_store('memory-relations')
        owner.upsert_case_actor(command_id='actor', actor_id='actor-A', actor='fixture')
        owner.upsert_case_session(command_id='session', session_id='session-A', actor_id='actor-A', actor='fixture')
        owner.upsert_case_object(command_id='object', object_ref='object-A', object_type='synthetic', owner_actor='actor-A', actor='fixture')
        seed = owner.experience_entity('actor', 'actor-A')
        before = snapshot(owner)
        missing = query_relations(runtime, owner.target, seeds=[seed])
        check(missing['status'] == 'unavailable' and missing['paths'] == [] and missing['remaining'] == 'unknown',
              'Missing graph is explicit unknown, not no relations')
        check(before == snapshot(owner), 'Relation query does not create graph')
        built = build_relations(runtime, owner.target)
        check(built['health']['status'] == 'ready' and built['edge_count'] == 2, 'Owner actor/session/object graph builds')
        before = snapshot(owner)
        page = query_relations(runtime, owner.target, seeds=[seed], max_paths=1)
        check(len(page['paths']) == 1 and page['continuation'], 'Relation query honors bound and continues')
        continuation = query_relations(runtime, owner.target, seeds=[seed], max_paths=1, cursor=page['continuation'])
        paths = page['paths'] + continuation['paths']
        check(len(paths) == 2 and all(path['epistemic'] == 'hypothesis' and path['executable'] is False for path in paths),
              'Relation paths stay hypotheses without execution authority')
        check(all(path['unverified_conditions'] for path in paths), 'Unknown conditions remain visible')
        check({path['edges'][0]['predicate'] for path in paths} == {'has_session', 'owns_object'}, 'Relation paths match owner records')
        check(relation_status(runtime, owner.target)['health']['status'] == 'ready', 'Relation status ready')
        check(before == snapshot(owner), 'Graph query and status are read-only')
        foreign = new_store('memory-relations-foreign')
        foreign.upsert_case_actor(command_id='foreign-actor', actor_id='foreign-actor', actor='fixture')
        rejected(lambda: query_relations(runtime, owner.target, seeds=[foreign.experience_entity('actor', 'foreign-actor')]),
                 ValueError, 'Foreign Store seed rejected')
        pointer = runtime / 'state' / owner.key / 'recall-index/relations/CURRENT'
        previous = pointer.read_bytes()
        owner.upsert_case_object(command_id='object-new', object_ref='object-B', object_type='synthetic', owner_actor='actor-A', actor='fixture')
        stale = query_relations(runtime, owner.target, seeds=[seed])
        check(stale['status'] == 'stale' and stale['paths'] == [] and stale['remaining'] == 'unknown',
              'Stale graph is not consumed as current')
        check(pointer.read_bytes() == previous, 'Stale graph query does not rebuild')
        rebuilt = build_relations(runtime, owner.target)
        check(rebuilt['health']['status'] == 'ready' and rebuilt['edge_count'] == 3, 'Explicit graph rebuild includes new owner record')
        rejected(lambda: query_relations(runtime, owner.target, seeds=[seed], max_paths=1, cursor=page['continuation']),
                 ValueError, 'Old graph continuation rejected')
        FACTS['relations'] = {'initial_edges': built['edge_count'], 'updated_edges': rebuilt['edge_count'],
                              'path_epistemic': paths[0]['epistemic'], 'stale_status': stale['status']}

    def distill_projection():
        owner = new_store('iteration-distill')
        refs, raw = evidence(owner)
        remember(owner, 'distill-negative', 'negative', refs=refs)
        remember(owner, 'distill-correction')
        link(owner, 'distill-refutation', 'distill-correction', 'distill-negative')
        current = owner.experience('distill-negative')
        check(current['review_state'] == 'disputed' and current['correction_refs'], 'Source carries exact distillation correction')
        before = snapshot(owner)
        view = build_evidence_view(runtime, owner.target)
        rendered = json.dumps(view)
        check('distill-negative' in view['view'] and 'tenant=A; release=1' in view['view']
              and 'release changes' in view['view'], 'Distillation retains statement, condition, reopening condition')
        check(all(marker in rendered for marker in ('disputed', 'review_state', 'source_health',
                                                    'distill-refutation', 'correction_refs')),
              'Distillation preserves correction and source status')
        check(before == snapshot(owner), 'Distill is read-only')
        for number in range(11):
            remember(owner, f'pagination-{number}')
        bounded = build_evidence_view(runtime, owner.target)
        window = bounded['windows']['experiences']
        check(window['total'] == 13 and window['remaining'] == 3 and window['has_more'], 'Distillation experience window counts are exact')
        check(window['next_command'] and window['expand_command'], 'Distillation exposes owner continuation and expansion')

    def synthetic_publication(root, card_id='synthetic-card', metadata=None):
        card_ref = f'knowledge/cards/{card_id}.md'
        review_ref = f'knowledge/candidates/{card_id}.review.json'
        frontmatter = {'id': card_id, 'maturity': 'tested', 'trigger_tags': ['synthetic'], **(metadata or {})}
        published = ('---\n' + json.dumps(frontmatter) + '\n---\n# SYNTHETIC ONLY\n'
                     'Protocol fixture. No real method, model experiment, or human review.\n').encode()
        blind = {'verdict': 'incremental', 'model': 'SYNTHETIC-NO-MODEL', 'configuration': 'Protocol fixture only',
                 'criteria': 'Protocol fixture only', 'increment': 'Protocol fixture only'}
        for field in ('question', 'allowed_material', 'response'):
            name = f'{card_id}-{field}.txt'
            raw = f'SYNTHETIC {field}; no actual experiment'.encode()
            put(root / 'knowledge/candidates' / name, raw)
            blind[field] = {'file': name, 'sha256': sha256(raw)}
        review = {'schema_version': 1, 'decision': 'accept', 'card_id': card_id,
                  'candidate_sha256': sha256(published), 'reviewer': 'SYNTHETIC-NOT-A-HUMAN-REVIEW',
                  'reviewed_at': '1970-01-01T00:00:00Z', 'rationale': 'Synthetic binding fixture only',
                  'transferability': 'Synthetic binding fixture only', 'intake_kind': 'new-method',
                  'three_questions': {key: 'Synthetic protocol fixture only'
                                      for key in ('model_seen', 'inferable_from_evidence', 'real_cost_delta')},
                  'blind_answer': blind}
        review_bytes = json.dumps(review).encode()
        receipt = publication_receipt(card_id=card_id, file=card_ref, candidate=published, published=published,
                                      review_ref=review_ref, review_bytes=review_bytes, replaced_refs={})
        receipt_ref = publication_ref(card_id, sha256(published), sha256(review_bytes))
        entry = {'id': card_id, 'kind': 'card', 'file': card_ref, 'review_receipt': receipt_ref, 'status': 'active'}
        put(root / card_ref, published)
        put(root / review_ref, review_bytes)
        put(root / receipt_ref, json.dumps(receipt))
        put(root / 'knowledge/capabilities.yaml', json.dumps({'capabilities': [entry], 'contracts': {}}))
        return entry, published, blind

    def knowledge_integrity():
        root = fixture / 'synthetic-knowledge'
        entry, published, blind = synthetic_publication(root)
        review = read_published_review(root, entry, published)
        check(review['status'] == 'ready', 'Synthetic publication binds exact bytes')
        check(capture_source(root, entry['id'])['status'] == 'available', 'Experience source admits valid review binding')
        docs, health = acquire_knowledge(root)
        check(len(docs) == 1 and docs[0]['review_state'] == 'reviewed', 'Shared recall uses verified review binding')
        changed = published + b'\nUNREVIEWED SYNTHETIC CHANGE\n'
        put(root / entry['file'], changed)
        check(read_published_review(root, entry, changed)['status'] == 'review-unverified', 'Changed published bytes invalidate review')
        check(capture_source(root, entry['id'])['status'] == 'review-unverified', 'Experience source rejects changed publication')
        docs, health = acquire_knowledge(root)
        check(not docs and health['errors'][0]['status'] == 'review-unverified', 'Shared recall refuses changed publication')
        put(root / entry['file'], published)
        artifact = root / 'knowledge/candidates' / blind['response']['file']
        previous = artifact.read_bytes()
        put(artifact, previous + b' changed')
        check(read_published_review(root, entry, published)['status'] == 'review-unverified', 'Changed blind artifact invalidates review')
        put(artifact, previous)
        check(read_published_review(root, {**entry, 'status': 'retired'}, published)['status'] == 'review-unverified',
              'Retired entry not admitted')
        check(read_published_review(root, {key: value for key, value in entry.items() if key != 'review_receipt'}, published)['status']
              == 'review-unverified', 'Missing review receipt not admitted')
        check(capture_source(root, entry['id'])['status'] == 'available', 'Restoring exact bytes restores valid binding')
        FACTS['knowledge_integrity'] = {'fixture_only': True, 'real_review_performed': False,
                                       'review_binding_checked': True, 'content_truth_evaluated': False}

    def advisory_review_bypass():
        root = fixture / 'synthetic-surface-knowledge'
        material = {family: {'questions': ['SYNTHETIC question'], 'stop_conditions': ['SYNTHETIC stop'],
                             'action': 'SYNTHETIC inspect', 'why': 'SYNTHETIC reason', 'hint': 'SYNTHETIC hint'}
                    for family in ('multipart_request', 'structured_request', 'parameterized_surface',
                                   'request_shape_hint', 'scanner_signal', 'unobserved_request')}
        entry, published, _ = synthetic_publication(root, 'surface-unknown-probes', {'surface_advisory': material})
        candidates = [{'url': 'https://advisory-fixture.invalid/path?key=value'}]
        baseline = build_surface_advisory(candidates, target='advisory-fixture.invalid', repo_root=root)
        check(baseline['status'] == 'ready' and baseline['items'], 'Valid synthetic surface material is consumed')
        changed = published.replace(b'SYNTHETIC question', b'UNREVIEWED changed question')
        put(root / entry['file'], changed)
        check(capture_source(root, entry['id'])['status'] == 'review-unverified', 'Changed surface card is rejected by canonical review consumer')
        docs, health = acquire_knowledge(root)
        check(not docs, 'Changed surface card is excluded from canonical recall')
        advisory = build_surface_advisory(candidates, target='advisory-fixture.invalid', repo_root=root)
        check(advisory['status'] == 'unavailable' and not advisory['items'],
              'Advisory refuses unreviewed changed bytes')
        check(advisory['network_requests'] == 0,
              'Advisory bypass does not itself request network or queue action')
        unsigned = {key: value for key, value in entry.items() if key != 'review_receipt'}
        put(root / 'knowledge/capabilities.yaml', json.dumps({'capabilities': [unsigned], 'contracts': {}}))
        unreviewed = build_surface_advisory(candidates, target='advisory-fixture.invalid', repo_root=root)
        check(unreviewed['status'] == 'unavailable', 'Advisory rejects missing publication receipt')

    section('evidence-backed memory, conditional corrections, revocation', memory_corrections)
    section('retained versions and basis propagation', retained_versions)
    section('text recall, lifecycle and honest model degradation', text_recall)
    section('explicit relationship recall and stale-index boundaries', relations)
    section('distillation projection and correction-status fault probe', distill_projection)
    section('synthetic knowledge publication integrity', knowledge_integrity)
    section('surface advisory publication-review fault probe', advisory_review_bypass)


    def process_recovery():
        from tools.target_memory import load_goal_memory
        owner = new_store('process-a')
        cli('tools/target_memory.py', 'note', '--repo-root', runtime, '--target', owner.target,
            '--command-id', 'process-note', '--conditions', 'tenant=A; build=7',
            '跨进程保存 orbitneedle；结论仅限 build=7', '--json')
        cli('tools/target_memory.py', 'handoff', '--repo-root', runtime, '--target', owner.target,
            '--command-id', 'process-handoff', '--conditions', 'tenant=A; build=7',
            '--next-intent', '检查只读导出预览', '导出尚未检查', '--json')
        for i in range(25):
            remember(owner, f'noise-{i:04}')
        context = owner.memory_context(limit=5)
        check(context['current_handoff']['id'] == 'process-handoff', 'Handoff survives bounded recent window')
        check('process-handoff' not in [x['id'] for x in context['experiences']['items']], 'Handoff actually outside recent five')
        shown = cli('tools/target_memory.py', 'show', owner.target, '--repo-root', runtime, '--json').stdout
        check('检查只读导出预览' in shown, 'Fresh CLI restores explicit next intent')
        recalled = json.loads(cli('tools/experience_recall.py', 'query', '--repo-root', runtime,
                                 '--target', owner.target, '--query', 'orbitneedle', '--no-knowledge', '--json').stdout)
        check(recalled['recalled'][0]['source_ref'] == 'experience:process-note', 'Fresh process finds older memory by query')
        peer = new_store('process-b')
        remember(peer, 'process-note', conditions='tenant=B; private=secret-canary')
        check(not query_recall(runtime, target=peer.target, query='orbitneedle', include_knowledge=False)['recalled'], 'Same command ID in other target does not leak text')
        check('secret-canary' not in json.dumps(query_recall(runtime, target=owner.target, query='process-note', include_knowledge=False)), 'Other target conditions stay private')
        before = owner.binding()
        rejected(lambda: remember(owner, 'process-note'), StoreError, 'Same ID with changed content rejected', owner)
        remember(owner, 'cancel-handoff', conditions='tenant=A; build=7')
        link(owner, 'cancel-handoff-link', 'cancel-handoff', 'process-handoff', conditions='tenant=A; build=7')
        memory = load_goal_memory(runtime, owner.target, experience_limit=5)
        current = memory['target']['current_handoff'] if 'current_handoff' in memory.get('target', {}) else memory.get('current_handoff')
        FACTS['challenged_handoff'] = memory
        check('disputed' in json.dumps(memory, ensure_ascii=False), 'Recovery preserves challenged handoff status')
        cli('tools/resume.py', '--repo-root', runtime, '--memory-dir', runtime / 'hunt-memory', '--target', owner.target, '--json')
        absent = 'never-initialized.invalid'
        cli('tools/target_memory.py', 'show', absent, '--repo-root', runtime, '--json', expected=2)
        check(not (runtime / 'state' / absent / 'metadata.sqlite3').exists(), 'Read of missing target never initializes')

    def multilingual_recall():
        owner = new_store('multilingual')
        for identity, statement in [('zh', '匿名访问财务导出被拒绝'), ('en', 'Unauthenticated invoice export is denied')]:
            owner.remember(command_id=identity, kind='note', statement=statement, conditions='tenant=A; release=1',
                           reopen_when='', next_intent='', evidence=[], actor='fixture')
        queries = ['匿名访问财务导出被拒绝', '匿名', '未登录导出账单', 'Unauthenticated', 'unauthenticated invoice export', 'download bills without login']
        def samples():
            rows = {}
            for q in queries:
                result = query_recall(runtime, target=owner.target, query=q, include_knowledge=False)
                rows[q] = [{'id': x['source_ref'], 'channel': x['match']['channel']} for x in result['recalled']]
            return rows
        before = samples()
        build_text_index(runtime, owner.target, include_knowledge=False)
        after = samples()
        FACTS['multilingual'] = {'without_index': before, 'with_fts': after,
                                  'paraphrase_guarantee': False, 'semantic_requested': False}
        check(before[queries[0]] and after[queries[0]], 'Whole Chinese token matches with/without index')
        check(before['Unauthenticated'] and after['Unauthenticated'], 'English word matches with/without index')
        check(before['匿名'] and after['匿名'], 'Building FTS must not lose existing Chinese substring recall')

    def accumulated_recall():
        owner = new_store('accumulated')
        timings = []
        for i in range(1000):
            statement = 'deepneedle archived export boundary' if i == 0 else f'noise topic {i:05}'
            owner.remember(command_id=f'acc-{i:05}', kind='note', statement=statement,
                           conditions='tenant=A; release=1', reopen_when='', next_intent='', evidence=[], actor='fixture')
            if i in (199, 999):
                started = time.monotonic()
                result = query_recall(runtime, target=owner.target, query='deepneedle', include_knowledge=False)
                timings.append({'records': i+1, 'query_seconds': round(time.monotonic()-started, 4),
                                'hits': [x['source_ref'] for x in result['recalled']]})
                check(result['recalled'][0]['source_ref'] == 'experience:acc-00000', 'Oldest relevant item survives accumulation')
        started = time.monotonic()
        build_text_index(runtime, owner.target, include_knowledge=False)
        build_seconds = round(time.monotonic()-started, 4)
        started = time.monotonic()
        result = query_recall(runtime, target=owner.target, query='deepneedle', include_knowledge=False)
        indexed_seconds = round(time.monotonic()-started, 4)
        check(result['recalled'][0]['source_ref'] == 'experience:acc-00000', 'FTS finds oldest accumulated memory')
        ids, cursor = [], None
        while True:
            page = owner.experience_page(limit=200, cursor=cursor)
            ids.extend(x['id'] for x in page['items'])
            cursor = page['next_cursor']
            if not cursor:
                break
        check(len(ids) == len(set(ids)) == 1000, 'All accumulated records accessible without loss/duplicates')
        FACTS['accumulation'] = {'samples': timings, 'fts_build_seconds': build_seconds,
                                 'indexed_query_seconds': indexed_seconds, 'records': len(ids)}
        pointer = runtime / 'state' / owner.key / 'recall-index/text/CURRENT'
        previous = pointer.read_bytes()
        put(pointer, b'{broken')
        damaged = query_recall(runtime, target=owner.target, query='deepneedle', include_knowledge=False)
        check(damaged['recalled'] and damaged['recalled'][0]['match']['channel'] == 'fresh-source-lexical', 'Damaged index preserves fresh-source lookup')
        check(pointer.read_bytes() == b'{broken', 'Read does not silently repair damaged index')
        put(pointer, previous)
        refs, raw = evidence(owner, 'integrity-probe')
        remember(owner, 'integrity-experience', 'primitive', refs=refs)
        build_text_index(runtime, owner.target, include_knowledge=False)
        revision = owner.binding()['revision']
        put(raw, b'TAMPERED SYNTHETIC BYTES')
        stale = query_recall(runtime, target=owner.target, source_ref='experience:integrity-experience', include_knowledge=False)
        check(owner.binding()['revision'] == revision, 'External byte mutation leaves Store revision stable')
        check('needs_review' in json.dumps(stale), 'Unchanged revision cannot hide evidence byte damage')

    section('real process persistence and isolated recovery', process_recovery)
    section('multilingual indexed and fresh-source relevance', multilingual_recall)
    section('1000-record accumulation, damaged index and changed bytes', accumulated_recall)


    def summary_correction_warning():
        from tools.target_memory import load_goal_memory, format_current_handoff
        from tools.context_pack import _build_evidence_anchors
        owner = new_store('summary-correction')
        owner.remember(command_id='h-old', kind='handoff', statement='旧方向', conditions='tenant=A',
                       reopen_when='', next_intent='继续旧方向', evidence=[], actor='fixture')
        remember(owner, 'counter', conditions='tenant=A')
        link(owner, 'counter-link', 'counter', 'h-old', conditions='tenant=A')
        memory = load_goal_memory(runtime, owner.target)
        anchors = _build_evidence_anchors({}, memory, [], [], {})
        FACTS['summary_warning'] = {'handoff_state': memory['target']['current_handoff']['review_state'],
                                    'next_actions': memory['target']['next_actions'], 'anchors': anchors}
        check(memory['target']['current_handoff']['review_state'] == 'disputed', 'Handoff source challenged')
        check('disputed' in json.dumps(anchors), 'Summary anchors must preserve challenged next-intent warning')

    def index_update_partial():
        owner = new_store('partial-index')
        invalid = cli('tools/target_memory.py', 'note', '--repo-root', runtime, '--target', owner.target,
                      '--command-id', 'invalid-update', '--update-index', 'text', '--index-encoder',
                      fixture/'missing-encoder', '合成提交后索引失败', '--json', expected=2)
        response = json.loads(invalid.stdout)
        FACTS['index_partial'] = response
        saved = owner.experience('invalid-update')
        check(saved['statement'] == '合成提交后索引失败', 'Index failure keeps committed owner fact')
        check(response['partial'] is True and response['index_update']['status'] == 'partial', 'Index failure reports partial')
        check('index-build' in invalid.stdout, 'Index-only recovery command supplied')
        check(owner.experience_page()['total'] == 1, 'Partial does not duplicate owner experience')

    def distill_ledger_window():
        owner = new_store('ledger-window')
        for i in range(45):
            evidence(owner, f'obs-{i:02}')
        view = build_evidence_view(runtime, owner.target)
        lines = [x for x in view['view'].splitlines() if x.startswith('- ') and 'result=' in x]
        FACTS['distill_ledger'] = {'source_count': view['evidence_counts']['ledger'], 'visible_count': len(lines),
                                  'windows': view['windows'], 'view_head': view['view'][:800]}
        check(view['evidence_counts']['ledger'] == 45 and len(lines) == 40, '45-observation fixture exercises ledger truncation')
        check('ledger' in view['windows'] and view['windows']['ledger'].get('next_command'), 'Truncated ledger must expose usable continuation')

    section('corrected handoff summary warning', summary_correction_warning)
    section('save committed but explicit index update fails', index_update_partial)
    section('distillation ledger continuation beyond forty records', distill_ledger_window)


    def bootstrap_memory():
        from tools.autopilot_bootstrap import compact_autopilot_state
        from tools.resume_read import load_resume_summary
        from tools.resume import _checkpoint_followup
        from tools.target_memory import load_goal_memory
        from tools.context_pack import _build_evidence_anchors
        owner = new_store('bootstrap-memory')
        owner.remember(command_id='remembered-handoff',kind='handoff',statement='长正文'+('旧方向'*150),
                       conditions='tenant=A; release=r7',reopen_when='',next_intent='比较本租户与另一租户',evidence=[],actor='fixture')
        remember(owner, 'counter', conditions='tenant=A; release=r7')
        link(owner, 'counter-link', 'counter', 'remembered-handoff', conditions='tenant=A; release=r7')
        for i in range(25): remember(owner, f'boot-noise-{i:03}')
        summary = load_resume_summary(runtime/'hunt-memory',owner.target,repo_root=runtime)
        state = {'target_kind':'domain','resume_summary':summary,'next_action':'wait_recon',
                 'hard_gate':{'action':'wait_recon','reason':'active phase'}}
        before = snapshot(owner)
        compact = compact_autopilot_state(state)
        memory = compact['target_memory']
        check(memory['source_binding'] == owner.binding(), 'Bootstrap carries exact existing owner binding')
        check(memory['current_handoff']['review_state'] == 'disputed', 'Bootstrap preserves old-window handoff and correction')
        check(len(memory['recent_entries']) == 5 and memory['experience_window']['remaining'] == 22, 'Bootstrap carries existing bounded history and continuation')
        check(compact['next_action'] == 'wait_recon' and compact['wait'], 'Memory injection never overrides lock wait')
        check(before == snapshot(owner), 'Bootstrap compaction is read-only')
        check(compact_autopilot_state({**state, 'target_kind':'list'})['target_memory']=={}, 'List does not inject member memory')
        empty = new_store('bootstrap-empty')
        em = load_resume_summary(runtime/'hunt-memory',empty.target,repo_root=runtime)
        check(compact_autopilot_state({'target_kind':'domain','resume_summary':em})['target_memory']['current_handoff'] is None, 'Initialized empty memory stays empty')
        anchors = _build_evidence_anchors({},load_goal_memory(runtime,owner.target),[],[],{})
        checkpoint = {'context_pack':{'evidence_anchors':anchors},'decision':'handoff'}
        following = _checkpoint_followup(checkpoint)
        rendered = json.dumps(following,ensure_ascii=False)
        check('disputed' in rendered and 'counter-link' in rendered and '--id remembered-handoff' in rendered, 'Resume retains correction references and actionable expansion after long statement')
        # Crowded non-memory evidence must not evict the owner correction window.
        crowded = {'review_pool':[{}]*3, 'workflow_leads':[{'title':f'flow-{i}'} for i in range(3)]}
        local = {'browser':{'xhr_endpoints':[f'https://synthetic.invalid/{i}' for i in range(3)],
                            'params':[f'p{i}' for i in range(3)]}}
        goal = load_goal_memory(runtime,owner.target)
        handoff = goal['target']['next_actions'][0]
        goal['target']['active_leads'] = [{**handoff,'entry_id':f'lead-{i}'} for i in range(2)]
        goal['target']['dead_ends'] = [{**handoff,'entry_id':f'dead-{i}'} for i in range(2)]
        goal['target']['next_actions'] = [handoff, {**handoff,'entry_id':'other-intent'}]
        handoff['structured']['conditions'] = 'long conditional scope; ' * 150
        anchors = _build_evidence_anchors(crowded,goal,[],[],local)
        check(len(anchors)==12, 'Crowded anchor projection stays within twelve entries')
        checkpoint = {'context_pack':{'evidence_anchors':anchors},'decision':'handoff',
                      'recommended_executable_action':{'id':'action','evidence_ref':'queue evidence','evidence':'second queue evidence','result':'third queue evidence'}}
        following = _checkpoint_followup(checkpoint)
        recent = following['recent_evidence']
        check(len(recent)==6 and all('review_state=disputed' in value for value in recent), 'All six owner anchors survive crowded Context Pack and Resume budgets')
        chosen = next(value for value in recent if '--id remembered-handoff;' in value)
        check('context incomplete; expand before use' in chosen, 'Oversized correction context explicitly requires owner expansion')
        check(following['current_action']['evidence_ref']=='queue evidence', 'Current action reference remains available in its dedicated field')
        FACTS['bootstrap_memory'] = {'bytes':len(json.dumps(memory).encode()),'recent_count':len(memory['recent_entries'])}

    def partial_fts_union():
        owner = new_store('partial-fts-union')
        for identity,statement in [('en','Unauthenticated invoice download'),('zh','匿名访问财务导出被拒绝'),('both','Unauthenticated 匿名导出')]:
            owner.remember(command_id=identity,kind='note',statement=statement,conditions='synthetic scope',reopen_when='',next_intent='',evidence=[],actor='fixture')
        build_text_index(runtime,owner.target,include_knowledge=False)
        page = query_recall(runtime,target=owner.target,query='Unauthenticated 匿名',limit=1,include_knowledge=False)
        ids=[]
        first=page
        while True:
            ids.extend(x['source_ref'] for x in page['recalled'])
            cursor=page['pagination']['next_cursor']
            if not cursor: break
            page=query_recall(runtime,target=owner.target,query='Unauthenticated 匿名',limit=1,cursor=cursor,include_knowledge=False)
        check(set(ids)=={'experience:en','experience:zh','experience:both'} and len(ids)==3, 'Partial FTS hits union Chinese-only match without duplicate across pages')
        check(ids[-1]=='experience:zh', 'FTS ordering kept before supplemental lexical matches')
        check('fresh-source-lexical' in first['recalled'][0]['match']['channel'], 'Mixed ranking channel reports supplemental lexical source')
        remember(owner,'new-source')
        rejected(lambda: query_recall(runtime,target=owner.target,query='Unauthenticated 匿名',cursor=first['pagination']['next_cursor'],include_knowledge=False),ValueError,'Union cursor rejects source revision changes')
        check(not query_recall(runtime,target=owner.target,query='!!!',include_knowledge=False)['recalled'], 'Punctuation-only query preserves empty result')

    def operation_navigation():
        import shlex
        owner = new_store('operations-navigation')
        refs=[]
        for i in range(45): refs.append(evidence(owner,f'op-{i:02}'))
        view=build_evidence_view(runtime,owner.target)
        window=view['windows']['ledger']
        check(window['unit']=='observations' and window['total']==45 and window['remaining']==5, 'Preview count remains in observation units')
        argv=shlex.split(window['next_command'])
        page=json.loads(cli(argv[1],*argv[2:]).stdout)
        check(page['kind']=='operations' and page['order']=='id' and page['artifact_health']['status']=='not_checked', 'History starts with explicit operation metadata page')
        ids=[];first=page
        while True:
            ids.extend(x['id'] for x in page['items'])
            if not page['next_cursor']:break
            page=json.loads(cli('tools/target_store.py','operations','--repo-root',runtime,'--target',owner.target,'--limit','10','--cursor',page['next_cursor']).stdout)
        check(len(ids)==len(set(ids))==45, 'All operations are reachable using returned cursor')
        oid=refs[0][0][0]['operation_id']
        detail=json.loads(cli('tools/target_store.py','operations','--repo-root',runtime,'--target',owner.target,'--id',oid).stdout)
        check(detail['artifact_health']['integrity']=='valid' and len(detail['observations'])==1, 'ID expansion includes observation and current byte verification')
        before=owner.binding();put(refs[0][1],b'SYNTHETIC DAMAGED')
        bad=json.loads(cli('tools/target_store.py','operations','--repo-root',runtime,'--target',owner.target,'--id',oid).stdout)
        check(bad['artifact_health']['integrity']=='invalid' and bad['observations'], 'Damaged original stays inspectable with explicit invalid health')
        check(owner.binding()==before,'Read and health check never alter owner revision')
        remember(owner,'change')
        cli('tools/target_store.py','operations','--repo-root',runtime,'--target',owner.target,'--cursor',first['next_cursor'],expected=2)
        cli('tools/target_store.py','operations','--repo-root',runtime,'--target',owner.target,'--id','missing',expected=2)

    section('bootstrap bounded memory and correction-safe resume', bootstrap_memory)
    section('partial FTS and substring union pagination', partial_fts_union)
    section('real operation history navigation and damaged evidence', operation_navigation)

    result = {'commit': COMMIT, 'checks': CHECKS, 'seconds': round(time.monotonic() - START, 3),
              'sections': SECTIONS, 'issues': ISSUES, 'facts': FACTS,
              'isolation': {'source_files': len(selected), 'source': 'fixed commit archive',
                            'project_tests_read_or_run': False, 'real_target_data_read': False,
                            'real_knowledge_read_or_published': False, 'network_allowed': False,
                            'model_experiment_or_human_review': False,
                            'production_code_changed': True}}
    put(RESULT, json.dumps(result, ensure_ascii=False, indent=2) + '\n')
    print(json.dumps({'result': str(RESULT), 'checks': CHECKS, 'issues': len(ISSUES),
                      'failed_sections': [item['name'] for item in SECTIONS if item['status'] == 'failed']}, ensure_ascii=False))
    failed = any(item['status'] == 'failed' for item in SECTIONS)
    os.chdir(fixture.parent)  # Keep audit guard path resolution valid during recursive temporary cleanup.
sys.exit(1 if failed else 0)
