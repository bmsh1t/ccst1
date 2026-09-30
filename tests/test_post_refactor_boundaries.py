"""Four owner-boundary regressions from the post-refactor review."""
from copy import deepcopy
import json
import pytest
from tools.runtime_doctor import sync_runtime
from tools.target_store import TargetStore
from tools.identity_contract import build_closure_cell
from tools.current_truth import current_cell_projection
from tools.autopilot_state import _surface_review_completion


def test_disabled_retirement_preserves_ownership_until_removal(tmp_path):
    repo, runtime = tmp_path/'repo', tmp_path/'runtime'
    (repo/'commands').mkdir(parents=True)
    source = repo/'commands/sample.md'
    source.write_text('managed')
    sync_runtime(repo, runtime)
    disabled = runtime/'commands/.disabled.sample.md'
    (runtime/'commands/sample.md').rename(disabled)
    source.unlink()
    result = sync_runtime(repo, runtime, prune=True)
    assert not disabled.exists() and not result['conflicts']
    assert str(disabled) in result['removed']


def test_missing_source_refuses_prune_without_touching_installed_bytes(tmp_path):
    repo, runtime = tmp_path/'repo', tmp_path/'runtime'
    (repo/'commands').mkdir(parents=True)
    (repo/'commands/sample.md').write_text('managed')
    sync_runtime(repo, runtime)
    receipt = (runtime/'.ccst-installed.json').read_bytes()
    with pytest.raises(ValueError, match='source directory missing'):
        sync_runtime(tmp_path/'missing', runtime, prune=True)
    assert (runtime/'commands/sample.md').read_text() == 'managed'
    assert (runtime/'.ccst-installed.json').read_bytes() == receipt


@pytest.mark.parametrize('replacement', ['invalid', 'empty'])
def test_new_registration_never_revives_previous_closure(tmp_path, replacement):
    store = TargetStore(tmp_path, 'fixture.test'); store.initialize()
    raw = tmp_path/'evidence/fixture.test/response'
    raw.parent.mkdir(parents=True); raw.write_text('response')
    key = build_closure_cell('https://fixture.test/items', 'SQLi', {'method':'GET','parameter':'q'}, technique='check').key
    obs = {'endpoint':key.endpoint, 'method':'GET', 'family':key.family,
           'observed_at':'2026-09-30T00:00:00Z', 'description':'Recorded response',
           'state_changing':False, 'result':'tested_clean',
           'artifacts':{'response':str(raw.relative_to(tmp_path))},
           'detail':{'evidence_role':'subject'}, 'identity_status':'complete',
           'identity_v2':key.to_dict(), 'identity_technique':'check', 'identity_dimensions':key.dimension_map}
    store.start_attempt(attempt_id='attempt', source='native', started_at=obs['observed_at'], actor='operator')
    first = store.record_execution(attempt_id='attempt', outcome='complete', actor='operator', observations=[obs])
    new = deepcopy(obs); new['identity_v2']['kind'] = 'invalid'; new['result'] = 'candidate'
    store.record_execution(attempt_id='attempt', outcome='complete' if replacement=='invalid' else 'unknown',
                           actor='operator', observations=[new] if replacement=='invalid' else [],
                           expected_operation=first['entity_id'])
    truth = current_cell_projection(tmp_path, 'fixture.test')
    assert truth['projection']['closed_cells_v2'] == []
    assert truth['records'][0]['superseded'] is True
    assert store.execution(first['entity_id'])['observations']
    if replacement == 'invalid':
        assert truth['health']['status'] == 'partial'


@pytest.mark.parametrize('changed', ['host', 'method', 'auth', 'shape', 'missing_method', 'exact'])
def test_surface_review_requires_same_asset_method_and_context(changed):
    url = 'https://a.fixture.test/items'
    candidate = {'url':url, 'method':'GET', 'vuln_class':'SQLi',
                 'auth_context':'owner', 'semantic_shape_id':'query:q', 'closure_blocking':True}
    metadata = {'endpoint':url, 'method':'GET', 'vuln_class':'SQLi',
                'auth_context':'owner', 'semantic_shape_id':'query:q'}
    if changed == 'host': candidate['url'] = 'https://b.fixture.test/items'
    if changed == 'method': metadata['method'] = 'POST'
    if changed == 'auth': metadata.pop('auth_context')
    if changed == 'shape': metadata.pop('semantic_shape_id')
    if changed == 'missing_method': candidate.pop('method')
    key = build_closure_cell(url, 'SQLi', {'method':'GET','parameter':'q'}, technique='check').key
    candidate['identity_v2'] = key.to_dict()
    metadata['identity_v2'] = key.to_dict()
    matrix = {'endpoints':[{'endpoint':'/items', 'cells':{'SQLi':{'status':'untested'}}}],
              'closure_projection':{'closed_cells_v2':[{'identity_v2':key.to_dict(), 'result':'tested_clean'}]}}
    result = _surface_review_completion({'surface_review_candidates':[candidate]}, matrix,
                                        {'actions':[{'status':'tested','metadata':metadata}]})
    assert (result['status'] == 'complete') is (changed == 'exact')
    if changed != 'exact': assert result['closure_blocking'] is True


def test_real_coverage_output_completes_only_exact_review(tmp_path):
    from tools.coverage_matrix import read_matrix
    store = TargetStore(tmp_path, 'fixture.test'); store.initialize()
    raw = tmp_path/'evidence/fixture.test/response'
    raw.parent.mkdir(parents=True); raw.write_text('raw response')
    key = build_closure_cell('https://fixture.test/items', 'SQLi', {'method':'GET','parameter':'q'}, technique='check').key
    store.start_attempt(attempt_id='a', source='native', started_at='2026-09-30T00:00:00Z', actor='operator')
    store.record_execution(attempt_id='a', outcome='complete', actor='operator', observations=[{
        'endpoint':key.endpoint, 'method':'GET', 'family':'SQLi', 'observed_at':'2026-09-30T00:00:00Z',
        'description':'Recorded boundary', 'state_changing':False, 'result':'tested_clean',
        'artifacts':{'response':str(raw.relative_to(tmp_path))}, 'detail':{'evidence_role':'subject'},
        'identity_status':'complete', 'identity_v2':key.to_dict(), 'identity_technique':'check',
        'identity_dimensions':key.dimension_map}])
    matrix = read_matrix('fixture.test', tmp_path)
    assert matrix['endpoints'][0]['endpoint'] == '/items'
    candidate = {'url':key.endpoint,'method':'GET','vuln_class':'SQLi','identity_v2':key.to_dict(),'closure_blocking':True}
    metadata = {'endpoint':key.endpoint,'method':'GET','vuln_class':'SQLi','identity_v2':key.to_dict()}
    state, queue = {'surface_review_candidates':[candidate]}, {'actions':[{'status':'tested','metadata':metadata}]}
    assert _surface_review_completion(state, matrix, queue)['status'] == 'complete'
    changed = build_closure_cell(key.endpoint, 'SQLi', {'method':'GET','parameter':'other'}, technique='check').key
    candidate['identity_v2'] = changed.to_dict()
    assert _surface_review_completion(state, matrix, queue)['status'] == 'unresolved'
    candidate['identity_v2'] = key.to_dict(); metadata.pop('identity_v2')
    assert _surface_review_completion(state, matrix, queue)['unresolved'][0]['reason'] == 'review_outcome_missing'


def test_required_source_missing_keeps_installed_release(tmp_path):
    repo, runtime = tmp_path/'repo', tmp_path/'runtime'
    (repo/'commands').mkdir(parents=True); (repo/'skills/core').mkdir(parents=True)
    manifest = {'schema_version':1, 'paths':[{'kind':'commands','relative_path':'autopilot.md'},
                                          {'kind':'skills','relative_path':'core/SKILL.md'}]}
    (repo/'commands/autopilot.md').write_text('<!-- AUTOPILOT_CRITICAL_RUNTIME_MANIFEST\n'+json.dumps(manifest)+'\nAUTOPILOT_CRITICAL_RUNTIME_MANIFEST -->')
    skill = repo/'skills/core/SKILL.md'; skill.write_text('required')
    sync_runtime(repo,runtime)
    receipt = (runtime/'.ccst-installed.json').read_bytes()
    skill.unlink()
    for kinds in (None, ['skills']):
        with pytest.raises(ValueError, match='required runtime source'):
            sync_runtime(repo,runtime,kinds=kinds,prune=True)
    assert (runtime/'skills/core/SKILL.md').read_text() == 'required'
    assert (runtime/'.ccst-installed.json').read_bytes() == receipt


def test_reenabled_command_upgrades_and_preserves_local_changes(tmp_path):
    repo,runtime=tmp_path/'repo',tmp_path/'runtime'
    (repo/'commands').mkdir(parents=True)
    source=repo/'commands/sample.md';source.write_text('v1')
    sync_runtime(repo,runtime)
    active,disabled=runtime/'commands/sample.md',runtime/'commands/.disabled.sample.md'
    active.rename(disabled);sync_runtime(repo,runtime,prune=True)
    disabled.rename(active);source.write_text('v2')
    assert not sync_runtime(repo,runtime,prune=True)['conflicts']
    assert active.read_text() == 'v2'
    assert 'commands/sample.md' in json.loads((runtime/'.ccst-installed.json').read_text())
    active.rename(disabled);sync_runtime(repo,runtime,prune=True)
    disabled.rename(active);active.write_text('local changes');source.write_text('v3')
    assert str(active) in sync_runtime(repo,runtime,prune=True)['conflicts']
    assert active.read_text() == 'local changes'
    assert 'commands/sample.md' in json.loads((runtime/'.ccst-installed.json').read_text())
