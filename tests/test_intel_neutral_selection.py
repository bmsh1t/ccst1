from copy import deepcopy
from tools.intel_engine import prioritize_advisories
from tools.intel_artifact import _query_sort_key


def test_intel_preserves_facts_without_weighted_ranking():
    low = {'id':'A', 'severity':'LOW', 'applicability':'affected', 'component':{'name':'pkg','version':'1'},
           'kev':True, 'epss':0.95, 'source_refs':[{'source':'osv','id':'A'}], 'score_hint':999}
    high = {**deepcopy(low), 'id':'Z', 'severity':'HIGH', 'score_hint':-999}
    before = deepcopy([high, low])
    view = prioritize_advisories([high, low], {})
    assert [row['id'] for row in view['advisories']] == ['A','Z']
    assert [row['id'] for row in view['high']] == ['Z']
    for row in view['advisories']:
        assert 'score_hint' not in row and 'score_reasons' not in row
        assert row['kev'] and row['epss'] == 0.95 and row['source_refs']
    assert [high, low] == before
    assert _query_sort_key(low) == _query_sort_key({**low, 'score_hint':-1000})
