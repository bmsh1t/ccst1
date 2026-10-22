"""Summarize only retained visible records and compare isolated owner state."""
from pathlib import Path
import collections,hashlib,json,sqlite3,sys
ROOT=Path(__file__).resolve().parent
meta=json.loads((ROOT/'run.json').read_text());cases=json.loads((ROOT/'cases.json').read_text())
before=json.loads((ROOT/'audit/controls-before.json').read_text())
summary={}
for name,spec in cases.items():
    session=ROOT/'sessions'/name;project=Path(spec.get('project',meta['project']))
    result=json.loads((session/'result.json').read_text())
    receipt=json.loads((session/'process.json').read_text())
    host=json.loads((session/'host.json').read_text())
    rows=[json.loads(x) for x in (session/'visible.jsonl').read_text().splitlines()]
    assert all(x['type'] in ('text','tool_use','tool_result') for x in rows)
    tools=[x for x in rows if x['type']=='tool_use']
    texts='\n'.join(x['text'] for x in rows if x['type']=='text')
    plan=project/'offline/request-plan.md'
    output=texts+'\n'+(plan.read_text() if plan.exists() else '')
    with sqlite3.connect(f'file:{project}/state/memory-lab.invalid/metadata.sqlite3?mode=ro',uri=True) as db:
        binding=dict(zip(('store_id','revision'),db.execute('select store_id,revision from store').fetchone()))
        counts={t:db.execute('select count(*) from '+t).fetchone()[0] for t in ('experiences','observations','findings','reports')}
        integrity=db.execute('pragma integrity_check').fetchone()[0]
        fk=db.execute('pragma foreign_key_check').fetchall()
    source_changed=[n for n,h in meta['source_hashes'].items() if hashlib.sha256((project/n).read_bytes()).hexdigest()!=h]
    owner_calls=[{'line':x['line'],'name':x['name'],'input':x['input']} for x in tools if any(s in json.dumps(x['input']) for s in ('target_memory.py','experience_recall.py','resume.py','context_pack.py','remember.py'))]
    changed=[]
    if name in before:
        for n,h in before[name]['files'].items():
            p=project/n
            if not p.exists() or hashlib.sha256(p.read_bytes()).hexdigest()!=h:changed.append(n)
    summary[name]={'model':host['model'],'cli':host['claude_code_version'],'exit':receipt['exit_code'],'seconds':receipt['seconds'],
                   'subtype':result['subtype'],'turns':result['num_turns'],'cost_usd_cli':result['total_cost_usd'],
                   'tools':dict(collections.Counter(x['name'] for x in tools)),'owner_calls':owner_calls,
                   'plan_exists':plan.exists(),'binding_after':binding,'counts_after':counts,'changed_before_files':changed,
                   'source_changed':source_changed,'db_integrity':integrity,'fk_errors':fk,
                   'expected_tokens_in_output':{s:s in output for s in ('ledger_csv','rows_json','exp-c7-042','exp-b7-109','Copper','Brass','format=csv','匿名','401','LANTERN-4821')},
                   'unexpected_network_tool_calls':[x['name'] for x in tools if x['name'] in ('WebFetch','WebSearch')],
                   'stderr_bytes':(session/'stderr.private.txt').stat().st_size}
    if name in before:summary[name]['revision_before']=before[name]['binding']['revision']
    assert not source_changed and integrity=='ok' and not fk
(ROOT/'audit/session-summary.json').write_text(json.dumps(summary,ensure_ascii=False,indent=2))
print(json.dumps({n:{k:v for k,v in x.items() if k not in ('owner_calls','expected_tokens_in_output')} for n,x in summary.items()},ensure_ascii=False,indent=2))
print('total_cli_cost_usd',sum(x['cost_usd_cli'] for x in summary.values()))
