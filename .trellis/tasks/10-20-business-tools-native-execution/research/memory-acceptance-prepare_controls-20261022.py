"""Freeze independent pre-session projects; no previous text/artifacts given to B."""
from pathlib import Path
import hashlib,json,os,shutil,subprocess,sys
ROOT=Path(__file__).resolve().parent
meta=json.loads((ROOT/'run.json').read_text());base=Path(meta['project'])
os.umask(0o077)
sys.dont_write_bytecode=True
sys.path[:0]=[str(base),str(base/'tools')]
from tools.target_store import TargetStore
base_owner=TargetStore(base,'memory-lab.invalid')
a_rows=base_owner.experience_page(limit=1000)['items']
assert len(a_rows)==6
(ROOT/'audit/a-saved-experiences.json').write_text(json.dumps(a_rows,ensure_ascii=False,indent=2))
cases=json.loads((ROOT/'cases.json').read_text())
receipts={}
for name in ('b_recall','b_empty','c_corrected','d_unrelated','e_readonly'):
    project=ROOT/name/'project'
    project.parent.mkdir()
    shutil.copytree(base,project,ignore=shutil.ignore_patterns('state','offline','hunt-memory','__pycache__'))
    (project/'offline').mkdir()
    if name!='b_empty':
        shutil.copytree(base/'state',project/'state')
    owner=TargetStore(project,'memory-lab.invalid')
    if name=='b_empty':owner.initialize()
    if name in ('b_recall','c_corrected'):
        for i in range(30):
            owner.remember(command_id=f'noise-{i:02}',kind='note',statement=f'无关本地演练噪音项目 {i}',conditions='other feature',reopen_when='',next_intent='',evidence=[],actor='acceptance-fixture')
    if name=='c_corrected':
        old=next(x for x in a_rows if x['kind']=='handoff')
        statement='当前部署 r8：账单导出的只读预览改用 representation=rows_json。旧 file_kind=ledger_csv 仅属于 r7；r8 已停用，不能用旧返回来判断权限。两租户受控对象仍是 Copper exp-c7-042 与 Brass exp-b7-109；身份仍未提供。以上是合成变更说明，不是真实执行证据。'
        owner.remember(command_id='r8-change',kind='note',statement=statement,conditions='tenant=Copper; release=r8',reopen_when='',next_intent='',evidence=[],actor='acceptance-fixture')
        owner.link_experience(command_id='r8-conditional-update',experience_id='r8-change',target_id=old['id'],relation='supersedes',conditions='tenant=Copper; release=r8',rationale='版本变化只在 r8 替代旧适用建议；保留 r7 历史',expected_revision=owner.binding()['revision'],actor='acceptance-fixture')
        owner.remember(command_id='r8-handoff',kind='handoff',statement=statement,conditions='tenant=Copper; release=r8',reopen_when='',next_intent='为 r8 准备两租户的 rows_json 只读预览比较；身份与执行授权不足，不执行请求。',evidence=[],actor='acceptance-fixture')
    cases[name]['project']=str(project)
    receipts[name]={'binding':owner.binding(),'experiences':len(owner.experience_page(limit=1000)['items']),
                    'files':{p.relative_to(project).as_posix():hashlib.sha256(p.read_bytes()).hexdigest() for p in project.rglob('*') if p.is_file() and '.git' not in p.parts and not p.name.endswith(('-wal','-shm'))},
                    'original_material_absent':not (project/'offline/export-notes.md').exists(),
                    'old_plan_absent':not (project/'offline/request-plan.md').exists()}
    assert receipts[name]['original_material_absent'] and receipts[name]['old_plan_absent']
(ROOT/'cases.json').write_text(json.dumps(cases,ensure_ascii=False,indent=2))
(ROOT/'audit/controls-before.json').write_text(json.dumps(receipts,ensure_ascii=False,indent=2))
print({n:{k:v for k,v in x.items() if k!='files'} for n,x in receipts.items()})
