"""One isolated Claude session; retain visible output only, never thinking blocks."""
import hashlib,json,os,signal,subprocess,sys,time,uuid
from datetime import datetime,timezone
from pathlib import Path
ROOT=Path(__file__).resolve().parent
META=json.loads((ROOT/'run.json').read_text())

def main():
    os.umask(0o077)
    name=sys.argv[1]
    spec=json.loads((ROOT/'cases.json').read_text())[name]
    project=Path(spec.get('project',META['project']))
    session=ROOT/'sessions'/name
    session.mkdir()
    home=session/'home';runtime=home/'.claude';runtime.mkdir(parents=True)
    (runtime/'settings.json').write_text(json.dumps({'permissions':{'defaultMode':'acceptEdits'},'env':{'CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC':'1'}}))
    (runtime/'.claude.json').write_text(json.dumps({'hasCompletedOnboarding':True,'lastOnboardingVersion':'2.1.304','projects':{str(project):{'hasTrustDialogAccepted':True,'hasCompletedProjectOnboarding':True}}}))
    (session/'mcp.json').write_text('{"mcpServers":{}}')
    env={'HOME':str(home),'CLAUDE_CONFIG_DIR':str(runtime),'CCST_RUNTIME_ROOT':str(runtime),
         'XDG_CONFIG_HOME':str(session/'config'),'XDG_RUNTIME_DIR':str(session/'xdg'),
         'PATH':'/root/.local/bin:/usr/local/bin:/usr/bin:/bin','LANG':'C.UTF-8',
         'PYTHONDONTWRITEBYTECODE':'1','PYTHONNOUSERSITE':'1','CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC':'1',
         'DISABLE_ERROR_REPORTING':'1','DISABLE_TELEMETRY':'1',
         'GIT_CONFIG_COUNT':'1','GIT_CONFIG_KEY_0':'safe.directory','GIT_CONFIG_VALUE_0':str(project)}
    for key in ('ANTHROPIC_AUTH_TOKEN','ANTHROPIC_API_KEY','ANTHROPIC_BASE_URL','CLAUDE_CODE_DISABLE_EXPERIMENTAL_BETAS'):
        if os.environ.get(key):env[key]=os.environ[key]
    assert any(env.get(k) for k in ('ANTHROPIC_AUTH_TOKEN','ANTHROPIC_API_KEY'))
    for key in ('ANTHROPIC_MODEL','ANTHROPIC_DEFAULT_OPUS_MODEL','ANTHROPIC_DEFAULT_SONNET_MODEL','ANTHROPIC_DEFAULT_HAIKU_MODEL','ANTHROPIC_DEFAULT_FABLE_MODEL'):
        env[key]=META['model']
    sync=subprocess.run(['python3',str(project/'tools/runtime_doctor.py'),'--repo-root',str(project),'--runtime-root',str(runtime),'--sync','--prune','--json'],cwd=project,env=env,capture_output=True,text=True,timeout=30)
    (session/'sync.json').write_text(sync.stdout)
    if sync.returncode: raise RuntimeError('Private runtime sync failed: '+sync.stderr[-300:])
    args=['bwrap','--die-with-parent','--unshare-user','--uid','0','--gid','0','--unshare-pid','--unshare-ipc','--unshare-uts','--ro-bind','/usr','/usr','--symlink','usr/bin','/bin','--symlink','usr/sbin','/sbin','--symlink','usr/lib','/lib','--symlink','usr/lib64','/lib64','--proc','/proc','--dev','/dev','--tmpfs','/tmp','--tmpfs','/run']
    for path in ['/etc/resolv.conf','/etc/hosts','/etc/nsswitch.conf','/etc/passwd','/etc/group','/etc/ssl','/etc/alternatives','/etc/localtime']:
        if Path(path).exists():args+=['--ro-bind',path,path]
    args+=['--ro-bind',META['claude'],META['claude'],'--ro-bind',META['claude'],'/root/.local/bin/claude','--bind',str(project),str(project),'--bind',str(session),str(session)]
    for part in ('tools','commands','agents','skills','rules','knowledge','docs','templates','schemas','.git'):
        if (project/part).exists():args+=['--ro-bind',str(project/part),str(project/part)]
    for path in [*(project/'memory').rglob('*.py'),project/'CLAUDE.md',project/'config.json']:
        args+=['--ro-bind',str(path),str(path)]
    constraints=f'''这是 CCST 记忆连续性验收的隔离离线工作区，根目录 {project}，合成目标 memory-lab.invalid。\n任务严格限于本地材料的读取、分析与必要的目标内记忆写回；不发任何目标网络请求，不运行 recon/scanner/browser，不建 Finding，不发布报告，不修改产品源码或方法。模型服务网络是宿主通信，不属于目标操作。\n使用项目现有入口与契约，自行决定读取/恢复方式。旧会话和预期答案在隔离区外，不可见。不要查找宿主、密钥、个人配置或 /proc 环境；不要输出隐藏思考。\n在 6 分钟与 16 轮调用上限内完成。若无执行授权，给出待授权的具体下一步，不模拟执行。\n本次具体任务：{spec['task']}'''
    sid=str(uuid.uuid4())
    command=['timeout','--signal=TERM','--kill-after=10s','6m',*args,'--chdir',str(project),'--',META['claude'],'-p','--model',META['model'],'--tools','default','--allowedTools','Bash','Read','Write','Edit','Grep','Glob','Skill','--permission-mode','acceptEdits','--permission-prompts','none','--setting-sources','user','--settings',str(runtime/'settings.json'),'--strict-mcp-config','--mcp-config',str(session/'mcp.json'),'--no-chrome','--no-session-persistence','--session-id',sid,'--max-turns','16','--output-format','stream-json','--verbose','--append-system-prompt',constraints,spec['prompt']]
    if spec.get('compact_sequence'):
        command=command[:-1]+['--input-format','stream-json']
    (session/'constraints.txt').write_text(constraints)
    (session/'prompt.txt').write_text(spec['prompt'])
    receipt={'model_requested':META['model'],'session_id':sid,'name':name,'start':datetime.now(timezone.utc).isoformat(),'environment_names':sorted(env),'project':str(project)}
    started=time.monotonic()
    with (session/'stderr.private.txt').open('x') as err, (session/'visible.jsonl').open('x') as visible:
        p=subprocess.Popen(command,cwd=project,env=env,stdin=subprocess.PIPE if spec.get('compact_sequence') else subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=err,text=True,start_new_session=True)
        receipt['pid']=p.pid
        (session/'process.json').write_text(json.dumps(receipt,indent=2))
        print(json.dumps({'started':name,'pid':p.pid,'model':META['model']}),flush=True)
        stage=0
        compact_seen=False
        def send_prompt(prompt):
            p.stdin.write(json.dumps({'type':'user','message':{'role':'user','content':prompt}})+'\n');p.stdin.flush()
        if spec.get('compact_sequence'):send_prompt(spec['prompt'])
        try:
            for number,line in enumerate(p.stdout,1):
                try:event=json.loads(line)
                except ValueError:continue
                if event.get('type')=='system' and event.get('subtype')=='init':
                    host={k:event.get(k) for k in ('model','tools','mcp_servers','permissionMode','claude_code_version','session_id','skills','slash_commands')}
                    (session/'host.json').write_text(json.dumps(host,indent=2))
                if event.get('type')=='system' and event.get('subtype')=='compact_boundary':
                    compact_seen=True
                    (session/'compact-boundary.json').write_text(json.dumps({k:event.get(k) for k in ('type','subtype','compact_metadata')},ensure_ascii=False,indent=2))
                if event.get('type')=='result':
                    result={k:event.get(k) for k in ('subtype','is_error','duration_ms','duration_api_ms','num_turns','result','total_cost_usd','usage','modelUsage','permission_denials','errors')}
                    result_name='result.json' if stage==0 else ('compact-result.json' if stage==1 else 'recovery-result.json')
                    (session/result_name).write_text(json.dumps(result,ensure_ascii=False,indent=2))
                    if spec.get('compact_sequence'):
                        if stage==0 and not result.get('is_error'):
                            send_prompt('/compact')
                        elif stage==1 and compact_seen:
                            send_prompt('继续刚才的任务。只读确认当前进度、适用边界和下一步，不写文件或更新状态。')
                        else:p.stdin.close()
                        stage+=1
                blocks=(event.get('message') or {}).get('content',[])
                if not isinstance(blocks,list):continue
                for block in blocks:
                    if isinstance(block,dict) and block.get('type') in ('text','tool_use','tool_result'):
                        visible.write(json.dumps({'line':number,'stage':stage,'role':event.get('type'),**block},ensure_ascii=False)+'\n');visible.flush()
            p.wait()
        except BaseException:
            if p.poll() is None:
                os.killpg(p.pid,signal.SIGTERM)
                try:p.wait(timeout=10)
                except subprocess.TimeoutExpired:os.killpg(p.pid,signal.SIGKILL);p.wait()
            raise
        finally:
            receipt.update(exit_code=p.poll(),seconds=round(time.monotonic()-started,3),end=datetime.now(timezone.utc).isoformat())
            (session/'process.json').write_text(json.dumps(receipt,indent=2))
    print(json.dumps(receipt),flush=True)
    return p.returncode
if __name__=='__main__':raise SystemExit(main())
