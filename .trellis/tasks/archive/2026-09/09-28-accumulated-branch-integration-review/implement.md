# 评审步骤与已批准的本地集成计划

最终方案后的用户 `go` 已批准本文件最后一节的固定起点/终点与操作边界，不包含其他范围。

## 第一阶段只读交付（已完成）

1. 读取已保存引用清单，核对 main→HEAD 的累计关系、历史引用排除项和当前工作区保护基线。
2. 将已完成的关键 owner/恢复/执行/输入/安装检查整理到 `research/findings.md`，标明精确来源和证据限制。
3. 完成 PRD、设计和本文件；两个 JSONL 仅作为真实规范/研究索引，不派子代理，不运行 `task.py start`。
4. 做一次定向状态/文档检查，记录实际结果；通过后更新 PRD AC，不叠加产品全量或构建。
5. 呈现评审结论和下阶段边界，等待用户对最新提案的明确批准；不提交、不归档、不写全局 journal。

## 第一阶段验证（已执行）

以下为快进前的历史检查命令，不是快进后的预期 main/status；结果见 verification.md。
从仓库根目录执行；无网络、产品执行、索引写入或引用变更：

```bash
python3 - <<'PY'
import hashlib
import json
import subprocess
from pathlib import Path

task = Path('.trellis/tasks/09-28-accumulated-branch-integration-review')
baseline = Path('/tmp/fact-contract-baseline.vmDsm7')
refs = json.loads((task / 'research/refs.json').read_text())

def git(*args):
    return subprocess.check_output(['git', *args])

assert git('rev-parse', 'HEAD').decode().strip() == refs['head']
assert git('branch', '--show-current').decode().strip() == refs['branch']
assert git('rev-parse', 'main').decode().strip() == refs['local_main']
assert git('rev-parse', refs['main_upstream']).decode().strip() == refs['cached_upstream']
assert git('rev-list', '--left-right', '--count', 'main...HEAD').split() == [b'0', b'25']
assert not git('rev-list', '--merges', 'main..HEAD')
assert not git('diff', '--name-only')
assert git('status', '--porcelain=v1').decode().splitlines() == refs['working_changes']
patch = git('diff', '--cached', '--binary')
assert patch == (baseline / 'staged-before.patch').read_bytes()
assert hashlib.sha256(patch).hexdigest() == refs['staged_patch_sha256']
for row in (baseline / 'worktree.sha256').read_text().splitlines():
    digest, filename = row.split(maxsplit=1)
    assert hashlib.sha256(Path(filename).read_bytes()).hexdigest() == digest, filename
for name in ('implement.jsonl', 'check.jsonl'):
    entries = [json.loads(line) for line in (task / name).read_text().splitlines() if line.strip()]
    assert entries, name
    for entry in entries:
        assert Path(entry['file']).is_file() and entry['reason'].strip(), entry
for name in ('prd.md', 'design.md', 'implement.md', 'research/findings.md'):
    assert (task / name).read_text().strip(), name
assert json.loads((task / 'task.json').read_text())['status'] == 'planning'
subprocess.run(['git', 'diff', '--check'], check=True)
print('PASS: fixed refs, linear graph, worktree/index preservation, manifests, planning artifacts')
PY
```

人工复核文档没有把历史通过冒充本轮执行，没有遗漏 Surface cache 版本变化，没有把建议写成已执行操作。
本轮没有产品变更，产品测试不提供额外所需证据；状态检查不是行为测试、CI 结果或发布认证。

## 已批准的本地快进阶段

用户已在最终摘要后明确批准目标为**仅本地 main**及以下范围。更新授权记录后按 Trellis 审阅门进入执行；
若发现起点漂移或需要实质扩展范围，停止并重做规划审阅。

- [x] 重读起点 `0b00619f3975fdff3074d7f98007b57c7b39dc5c` 和终点
   `857dc634828c5363842691dc58edacbdd81589c3`，核对 refs、祖先关系及原暂存保护仍成立。
- [x] 新建一个隔离 worktree 检出本地 main；不切换当前工作区分支，不暂存或搬动日志。
- [x] 在隔离 worktree 中对上述固定终点执行一次 `git merge --ff-only`；拒绝则停止，不退而求其次重放提交。
- [x] 验证 main 等于固定终点、tree 完全一致、原分支/HEAD/工作区/index 不变；按实际结果记录操作。
- [x] 仅在隔离 worktree 无改动时移除它；若有异常保留现场。不创建 merge commit、修改产品或重跑全量。

Git checkout/merge 使用单次 `-c core.hooksPath=/dev/null -c submodule.recurse=false`，
避免外部 hook 或子模块副作用；不改变持久配置。操作命令、固定引用、tree 与保护断言记录于
`research/integration.log`；失败保留已创建的 worktree 并报告，不自动 reset 或强制清理。

任何阶段都不附带 fetch、push、分支删除、tag、部署、CI 补门禁或旧证据 force-add。
远端是否可快进必须在另行批准刷新后重新判断；不能从本次本地结论推导。
