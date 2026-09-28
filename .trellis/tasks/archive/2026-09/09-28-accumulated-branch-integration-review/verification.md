# 只读评审交付检查

日期：2026-09-28。以下只读阶段在 `planning` 下完成，当时未 `task.py start`、提交或归档。
后续用户批准的本地集成及记录收尾见文末；当前阶段以 task.json 和末节记录为准。

## 实际运行

执行了 `implement.md`「本轮验证」中完整的 Python 标准库检查，退出码 0：

```text
PASS: fixed refs, linear graph, worktree/index preservation, manifests, planning artifacts
```

该检查通过真实 Git 命令和 SHA-256 比较确认：

- HEAD 仍为 `857dc634828c5363842691dc58edacbdd81589c3`，分支仍为 `fix/installer-runtime-file-selection`。
- main 和缓存 `ccst1/main` 均与 `research/refs.json` 一致；`main...HEAD` 为 0/25，区间内无 merge commit。
- `git diff --name-only` 为空；`git status --porcelain=v1` 仍仅包含原两份暂存日志。
- `git diff --cached --binary` 与 `/tmp/fact-contract-baseline.vmDsm7/staged-before.patch` 字节相同，
  SHA-256 仍为 `8d9d6801cb745a626465a4fd20b4a43a20e4359fd6f9c1eff4177e3791a893ee`。
- 两份日志的工作区字节与既有 `worktree.sha256` 一致；没有用新基线替换旧基线。
- 两个 JSONL 均有真实条目、可解析且指向存在的规范/研究文件；PRD/design/implement/findings 均非空。
- task.json 的 status 仍为 planning，`git diff --check` 通过。

这里只运行状态/文档检查，没有产品测试、构建、真实目标请求或远端 CI 查询。
`git diff --check` 不覆盖被忽略的任务 Markdown；任务材料另经原文审阅，不冒充产品 diff 验收。

## 交付审阅

| 条件 | 结果 |
|---|---|
| AC1 | refs.json 精确记录全部引用；报告明确重复 tip、历史独有提交和无共同祖先，不重复合入 |
| AC2 | 报告关联关键 owner 源码与已有回归；2328/68/67/31 等均标为历史不同批次，不冒充本轮或当前完整发布验收 |
| AC3 | I1–I6 区分操作决策、兼容性、维护建议和证据限制；仅本地 main 快进仍须用户确认 |
| AC4 | 固定 refs、无产品改动、原暂存补丁/工作区字节均通过上述检查；本轮命令没有集成、网络或部署操作 |

PRD 已按 Goal/Facts/Requirements/Acceptance/Technical Notes/Out of Scope 收敛并完整重读。
设计、执行计划和两份上下文清单已补齐；没有创建子任务或子代理。
文档审阅保留 Store schema 不变与 Surface cache schema 6→7 的区别，未引入新状态 owner、
隐藏 fallback、泛化框架、产品补丁或未授权操作。未来快进与本轮只读动作明确分开。

本轮写入仅限本任务目录：更新 prd.md、implement.jsonl、check.jsonl，新增 design.md、implement.md、
research/findings.md 和本记录；前段研究已生成 research/refs.json。目录仍依仓库规则被忽略，未暂存。
不触碰全局 journal，不强制追踪旧证据，也没有把评审已完成等同于任务已提交/归档。

## 获批本地快进结果

用户在最终摘要“仅隔离 worktree 内快进本地 main，不 fetch/push/部署”后回复 `go`，
批准既定方案。更新本任务授权记录后执行 `task.py start`，状态由 planning 进入 in_progress。
启动时报告旧自动 `base_branch` 与当前分支相同；按本次明确确认的目标将任务元数据修正为
`base_branch=main`，没有新建/切换当前分支。未使用子代理。

实际隔离目录：`/tmp/ccst-main-integration-_t3to8st`。核心操作为：

```bash
git -c core.hooksPath=/dev/null -c submodule.recurse=false worktree add --quiet /tmp/ccst-main-integration-_t3to8st main
cd /tmp/ccst-main-integration-_t3to8st
git -c core.hooksPath=/dev/null -c submodule.recurse=false merge --ff-only --no-stat 857dc634828c5363842691dc58edacbdd81589c3
```

实际输出：`Updating 0b00619..857dc63`、`Fast-forward`，完整命令和断言结果保存在
`research/integration.log`，操作脚本退出码 0。

| AC5 断言 | 实际结果 |
|---|---|
| 起点固定且是终点祖先 | 操作前 main 为 `0b00619f3975fdff3074d7f98007b57c7b39dc5c`，merge-base --is-ancestor 退出 0 |
| 只快进到审查 tip | main 为 `857dc634828c5363842691dc58edacbdd81589c3`；`main...HEAD = 0 / 0`，未产生新 commit |
| tree 身份一致 | main 和固定 tip 的 tree 均为 `0e138dc014c806c36883fc11825cc1e0dfef0a06` |
| 原工作区不动 | HEAD/当前分支仍为原 tip 与 installer 分支；无 unstaged 产品差异；status 仍仅有原两份暂存日志 |
| 日志内容和暂存内容保持 | 操作前后工作区 SHA-256 与既有基线一致，暂存二进制 patch 与 staged-before.patch 字节相同 |
| 远端缓存不动 | `ccst1/main` 仍为 `b078c2634b7685d9aad5a0474be9c59b289ff20f`；无 fetch/push，实时远端仍未知 |
| 临时 worktree 清理 | 检查 tracked/untracked/ignored 均无新增改动后，普通 worktree remove 成功；目录不存在，worktree list 与操作前完全相同 |

Git hook/子模块递归仅用单次 `-c` 禁用，未写持久 Git 配置；没有 reset/stash/rebase/cherry-pick、
分支删除、产品修改、CI 改动、标签、部署或个人 runtime 操作。没有产品行为变化，因此未重复运行产品测试。
这是引用/tree/状态完整性验收，不替代远端同步或最新完整发布验收。

产品规范和模板没有契约变化，无须修改。记录只写本任务目录，不改全局 journal，不自动提交/归档；
本次本地集成已经完成，Trellis 状态保留 in_progress 等待独立的记录收尾授权。

## 记录提交与归档授权

用户在“提交并归档本任务记录，保持两份原暂存日志不动”之后回复 `go`，批准此次收尾。

提交范围仅为本任务的十个文件：prd.md、design.md、implement.md、implement.jsonl、check.jsonl、
task.json、verification.md、research/refs.json、research/findings.md、research/integration.log。
工作记录提交使用 `chore: record accumulated branch integration review`；随后执行
`task.py archive accumulated-branch-integration-review --no-commit`，修正两个 context manifest 的
任务路径，再以精确旧/新路径提交 `chore(task): archive accumulated-branch-integration-review`。

两个提交均使用精确路径和 `git commit --only`，不使用裸 commit；Git hook 单次禁用，不修改持久配置。
日志记录不调用 add_session.py，由本文件代替，避免覆盖 `.trellis/workspace/Codex/` 两份用户暂存记录。
integration.log 中两段 `git diff --cached --binary` 的补丁正文在发布前移除，只保留命令及原 SHA-256，
避免把用户未提交的内容间接复制进本任务提交；原始保护基线和两份日志本身不改动。

Spec-sync 结论：没有新产品 API、schema、状态 owner 或执行契约变化；分支关系和操作证据属于本任务记录，
不新增通用 spec/framework。归档路径、提交文件集和暂存保护做定向检查，不重跑产品测试。
main 保持 `857dc63`；新增提交仅是当前工作分支的任务记录，不自动再次快进 main，不 fetch/push/部署。


## 收尾结果

- 工作记录提交：`35b809d5e707afb659a5925d11a6adf7637d9db4`，实际提交文件集精确为上述十个任务文件。
- 已使用 `task.py archive ... --no-commit` 归档至 `.trellis/tasks/archive/2026-09/09-28-accumulated-branch-integration-review/`；task.json 为 completed，完成日期 2026-09-28。
- implement.jsonl/check.jsonl 的本任务引用已改为归档路径，并逐条验证可解析和文件存在；旧活动目录不再存在。
- 归档后复核 main 仍为 `857dc63`，原日志工作区 SHA-256 及暂存二进制补丁仍与既有基线一致。
- 本记录随精确旧/新任务路径的归档提交保存；其 commit 身份由本文件的 Git 历史给出，不写入自身 SHA。
- AC1–AC6 完成；没有追加产品变更、产品测试或全局 journal 写入。其他任务保持原状，CI 补门禁尚未开始。
