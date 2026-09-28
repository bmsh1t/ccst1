# 累计分支集成评审

本文为只读规划阶段快照。最终摘要后的用户 `go` 已批准文末的仅本地 main 快进方案；
以下“未批准/未执行”描述保留其审查时点含义，后续实际结果以 `../verification.md` 为准。

日期：2026-09-28。基线：`main=0b00619f3975fdff3074d7f98007b57c7b39dc5c`。
审查 tip：`857dc634828c5363842691dc58edacbdd81589c3`。
完整引用 SHA、merge-base 和路径清单以同目录 `refs.json` 为准。

## 1. 结论和范围

本地相关修复已形成同一条累计提交链，main 是其祖先。最小集成建议是**一次将本地 main
快进到固定 tip**，不是顺次合并所有同名任务分支，更不是重新 cherry-pick 已包含的修复。
这只是仓库关系和操作路径结论，不代表当前 HEAD 已通过一次新的完整发布验收。

本次针对状态归属、恢复/Closure、共享执行、Scope/报告、Surface、Scanner 和安装边界作定向
源码/证据检查；没有穷尽审计 109 文件，没有新确认的产品缺陷，没有运行产品测试。
未访问个人 runtime、真实目标、远端 CI 或实时远端引用。

## 2. 引用关系（R1 / AC1）

计数列统一为 `HEAD-only / ref-only`，对应 `git rev-list --left-right --count HEAD...REF`。

| 引用 | tip（短 SHA） | 计数 | 处理 |
|---|---|---:|---|
| main | 0b00619 | 25 / 0 | 建议集成目标，尚未获批 |
| fix/practical-audit-fixes | b0b4d30 | 23 / 0 | 已包含，无须另合 |
| fix/web2-stable-release | 7c05aa9 | 7 / 0 | 已包含，与下一引用同 tip |
| refactor/surface-store-binding-owner | 7c05aa9 | 7 / 0 | 重复指针，不是独立待合工作 |
| fix/closure-evidence-snapshot-consistency | 7c3556d | 5 / 0 | 已包含 |
| fix/scanner-summary-input-contract | 45fdf1e | 3 / 0 | 已包含 |
| fix/installer-runtime-file-selection | 857dc63 | 0 / 0 | 当前累计 tip |
| backup/legacy-agent-compat-before-inline-cleanup | 2894ad1 | 352 / 0 | 历史祖先，不做额外合并 |
| backup/pre-logical-split | b9281ac | 695 / 1 | 无共同祖先，明确排除 |
| codex-support | e50b343 | 666 / 1 | 存在引用独有提交，历史用途未批准纳入 |
| recovery/ccst1-intel | 031b122 | 493 / 4 | 同上 |
| ccst1-work/main | 99d06b1 | 685 / 4 | 同上，不按 main 名称猜测目标 |
| ccst1/main（缓存） | b078c26 | 43 / 0 | 本地 main 的跟踪上游；不是实时远端证据 |

关键里程碑依次为：

```text
0b00619 main
→ e3931ab / b0b4d30 实战修复
→ 7048517 / 2af38df Web2 发布基线
→ 63decaf / 2dcec17 / 6e318cd / d5695e7 / 4a71da9 功能修复
→ 00ee853 / b99a6de / b67febb Closure、Surface 契约
→ 3f79faa / f81bf4a / 31782e8 无效查询删除、CI、记录
→ 797eb5a / e2d2e58 共享执行、CI
→ 7c05aa9 Surface Store binding owner
→ 916524c / 7c3556d Closure 证据一致性及归档
→ e755065 / 45fdf1e Scanner 输入契约及归档
→ 8227cd2 / b514282 安装筛选及归档
→ 857dc63 父任务归档
```

`main...HEAD = 0 / 25`；`ccst1/main...main = 0 / 18`。
累计 diff：109 文件，4727 行增加、749 行删除。配置了 `ccst1`、`origin` 两个 remote，不能默认向 origin 推送。
首次引用采集对无共同祖先处理不足而失败；已修正为 `merge_base: null`，成功结果才写入 `refs.json`，未改仓库状态。

## 3. 关键契约（R2 / AC2）

权威边界来自 `docs/architecture-contract.md`：Store 是结构化事实 owner，raw 保留文件，
查询/派生投影不是第二套事实；Claude 保留判断权，机械工具不替代业务判断。

| 边界 | 源码定位 | 定向检查结论 / 已有回归 |
|---|---|---|
| 状态身份与 raw 归属 | `tools/target_paths.py:22`、`tools/target_store.py:641` | 目标 raw 归属共用低层 helper；Store binding 由 owner API 提供，不由 Surface 复制 SQL；对应 `test_practical_audit_fixes.py`、`test_surface_primary_owner.py` |
| Case 重放 | `tools/target_case_state.py:124`、`:129` | 命令身份含 revision，同材料不变不写，A→B→A 不被旧收据吞掉；对应 `test_target_case_state.py` |
| Closure 一致性 | `tools/coverage_matrix.py:1002`、`tools/autopilot_state.py:2559`、`tools/autopilot_round.py:51` | Coverage 唯一比较 owner；Closure 装配先拒绝混合输入；仅专用异常在原两次循环内重建，普通 Store/I/O 错误不宽泛重试 |
| 恢复与完整材料 | `tools/checkpoint.py`、`tools/current_truth.py`、`tools/autopilot_state.py` | 复用已取得的 Store handle，不缓存旧 truth 代替新证据校验；bounded/full 决策事实、pending Actions、lane 进度和展开引用由既有定向验收约束 |
| 执行与锁 | `tools/runtime_exec.py:433`、`tools/runtime_phase_exec.py:40`、`tools/hunt.py:877`、`:942` | 共享 argv 执行入口；进程组清理和资源锁留在现有 owner，不增加第二套执行框架；对应 runtime/phase/scanner registration 回归 |
| Surface 消费边界 | `tools/surface_projection.py:45`、`:454`、`tools/surface.py:986` | manual-review 文件选择共用 helper；Store binding 走 owner API；缺失/不兼容投影显式要求刷新，不回退成空事实 |
| Scope、报告、记忆 | `tools/auth_session.py:133`、`:514`、`tools/report_generator.py:728`、`tools/distill_target.py:157` | 保存的 Scope 进入请求和跳转；报告覆盖 eligible destinations，显式严重度、不可变 body 保留；健康信息与展开引用不以静默空值代替 |
| Scanner 输入 | `tools/autopilot_state_read.py:222`、`tools/finding_index.py:151`、`tools/autopilot_gate.py` | 计数由现有 reader 统一解释；坏编码可见，Scanner summary 不冒充 root claim；67 项归档验收覆盖真实 Store→Closure 链 |
| 安装筛选 | `install.sh:77`、`:97` | commands/agents 同等大小写 patch 排除；保留普通/近似名称、disabled 路由和 Doctor 显式 prune；31 项归档验收覆盖 rsync/cp |

## 4. 证据归属和限制

| 证据 | 记录位置 | 能证明什么 / 不能证明什么 |
|---|---|---|
| 实战修复 | 提交版 `journal-1.md:467–487`；本机 `09-26-practical-audit-fixes/research/implementation-results.md` | 历史全量 2319 passed / 1 failed，修正后定向 27 和 Scope 52 通过；不能写成该全量全绿 |
| Web2 发布基线 | 提交版 `journal-1.md:489–509`；本机 `09-27-web2-stable-release/research/acceptance-results.md:8–29` | 绑定 `7048517`，Linux/Python 3.13.5/Claude 2.1.278，2328 passed、零 skip；之后测试 fixture 隔离修正仅独立重测，不是当前 tip 全量结果 |
| 查询减负 / CI | 提交版 `journal-1.md:511–529` | 历史 100 passed in 18.85s，绑定相应批次；不是本轮测试 |
| Closure 一致性 | 已跟踪 `09-28-coverage-closure-fact-contract/verification.md` | 68 项定向回归，包含证据双向变化、有限重试、pending 恢复和幂等回放 |
| Scanner | 已跟踪 `09-28-scanner-summary-input-contract/verification.md` 和 `research/final-check.log` | 67 passed / 225 deselected；保留早先失败及根因修正记录，不用局部通过掩盖整链失败 |
| 安装 | 已跟踪 `09-28-installer-runtime-file-selection/verification.md` 和 `research/final-check.log` | 31 passed，无 skip，rsync/cp 均执行；临时 HOME/checkout，不是个人 runtime 部署 |

表中任务路径统一位于 `.trellis/tasks/archive/2026-09/`。journal 使用 `git show HEAD:...` 的
提交版，未把用户尚未提交的暂存日志当证据或改写它们。
前两项任务的完整附件按当时策略只保存在本机，`git ls-files` 不包含其目录；不是新发现的丢失文件。
较新的任务档案已受跟踪。保留这些不同证据层级，不加总通过数量冒充一次整体验收。
线上模型能力提升、当前外部 scanner 兼容性、实时 CI 和新 tip 的完整发布验收均未在本轮建立。

## 5. 风险分类与最低成本处置（R3 / AC3）

| 编号 / 分类 | 已确认事实与影响 | 建议 / 授权边界 |
|---|---|---|
| I1 操作前置决策 | task 创建时默认分支无法解析，`base_branch` 自动填为当前修复分支；它不是集成目标的用户确认 | 用户确认仅本地 main 路径后再实施；本轮不 `task.py start` |
| I2 工作区保护 | 两份暂存日志同时位于累计 diff 中；当前仅一个 worktree | 不原地 checkout/reset/stash；获批后用 Git 原生独立 worktree 操作 main，保留原工作区和 index |
| I3 兼容性告知 | `target_store.py:41` schema 10 未变；`surface_projection.py:29` schema 6→7，`:454–455` 对旧版返回 invalid/schema-mismatch | 部署/运行前按既有显式刷新入口重建派生投影；不暗中迁移 Store，不自动回退旧 cache；本轮不运行刷新 |
| I4 持续回归建议 | `.github/workflows/ci.yml:34–51` 的 PR core job 未直接列入 `test_autopilot_state_tool.py`、`test_scanner_pass.py`、`test_install_script.py`、`test_runtime_doctor.py` | 后续最小 CI 变更复用现有 job 和既有回归，不新建 pipeline；这是门禁覆盖建议，不是当前测试失败或产品阻断 |
| I5 证据可携带性 | 早期全量/升级附件仅本机可读；本次规划目录也被忽略 | 发布交接时另行决定最小证据归档范围，不擅自 force-add 旧目录或大日志 |
| I6 远端边界 | 缓存上游落后不证明实时远端无新提交 | 本地快进与远端集成拆开；远端操作前另行确认 remote/branch 并刷新引用，若分叉则重新规划，不强推 |

`full-suite` 仅在手工触发、定时或 push main 时运行（CI 配置 `:57–61`），不能以此声称 PR
已经直接运行新增边界测试。本轮未查询任何 CI run。没有因本次定向检查而确认的新产品阻断。

## 6. 推荐下一步

先审阅本任务规划与报告。若确认集成范围：在独立 worktree 中将本地 main 从固定基线一次
`--ff-only` 快进到审查 tip；核对 tip/tree 身份和原工作区保护，不创建 merge commit、不重放修复。
引用或未提交状态变化即停下重新比较；不自动调整基线。

本地快进不包含 fetch、push、标签、部署、个人 runtime 更新、CI 改动或分支删除。
如果暂不确认目标，就保留评审而不移动引用。CI 补门禁、证据发布和部署兼容验收按各自需求另行授权，
不为它们预先创建框架或拆分任务。当前状态保护结果见任务根目录 `verification.md`。
