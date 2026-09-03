# 当前项目架构审核报告

> **历史快照说明**：本文记录 2026-08-30 的审核结果，验证数字、runtime drift 和结论
> 仅适用于该时间点，不是当前发布基线。当前架构契约以
> [`docs/architecture-contract.md`](../docs/architecture-contract.md) 为准；当前验证状态以
> `.trellis/workspace/Codex/current-context-summary.md` 和实际质量门禁输出为准。

审核日期：2026-08-30（基于 2026-07-13 初始审核更新）
范围：以 Claude CLI `/autopilot` 为核心，关注功能、能力、架构、流程、2–8GB 个人机器
顺序使用和失败恢复；不把项目自身安全加固作为本轮主线。

## 结论

仓库实现已经达到**个人顺序使用下的首个实战稳定架构**：参数、runtime preflight、目标
身份、recon/surface/context、action/evidence/finding/report/checkpoint 已形成可测试闭环；此前
四个 P1 状态正确性问题、runtime orphan marker 恢复问题，以及本轮确认的 taxonomy 第二
事实源和 report 跨 owner 重放问题均已修复，没有未解决 P0/P1。

稳定成立的边界是：

- Claude CLI `/autopilot` 在当前 Claude 会话 inline 运行，由一个 controller 负责目标状态；
- specialist 默认关闭，最多一个非嵌套、范围受限的 evidence 子任务；
- 单目标顺序执行；list target 只做 recon/handoff，再选择一个域进入后续流程；
- scanner quick 只是 breadth sensor，AI 仍负责证据价值、下一步和停止判断；
- 2–8GB 机器不同时运行多套 browser、scanner 和 agent runtime。

2026-07-13 的本机快照曾由 `runtime_doctor.py --fail-on-drift` 检出 `distill.md`、`kb.md`
两项 command diff。2026-08-30 更新不读取或修改真实 `~/.claude`，因此不把该历史快照
继续陈述为当前 runtime 事实；实际使用前仍由 repository preflight 给出权威 drift 结果。

## 规模与入口

当前架构只有一套 controller 入口：

1. **Claude inline runtime**：`commands/autopilot.md` ->
   `tools/autopilot_bootstrap.py` -> 当前 Claude 会话控制循环。

原本独立的本地 agent controller 已由 `f3a1045` 退役；deterministic tools 仍由 inline
controller 复用，不再维护第二套 controller/session 语义。

## 分层架构

```text
Claude CLI /autopilot
  -> autopilot_args               参数、cadence、target/auth file 契约
  -> runtime_doctor               repo <-> ~/.claude drift blocking gate
  -> capability_profile           browser/recon/scanner advisory 快照
  -> autopilot_state              目标当前事实和下一步投影
       -> runtime_state           session v2 + phase flock + artifact 派生
       -> recon_adapter/surface   recon/browser/source/JS 观察面
       -> context_pack            Skill/knowledge/check 最小上下文
       -> case/action/coverage    可继续工作和闭环缺口
       -> evidence_ledger         replay/actor/object/variant 证据
       -> finding_index           canonical finding 生命周期
       -> report_generator        排他报告文件 + finding/queue 同步
       -> checkpoint              handoff、target-memory 提案、runtime witness
```

### 职责和失败行为

| 层 | 入口/所有者 | 主要输出 | 失败行为 |
|---|---|---|---|
| 参数 | `autopilot_args.py` | 稳定 JSON、target、cadence、flags | 无效参数先于 runtime/state 停止 |
| runtime 安装 | `runtime_doctor.py` | commands/agents/skills diff | drift 阻断 `/autopilot`，不自动同步 |
| 能力快照 | `capability_profile.py` | advisory available/fallback | 探测异常降级 unknown，不阻断 |
| runtime 状态 | `runtime_state.py` | v2 breadcrumb、phase liveness、derived view | 活跃 flock 才 wait；孤儿 marker 不阻塞 |
| recon | `hunt.py`、`recon_engine.sh`、`recon_adapter.py` | `recon/<target>/` artifacts | no-live-host 明确 blocker，不无限重跑 |
| 决策上下文 | `surface.py`、`context_pack.py` | evidence-rich review pool、1–2 cards | 缺 artifact 保留未知，不伪造 tested-clean |
| 动作 | `action_queue.py` | durable action 和终态 | final dedupe；单 controller 文件写入 |
| 证据 | `evidence_ledger.py`、validation runners | raw artifact + ledger row | runner 结果先进入 AI review，不直接报告 |
| finding | `finding_index.py` | canonical object schema | legacy list 迁移；mutation API 原子写入 |
| report | `report_generator.py` | 唯一 Markdown、`INDEX.json` | 碰撞重新分配；不同 finding 不覆盖 |
| 收敛 | `checkpoint.py`、`target_memory.py` | next action、handoff、memory proposal | 先复核再写 target memory；witness 原子写 |

## 端到端控制流

### 启动和 preflight

`autopilot_bootstrap.build_autopilot_bootstrap()` 固定执行顺序：

```text
arguments -> runtime compare -> advisory capabilities -> compact target state
```

arguments 和 runtime drift 是唯一 blocking gate。参数错误不会读取目标状态；runtime drift
时不会继续 capability/state；capability 探测失败只影响推荐路径。该顺序由
`tests/test_autopilot_bootstrap.py` 和 `tests/test_autopilot_startup_contract.py` 固定。

### Fresh / Existing

- Fresh：recon -> business model/crown jewels -> surface/context -> browser/source/JS ->
  scanner quick -> AI hypothesis -> minimal proof -> candidate validation -> checkpoint。
- Existing：先读取 compact state，再检查 checkpoint/action queue；历史 focus 只是上下文，
  没有可执行动作时不能强行恢复旧路线。
- `wait_recon`/`wait_scan` 只有 running marker 与对应 phase flock 同时成立时出现；进程被终止
  后 flock 自动释放，状态立即恢复可执行。

### Batch

list target 的磁盘身份由 `target_storage_key()` 生成：`stem + canonical-path SHA-256 digest`。
batch 只运行 recon/handoff，不把 list 当成聚合扫描目标；从 completed candidates 中选择一个
域后重新进入单目标状态。`recon_engine.sh` 调用同一 Python identity API，避免 Shell/Python
算法漂移。

### Evidence -> Finding -> Report

```text
browser/source/recon observation
  -> AI hypothesis / durable action
  -> deterministic replay + raw evidence
  -> evidence ledger / runner candidate
  -> AI review + /validate rubric
  -> finding_index canonical mutation
  -> report_generator exclusive create
  -> finding/report/action closure
```

scanner、coverage 和知识卡只提供 signal。Candidate 需要 baseline/variant、角色/对象或副作用
证据；Validated Finding 才能进入 report。report 是 phase closure asset，不应抢在仍存在的
实质 validation/surface/case-state 动作之前。

## 已修复的 P1

### 1. Finding schema 和多写者

- `tools/finding_index.py::_legacy_list_to_index()` 把历史 list 迁移为 canonical object。
- `_write_finding_payload()` 使用同目录临时文件、flush/fsync 和 replace。
- `upsert_finding(s)`/`update_finding_status()` 成为 target-level mutation boundary。
- `tests/test_finding_index.py` 覆盖迁移、semantic identity、生命周期保留和外部 runner 行。

结果：coverage、parallel join、validation runner 和 `/validate` 不再各自覆盖
`findings.json`，重建 scanner projection 不会丢失已验证/已报告状态。

### 2. 同类型报告覆盖

- `report_generator._occupied_report_ids()` 同时读取 finding、`INDEX.json` 和磁盘文件。
- `_next_report_id()` 分配下一个未占编号；`_create_or_reuse_report()` 使用排他 `x` 创建。
- 只有 Markdown 内 Finding ID 匹配时才允许 crash-recovery 复用。

结果：两个同类型 finding 获得不同 report ID，已有其他 finding 的 Markdown 不会被覆盖。

### 3. 同名 batch list 状态冲突

- `tools/target_paths.py::target_storage_key()` 对 list 使用 canonical absolute path digest。
- `migrate_legacy_list_storage()` 只有旧 session 能证明 owner 时才迁移 stem-only 目录。
- `recon_engine.sh` 复用 Python API；`tests/test_core_foundation_tools.py` 覆盖同 stem 隔离。

### 4. Runtime v2 压测误判

- `session.json` 只保留不可派生 breadcrumb；recon/finding/evidence readiness 动态投影。
- `checkpoint.write_checkpoint_witness()` 写入 `checkpoint_latest.json`，证明 context-pack 路由
  实际经过 checkpoint，而不把 v1 派生字段塞回 session。
- `tests/test_autopilot_run_contract.py` 和 localhost pressure test 使用真实 v2 writer/witness。

### 5. 被终止后台 phase 的恢复

- `runtime_phase_lock()` 为 recon/scan 提供内核自动释放的非阻塞 flock。
- marker 只表示启动意图；`runtime_phase_is_active()` 才是实际 liveness。
- checkpoint/action queue/autopilot state 统一按“marker + flock”判断 wait。

结果：活跃长任务仍被保护；宿主终止进程后留下的 `*_running` marker 不再阻塞两小时。

## 已验证优势

1. **AI 与工具分层正确**：工具输出 evidence、diff 和 advisory route，Claude 保留价值排序和
   链路推理。
2. **目标身份统一**：URL/domain/IP/CIDR/list 均由 `target_paths` 归一化，核心状态目录一致。
3. **Finding/report 主链有 owner**：最容易丢数据的 schema、mutation、ID 和写入碰撞已有
   单一边界和回归。
4. **Runtime preflight 可阻止新旧混用**：仓库命令变更未同步时明确停止，而不是使用混合
   Skills/commands。
5. **测试层次完整**：unit、cross-layer、runtime staging、slash-command contract 和
   localhost pressure 均存在，不只测试文档字符串。
6. **资源模型保守**：inline 单 controller、默认零 specialist、batch 逐域选择，适合
   2–8GB 个人机器。

## 保留的 P2 / 技术债务

### P2-1：部分目标状态仍是直接覆盖和空状态回落

`action_queue.py`、`target_memory.py` 等个人顺序路径仍直接 `write_text()`；部分 loader 在
JSON 损坏时回到空状态。单 controller 下可用，但这不是多进程事务能力，也可能把损坏误解
为“没有历史”。后续若要支持并发 controller，应在 owner writer/loader 统一增加原子写、
损坏状态和恢复契约。

### P2-2：多文件更新是最终一致，没有通用 reconcile

runner -> ledger -> finding -> queue 和 report -> finding -> queue 涉及多个文件。主路径已有
幂等键、排他创建和 best-effort sync，但没有通用 transaction/reconcile journal。个人顺序
运行风险可控；若增加并发或自动恢复 daemon，需要单独设计事件/重放边界。

### P2-3：协调模块较大且存在高耦合环

`hunt.py`、`checkpoint.py`、`context_pack.py`、`autopilot_state.py` 等协调器尺寸较大，新增
跨层字段时修改面较广。当前 owner API 和测试抑制了回归，因此不能仅按行数判 P1；后续应
按状态所有权逐步提取 projection/normalizer，不做大爆炸目录重构。

### P2-4：Shell/Python artifact 契约仍依赖跨层回归

batch key 已统一，但 recon Shell 仍生产大量 Python 消费的文件。新增/重命名 artifact 时
必须同步 `recon_adapter`、state/checkpoint 和 staging tests。保持单一 manifest/adapter
入口比重写 recon pipeline 更稳妥。

## 2–8GB 资源建议

- 2GB：单 target、`--quick` recon/scanner、一个 browser 会话、不开 specialist/parallel；
  每个 coherent lane checkpoint 后释放重型进程。
- 4GB：默认 `--normal`，browser + 一个 scanner 顺序运行；source/JS 分析按需加载。
- 8GB：可以使用 `--deep` 和一个 bounded specialist，但仍不应同时启动多域扫描、多个浏览器
  和多套额外 agent 进程。

`--normal` 控制 checkpoint cadence，不是能力开关；不传 cadence 时按解析器默认策略运行。
`--deep` 增加 evidence-first 深度，不放宽 red lines；`--quick` 降低 recon 成本，不跳过
browser/source/validation，也不代表完成。

## 不应改变的原则

- 保持 Claude inline 单 controller，除非另立并发状态架构任务。
- 保持 target memory、evidence ledger、finding lifecycle、knowledge candidate 分层。
- 保持 scanner/regex/score advisory，最终价值判断属于 AI。
- 保持 runtime drift blocking 且同步需要显式确认。
- 保持 list 只做 recon + 逐域选择，不聚合扫描/报告。
- 保持 raw evidence 与摘要/知识分离，报告必须来自 validated finding。

## 验证快照

- Python compile：通过。
- 知识质量门：`capabilities=54 documents=52 errors=0 warnings=0`。
- 候选生命周期严格审计：通过，当前候选数 0。
- pytest：分批全量 2255 passed（本轮文档收尾后重新执行）。
- `git diff --check`：通过（本轮文档收尾后重新执行）。
- runtime doctor：2 项 drift，均为当前仓库 `commands/distill.md`、`commands/kb.md` 与
  `~/.claude/commands/` 不同；agents/skills clean。

## 最终判断

**仓库：有条件稳定，可用于个人顺序实战。** 现有 P2 不阻断该模型，也不应为了“更漂亮”
而立即重构。

**真实 Claude runtime：当前需先同步 2 个命令文件，才能按最新 `/autopilot` 契约运行。**
preflight 正确阻断说明保护机制有效；同步属于环境变更，应在提交/确认后单独执行。
