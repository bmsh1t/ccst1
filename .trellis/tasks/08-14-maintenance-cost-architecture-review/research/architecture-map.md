# 当前架构与数据流地图

日期：2026-08-14

## 1. 架构结论

项目是面向 Claude CLI 的单仓 Python/Shell 插件，不是传统服务。正式控制器是当前 Claude session
内的 inline `/autopilot`；工具层负责确定性执行、证据和文件状态。整体采用“一个控制器、多个
事实 owner、若干只读/可重建投影”的架构，边界清楚，但 Checkpoint/Autopilot/Context Pack 的
组合逻辑集中，修改这些模块需要较多跨 owner 理解。

权威目录契约在 `.trellis/spec/backend/directory-structure.md:3-7,25-42`，状态 owner 清单在
`.trellis/spec/backend/database-guidelines.md:9-34`。

## 2. 控制面

| 层 | 当前职责 | 证据 |
|---|---|---|
| `commands/autopilot.md` | inline 唯一控制器；按 state-first loop 选择并 claim 一个有界 Action | `commands/autopilot.md:36-54,59-96` |
| `tools/autopilot_bootstrap.py` | 比较 runtime、构造 capability/scope/state compact projection；critical drift 或状态错误时停止 | `tools/autopilot_bootstrap.py:650-696` |
| `tools/autopilot_state.py` | 读取 owner 状态和 exact-hit Surface projection，生成有界控制投影；bootstrap 不迁移或重建大型状态 | `tools/autopilot_state.py:2396-2454` |
| `tools/context_pack.py` | 汇总 Surface、Coverage、Ledger、Finding 和知识候选，稳定选择/延期 Card | `tools/context_pack.py:20-55,2060-2154` |
| `tools/checkpoint.py` | 汇总 state/context/coverage/evidence/case，生成恢复 witness 和 Queue 候选 | `tools/checkpoint.py:3830-3952` |

`autopilot_state`、Context Pack 和 Checkpoint 都是投影/恢复层，不拥有 Finding、Ledger、Queue、
Coverage 或 Card 生命周期。这一方向与实现一致，没有发现新的第二控制器。

## 3. 端到端数据流

```text
command arguments / target / ScopeContext / AuthSession
  -> runtime comparison + compact bootstrap
  -> recon / browser / source artifacts
  -> Surface Index + Observation Inventory + bounded Surface Projection
  -> Context Pack + knowledge recall + Coverage gaps
  -> inline controller chooses and claims one Action Queue item
  -> deterministic validation runner writes raw evidence + durable summary
  -> Evidence Ledger -> Finding Index -> Action Queue reconciliation
  -> Checkpoint witness / report gate / target memory / next-session projection
```

Runner 使用稳定 material 生成 `operation_id`（`tools/validation_runner.py:258-283`），再由
`sync_runner_artifacts()` 按 Ledger、Finding、Queue 顺序调用各 owner；任一边界失败记录为
`partial`，summary witness 保持可重放（`tools/validation_runner.py:1178-1242`）。

## 4. 状态 owner

| 状态 | Owner | 持久化与恢复边界 |
|---|---|---|
| Runtime State | `tools/runtime_state.py` | 原子 writer `:149-179`；target-local lock `:305-314`；损坏状态 fail-fast |
| Action Queue | `tools/action_queue.py` | lock/load/save `:612-711`；claim/resolve 和 monotonic gate `:1548-1729` |
| Checkpoint witness | `tools/checkpoint.py` | 同目录临时文件、`fsync`、replace `:97-119`；witness lock `:125-139` |
| Case State | `tools/target_case_state.py` | mutation lock `:88-98`；validated public/private state write `:206-280` |
| Evidence Ledger | `tools/evidence_ledger.py` | target lock `:138-149`；append event dedupe 与 `fsync` `:328-539` |
| Finding Index | `tools/finding_index.py` | owner lock `:191-202`；canonical JSON 后追加 provenance，失败可检测/重放 `:494-520,549-622` |
| Target Memory | `tools/target_memory.py` | 原子 writer `:60-87`；mutation lock `:93-104` |
| Target profile | `memory/target_profile.py` | 缺失与损坏分离 `:97-112`；原子替换 `:115-142` |
| Request telemetry | `tools/request_guard.py` | schema fail-fast `:90-123`；原子替换 `:126-157` |
| Surface/Observation projections | `surface_index.py`, `surface_projection.py`, `observation_inventory.py` | 完整事实与 bounded 可重建投影分离；投影不能 author closure |

核心 canonical JSON 未发现绕过 owner 的直接覆盖。并行 worker 的 `findings.json` 只存在于隔离
scratch 目录，最终通过 `finding_index.upsert_findings()` 合并（`tools/parallel_workers.py:53-58`）。

## 5. 知识平面

```text
knowledge/capabilities.yaml
  -> knowledge_registry.py (registry/frontmatter owner)
  -> context_pack.py (runtime routing, selected/deferred/reason)
  -> knowledge_candidates.py (候选生命周期)
  -> knowledge_lifecycle.py (正式 Card append-only 生命周期)
  -> knowledge_audit.py / capability_governance.py (治理门禁)
```

`CARD_PATHS` 从 registry 加载（`tools/context_pack.py:592-618`），运行时信号仍由
`DISTILLED_TOKEN_TO_CARDS`、`TOKEN_TO_CARDS` 和 focus 规则明确路由（`:668-718,1521-1755`）。
这种分层避免 registry 直接控制执行，但新增路由信号仍需同时理解 registry、Context Pack 和召回
测试，是受控的中等维护面。

## 6. Legacy 边界

- inline 主路径与 Legacy session 明确分离：`README.md:195-214`、
  `tests/test_autopilot_inline_contract.py:255-279`。
- `agent.py` / `tools/hunt.py --agent` 只拥有显式 Legacy ReAct session 和 exact trace resume。
- `brain.py` 按已归档架构决策冻结为 Legacy 推理/分析库，不拥有独立正式循环或状态；不应再把它
  计入主架构协调器或推动重构。
- 当前 Legacy `HuntMemory` 仍直接读写 `agent_session.json`；该局部可靠性问题见维护报告。

## 7. 依赖方向热点

Checkpoint 直接消费多个 owner，并从 Action Queue 导入若干私有 projection helper
（`tools/checkpoint.py:29-59`）。Action Queue 在未传入 checkpoint 时又延迟导入
`build_checkpoint()`（`tools/action_queue.py:1404-1410`），形成一个显式兼容循环。

该循环有大量 ingest/checkpoint 行为测试，当前未复现错误；它增加的是变更协调成本，而不是状态
所有权混乱。除非后续修改正好触及这一边界，不值得为了“消除循环”拆模块或增加新 coordinator。
