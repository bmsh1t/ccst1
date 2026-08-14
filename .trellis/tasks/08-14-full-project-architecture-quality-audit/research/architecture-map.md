# 架构与数据流地图

日期：2026-08-14（初始盘点；最终报告会在验证后修订）

## 1. 入口层

| 入口 | 角色 | 证据 |
|---|---|---|
| `commands/autopilot.md` | 当前 Claude inline 主入口；调用 `autopilot_bootstrap.py`，读取 bounded state/context，驱动一个当前会话 controller | `commands/autopilot.md:10-18,36-54` |
| `tools/autopilot_bootstrap.py` | 只读启动契约：解析参数、比较 runtime、构造 scope/capability/state projection，并返回 `continue` 或 stop action | `tools/autopilot_bootstrap.py:12-30,37-81,660-696` |
| `commands/hunt.md` | 兼容/人工 hunting 入口，继续调用本地工具与历史产物；runtime drift 约束由命令契约声明 | `commands/hunt.md:1-20` |
| `agent.py` / `brain.py` / `tools/hunt.py --agent` | legacy local-agent 运行时；拥有独立 session/trace 语义，不应与 `/autopilot` session 混用 | `.trellis/spec/backend/directory-structure.md:31-35`; `docs/PRODUCT.md` Agent Session 章节 |

主入口的关键性质：runtime 比较是 blocking gate，capability profile 是 advisory；缺失工具不得伪装成
tested-clean，也不得触发安装。具体 lane 继承 Scope/Auth、Evidence、Checkpoint、Queue 和 finish 契约。

## 2. 端到端数据流

```text
command args / Scope / Auth
  -> bootstrap + compact target state
  -> recon / browser / source evidence
  -> surface index + projection + Context Pack / knowledge recall
  -> AI hypothesis + Action Queue claim
  -> deterministic validation runner
  -> raw evidence + Evidence Ledger event
  -> canonical Finding owner + provenance event
  -> Action Queue outcome / Checkpoint witness
  -> validation/report/memory projections
```

约定由 `commands/autopilot.md:43-96,169-201` 和 backend quality/contracts 规定：工具负责 schema、
replay、raw evidence 和持久化，AI 负责选择、假设、价值判断、升级/降级。

## 3. 状态与持久化 owner

| 状态 | owner/入口 | 关键约束 | 初始核验点 |
|---|---|---|---|
| Runtime session | `tools/runtime_state.py` | v2 只持久化不可派生事实；v1 兼容迁移；target-local lock 与临时文件 + `fsync` + replace | `tools/runtime_state.py:55-90,149-179` |
| Autopilot/control state | `tools/autopilot_state.py` | 从目标 artifact 派生 bounded projection；不能把 v2 派生字段写回 session | module docstring; `tools/autopilot_state.py:2396-2510` |
| Target Case State | `tools/target_case_state.py` | 目标身份、case lifecycle、恢复投影和原子状态写入 | `tools/target_case_state.py:730-830` |
| Action Queue | `tools/action_queue.py` | target-owned queue；claim/resolve identity、runner outcome、monotonic status；atomic JSON writer | `tools/action_queue.py:620-725,1010-1110` |
| Checkpoint witness | `tools/checkpoint.py` | target lock；terminal lane 不可冲突重写；atomic witness/round writes | `tools/checkpoint.py:70-130,420-518` |
| Evidence Ledger | `tools/evidence_ledger.py` | canonical target/event/operation identity；event replay/dedup；target lock | `tools/evidence_ledger.py:340-520` |
| Finding | `tools/finding_index.py` | canonical index owner；final lifecycle 必须有 owner provenance；canonical JSON 与 mutation event 分开写 | `tools/finding_index.py:440-520,549-660` |
| Derived surface/observation | `tools/surface_index.py`, `surface_projection.py`, `observation_inventory.py` | 可删除重建的索引/sidecar/cache，不得成为 finding/action/coverage owner | `.trellis/spec/backend/directory-structure.md:36-39` |

`finding_index` 明确声明 canonical JSON 与 provenance append 没有跨文件事务；故障注入、重放和
runtime-invalid row 的检测/修复路径是重点审核对象，而不是预先判定为缺陷。

## 4. 知识链

```text
knowledge/capabilities.yaml
  -> knowledge_registry.py (唯一 registry/frontmatter parser)
  -> context_pack.py (bounded routing/selected/deferred/recall reason)
  -> knowledge_candidates.py (target-memory candidate lifecycle)
  -> knowledge_lifecycle.py (正式卡 append-only governance replay)
  -> capability_governance.py / knowledge_audit.py (error/warning/advisory gates)
```

registry 负责 capability/card identity 与 source refs（`tools/knowledge_registry.py:19-22,50-137,140-193`）；
正式卡治理事件由 lifecycle replay，candidate 晋升独立；Context Pack 选卡和预算仍是运行时路由，
value review 只是 advisory 投影。重点核验 collision 词的稳定排序、selected/deferred 预算、重复加载、
reason 输出以及治理状态是否被错误当成路由状态。

## 5. 外部边界

- Scope/Auth：`scope_context.py`、`auth_session.py`、`target_paths.py`；核验 canonical target、
  off-target redirect、认证来源隔离、argv/log/artifact 泄露。
- Browser/JS/MCP：`browser_mcp_import.py`、`browser_surface.py`、`deep_js_packer.py`；核验
  证据归档、target ownership、缓存 freshness 和缺失工具的降级。
- Shell/scanner/integration：`tools/*.sh`、`spray_contract.py`、`external_arsenal.sh` 等；核验
  参数边界、退出码、超时、日志和副作用门禁。

## 6. 测试映射初稿

- Runtime/doctor：`tests/test_runtime_doctor.py`、`tests/test_claude_runtime_integration.py`。
- State/queue/checkpoint：`tests/test_runtime_state.py`、`test_target_memory.py`、`test_action_queue.py`、
  `test_checkpoint.py`、`test_target_case_state.py`。
- Ledger/Finding/validation：`test_evidence_ledger.py`、`test_finding_index.py`、
  `test_validation_runner.py`、`test_autopilot_hypothesis_replay.py`。
- Knowledge/context：`test_knowledge_registry.py`、`test_knowledge_lifecycle.py`、
  `test_knowledge_candidates.py`、`test_knowledge_governance.py`、`test_context_pack.py`。
- Scope/integration/browser：对应 `test_scope_context.py`、`test_auth_session.py`、
  `test_browser_mcp_import.py`、integration/staging tests。

这只是职责地图，不代表覆盖已足够；Phase D 会把 invariant、生产入口和真实故障路径逐项对照。
