# 实施进展：原生优先目标架构重构

> 本文件是 implement.md 各阶段结果的落盘载体。只记录已由工作区代码/测试证明的事实，
> 不把 checkbox 当完成证据。基线：`main@9cdf822` + 当前工作区改动（未提交）。
> 最新接续见 §8；§0–§7 是历史记录，其阶段勾选/计数不代表当前 B0–B6 已完成。

## 0. 基线事实

- 代码基线：`main@9cdf822 fix: close request-diff audit findings`。
- 工作区 16 个改动路径（10 tracked + 6 untracked），全部属于本任务；无对应 commit。
- 全量测试基线：`2059 passed`（本轮修复回归后；修复前为 `2057 passed, 1 failed`）。
- 数据根：`state/`（旧队列/Case）、`findings/`（Finding index）、`memory/evidence/`（Ledger）、
  `memory/goals/`（目标记忆）、`knowledge/`（版本化知识）。目标真源：`state/<key>/metadata.sqlite3`。

## 1. 阶段 1：基线与目标契约

| 条目 | 状态 | 证据 |
|---|---|---|
| 刷新 HEAD/改动，保留 `tests/test_recon_candidates_asset_relation.py` | 完成 | 该文件未改、未暂存 |
| 按 design 制定字段/身份/状态/命令错误契约 | 完成 | `tools/target_store.py` `_SCHEMA`（15 表 + CHECK/UNIQUE/FK） |
| 明确五个核心边界 | 完成 | design.md §2 领域模型表 |
| 枚举旧生产者/消费者/导入入口/数据根 | 完成 | 见 §4 消费者表 |
| 固定隔离 fixture 基线 | 完成 | `tests/test_target_store.py`(330 行)、`test_target_migration.py` |
| 更新架构契约物理存储/owner/兼容约束 | 完成 | `docs/architecture-contract.md`(±289 行)、`.trellis/spec/backend/*` |

## 2. 阶段 2：领域事实与事务边界

`tools/target_store.py`（792 行）已实现：

- **schema/身份**：每目标单库、`schema_version`、`store_id`、`revision`、目标绑定校验、0600 文件权限、符号链接防护、legacy 存在时拒绝初始化。
- **唯一行动源**：`create_action` / `transition_action`（状态机 ready/claimed/blocked/completed/cancelled + claim_token/claimed_by CHECK）。
- **执行观察**：`start_attempt` → `record_execution`（attempt 与 operation 分离，新执行需新 attempt_id；`supersedes` 显式引用前序 operation）。
- **技术裁决**：`assess`（confirmed/refuted/inconclusive；confirmed 拒绝 partial/unknown/未核 redline 的状态改变证据）。
- **交付裁决**：`decide_delivery`（eligible 需 confirmed；与 assess 分离，`stale` 标记）。
- **条件化经验**：`remember`（primitive/negative/hypothesis/handoff，negative/primitive 必须引用观察）。
- **事务一致性**：`_command` 把领域变更 + `revision` + `audit` 放同一事务；`command_id` 幂等（同内容 replay，异内容 ConflictError）。
- **只读查询**：`page`（稳定 ID 序 + revision 绑定游标 + 真实余量）、`execution`、`experience`、`finding`、`verify_operation`、`backup`。查询 `PRAGMA query_only=ON`，零领域 mutation。

测试：`tests/test_target_store.py` 330 行全通过。

## 3. 阶段 3：消费者重建（进行中）

### 已完成

- 新建 `tools/evidence_identity.py`（197 行）：开放 family（`normalize_family` 保留合法未知值）+ canonical Coverage 映射（`coverage_family`/`normalize_vuln_class`）分离。
- **消除 Ledger→Coverage normalizer 依赖**（design §5）：`evidence_ledger` 改接 `normalize_family`；`coverage_matrix`/`closure_resolver` 改从 `evidence_identity` 导入。`closure_resolver` 删除本地 enum/alias 副本（-165 行）。
- 新增测试 `test_record_evidence_accepts_unknown_family_without_closing_canonical_coverage`：未知 family 可登记且不误关 canonical coverage。

### 未完成

- `TargetStore` 目前**只被 `target_migration.py` 引用**；无 CLI/Surface/Context Pack/Resume/Report/Checkpoint 消费者接新 API。
- 真源未切换：20 个模块仍读写旧 owner 文件（见 §4）。
- `coverage_matrix` 仍持有 Coverage 派生逻辑，尚未合并进统一只读查询。

### 本轮新增：统一只读查询视图（阶段 3 第 1 项）

`tools/target_store.py` 新增 `context` / `candidates` / `failures` / `primitives` 四个快照一致查询视图，
并抽出 `_binding` / `_cursor_after` / `_cursor_next` / `_slice` / `_experience_page` 消除重复游标逻辑。

- 单快照：一次连接内完成多表查询；`revision` 与 `store_id` 随结果返回。
- 零 mutation：`PRAGMA query_only=ON`，查询后 `revision` 不变。
- 余量/展开：复用 revision 绑定游标；游标过期返回 `ConflictError`，不静默重置。
- 无 ROI 排序：仅稳定 ID 序；存储经验不自动生成 action。
- 测试：`test_read_only_views_answer_facts_on_one_snapshot_without_side_effects`、
  `test_candidates_report_current_posture_without_ranking`。全量 `2061 passed`。

### 本轮新增：终态词汇单一来源（阶段 3 第 2 项，部分）

design §4「Coverage/Closure 共用一次语义定义」与 §5「消除 Ledger→Coverage normalizer 依赖」的落点：

- `evidence_identity.py` 新增 `LEDGER_RESULTS` / `COVERING_RESULTS` / `CLOSED_LEDGER_RESULTS` / `CLOSED_MATRIX_STATUSES`。
- `evidence_ledger.py`：删除本地 `RESULTS` 字面量与 `COVERING_RESULTS`/`CLOSED_CELL_RESULTS` 重复集合，改为导入共享定义（`RESULTS = LEDGER_RESULTS`，`CLOSED_CELL_RESULTS = set(CLOSED_LEDGER_RESULTS)`）。
- `closure_resolver.py`：删除本地 `CLOSED_LEDGER_RESULTS`/`CLOSED_MATRIX_STATUSES` 重复定义，改为导入。
- 边界测试 `test_terminal_vocabulary_is_defined_once_for_ledger_and_closure`：值相等 + 源码级「不得重述集合字面量」。
- 全量 `2062 passed`。

**未完成（本项剩余）**：Surface/Context Pack/Resume/Report 尚未统一消费 `TargetStore` 查询结果；
`coverage_matrix` 仍持有 Coverage 派生与矩阵投影逻辑。

### 本轮新增：删除 Case 替代性价值排序（阶段 3 第 3 项，部分）

design §4「取消所有路径词、类别名、hint 数的价值替身」的落点：

- `tools/target_case_state.py`：删除 `HIGH_IMPACT_OBJECT_TYPES` 与 `_impact_weight`（对象类型 +30、路径词 order/invoice/admin/billing +20）。
- `_score_backlog_item` 移除 `impact` 与 `chain_potential = 10 × hint 数`；排序只剩**AI 显式 priority + 机械 readiness − 真实风险/阻塞成本**。
- `why_now` 文案从「priority, impact, chain potential, and risk cost」改为「explicit priority, mechanical readiness and risk cost」。
- 边界测试：`test_next_ranking_ignores_path_words_and_chain_hint_counts`（路径词/hint 不再提升排序）、
  `test_explicit_priority_still_orders_ready_items`（AI 显式 priority 仍有效）。
- 全量 `2064 passed`。

**未完成（本项剩余）**：Case backlog 的行动身份/执行状态尚未迁入唯一行动源（`TargetStore.actions`）；
当前仍是 Case 内排序，只是去掉了价值替身。行动源迁移属阶段 4。

### 本轮新增：单一闭合投影 + store 观测契约（阶段 3 第 1 项主体完成）

design §4「Coverage/Closure 共用一次语义定义」与 §5「消除多处身份/闭合推导」的落点：

- 新建 `tools/closure_projection.py`：`build_current_cell_projection` / `derive_identity_fields` /
  `identity_fact_conflicts` 从 `evidence_ledger` 原样迁出，成为唯一闭合语义定义；Ledger 文件侧条目与
  TargetStore 观测记录喂同一个函数（provenance 断言：`evidence_ledger.build_current_cell_projection.__module__`
  以 `closure_projection` 结尾；ledger 源码不得再出现 `_project_v2_cells`/`_project_legacy_cells`/`_identity_fact_conflicts`）。
- `derive_identity_fields` 只在记录自带 `identity_dimensions` 且**非空**时推导身份；空 dimensions 表示
  「未做身份声明」，记录保持 legacy 形态并可关闭 endpoint×family 单元（这是 store 复现 v1 闭合的前提）。
  投影内部复制记录，绝不改写调用方对象。
- `TargetStore` 观测契约扩展（`SCHEMA_VERSION = 2`）：`observations` 增加 `result`（共享终态词表，
  词表外的值拒绝）与 `identity_dimensions`（结构准入：≤16 字段、名 ≤64、值 ≤256、canonical JSON 排序；
  未知维度键与开放 family 不因分类而拒绝）。store 只存事实、不存 `identity_status`（源码级断言）。
- store 新增只读视图 `closure_records()`：按 `observed_at, operation_id, step` 稳定排序输出 canonical records，
  显式报告 `truncated`（不因小默认值静默截断）。
- `coverage_matrix` 删除 `_ROUTE_*` 正则与 endpoint 形态拷贝，改从 `evidence_identity` 导入
  `split_path_query`/`path_with_query`/`query_param_names`/`collapse_dynamic_path_segments`；
  准入策略（静态资源/公开元数据短路）仍留在 Coverage。
- 边界测试：`test_closure_projection_is_defined_once_and_fed_by_both_producers`（含 store 源码不得出现
  `identity_status`）、`test_endpoint_shape_helpers_are_defined_once_and_stay_policy_free`（行为等价 +
  源码不得重述定义）、store 侧 `test_closure_records_feed_the_one_shared_projection` /
  `test_closure_records_stay_honest_about_truncation`。全量 `2088 passed`。

**更正：真实数据里没有 v2 身份。** sandbox-10 的 126 条 ledger 记录中
`identity_status`/`identity_v2`/`identity_dimensions` 全为 0，`file_side_closed_v2 == 0`：真实闭合全部是
v1（endpoint×family）。因此 v2 身份/维度机制是**前瞻能力而非现行数据损失**；此前「14 个已闭合单元依赖
store 无法绑定的 provenance」的读法不成立（该差异来自 45 条被拒记录，见 §5）。

**未完成（本项剩余）**：`coverage_matrix` 仍持有矩阵派生与投影。

### 本轮新增：当前真源 seam + store 角色列（阶段 3 第 1 项收尾）

implement.md 第 29 行「Surface/Context Pack/Resume/Report 消费统一结果；Ledger 不再依赖 Coverage 投影代码」：

- 新建 `tools/current_truth.py::current_cell_projection(repo_root, target)`——唯一的「这个目标当前闭合了什么」读口。
  两个来源**互斥**：store 处于 `primary` 角色时只读 store，否则只读 legacy ledger，**绝不相并**
  （退役事实与现行事实都能授权同一单元即为静默说谎）。返回值
  `{source:{kind,status,path_label,store_id,revision,truncated,store_claim}, health:{status,source_kind,...}, records, projection}`：
  `records` 就是投影所读的那批 canonical 行，`path_label` 为仓库相对路径（不泄漏绝对路径）。
- `preview` 角色 store **永不作答**，但在 `source.store_claim` 中如实上报（它是迁移隔离产物，与活数据并存）；
  存在却读不出的 store（缺角色列/异 schema/权限/不可读）**抛错而不回退**——从目标已离开的来源给出看似合理的
  答案是无声谎言。
- store 角色写入 schema：`store` 单例行新增 `backend TEXT NOT NULL CHECK (backend IN ('preview','primary'))`，
  `SCHEMA_VERSION 2 → 3`（未发布 schema，模块常量外无持久引用）；`initialize()` 独占创建 → `primary`，
  `initialize(allow_legacy=True)`（隔离副本迁移）→ `preview`；`backend()` 在列缺失时
  `StoreError("target store claims no backend role: ...")`，**不猜角色**。
- 损伤规则上移到 seam（原先只在 Closure loader 里）：partial/unreadable/truncated 输入清空
  `closed_cells`/`closed_cells_v2`，写 `identity_v2_diagnostics.suppressed_closed_count`（保留原义：完整 v2 身份数）
  与新增 `suppressed_legacy_closed_count`（被清空的 endpoint×family 单元数），并用
  `identity_v2_shadow = {"status":"unavailable","reason": f"{source_kind}_{status}"}`
  （`ledger_partial` / `store_partial`）。**记录本身仍可读**：损伤只压制授权，不抹掉事实。
- 消费方收敛为一份结果：`surface.py`（`ledger_entries`/`ledger_summary`/新增 `evidence_source`，键名保留兼容既有读者）、
  `autopilot_state.py`（loader 改为 seam 读；`_coverage_terminal_evidence` 不再自行重投影，改为消费 loader 的统一投影，
  键 `ledger_entry_count` → `record_count`，已确认无外部消费者；closure 与 closure_state 均写入 `evidence_source`）、
  `autopilot_loop_guard.py`（seam 读 + `ledger_health_projection` 定义迁至 `current_truth` 并以
  `_ledger_health_projection` 复出，删除本地副本）。原因字符串改为 `f"{source_kind}_{status}"`，
  `source_kind` 缺省 `ledger`，故今日 ledger-only 行为逐字节不变，而 store 来源不会被误标。
- 有意保留的文件侧例外：`surface_projection.py::_semantic_evidence_ledger` 指纹的是 legacy ledger **文件**
  （Surface 输入清单条目），不是目标的闭合真源；store 在切换时才成为清单输入。已写进边界测试。
- 测试：`tests/test_current_truth.py`（8 项：primary 独占到同批遗留 ledger 行不得入内、preview 只上报不作答、
  三种不可读 store 抛错、坏 ledger 抑制与 `suppressed_legacy_closed_count`、truncated store 同类损伤、边界断言三个消费者
  不再自行读源/重投影且 `surface_projection` 仍为文件侧）；`tests/test_target_store.py` 新增角色测试
  （独占→primary、副本→preview、第三角色被 CHECK 拒绝且仍是 preview）。
  全量 `2097 passed`（基线 2088 + 新增 9）。
### 本轮新增：Context Pack/Checkpoint/Resume 消费同一真源（阶段 3 第 1 项收尾）

- 损伤规则（不可读证据不得授权任何闭合）从 seam 迁到**唯一闭合语义定义** `closure_projection.py::
  suppress_unauthorized_closures`；`current_truth` 与 `evidence_ledger.build_summary` 都调用它，
  不再各写一份。此前 ledger 聚合侧那份更弱（只清 `closed_cells`、只写 `suppressed_closed_count`，
  无 legacy 计数）——同一份坏输入会得到两份措辞不同的答案，现已逐字节一致（含 `ledger_partial` 原因）。
- `evidence_ledger.build_summary(_diagnostics=…)` → `build_summary(_truth=…)`：直接复用 seam 的
  `records` + `projection` + `health`，**不重读、不重投影**；没有快照时也走 seam（函数级 import 规避循环），
  因此即使直接调用者也拿不到第二份闭合答案。summary 新增 `evidence_source`（seam 的 source 块），
  `path`/`path_exists` 改由来源标签决定（store 时可指向 store），`ledger_diagnostics` 增加 `source_kind`。
- `context_pack.build_context_pack(ledger_diagnostics=…)` → `ledger_truth=…`，并把 truth 透传给 summary；
  pack 的 `source_summary` 新增 `evidence_source_kind`/`evidence_source_status`，如实转述 seam 决定的来源
  （store 为 primary 时即 store），不在 Pack 里再选一次来源。
- `checkpoint.py` 改为读一次 `current_cell_projection` 并把同一份 truth 传给 context pack 与自己的 summary；
  Resume 消费 checkpoint 的 `evidence_ledger`（经此继承），Report 侧闭合词汇仍走 `closure_resolver` 单一来源。
  原先「同一 ledger 一轮读 3 次」的快照优化改为「真源一轮读 1 次」。
- `surface_projection` 的投影 import 从 `evidence_ledger` 再导出改为直连 `closure_projection`（文件侧语义不变）；
  ledger 模块现在只依赖 `identity_fact_conflicts` 这一共享谓词，不再携带/转发任何闭合投影代码。
- 测试：`test_current_truth.py` 增 3 项（持有 truth 时 `load_entries_diagnostic` 若被调用即失败且 summary 的闭合单元
  与计数等于 seam 投影；无快照时经 seam 并记录调用；坏 ledger 下 summary 的抑制与 seam 逐字节相同）并扩展边界断言
  （`surface_projection` 直连单一投影、损伤规则只在一处定义）；`test_context_pack.py` 断言来源种类/状态；
  `test_closure_resolver.py` 的单一定义断言改为「ledger 不得携带或再导出投影代码」。全量 `2100 passed`。
- **本项剩余**：`validate.py:884`、`distill_target.py:45` 仍各自读 ledger（属 implement.md 后续行）；
  `target_migration.py:433` 是迁移读口（按设计保留）；`surface_projection` 的文件指纹在切换时才纳入 store。

## 4. 旧→目标映射与消费者枚举

| 旧 owner | 现状文件 | 目标承载 | 迁移映射 |
|---|---|---|---|
| `action_queue.json` | state/<key>/ | `actions` + `attempts` + `operations` | id→action_id；action/title→intent；metadata.endpoint→endpoint；metadata.family/vuln_class→family；priority 保留；**Case 独立 next 评分不迁移** |
| `case_state.json` | state/<key>/ | `actions`（执行状态）+ 身份/对象留上下文 | validation_backlog 行动身份并入 actions；actors/objects/sessions 保留为上下文，不另起生命周期 |
| `findings.json` | findings/<key>/ | `findings` + `assessments` + `delivery_decisions` | id→finding_id；claim→claim；**导入不自动生成 assessment**；无原始证据的 claim 隔离待复核 |
| `ledger.jsonl` | memory/evidence/<key>/ | `observations` + `artifacts` | event→observation；evidence_ref→artifact（ref+sha256+size）；result 语义映射，坏行隔离 |
| `memory/goals/*.json` | memory/goals/ | `experiences`(hypothesis/handoff) | 条件化事实；不自动排队 |

**写旧 owner 文件的模块（20 个，切换/退役目标）**：
`validation_runner`、`validate`、`target_paths`、`surface_projection`、`target_case_state`、`surface_index`、
`structured_findings`、`source_hunt`、`runtime_state`、`scanner_pass_writer`、`runner_witness`、
`repo_source_artifacts`、`resume`、`knowledge_eval_draft`、`finding_index`、`intel_engine`、
`coverage_matrix`、`evidence_ledger`、`target_store`、`target_migration`。

**导入消费者规模**：finding_index 27、action_queue 24、runtime_state 21、evidence_ledger 20、surface 20、
closure_resolver 16、coverage_matrix 14、autopilot_state 12、validation_runner 11、checkpoint 11、
target_case_state 8、context_pack 8。

## 5. 阶段 4/5：迁移、切换与退役

### 已完成：映射 IDs/关联/timestamps/未决工作/旧裁决/材料 hash（阶段 4 第 2 项 + 第 1 项覆盖）

`tools/target_migration.py`（444 行，隔离导入器 + dry-run 报告，不写活目标）落实 design §7.1/§7.2：

- **IDs**：action 用 `execution_key=<旧 id>`；finding 用 `finding_id=<旧 id>`；attempt 用
  `migrate:attempt:<_stable_id(...)>`（内容派生的稳定 id，同输入重放得到同 id）。旧 id 同时进报告。
- **关联（claim↔材料）**：仅当 endpoint+method+family 与某条 ledger 记录**精确相等**时才绑定
  （`record_execution(candidate=...)`，逐桶取首个未占用条目），不用文本相似度；绑定结果在
  `links[{finding_id, operation_id, step, event_id}]`。没绑上的 claim 不生成 finding。
- **timestamps**：ledger `ts` → `observation.observed_at`（UTC 归一化），attempt `started_at` 取同一
  时间；迁移不把旧时间改写成当前时间。
- **未决工作**：仅 `queued` → `ready` action；`validated/tested/reported/dead-end/n/a` 是终态裁决，
  写 `completed` 会伪造验证、写 `cancelled` 会伪造操作员决定，故整体隔离并在
  `legacy.action_verdicts` 保留原裁决文本。
- **旧裁决**：`legacy.finding_verdicts`（validation/report/claim status、confidence、severity、
  source_file）与 `legacy.observations[].result` 原样保留；迁移**不生成 assessment**
  （`finding()["assessment"] is None`），技术裁决仍归 AI。
- **材料 hash**：`evidence_ref` → artifact，登记 `ref`+`sha256`+`size`（对隔离副本内真实文件计算）；
  非空普通文件校验；绝对路径越出隔离副本、缺失或空文件一律隔离（`_escapes_root`/`_unbindable_reason`），
  不重解释、不伪造。
- **路径型 endpoint**：仅当目标自身记录里**只有一个** origin 时补全（`legacy.path_endpoint_origin`），
  多 origin 或空 → 隔离（不臆造 scheme/host）。

**失败类别覆盖（implement.md 第 38 行：有效/历史/损坏/半提交/冲突/秘密引用）**：

| 类别 | 迁移器行为 | 证据 |
|---|---|---|
| 有效 | 精确匹配导入，保留原 ID/时间/引用/hash | dry-run 11 findings / 81 observations / 81 artifacts |
| 历史 | 终态裁决隔离保留原文，不写成 completed/cancelled | `test_legacy_terminal_action_status_is_quarantined_not_promoted` |
| 损坏 JSON | queue/findings 解析失败 → 隔离条目（含错误与路径），不当作空队列继续 | `test_corrupt_queue_json_is_reported_not_read_as_an_empty_queue` |
| 损坏 JSONL | 逐行结构化隔离（line+reason）；**并清点被 trusted-prefix 规则截断的尾部行数**，不静默吞掉后续行 | `test_corrupt_jsonl_reports_the_row_and_accounts_for_the_unread_tail` |
| 半提交 | 双向清点：provenance 无材料（缺失/空文件，已隔离）；材料无 provenance（`legacy.unreferenced_material`，只读列举，不导入不删除） | `test_unreferenced_raw_material_is_listed_without_being_imported` |
| 目标冲突 | 行声明 target ≠ 请求 target → 该条隔离，不参与 origin 推断；queue 整文件冲突则 0 action 导入 | `test_cross_target_records_are_reported_and_imported_by_nobody` |
| 未知字段 | `legacy.unknown_fields{queue,findings,ledger}` 计数上报，不阻断导入；metadata 按其开放契约排除 | `test_unknown_fields_and_sensitive_metadata_are_reported_without_values` |
| 秘密引用 | `.private` 非 validation 子树 → 硬隔离（不进 store、不算 hash）；敏感 metadata 键名上报、值不复制；notes 内**高特异**凭据（Bearer≥20/JWT/PEM）隔离 | `test_private_secret_reference_is_quarantined_and_never_hashed`、`test_live_credential_in_free_text_is_quarantined_not_copied`、`test_secret_shaped_evidence_file_is_flagged_but_still_a_real_observation` |

凭据规则先用真实数据验证过误报：宽关键词（`bearer`/`cookie:` 等）在 126 条 notes 命中 3 条，
全部是描述性文案（"owner Bearer replay returns 200"），故最终只保留高特异模式（真实命中 0）；
文件名形态（`*token*`/`*.key` 等）只标记不隔离，避免为文件名丢掉真实 observation。

**真实数据 dry-run（隔离硬链接沙箱 `/root/mig-sandbox-10`，活目标只读，inode 校验未变）**：

| 项 | 结果 |
|---|---|
| imported | findings 11 / observations 81 / artifacts 81 / actions 0 |
| links | 11（每个 finding 绑定一条 observation） |
| observed_origins | `['http://127.0.0.1:3001']`（单一 origin，路径型 endpoint 可解析） |
| legacy.action_statuses | queued 4 / validated 15 / n/a 18 / dead-end 8 / tested 20 / reported 2（共 67） |
| legacy.ledger_results | tested_finding 70 / tested_clean 24 / lead 15 / candidate 14 / dead_end 2 / blocked_redline 1（共 126） |
| quarantined | 112：ledger 25 无 evidence 引用 + 19 绝对引用越出副本 + 1 缺失文件；queue 63 终态裁决 + 4 缺 endpoint/family |
| unknown_fields | 三类全空 —— 已知字段集与真实写入方字段完全吻合 |
| target_conflicts / sensitive_metadata / secret_material_refs | 0 / 0 / 0（真实数据无一命中） |
| unreferenced_material | 1144 个 raw 文件无 ledger provenance，其中 1079 个连所在目录都未被引用（含 `validation/aq0043-redirect-xss/.../diff.json` 这类"材料已发布、provenance 缺失"的真实半提交） |

上游 126 条 ledger = 81 observation + 45 隔离；67 条 queue = 0 action + 67 隔离，无静默丢弃，
也没有把不完整记录洗成已验证。有隔离项时 `report.status == "partial"`，即当前真实状态。
1144/1079 是无 provenance 的材料（不是被拒记录），只进报告不改变 status —— 它属于切换验收要看的
"未完成工作"事实。

测试：`tests/test_target_migration.py` 14 passed（本轮新增 8）；全量 `2077 passed`。

### 本轮新增：closure 事实迁移 carry 与真实数据 parity

迁移器此前只把「记录自报 complete 的 identity」带进 store，会漏事实。现在：

- `_carried_identity_dimensions`：complete 记录带 `identity_v2.dimensions`；被判 incomplete/conflict 的记录带
  **它自己的 `identity_dimensions` 原值**，由共享推导重新裁决同一批事实（不拿 actor/object_scope 别名补全，
  那属于洗白）。`_uncarryable_identity_reason`：声称了身份但维度不可恢复的记录**隔离报告**，不降格成普通
  观测——否则 store 会关闭 Ledger 未关闭的单元。
- `legacy.identity_carry` 改为在 `record_execution` 成功后计数（报告只描述 store 真正持有的事实）：
  `records_with_complete_identity` / `partial_identities_carried` / `uncarryable_identity_claims` /
  `results_carried` / `results_outside_shared_vocabulary`。真实数据：81 条观测，`results_carried = 81`。
- 真实数据 parity（sandbox-12 硬链接隔离副本，`/root/measure-parity2.py` 只读测量）：126 条 ledger 记录 →
  45 条命中报告中的拒收（25 无 evidence_ref、19 绝对引用逃出副本、1 材料不可读）→ 81 条导入；
  **文件侧闭合 35 个单元，未受损记录蕴含 21 个，store 恰好闭合这 21 个**（`store_only = []`、`missing = []`，
  v2 两侧都是 0）。
- 放开沙箱路径因素（切换时根目录就是活仓库根，19 条绝对引用可解析）后：**store 闭合同样的 35 个单元，
  不多不少**。25 条无 evidence_ref 的记录在任何情况下都拒收，其单元已被其他可导入记录覆盖。
- 回归测试：`test_plain_record_still_closes_its_endpoint_cell_after_migration`（v1 复现）、
  `test_partial_identity_is_carried_as_facts_and_stays_open`（不补全）、
  `test_identity_verdict_without_its_dimensions_is_quarantined`（不可载身份隔离）、
  `test_refused_record_leaves_a_reported_gap_not_a_silent_one`（缺口必须被报告）。

### 未完成

- 无切换、无退役、无双写禁止落地；`report.status` 有隔离项时为 `partial`。
- **切换前置未满足**：queue 侧 63 条终态裁决与 4 条缺 endpoint 的 queued 记录只能留在隔离报告里，
  在验收前不得写入唯一行动源。
- **迁移器能力覆盖已按 implement.md 第 38 行完成**（有效/历史/损坏/半提交/冲突/秘密引用，见上表）。
  尚未接线的仅是"谁消费这份报告"：目前只有 CLI dry-run 输出，还没有把报告纳入切换验收检查。
- 1144/1079 个无 provenance 的 raw 文件需要在切换验收时定性（旧 writer 只登记每 run 一个代表文件，
  或真实半提交），定性前不得据此删除或改写任何材料。
- 活目标数据完整性事故（见 §6）：`state/`、`findings/`、`recon/` 曾被外部清空，已从硬链接副本恢复
  `state/`、`findings/`、`evidence/`（sha256 抽查一致），`recon/` 无可用副本；已部署监视器归因。

### 本轮新增：Case 待办责任移除与旧 backlog 迁移 carry（阶段 3 第 3 项完成）

implement.md 第 30 行「将 Case 待办/评分责任移到唯一行动源并删除替代性价值排序」的落点：

- **Case 只剩上下文**：`target_case_state.py` 删除 `validation_backlog` 的整条生产/消费 API
  （`add_backlog`/`complete_backlog`/`next_action`/`recover_hypothesis`/`PRIORITY_SCORE`/
  `_score_backlog_item`/`_readiness`/`_matching_final_findings`，-696 行）；`add_hypothesis`
  不再接受 `next_action`（"下一步做什么"属于唯一行动源）。Case 不再归一化也不再校验旧
  `validation_backlog` 的形状——它不是 owner，形状由迁移搬运/隔离。
  投影 API（`project_hypothesis_metadata`/`HYPOTHESIS_METADATA_KEYS`/`_bounded_metadata_value`）
  随后也被删除：状态投影方（`_load_case_state_projection`）已只读上下文计数，投影器没有消费者，
  保留它只会是"Case 还有第二份可读子集"的假象；写入校验器 `_validate_hypothesis_metadata`
  保留（凭证值仍在写入前被拒）。
- **唯一行动源成为唯一路线**：`_pick_next_action`/loop guard/gate frontier 里的 Case 分支只剩
  未决假设（上下文义务，`item_id="open-hypothesis"`）；`case_state_canonical_conflict` 闭包理由删除，
  裁决冲突搬进迁移报告。旧 Case 行动类型（`case-state-validation`/`-backlog-create`/`-seed`）
  仅保留 `ACTION_DECISIONS` 路由键，用于**已经落在持久队列里的历史行**（迁移期薄适配，不产出新行）。
- **迁移 carry（§7.1 显式关联，歧义隔离）**：`tools/target_migration.py` 新增 `sources.paths["case_state"]`、
  `legacy.case_context`（actors/sessions/objects/hypotheses/open_hypotheses/backlog 形状）、
  `legacy.case_backlog`（原裁决：id/status/endpoint/family/runner/priority/evidence_ref）、
  `legacy.case_backlog_relations`、`legacy.case_backlog_conflicts`、`legacy.unknown_fields.case_state|case_backlog`。
  关联只认旧文件里写下的相等 id（action `id`/`source_id`/`metadata.backlog_id`，与 `validation_runner`/
  `action_queue` 同一张身份表）；仅 endpoint 相同的候选一律标 `requires_explicit_decision` 并隔离，
  家族未知不算匹配也不算拒绝（报 `family_match: unknown`）。文件不可读/非对象/声明他目标 → 隔离，
  不重解释为空上下文。
- **真实 dry-run（sandbox-16 硬链接隔离副本，活 `state/127.0.0.1:3002`）**：
  `case_context = {present, actors:2, sessions:2, objects:5, hypotheses:0, backlog:2}`；
  `val_001 → AQ-0018`（显式 `metadata.backlog_id`，`explicit-id-in-queue-record`）；
  `val_order_track → AQ-0050`（仅 endpoint 相同 + 家族未知 → `endpoint-candidate`,
  `requires_explicit_decision: true`，同时隔离）；迁移前后活文件 sha256 不变
  （`case_state.json f712552127ef5af1…`）。
- 测试：`tests/test_target_case_state.py` 40、`tests/test_checkpoint.py` 177、
  `tests/test_autopilot_state_tool.py` 221、`tests/test_autopilot_bootstrap.py` 40、
  `tests/test_target_migration.py` 27；全量 **2091 passed**。

**未完成（迁移期）**：真实目标切换、双写禁止、旧文件冻结归档仍未落地（阶段 4）；
`case-state-enrichment`（actor 矩阵缺口 → 上下文补齐工作）仍由 checkpoint 生产，它不是 backlog。

## 6. 本轮（回归修复）记录

- 问题：`tests/test_probe.py::test_bad_ledger_enum_rejected_before_request` 失败。
- 根因：R4 开放 family 后 `normalize_ledger_vuln_class` 保留未知值，测试仍断言未知 family 被拒（设计冲突，非代码 bug）。
- 修复：改为按目标行为——actor/variant/result 拼写错误与 family 结构非法（空/控制字符/>256）仍前置拒绝；未知合法 family 放行。新增 `test_unknown_but_valid_family_recorded_without_coverage`。
- 结果：`tests/test_probe.py` 22 passed；全量 `2059 passed`。

### 运行数据被外部清空（18:27–18:32）与恢复

- 事实：`state/`（110 个 target 目录）、`findings/`、`recon/`、`evidence/` 在 18:27:30–18:32:27
  之间被清空；`reports/`、`memory/` 未动。目录 mtime 显示是四次间隔数分钟的独立操作。
- 排除项（均有记录佐证）：本线程 pytest（受控实验：恢复后跑全量 `2069 passed`，文件计数不变）、
  `git status`、hook（`session-start.py`/`inject-*.py` 无删除逻辑）、`reset_target.sh`（无人调用；
  且它会连 `reports/`、`memory/evidence/` 一起删，与实际不符）、Codex 会话（rollout 内无删除命令、
  未引用该路径）、`ccst1` 会话（17:45 后无活动、无删除痕迹）、旧 claude 会话（空闲）。
  外部清空者尚未定位。
- 恢复：从 18:27:11 的硬链接副本 `/root/mig-sandbox-3` 恢复 `state/`、`findings/`、`evidence/`
  （`cp -a`，保留原 mtime；抽查 `action_queue.json`/`case_state.json`/`findings.json` sha256 与副本一致）。
  `recon/` 没有可用副本，未恢复。
- 副作用清理：该副本里含沙箱迁移产生的 `metadata.sqlite3`（+`-wal`/`-shm`），`cp -a` 会把它带进活
  仓库并让后续真实迁移因 “destination already exists” 失败；已核实四个沙箱的 store 均为 `links=1`
  的独立 inode、活仓库在清空前无 store，确认它是迁移产物而非用户数据，已删除。
- 归因监视：`/root/evidence-watch.py`（只读观察者）后台运行，`state/findings/evidence/recon/reports/memory`
  文件数一旦下降即把当时完整进程表写进 `/root/evidence-watch.log`。

## 7. 下一步（按 implement.md 顺序）

1. 阶段 3 剩余：Runner/native record-evidence 只适配统一观察登记（implement.md 第 31 行；
   Case 待办/评分责任移除已完成，见 §3「Case 待办责任移除与旧 backlog 迁移 carry」）。
   「当前真源」seam 已由 Surface/Closure/loop guard/Context Pack/Checkpoint（Resume 经 checkpoint 继承）
   统一消费，见 §3。
2. 阶段 4 剩余：所有命令/执行器/投影消费者接新 API（迁移期薄适配不重复逻辑）；在获准且目标无活跃
   写操作时切换；删除旧元数据写入、冻结原始历史档案；切换后回退采用真源导出/迁移或前向修复。
   （映射本身已完成，见 §5。）
3. 阶段 5：整体验收（领域正确性/事务恢复/只读完整性/迁移/效率/实战/维护性），再评估切换。
4. 数据完整性：监视 `/root/evidence-watch.log`，定位 18:27–18:32 清空 `state/`、`findings/`、`recon/`、
   `evidence/` 的外部进程后再决定是否需要冻结这些目录。

## 8. 2026-09-21 go 后接续：B0/B1 部分实现

用户以 `go` 确认本版规划。主线程实施与审核；本次恢复仅使用 `gpt-5.6-luna` 做只读状态核验，未将实现委托给子代理。未提交/推送、未修改安装 runtime，
未迁移或切换真实目标。`task.py start` 已绑定当前 Codex session，任务仍为 `in_progress`。

### B0 数据保护与证据边界

- 开始实施时保存了既有 dirty diff、565 个源码/文档指纹及待修改文件副本：
  `/tmp/ccst-native-implementation-20260921/`。规划备份另在 `/tmp/ccst-native-plan-20260921/`。
- `research/writer-inventory.md` 是 AST import 消费者清单，含读/写，**不是完整直接 writer 审计**；
  B0 的逐 mutation/旁路写入及接线/保留/退役结论仍待补。
- `research/baseline-20260921.json`：`/tmp` 合成 100 条行动，完整 ID 枚举一致；15 次样本，
  legacy JSON 中位约 0.183 ms、Store 约 0.870 ms。仅一个查询的小样本，未测 I/O/内存/端到端，
  不能称 SQLite 已提速，也不能代表新 schema v4 的性能验收。
- 历史事故仅据既有记录核对：state/findings/evidence 曾恢复，recon 未恢复，归因未闭环。
  本轮未读写真实目标数据、未操作监视器；不据旧硬链接副本宣称满足新隔离/切换要求。
- 结束前与备份指纹比较：原清单无文件消失，仅以下 5 个产品/测试路径变化：
  `tools/{target_store,current_truth,target_migration}.py`、`tests/{test_target_store,test_current_truth}.py`。
  另更新当前任务文档和事务规范。受保护文件 `tests/test_recon_candidates_asset_relation.py`
  保持未跟踪、未修改、未暂存；SHA-256：
  `b590266d9cc8b07ce59af5cb8e0c9636ea3b4fbc962e1998b66a18a562dfbb85`。

### B1 已实现的领域增量

- **后端准入基础**：`target_backend()` 共用角色/目标/版本校验。primary 必须匹配受限持久
  `legacy-frozen.json`；缺库、有标记未完成切换、坏标记/错 store/错目标/权限宽/symlink/FIFO
  均拒绝，不回退旧 Ledger。新 primary 初始化失败保留 fence。preview 默认拒绝领域写入，
  只有显式 `allow_preview=True` 的隔离导入者可写；迁移器已显式传入此参数。
- **独立主张**：`create_finding()` 在没有 observation/attempt 时保存未裁决主张；与
  `record_execution(candidate=...)` 共用身份与建档规则，后续证据绑定不改创建时间，不制造判断。
- **通用行动**：schema **3 → 4**。`kind=execution` 保留已有 HTTP endpoint/family 准入；
  明确 `kind=work` 才允许无 HTTP 身份，工作对象为 target/URL/目标 artifact/Finding/experience。
  Artifact 复用现有 hash/归属校验，实体关系用 FK；非执行工作不能创建 attempt，不增加 Case 待办。
- **显式完成引用**：`transition_action(..., completion=...)` 必须提供一种实际引用。
  执行型只能使用当前 claim 的完整、未被替代且文件完好的 operation；普通工作用发布的目标产物，
  或本 action/本 claimant/本次 claim 后的 `remember` receipt。创建/claim、别的行动/操作者、旧 claim
  的 receipt 都不是完成证据。`action_completions` 保存 claim/version/proof，与状态及 audit 同事务。
  `action(id)` 只读展开工作对象和历史完成引用；不是重新校验文件的授权接口。
- **审计身份一致**：共享 `_command` 拒绝 command_id/actor 周围空白，避免只规范化 audit、
  mutation 却持有原字符串，形成不可释放 claim 或断开的 receipt 引用。不是逐调用方补丁。
- **版本边界**：旧 schema 明确拒绝，不自动擦库/升级；没有改动任何真实数据库。

### 实际验证与审核

```bash
rtk proxy python3 -B -m pytest -q -p no:cacheprovider \
  tests/test_target_store.py tests/test_current_truth.py tests/test_target_migration.py
```

- 接续前遗留补丁：82 passed。通用行动首轮：96 passed、1 failed，失败是缺角色列 fixture
  硬编码 v3，被新增版本校验先拦截；改用 `SCHEMA_VERSION` 保持其原有角色缺失断言，随后 97 passed。
- 审计身份回归补齐后最终：**103 passed in 1.25s**。仅隔离 fixture，无网络请求，无全量测试。
- 已审查源码增量、创建/claim/登记/完成/查询调用链和受保护文件指纹；新字段没有重建 HTTP 观察或闭合状态。
- 新增文件相对备份的 `git diff --no-index --check` 无空白告警。全仓 `git diff --check` 仅报告
  既有 `tools/autopilot_loop_guard.py:488` EOF 空行；本轮未修改，不将它报告为通过。

### 尚未完成与下一步

**B0/B1 尚未退出，不进入 B2 生产接线，不称单可写后端已完成。**

1. B0 补真实 writer/旁路清单及可复现的更完整效率基线。
2. B1 补 Case actor/object/session 及关系、私密引用准入与脱敏，假设复用 experience；
   现有 `.private/case-state/<key>/sessions/` 与 Store 目前只接纳 `.private/validation/<key>/`
   是待显式衔接的边界，不能为省事整体开放 `.private/`。
3. B1 补报告产物及 assessment/delivery 关系和 receipt；当前 work receipt 仅接 `remember`，
   保存任意报告正文作为 work 产物不等于报告领域登记或外部提交。
4. B1 补 Queue 六项机械不变量（含 HTTP 请求身份/预算/引用）、目标共享/排他锁和所有旧 writer 准入。
   当前 fence 只守 Store 与已接入读取 seam，尚不能阻止未改造旧 writer；`allow_preview` 不是隔离沙箱。
5. 再依 B2–B6 完成 Runner/native、裁决/报告、Checkpoint/Memory、迁移发布/演练与验收。
CLI 旧 dry-run 仍会建 preview DB；未运行真实切换或在线能力对照，它们仍需单独批准。

### B1 续接：Case 上下文接入隔离 Store（2026-09-21）

- `TargetStore` 新增 `case_actors`、`case_sessions`、`case_objects`、
  `experience_case_context` 及 actor/object 关系表；`upsert_case_actor`、
  `upsert_case_session`、`upsert_case_object`、`remember_hypothesis` 均复用
  `_command` 的 revision/audit/idempotency 事务。假设继续是
  `experiences(kind='hypothesis')`，没有第二份 hypotheses 生命周期或行动队列。
- `tools/target_case_state.py` 在 primary 后端改走上述命令；legacy 目标保留旧
  JSON 兼容，preview/故障状态不回退写入。`case_state.json` 在 primary 下只读，
  `case_context()` 检查私密引用存在、权限和实体身份；公开 summary 仅返回私密材料
  的 `<redacted>` 标记，headers 仍通过受限私有文件按需加载。
- 新回归覆盖 primary Case 命令、假设 actor/object 关系、只读投影、私密引用缺失和
  legacy writer 拒绝；定向组合验证：`144 passed in 1.58s`。
- 旧 owner 准入再收紧：`action_queue.save_queue`、unsafe-review JSON writer 和
  `finding_index` 的公共 mutation 在目标 Store 为 preview/primary 或 fenced 缺库时
  失败关闭；新增 primary Queue/Finding writer 回归。目标 Store 写连接与同目标锁序列化，
  读连接保持只读不创建锁目录。Queue/Case/Finding 仍未完成完整消费者迁移，故不宣称全局
  单写后端已切换。
- 这只是 B1 的 Case 子项，不表示报告登记、Queue 全部机械准入、目标切换锁或旧 writer
  全面退役已完成；B2 生产 Runner 接线仍未开始。
- `TargetStore.register_report()` 与 `reports` 表已补齐最小报告登记：报告文件先由
  `_artifact()` 校验目标归属/hash，再在同一命令事务中绑定 finding、assessment、eligible
  delivery、artifact 与 audit receipt；重复命令幂等，ineligible/stale delivery 拒绝。
  `finding()` 只读展开已登记报告。`report_generator` 在 primary 目标已接入该命令：正文
  先落盘，再绑定当前 assessment/eligible delivery；primary 不再更新旧 Finding/Queue/INDEX
  JSON，legacy 目标继续走兼容流程。登记失败会保留正文但不推进旧状态。
- 本轮缺口修复：legacy Case 的部分更新保留既有 role/source/validity/status；Case JSON
  强校验 target/target_key；session 私密材料统一校验 schema、target、session/actor/kind、
  内容 digest 与文件名 digest；Store 写入时立即校验 session/object private_ref，object
  marker 绑定 owner_actor。组合回归为 408 passed（其中 Case/Store/report 相关 111+106）。
- B1 仍未退出：evidence ledger、完整 Queue 机械字段/所有旁路 writer、目标切换锁和完整
  消费者迁移仍未完成；B2/B3 其他部分与真实切换继续保持未开始/未授权。

### 规划修订：认知自由与领域契约分层（2026-09-21）

- 接受架构审查意见：AI 自行选择测试顺序、查询问题、推理路径和知识应用；项目不新增固定测试路线、类别优先级或 ROI 价值替身。
- 领域语义不能交给模型每次猜测：observation/technical assessment、unknown/partial、合法 unknown family、证据完整性、完成条件、delivery eligibility 和失效压制必须进入领域契约，并由 API/存储在可机械验证处强制。
- Skills/Rules 只解释项目语义和接口，不规定具体测试顺序；核心渗透测试技能不在本轮重写范围，后续测试暴露具体契约缺口时再迭代。
- 新增静态边界：command/attempt/operation 身份、追加失效事实、artifact bridge、封闭 projection 输入、Case/Experience 不激活行动、report draft/artifact/delivery decision/event 分层，以及目标内容始终是数据而非指令。
- 该规划修订步骤仅更新 `.trellis/tasks/09-20-native-first-practical-optimization/{prd.md,design.md,implement.md}` 与本进展记录；当时未修改产品代码、核心渗透测试技能、真实目标或任务生命周期。后续报告接线测试与 Ledger fence 变更另记于本节之后。

### B3 报告 primary 接线回归（2026-09-21）

- 新增 `tests/test_finding_index.py` 的真实 primary fixture：由 `TargetStore` 创建 finding、观察、confirmed assessment 和 delivery，再运行 `process_findings_dir()`。
- eligible delivery 场景证明：报告正文落在 `reports/<target-key>/`，`store.finding(finding_id)["reports"]` 有登记，旧 `findings.json` 字节不变，primary 不写旧 `INDEX.json`。
- ineligible delivery 场景证明：正文保留供补登记，Store 不产生 report 登记，旧 `findings.json` 不变，并以 `StoreError` 失败关闭。
- 定向验证：`python3 -B -m pytest -q -p no:cacheprovider tests/test_finding_index.py -k 'primary_report_generator or report_generator_consumes_structured_findings'` → **3 passed**。
- 相关回归：`python3 -B -m pytest -q -p no:cacheprovider tests/test_target_store.py tests/test_finding_index.py -k 'report or delivery or assessment'` → **32 passed**。
- 这只证明报告登记接线，不代表 B3 完成；Evidence Ledger、Runner 全入口、全部消费者切换和切换锁仍未完成。

### B2 先行准入：旧 Ledger writer primary fence（2026-09-21）

- `tools/evidence_ledger.py::record_entry()` 现在先读取统一 `target_backend()`；`primary` 和 `preview` 目标拒绝旧 JSONL 追加 writer，legacy 目标保持原行为。
- 该 guard 只阻止旁路写入，不冒充 native observation registration；Runner/native 的 attempt、artifact、operation 统一登记仍是 B2 未完成项。
- 验证：`python3 -B -m pytest -q -p no:cacheprovider tests/test_evidence_ledger.py` → **45 passed**（primary/preview 两种非 legacy 角色均覆盖）。

### B2/B3 接续：primary runner 完整登记与 stale 交付压制（2026-09-21）

- `validation_runner` 的 primary request-diff/native 路径在网络动作前固定 backend 与 attempt；登记只写
  operation/observation/artifact/finding 关联和 audit，不调用 legacy Ledger/Finding/Queue writer。
- request-diff 的 partial 结果分两类保存：已发布一侧材料登记为 `partial` observation；请求尚未发布任何材料时登记
  `unknown` operation，保留 attempt 和错误摘要，不伪造 response 或 candidate 证据。重复同步返回
  `deduplicated`；真实重跑使用新的 attempt。native 多步骤保留每步真实 method。
- partial summary 的 classifier family 现在与预创建 finding 一致，避免网络失败后的补登记把观察误绑定到
  `runner-observation`；同一 runner summary 仍是可重放的登记材料。
- `TargetStore.finding()`/`finding_page()` 重新计算 assessment 支撑 operation 的 raw 完整性，并给 delivery/report
  显式 `stale` 与 report `artifact_available`。assessment 被 supersede、delivery 被替代、证据/报告 artifact 缺失或篡改
  时历史行保留但不得继续授权当前报告；`register_report()` 重复检查当前 assessment/delivery，拒绝旧绑定。
- `report_generator` primary 投影只选择非 stale 的最新 report；正文先落盘，登记失败仍保留正文，legacy 目标路径不变。
- 定向验证：
  - `python3 -B -m pytest -q -p no:cacheprovider tests/test_validation_runner.py -k 'primary_request_diff or primary_record_evidence or primary_partial'` → **4 passed**；
  - `python3 -B -m pytest -q -p no:cacheprovider tests/test_target_store.py tests/test_current_truth.py tests/test_validation_runner.py tests/test_finding_index.py` → **241 passed**。

**仍未宣称完成**：B0 的完整动态 writer 清单/可比较性能基线、Queue 六项旧契约的全部迁入、目标切换排他锁、所有消费者迁移、
artifact 追加失效事实的独立迁移演练、B4–B6 离线验收及真实目标切换仍未完成。`evidence_ledger`/旧 report/index/probe 等
未切换目标 writer 保持兼容，primary 只失败关闭或走已接入 Store API；不把这轮 fence 当作全局退役。

最终工程验证：`python3 -B -m pytest -q -p no:cacheprovider` → **2151 passed**。

### B0/B1 接续：writer 清单、可复现基线与目标切换锁（2026-09-21）

- `research/writer-inventory.md` 新增按领域 owner 的直接 mutation 清单，区分 legacy 兼容、primary
  Store 接线和仍需迁移的旁路调用；浏览器/recon/scanner 原始材料写入不再与领域事实 owner 混列。
- 新增 `research/measure_baseline.py`。它在临时隔离根生成固定 100 条 action、finding、observation
  和 raw material，分别读取 legacy queue/findings/ledger 与 Store `context`/`finding_page`/
  `closure_records`，输出计数摘要、延迟、中位/范围、tracemalloc 峰值和输入字节。实测一次：
  两侧计数相同（100/100/100，digest `312e9695…`）；legacy 中位 3.005874 ms、峰值 247.06 KiB、
  60,263 bytes；Store 中位 13.571566 ms、峰值 416.43 KiB、611,794 bytes。该结果是离线正确性/性能
  基线，明确显示当前 Store 查询在小规模 fixture 上更慢更大，不能冒称 SQLite 已提速；后续索引/查询改动
  需重新运行脚本。
- `tools/target_store.py` 新增 `target_switch_lock()`/`target_cutover_lock()`；普通 Store mutation
  通过共享 `target-switch.lock` 再进入原有 `target.lock`，Queue、Case、Ledger owner mutation
  同样先持共享锁。排他锁测试覆盖 Store 与 legacy Queue，证明切换锁持有期间两类 mutation 均阻塞。
  这完成了统一锁原语，不等于迁移 CLI 已实现排他切换或所有旁路 writer 已接入。
- 定向验证：`python3 -B -m pytest -q -p no:cacheprovider tests/test_target_store.py -k 'exclusive_cutover or command_identity'` → **8 passed**；
  `tests/test_target_store.py tests/test_action_queue.py tests/test_evidence_ledger.py tests/test_target_case_state.py` → **263 passed**。

### B3 接续：primary validate/scaffold 与 delivery event 分层（2026-09-21）

- `tools/validate.py::run_scaffold()` 在 primary 目标直接读取 `TargetStore.finding()`，不读取或创建
  `findings.json`；`_build_machine_validation_input()` 的 primary 分支继续复用同一 Store finding。
- 缺少 method 的 primary validate 摘要只从 `current_truth.current_cell_projection()` 返回的 Store 事实推导；Store
  非 ready 或没有匹配观察时显式失败，不回退 GET 或 legacy Ledger。legacy 目标保留原兼容推导。
- Store schema v5 新增 `delivery_events` 与 `record_delivery_event()`：外部提交是独立追加事实，必须绑定当前
  eligible delivery、当前 report artifact，可选目标内 receipt artifact；报告生成/登记不会隐式生成提交事件。技术
  assessment 被替代后历史事件保留但 `current_binding=false`，receipt 可用性单独显示。
- 验证：`tests/test_decision_scaffold.py` → **11 passed**；`tests/test_validate_target_mode.py` → **52 passed**；
  `tests/test_target_store.py tests/test_finding_index.py -k 'report or delivery or primary'` → **43 passed**。

### B4/B5 接续：primary 查询只读与显式迁移链（2026-09-21）

- `coverage_matrix` primary rebuild 改从 `TargetStore.finding_page()` 投影 Finding，兼容 Store 的 `family` 字段；primary 不再读退役 `findings.json`。
- `surface_projection` primary manifest/semantic inputs 改绑定 Store metadata 与 `current_truth`，不再把 legacy action queue/ledger 当当前真源；legacy 目标继续保持文件 manifest 兼容。
- primary Surface manifest 现在显式携带 `target/store_id/revision/policy_version/as_of`；`as_of` 由调用方传入，不在 projection 内读取 wall-clock，Store revision 变化会使缓存 stale。
- `autopilot_state` primary 跳过 root-finding claim 扫描；`checkpoint` primary 构建改为零写入：不刷新 coverage projection、不发布 witness、不写旧 target memory。Store 真源仍共享 revision/health/closure 读口。
- `evidence_ledger.build_summary()` 在 Store 真源下不再额外聚合 legacy 子账本；primary checkpoint 的旧队列/记忆同步明确标记 skipped。
- `target_migration` 新增只读 `preview_target()`、显式 `import_target_staged(source,destination,target)`、`publish_preview()` 与 `promote_target()`：source/destination 必须隔离；preview 绑定 source manifest digest 和完成 receipt；promote 在排他切换锁内写持久 fence，再直接提交一次 SQLite primary 激活事务，避免锁升级自锁。默认 CLI 没有 source/destination 时只输出 preview，不创建 DB 或锁。
- 新增迁移演练测试覆盖：只读 preview 无 DB/lock、staging source 不变、publish/promote 后 backend 角色变化、receipt/digest 约束。真实目标未切换。
- 定向验证：`tests/test_coverage_matrix.py` → **129 passed**；B4 组合（checkpoint/autopilot/runtime/current_truth/context）→ **493 passed**；B5/Store/runtime 组合 → **153 passed**；checkpoint/current_truth/migration 组合 → **220 passed**；相关模块 `py_compile` 通过。随后全量离线回归 `python3 -m pytest -q -p no:cacheprovider` → **2160 passed in 46.35s**；primary checkpoint 零写入回归修正后 `tests/test_checkpoint.py -k primary_checkpoint` → **1 passed**。
- Surface/Context/Autopilot 绑定回归：**382 passed**。最终全量离线回归（含最新 Surface as-of binding）`python3 -m pytest -q -p no:cacheprovider` → **2160 passed in 47.28s**。

仍未宣称完成：完整 B5 目录冻结/恢复与 artifact bridge 断点演练、全部直接 writer 清单收口、projection 的完整 as-of/策略版本封闭输入、全量离线验收与 B6 旧责任退役。`git diff --check` 仍只报告接续前已有的 `tools/autopilot_loop_guard.py:488` EOF 空行。

### B5 接续：迁移断点与 artifact bridge 追加失效（2026-09-21）

- `target_backend()` 现在把已发布但缺失 `metadata.sqlite3` 的 migration receipt 识别为显式故障，
  不再把 published preview 误判为 legacy；损坏 DB、fence 已写但 primary 未激活、发布原子替换中断均保持
  fail-closed，staging 不被误标为已发布。
- `TargetStore` schema **v5 → v6** 新增 `artifact_events`：artifact 原始身份行不可变；
  `record_artifact_event()` 只追加 availability（available/unavailable）或 provenance（trusted/revoked）事实。
  当前 `available/authorized` 由最新事件与实时字节/hash 校验派生；失效/撤回不删除、不清空历史。
  operation 完整性、report stale 和 delivery receipt 可用性均消费同一派生状态。
- 新增回归：发布/激活断点、published preview 缺库、损坏 DB、post-cutover 新事实、旧 fence 阻断 preview 回退、
  artifact 失效与归属撤回后再验证；`tests/test_target_migration.py`、`tests/test_target_store.py`、
  `tests/test_current_truth.py` 组合 **118 passed**。
- 同步 `transactional-target-state.md` 与 `docs/architecture-contract.md` 的 schema/append-only artifact 契约。

**仍未宣称完成**：完整目录冻结/恢复归档、逐项迁移处置报告、全部旁路 writer 收口、artifact raw 发布但未登记的
全链演练、B6 离线整体验收和真实目标切换；本轮仍未操作真实目标、未提交/推送。

### B2 接续：observation envelope 的封闭头与开放 detail（2026-09-21）

- `observations` schema 增加 bounded canonical `detail_json`（schema **v6 → v7**）。
  `record_execution()` 接受对象型扩展载荷，严格 JSON/大小/键校验；`execution()` 还原为 `detail`。
- endpoint、method、family、observed_at、actor、result、identity dimensions、operation/artifact
  关系仍由强类型列和 FK 持有；detail 不能提供或覆盖查询键、关系键或闭合身份。
- 回归覆盖 detail 持久化、规范化与闭合投影不受 detail 污染；目标 Store、迁移、current_truth、报告和
  runner 组合均通过。`tests/test_target_store.py` 单文件 **73 passed**，相关组合 **172 passed**。
- 同步事务状态规范与架构契约的 schema/envelope 说明。

**仍未宣称完成**：完整 observation provenance 头的跨执行器统一适配、全部旧 writer/旁路入口收口、B5
目录冻结恢复和 B6 离线整体验收仍待继续；detail 只作为领域扩展载荷，不替代核心字段。

### B5 接续：报告 artifact 保留与交付关系隔离（2026-09-21）

- 迁移 manifest、隔离复制和只读预演现在包含 `reports/<target>`；报告正文/索引按路径、大小和 SHA-256
  逐项列入 `legacy.report_artifacts`，避免 staging 丢失不可变报告材料。
- 导入器只保留报告 artifact，不自动创建 report、delivery decision 或 delivery event；每项明确标记
  `registered: false`，后续需当前 finding/assessment/delivery 重新登记，避免把生成文件伪造成外部提交。
- 回归覆盖预演计数、staging 复制和逐项去向；`tests/test_target_migration.py` **34 passed**。
- `current_truth` 另有回归证明 provenance revoke 保留历史但抑制闭合授权；任务上下文校验和 backend/spec
  质量门通过。最新全量离线回归：`python3 -B -m pytest -q -p no:cacheprovider` → **2168 passed in 45.95s**。
- artifact bridge 断点补充覆盖 raw 已发布但未登记：迁移复制原始文件并列入 `unreferenced_material`，
  不凭文件存在创建 metadata/artifact 关系；迁移/Store/current_truth 组合最新 **122 passed**。

### B4/B5 接续：旁路 writer 与目标切换锁收口（2026-09-21）

- `runtime_state`、`coverage_matrix`、unsafe-review JSON writer 现在在各自原有
  read-modify-write 锁外先持有目标级共享 `target-switch.lock`，与 Store/Queue/Case/Ledger
  和排他 cutover 锁使用同一协调边界；锁顺序仍为 shared switch -> owner lock。
- `target_memory` 的 set/append/fact/handoff writer 统一在低层拒绝 `preview`、`primary` 或
  fenced 故障目标，避免迁移后旧 `memory/goals/targets/<key>.json` 重新成为 Experience
  第二真源；legacy 目标保持原读写兼容，checkpoint 的 primary 零写入路径不变。
- 目标 memory 与 checkpoint 的 legacy read-modify-write 也接入 shared switch lock；读取路径
  不创建 Store/lock，不改变 primary Store Experience recall。
- 验证：`tests/test_core_foundation_tools.py tests/test_checkpoint.py tests/test_runtime_state.py
  tests/test_coverage_matrix.py tests/test_action_queue.py` → **490 passed**；迁移定向测试此前
  **38 passed**；相关模块 `py_compile` 与本轮文件 `git diff --check` 通过。

仍未宣称完成：完整 B5 目录冻结/恢复故障注入与逐项迁移处置报告、所有消费者切换、B6
离线整体验收和真实目标切换；本轮未操作真实目标、未提交/推送。

### B5 接续：primary 提交后归档激活断点恢复（2026-09-21）

- `promote_target()` 现在区分“SQLite 已提交 primary、archive receipt 尚未 active”的恢复状态：
  重试只完成幂等的归档/迁移 receipt 激活，不把已 primary 的 Store 误报为不可提升的 preview，
  也不重新读取已被归档的旧 metadata 路径。
- 迁移 receipt 在激活后显式记录 `backend=primary`、`activation_status=active` 和 archive receipt
  路径；原始报告/raw 仍保留，旧领域 metadata 只存在受限归档目录。
- 新增 post-commit 中断/恢复回归；`tests/test_target_migration.py` → **39 passed**。
- 追加 primary 激活后数据库损坏回归：`target_backend()` fail-closed，绝不恢复已归档旧
  `action_queue.json`；迁移文件当前 **40 passed**。

### B4 接续：Coverage primary revision binding（2026-09-21）

- `coverage_source_fingerprint()` 在 Store backend 下现在绑定 `backend/store_id/revision`；
  primary Finding/Observation 发生新事务后，旧 Coverage 矩阵不会继续被当作 fresh。
- primary 矩阵显式保留 `store_id/store_revision`，legacy 矩阵继续使用文件输入指纹；未知或损坏
  Store 由统一 backend/Store 读取错误显式暴露，不回退旧 findings JSON。
- 回归：`tests/test_coverage_matrix.py` → **130 passed**（含 Store revision 使旧 projection stale）。

### B5 接续：target-memory 逐项处置报告（2026-09-21）

- staged import 现在读取并报告 `memory/goals/targets/<key>.json` 的字段计数、target 身份和
  可诊断状态；有效条目明确标记“保留到 legacy archive、暂不导入 Experience”，因为旧条目
  没有规范 operation 引用，不能把自然语言或文件路径猜成条件化经验。
- 缺失、非 regular、损坏 JSON、跨目标 target-memory 都单独报告并保留原材料；迁移不会因
  target-memory 缺少可导入条目而伪造 Store experience 或 observation。
- 回归：`tests/test_target_migration.py` → **42 passed**（含只读 preview 对损坏 target-memory 的
  partial/quarantine 处置）。

### 本轮质量门（2026-09-21）

- 全量离线回归：`python3 -B -m pytest -q -p no:cacheprovider` → **2177 passed in 44.42s**。
- `python3 ./.trellis/scripts/task.py validate 09-20-native-first-practical-optimization` → context
  manifests valid；相关模块 `py_compile` 通过。
- `git diff --check` 仍只报告接续前已有的 `tools/autopilot_loop_guard.py:488` EOF 空行，未扩大
  范围修复；未提交、未推送、未操作真实目标。

**仍未宣称完成**：旧 target-memory/experience 的逐项映射、目录冻结/恢复归档、全部旁路 writer 收口和
B6 离线整体验收仍待继续；报告 artifact 迁移不等于交付关系迁移。

### B4 接续：primary 经验读入口统一（2026-09-21）

- `tools/target_memory.load_goal_memory()` 在 primary 目标改为只读投影 TargetStore 的
  `experiences`/Case hypothesis；旧 `memory/goals/targets/<key>.json` 即使存在、损坏或已归档也不再
  参与当前上下文。条件、重开条件、下一意图和 observation 引用保留在投影条目中，未生成行动。
- `context_pack` 删除重复的 primary 记忆分支，复用同一公共读入口；Resume、Surface、Autopilot
  state-read 等既有调用因此共享后端角色和 Store revision 语义。
- 新增 primary 读隔离回归：Store hypothesis 可召回，损坏 legacy JSON 不影响投影；相关 Context/Memory/
  Resume/Experience 组合 **176 passed**，全量离线回归 **2179 passed in 44.69s**。

仍未宣称完成：目标经验的旧字段逐项处置报告、所有消费者/旁路 writer 的完整迁移、目录冻结/恢复故障注入、
B6 离线整体验收和真实目标切换仍待继续；本轮未操作真实目标、未提交/推送。

### B1 接续：primary Action metadata 与机械准入闭合（2026-09-21）

- `actions` schema **v7 → v8** 增加有界 `metadata_json` detail；primary `add|claim|resolve|list`
  不再丢弃 AI 的 hypothesis/route/dimension/evidence 引用上下文。该 detail 不是新的生命周期 owner，
  不保存 observation/assessment/delivery 终态。
- Store 在 action create/claim/resolve 入口拒绝 Runner-owned observation 字段，校验 target-owned
  `evidence_ref`/`baseline_ref` 与 selected knowledge card 引用，并在 claim 的 CAS 事务内执行
  `max_hypothesis_actions` cap；既有 explicit ID、execution-key/repeat、completion proof 和版本约束保持不变。
- 新增 primary metadata 持久化、cap、Runner-field、foreign-ref 回归；Store/Queue/Case 定向组合
  **227 passed**，相关模块 `py_compile` 通过。旧测试中“primary 永远拒绝 metadata”断言已按新契约改为
  metadata 保留与 claim 合并验证。

仍未宣称完成：B4 全部旁路 writer 的逐项运行接线、B5 完整目录冻结/恢复与 artifact bridge 断点全链、
B6 离线整体验收和真实目标切换仍待继续；本轮未操作真实目标、未提交/推送。

### B6 离线效率基线刷新（2026-09-21）

- 使用固定 `measure_baseline.py`、100 条 action/finding/observation、15 次采样重跑 legacy 与 Store
  查询对照；两侧计数均为 100，`counts_equal=true`。
- 当前 Store 查询中位数 **13.417915 ms**、峰值 **422.60 KiB**；legacy 为 **2.216763 ms**、
  **247.06 KiB**。这证明当前实现的正确性/可测量基线，不声称 SQLite 已带来性能提升；结果已写回
  `research/baseline-20260921.json`，后续优化需以相同 fixture 重测。

### B6 完整性重读后性能复测（2026-09-22）

- 使用同一 `research/measure_baseline.py`、100 条固定 action/finding/observation 和 15 次采样；
  `counts_equal=true`，`counts_sha256=312e969539730132d1d9d826c5f1192cef828d26af6c218d1ee04a9f64253f37`。
- 本次 legacy 中位数 **2.788709 ms**、峰值 **247.06 KiB**、输入 **60263 B**；Store 中位数
  **13.971934 ms**、峰值 **422.60 KiB**、输入 **652754 B**。波动来自本地运行环境，方向与历史基线一致：
  当前 Store 路径仍较慢且占用更大；该结果只证明正确性和可重复测量，不构成提速或全局最优声明。

### B5 接续：开放 Queue 上下文的逐项迁移处置（2026-09-21）

- legacy queued action 的非敏感 hypothesis/route 前提现在按显式白名单进入 Store 的 bounded action
  metadata；secret-shaped、Runner-owned 和未列入领域契约的字段仍只在迁移报告中列 key/处置，绝不把
  敏感值或未知 bag 带进新库。
- 新增迁移回归验证开放 action 的 metadata 保留、敏感值不出报告和 Store action 投影一致；migration+
  Store 组合 **119 passed**。
- 追加激活后旧 Queue/Finding/Ledger writer 的 fail-closed 演练；旧进程不能在 primary 目录恢复第二写入源。

### B2/B4 接续：probe primary 观察登记（2026-09-21）

- `tools/probe.py` 在 primary 目标不再调用旧 `record_entry()`；请求产生的 probe JSON 先保留为
  target-owned artifact，再以独立 attempt/operation 登记 observation。`lead` 仍是观察结果，不创建
  finding、assessment、delivery 或行动，`--no-ledger` 仍显式跳过登记。
- legacy 目标继续使用 JSONL Ledger 兼容路径；primary/preview 的旧 Ledger writer 仍失败关闭，避免
  同一目标双写。新增 primary probe 回归：raw、attempt、operation、artifact 关系完整且 legacy ledger 不创建。
- `tests/test_probe.py` → **23 passed**；其余全量回归待本轮质量门刷新。

仍未宣称完成：validate/CLI 旧 Ledger 旁路、Queue/Finding 全部消费者迁移、目录冻结/恢复故障注入、B6
离线整体验收和真实目标切换仍待继续；本轮未操作真实目标、未提交/推送。

### B1/B4 接续：primary Action Queue 薄适配（2026-09-21）

- `tools/action_queue.py` 的显式 `add`/`claim`/`resolve`/`list` 在 `primary` 后端改走
  `TargetStore.actions`：读取是 revision-bound Store 投影，创建根据真实 endpoint/family 或
  target/URL/artifact subject 建立 execution/work action，不伪造 HTTP 身份；claim 使用 Store
  version/CAS，重复 claim 返回 `resumed`；旧 `action_queue.json` 不创建、不读取、不更新。
- primary resolve 只接受 `blocked`、`dead-end`/`n/a` 或带明确 `operation_id=`、`artifact=`、
  `command_id=` 的完成证明；`lead`/`signal`/`candidate` 不被压成行动终态。终态重复 resolve
  返回显式 `replayed`，不因版本推进重新写入。
- `save_queue` 和 checkpoint 批量旧 JSON writer 继续在 primary/preview 失败关闭；legacy 目标
  的 JSON 行为不变。更新了 Action Queue、autopilot lanes、事务状态和架构契约中的适配说明。
- 回归：`tests/test_action_queue.py tests/test_target_store.py tests/test_checkpoint.py` →
  **358 passed, 1 deselected**；primary adapter 定向 **2 passed**；未操作真实目标、未提交/推送。

仍未宣称 B1/B4 完成：新 Store action 已覆盖锁、显式 ID、重复意图、artifact/operation 完成证明和
CAS，但旧 Queue 的 metadata 专属 hypothesis cap/runner-field/skill-card 规则不进入 primary
任意 JSON metadata（这些字段在 Store 中不存在）；剩余完整消费者迁移、B5 目录冻结/恢复和 B6
离线验收仍待继续。

### B2 退出核验：validate 旧 owner 旁路回归（2026-09-21）

- 扩展 `test_primary_machine_validation_uses_store_assessment_and_delivery`：在 primary
  运行 `/validate` 时同时拦截 `evidence_ledger.record_entry`、`action_queue.load_queue`、
  `action_queue.resolve_action`、旧 Finding upsert/status writer；任一调用都会使测试失败。
- 定向验证：`tests/test_validate_target_mode.py -k primary_machine_validation_uses_store_assessment_and_delivery`
  → **1 passed**。这证明 validate 的 primary 分支不会回退到 Ledger/Finding/Queue 旧 owner；
  legacy 分支行为仍由同文件其余回归覆盖。

### B5 接续：Case context 显式导入与私密材料桥（2026-09-21）

- `target_migration.import_target()` 现在把 legacy `case_state.json` 的 actor/session/object/
  hypothesis 逐项写入 TargetStore；使用稳定 command id 可重放，关系缺失、非法角色、敏感说明或
  不可用私密引用单项隔离并保留原因。`validation_backlog` 仍只进入旧裁决/关联报告，绝不重新成为 action owner。
- staged copy/manifest 纳入 `.private/case-state/<target>`，session 的 `private_ref` 在导入前验证
  目标归属、文件存在与 Store 私密材料契约；公共 Case projection 不包含 header 内容。
- 回归：`tests/test_target_migration.py` → **43 passed**，新增 Case context 关联和私密 session staging
  验证。报告 artifact 与 target-memory 仍保持“保留、待显式重新登记”语义，不能冒称 Experience/Delivery
  关系已自动迁移。

### B4 接续：primary Surface projection 完全不发布 recon sidecar（2026-09-21）

- `technology_inventory.load_or_build_inventory*()` 增加显式 `persist` 开关；primary Surface 只在内存中
  从 raw httpx/Nmap 观测构建组件投影，legacy 目标继续复用原有持久化 inventory 缓存。
- primary Surface 的 observation summary、filtered probe log 与 technology inventory 均不再由查询路径创建或
  刷新；SQLite 自身 WAL/SHM bookkeeping 不算 projection sidecar，回归断言已按该边界收窄。
- 定向回归：`tests/test_native_judgment_boundary.py tests/test_current_truth.py tests/test_context_pack.py tests/test_autopilot_state_tool.py`
  → **350 passed**；全量离线回归 `python3 -B -m pytest -q -p no:cacheprovider` → **2190 passed in 46.31s**。
- `task.py validate 09-20-native-first-practical-optimization`、修改模块 `py_compile` 与全量离线测试均已通过；
  真实目标切换、在线能力对照和 B5 完整目录冻结/恢复仍不宣称完成。

### B4 接续：Surface 查询固定一次 backend 角色（2026-09-21）

- `load_surface_context()` 现在在查询开始时读取一次 `legacy|preview|primary` 角色，并把该值传入
  inventory、Finding、Action 与 observation-summary 分支；同一次查询不会因重复打开 Store 而重新猜测后端。
- 定向回归：`tests/test_native_judgment_boundary.py tests/test_runtime_state.py tests/test_context_pack.py`
  → **154 passed in 6.47s**；任务 context validate、全量变更 Python `py_compile` 均通过。
- `git diff --check` 仍只命中接续前已有的 `tools/autopilot_loop_guard.py:488` EOF 空行；本轮未扩大范围修复。

### B5 接续：归档冻结中断恢复演练（2026-09-21）

- 新增冻结阶段断点回归：归档 receipt 已写入、旧 metadata 删除中途失败时，目录保持
  `activation_status=pending`，backend 判定 fail-closed；显式 `restore_legacy_metadata()` 可校验归档并恢复
  被删除的旧 owner 文件，不会把半冻结状态误报成 legacy 或 primary。
- `tests/test_target_migration.py` → **46 passed**；该演练仍只使用隔离 fixture，不触碰真实目标目录。

### 质量门刷新（2026-09-21）

- 全量离线回归：`python3 -B -m pytest -q -p no:cacheprovider` → **2191 passed in 45.93s**。
- `python3 ./.trellis/scripts/task.py validate 09-20-native-first-practical-optimization` 通过；所有当前
  tracked Python 改动 `py_compile` 通过。
- `git diff --check` 仍只报告接续前已有的 `tools/autopilot_loop_guard.py:488` EOF 空行；未修改该无关卫生问题。

### B4 接续：Surface revision-bound assembly（2026-09-21）

- `tools/surface.py::load_surface_context()` 在 primary 查询开始时捕获一次目标 Store 的
  `target/store_id/backend/revision` 绑定，并复用同一 `TargetStore` 实例读取 Finding/Action；查询结束前
  再从只读连接校验绑定未发生漂移。任何并发事实写入都会 fail-closed，要求重新构建 Surface，而不是返回
  混合 revision 的上下文。
- 新增 `tests/test_native_judgment_boundary.py::test_primary_surface_rejects_store_revision_drift_during_assembly`；
  Surface、Context Pack、Autopilot、迁移组合回归 **383 passed**，相关模块 `py_compile` 通过。
- 这只证明离线 revision-bound 组装契约；不宣称跨进程长事务快照，也不改变 legacy/preview 的读取语义。

仍未宣称完成：B4 全部旁路 writer 的最终逐项证明、B5 逐项人工处置清单的正式审核、B6 离线整体验收、
真实目标切换和在线能力对照；本轮未操作真实目标、未提交/推送。

### B4 接续：Knowledge evaluation active-owner read（2026-09-21）

- `tools/knowledge_eval_draft.py::_action_linkage_counts()` 对已迁移 primary 目标改读
  `TargetStore.actions`，不再扫描已归档的 `state/<target>/action_queue.json`；legacy 目标继续保留
  文件兼容读取。Store 损坏时不回退旧 JSON，避免知识卡信号复活退役事实。
- 新增 `tests/test_knowledge_eval_draft.py`，验证 primary action linkage 不采纳 archive-only 内容；定向回归
  **1 passed**。

仍未宣称完成：其余 scanner/source/intel 产物属于原始材料或非领域投影，仍需按 B4 清单逐项确认是否应
  迁入 artifact/Store；B6 离线整体验收、真实目标切换和在线能力对照保持未完成。

### B4/B5 接续：旁路产物边界与离线切换交付物（2026-09-21）

- `scanner_pass_writer` 现在使用同目录临时文件、flush/fsync、原子 replace；scanner pass 仍只提供
  advisory `scanner_swept`，不把 `untested` 变成 `tested_clean`。
- source-hunt JSON/Markdown 与 intelligence projection 也改为同目录临时文件、flush/fsync、原子 replace。
- 新增 `tests/test_scanner_pass.py`：覆盖空 scanner 目录、advisory 状态保持和 primary Store revision/事实
  不变；`tests/test_repo_root_seams.py` 与 `tests/test_intel_artifact_store_boundary.py` 证明 source-hunt、
  intel artifact/intelligence projection 是 raw/projection producer，不是 primary domain writer。
- `docs/architecture-contract.md`、`commands/validate.md`、`commands/checkpoint.md` 已区分 primary
  Store 真源与 legacy 写回；核心 Skills/Rules 未改写。
- 新增 `research/migration-disposition-20260921.md` 与 `research/cutover-review-checklist.md`。
  `/root/mig-sandbox-10/report.json` 的离线导入结果为 partial：11 findings、81 observations/artifacts、
  11 exact links、112 quarantine；未决处置仍阻断真实切换，不能把该报告当作 activation receipt。
- 定向回归：`tests/test_scanner_pass.py tests/test_repo_root_seams.py tests/test_intel_artifact_store_boundary.py`
  → **14 passed**；全量离线回归刷新为 `python3 -B -m pytest -q -p no:cacheprovider`
  → **2198 passed in 47.08s**。

### B6 离线工程验收（2026-09-21）

- 证据固化在 `research/offline-acceptance-20260921.md`：全量回归、编译、任务上下文、生产者边界测试、
  100 条固定 fixture 的 counts-equal 性能基线和迁移隔离报告均已复核。
- 该验收只关闭离线工程门槛；真实目标切换、旧 writer 退役和在线能力对照仍保持未完成，不以测试绿灯代替授权。

### B3/B6 接续闭环（2026-09-22）

- 恢复 session `01a0c208-e350-79c1-84fa-c362c0240b86`；接续前最新实际断点是
  validate owner-aware dispatcher 和 `120 passed`，不是较早交接摘要。工作区基线保存在
  `/tmp/ccst-resume-20260922/`，保留全部接续前改动及受保护文件。
- 完成 primary report 重放、不可变正文、存量/空集索引投影、失败重试和 revision/as-of
  绑定；preview 不再回落生成 legacy report。
- 收口 Finding 隐式 list 迁移、跨 target/output、Ledger 锁外准入和 Runner preview/换代
  登记缺口。共享切换锁保持至相应副作用完成，网络动作不持 DB 事务。
- Surface review 覆盖跨切换时序；Pack primary 重新读取快捷输入并校验 raw；Coverage
  通过只读 owner 与 current_truth/ClosureResolver 投影，不把候选或旧 cells 当作闭合。
  精确 query/hash/v2 不放宽，三类非 clean 终态不再重复出队，固定 as_of 的输入快照可核验。
- 默认 primary Checkpoint 不再因 rebuild_matrix 内部发布而写 Coverage；round settle
  不写旧 Finding/Queue，不隐式刷新 Surface，仅显式关闭 runtime round，重放保持只读。
- 全量最终验证：`rtk proxy python3 -B -m pytest -q -p no:cacheprovider`
  → **2254 passed in 55.68s**。中途的 fixture 签名漏接与 gate registry 缺项已修，未跳过测试。
- 最新证据、逐项兼容层处置及限制见 `research/offline-acceptance-20260922.md`；规范同步到
  `docs/architecture-contract.md` 和 backend `transactional-target-state.md`。
- 任务仍为 `in_progress`：未切换真实目标、未全局删除仍服务 legacy 的接口、未跑在线
  能力对照；代码已提交但未推送、未归档。完整性重读后的性能已复测，结果与历史方向一致；
  不构成性能收益声明。

### B5 接续：迁移处置账本身份与绑定修复（2026-09-22）

三轮独立审核对 `2885c69`（migration disposition ledger）确认 11 项缺陷，全部在本轮修复：

- **账本绑定了不完整的源（阻断）**：ledger 的 `source_manifest_sha256`
  `877ed02a…`（1,285 文件）精确匹配 `/tmp/ccst-cutover-source-20260922-127.0.0.1_3001`，
  而该 export **不含 `reports/`**。仓库真实 manifest `860c7d0d…` 为 1,295 文件，
  路径差集恰好是 `reports/127.0.0.1:3001/` 下 10 个文件，无其它差异。即 117 行账本
  只覆盖真实切换需要迁移的 1,295 个文件中的 1,285 个；其 `decision_rule`
  （"every item requires an explicit operator decision"）未覆盖真实导入会报告的 10 项
  保留 report artifacts。
- **绑定不覆盖决策表（阻断）**：`source_manifest_sha256` 取自 payload 自身，
  `ledger_sha256` 只覆盖 items，因此为一份报告生成的决策表只需改一个字段即可重绑到
  另一份输入。已复现：把 fixture 的 117 个 ID 用于 reports-complete 输入并改写
  manifest 字段，被接受并产出 `complete` receipt。
- **身份依赖报告顺序（中）**：117 行中 45 行无 event/id/line，其 ID 在报告重排后会变化，
  与"重排不改变身份"契约矛盾。
- **治理元数据仅装饰（中）**：`status: "pending"`、`count`、`staged_root`、
  `source_report_status`、`decision_rule` 被写出但从不读取或强制。
- **终局语义错误（高）**：`operator_review` 与 `rebind_after_export_verification`
  可清空发布门槛，但二者记录的是未完成动作。
- **CLI 静默忽略（中）**：`--disposition-ledger` 不带 `--import-source` 时不报错。

修复落点与验证（见 spec `transactional-target-state.md` § Migration Quarantine
Disposition Contract）：

- 身份移除报告位置，同字段组按 occurrence 计数区分，身份集合与顺序无关。真实 117 行
  上验证：反转与种子打乱后身份集合和 roster 摘要不变；改动任一上报事实则两者均变。
- 账本可声明 `quarantine_roster_sha256`（完整源身份集合摘要），现要求与输入一致。
  重绑尝试被拒：`disposition ledger quarantine roster does not match migration input`。
- `rebind_after_export_verification` 与 `operator_review` 归为非终局：记录为
  `recorded_decision`，行保留在 quarantine，报告保持 `partial`。只有 `preserve_verdict`
  和 `permanent_quarantine` 能清空发布门槛。
- 声明 cutover ledger `kind` 的 payload 强制治理元数据：占位 `status` 和与 `items`
  不符的 `count` 被拒。
- staged receipt 新增 `unregistered_artifacts`（数量、路径、摘要），使"保留但未登记"
  这一事实跨运行留存；`--disposition-ledger` 缺 `--import-source` 现为 CLI 错误。
- 真实 fixture 复验：旧 pending ledger 与 ready ledger 均被 manifest 校验拦住；
  复用旧 ID 被 roster+身份拦住；reports-complete 输入下 receipt 正确写出
  `unregistered_artifacts: {"report_artifacts": 10, ...}`。
- 验证：`tests/test_target_migration.py` **57 passed**；全量
  `rtk proxy python3 -B -m pytest -q -p no:cacheprovider` → **2265 passed in 56.51s**；
  `compileall`、`git diff --check` 通过。
- 修正后的两处不实描述已按"不改写历史"约定以追加更正段写入
  `research/cutover-readiness-20260922.md`；`research/cutover-review-checklist.md`
  补 ledger 归档项（receipt 只存 `ledger_sha256`/`quarantine_roster_sha256`，不存逐行决策）。
- 结论：fixture 账本对真实目标不可用（绑定于 reports-less manifest），每个隔离项都需
  重新生成并由 operator 给出终局决策。未提交、未推送，真实切换未授权。

### B5/B6 真实目标切换（2026-09-22，已授权执行）

目标 `127.0.0.1:3001` 已完成真实切换：`legacy → primary`，store_id
`022e4e9618264d8a92df6262a3a1b749`，manifest `31660dc141c0d173…`（1,287 文件），
receipt `complete` / `activation_status: active`。

切换前先解决了阻断真实切换的两类问题：

- **迁移兼容缺口（本轮修复）**：19 条 legacy 绝对 `evidence_ref`（文件都在，只是写死了
  运行目录前缀）、2 条 Case 相对 endpoint、3 个缺 `target`/`content_sha256` 的旧私密
  session 文件。修复方式分别是：按 §9.6 第 1 条**声明源根后显式 rebase**（`source_root=`
  显式传入，rebase 结果必须在副本内可读，否则照旧隔离）；复用已有的单一 origin 映射；
  **不重写私密材料**，记录照常导入、去掉无法验证的绑定并记入
  `legacy.private_bindings_dropped`。隔离项 117 → 0。
- **manifest/copy 规则不一致（本轮修复）**：manifest 把 9 个运行锁计入，而 copy 按设计
  排除 `locks/`，导致 promote 报"迁移输入消失"。抽出共享判定 `_is_migration_input()`，
  两侧共用，manifest 1,295 → 1,287 文件。

97 项处置的最终分类：19 绝对引用 + 2 case endpoint + 3 session 经修复后无损导入；
63 条 queue 终局裁决 `preserve_verdict`；30 条（25 无 raw 引用且 `operation_id` 全空、
4 缺 endpoint/family、1 raw 物理缺失）`permanent_quarantine`。

切换执行与验证：

- 静默复核（无 lock 持有者、无 writer 进程、无打开句柄）→ 备份 1,287/1,287 逐字节校验
  → staged import（receipt `complete`、隔离 0）→ install → promote。
- 事后验证：Store 可读（11 findings）、可写（新事实成功创建，探测 action 已按追加事实
  取消）、旧 writer 已被 fence 拒绝（`legacy action_queue writer is disabled for primary
  target`）；全量 **2,272 passed**。
- 现场：legacy 归档于 `state/127.0.0.1:3001/legacy-archive/`（6 文件，字节完整）；
  raw/reports/私密材料未冻结（evidence 186、reports 10、.private/validation 1035、
  .private/case-state 3）；备份在 `/root/ccst-cutover-20260922/backup/`。
- 审计：`/root/ccst-cutover-20260922/cutover-audit.json`；recon 目录清空事故按 operator
  选择以显式接受记录（`data-incident-acceptance.json`：投影 174 项输入中 130 项指向
  `recon/` 且全部悬空，无副本可恢复，未声称已恢复）。
- 回退边界：激活已提交，`restore_legacy_metadata` 拒绝回退；恢复只能前向（Store 导出或
  用归档材料）。
- 本轮代码改动仍未提交、未推送。

### B6 观察期与归档清理（2026-09-22）

切换后在 primary 上跑真实工作流验证 R6/R7：checkpoint/context_pack/scaffold 正常且
**revision 209 前后不变**（默认零写入）；真实 `request-diff` 执行（2 个真实请求）→ 证据
落盘 `.private/validation/` → Store 登记成功（revision 209→212），且新 finding
`assessment: None`（执行未冒充裁决）。迁移的 11 个 finding **11/11 有可解析证据链**
（`evidence` → `operation` → `observation`），含 19 条 rebase 修复的引用——这些引用若不修
即为此处的断链。旧 writer 已被 fence 拒绝；legacy sidecar 未重建。

观察期暴露并修复一个真缺陷：`promote_target` 在 `backend == primary` 时**无条件校验归档
材料字节**，等于让一次性迁移工具在切换完成后仍持有对归档的运行时依赖。后果：清理历史归档
会被误判为"迁移损坏"，且已完成的目标失去幂等重入路径（design.md 第 8 条要求恢复目标为
当前事实而非旧快照）。修复：以持久标记（role 提交 + fence + receipt
`activation_status == "active"`，三者 store/manifest 一致）识别**已完成**激活并短路返回
`recovered`，不读归档；**中断**激活（receipt 仍 `pending`）继续要求并逐字节校验归档。
`restore_legacy_metadata` 本就要求 `pending` 且 primary 已提交时拒绝，无需改动。

随后按 operator 决定清理该目标的归档（`legacy-archive/` + `legacy-archive.json`，6 文件
约 487 KB）：这些是 2026-09-11~15 自建 lab（`127.0.0.1:3001`）的演练记录，内容已全部
迁入 primary Store，且 `/root/ccst-cutover-20260922/backup/` 有 6/6 逐字节相同副本。清理
后 promote 仍幂等成功、Store 完整（12 findings / 101 observations）。切换审计与备份保留。

验证：`tests/test_target_migration.py` 66 passed；全量 **2,274 passed**；`git diff --check`
通过。

### B6 收尾审计：legacy 退役的真实阻塞（2026-09-22）

在 operator 指示"新的已经实现了的就把旧的完全删除"后做了完整审计，结论是**当前不具备删除条件**，
且阻塞是架构性的而非遗留清理。

事实：`tools/target_store.py:2059` 的 `target_backend()` 对**没有 Store 的目标返回
`"legacy"`**。因此 legacy 写入路径仍有真实消费者——**新目标**（新建靶场、新侦察域名在建立
Store 之前）。仓库现有目标只剩 `127.0.0.1:3001` 且已是 primary，但删除 legacy 分支会让新目标
既无法写 legacy、也没有 Store 可写（`initialize()` 的 `allow_legacy=True` 仅保留给迁移工具的
隔离副本）。

逐工具分类（Store 调用 / legacy 读 / legacy 写）：

- **已成对双路径（Store 路径已实现）**：`coverage_matrix`（`_append_primary_finding` 对
  `_append_finding`）、`report_generator`（`_process_primary_reports` 对
  `_process_findings_dir` 后半段）、`validate`、`surface`、`resume`、`runtime_state`、
  `autopilot_state`、`validation_runner`、`surface_projection`。这些是 `if primary … else legacy`
  结构，legacy 侧服务未切换目标，删除即制造功能缺口。
- **完全未接线**：`param_discovery`、`spray_contract`（无 Store 写路径，legacy 写回是其唯一
  结果落地方式；primary 下经 try/except 记成 `action_queue_sync: error`，扫描仍可完成）；
  `intel_engine`、`oast_listen`、`intel_continuation`（纯 legacy 读，无 Store 路径）。

正确顺序（`prd.md:64`「完成消费者迁移后删除旧逻辑与适配」）：

1. 让新目标**直接建立 Store**，把 `legacy` 从默认状态降为历史只读兼容；
2. 给 `param_discovery` / `spray_contract` / `intel_*` / `oast_listen` 补 Store 接线；
3. 此时 legacy writer 才真正无消费者，可以退役并删除兼容分支。

这属于独立的一轮工作，量级与本次切换相当，未在本轮执行。

### C0/C2 接续（2026-09-23，未完成整体任务）

- C0 补充了 Skill 路由遗留链清单；设计与实施计划明确 C4 在消费者接通后退役固定路由、双校验和 catalog，不保留 AI 自报的 Skill 使用审计字段。`param_discovery` 的固定 route 只在 legacy 分支；Store 校验有测试成功分支，但 Queue/Store 解析根不同。
- C1 已修复 fenced Store 丢库时 `runtime_store()` 静默回退 legacy；C2 已让 `/hunt` 在目标执行前调用显式初始化并传播拒绝，复用同一初始化原语和目标排他锁。普通 Action/参数/spray/OAST 等调用不自动初始化；这些调用的 legacy 兼容仍待 C3/C4 退役。
- 本轮修复显式初始化静默 `chmod` 已有目标目录的问题：fresh 的非私有目录拒绝且不建库，active 目录权限退化时也拒绝、不隐式修复。CLI 增加 legacy 拒绝和 `--help` 零目标写入回归。
- 本轮验证：`python3 -B -m pytest -q -p no:cacheprovider tests/test_target_store.py tests/test_hunt_initialization.py tests/test_primary_action_consumers.py`，104 passed。未对真实目标执行 schema、迁移、恢复或外部测试。
- C2 的 `target_memory set` 仍沿 legacy 写源；其 Store-only 选择及 `--goal` 写入依赖 C3 的 `active_goal`/`note` 显式 schema 升级，不能在 C2 偷存第二份意图。C3 先证明旧活动 v8 库在新代码下可读且升级失败可恢复，再接日常记忆 CLI；不以当前 104 项通过宣称 C2/C3 或整体任务完成。

### C3 记忆消费者接续（2026-09-23，局部完成）

- 隔离 Store 的 v9 记忆 schema、显式 v8 备份升级、`active_goal`/`note`、先过滤后分页的 `experience_page`、目标记忆 `set/show/note/lead/next/fact/dead-end/pattern/handoff` 适配和 `experience_recall --limit/--cursor/--id` 已落地；旧 JSON 写路径仍待 C4 退役。`show` 现展示最近 20 条 Store 经验的条件、重开条件、下一意图、作者、ID、余量和展开入口；`next` 写入后可在恢复投影的 next actions 找到。
- `/remember` 在 primary 上把明确提供的 technique/notes 或 operation 引用写为目标 Store 经验，journal 仍作审计；无 operation 的结果只标为未验证 note，带证据的阴性须有条件与重开条件，重放命令不重复追加 journal。primary 召回不再混入旧 PatternDB；legacy 侧仍保留原行为，新的条件/引用参数不能被静默忽略。
- 本轮验证：`python3 -B -m pytest -q -p no:cacheprovider tests/test_memory_loop_closure.py tests/test_experience_recall.py tests/test_core_foundation_tools.py tests/test_context_pack.py tests/test_resume_tool.py tests/test_target_store.py` → **283 passed**（在最后一次拒绝路径收紧前）；随后 `tests/test_memory_loop_closure.py -k remember` → **4 passed**。覆盖真实 CLI 新进程保存/召回、21 条/20 条窗口、legacy 单次 journal 和真实 observation 引用；最终跨消费者计数待收尾重跑。未读取或改变真实目标数据。
- 未完成：旧记忆源 manifest 绑定补导入、PatternDB 历史连续性、Checkpoint/Resume 三轮交接、蒸馏语义与知识复用、C4 正常 legacy/Skill 路由退役及 C5 工程/在线能力验收。上述局部通过不代表 C3 或整体架构完成。

### C3 蒸馏读口接续（2026-09-23，局部完成）

- `distill_target.py evidence` 的 primary Finding 直接消费 Store 查询字段，不再把 `family/claim/endpoint/assessment` 投进旧 `vuln_class/title/status` 渲染器而产生空白。技术裁决与目的地决定分列；目标经验有最近 10 条有界窗口、准确总数/余量/游标，并保留条件、重开条件、下一意图和按 ID 展开入口。多次 Store 读取前后检查 revision，变化时明确重试。
- 定向测试 `python3 -B -m pytest -q -p no:cacheprovider tests/test_distill_target.py` → **5 passed**，使用本地 observation、技术裁决、交付决定和 12 条经验。此项证明机器证据视图字段映射，不证明知识卡草稿质量、人工审核晋升或历史源补导入；这些仍属于后续 C3/C5。

### C3 历史目标记忆与跨轮恢复接续（2026-09-23，局部完成）

- 隔离 staged import 不再把所有旧目标记忆只归档：按源 manifest 的文件摘要和目标身份读取，逐条导入有用的旧 lead、note、next、handoff、fact、goal。缺少可验证 observation 的旧阴性/原语降为带 `Historical ... (unverified)` 标签的建议；精确 operation/step 且当前字节有效时才保留 negative/primitive。污染、错目标、无效条件、过大字段逐项隔离，不把历史文本当执行事实。
- 迁移 receipt 的 `memory_backfill.experience_map` 记录每个 Experience ID 的源路径、字段、索引或 key、旧 ID/时间；无正文副本。`--backfill-memory-source SOURCE --repo-root ROOT --target TARGET` 可在已 active 的隔离 Store 上按原 cutover manifest 显式补导入；同源重放不增长 revision，源摘要变化拒绝，已存在 receipt 时先核对再写。未对真实目标执行补导入。
- Resume 现在输出 Store 目标记忆窗口、条件、重开条件和按 ID 展开命令，不再把旧 JSON 路径当 primary 记忆来源。三个独立 checkpoint/pickup 轮次各有一次显式 handoff，旧记忆文件故意损坏、可重建投影删除后，经验和行动数量只随显式写入变化。
- 定向回归：`tests/test_target_migration.py tests/test_resume_tool.py` **90 passed**；`tests/test_target_migration.py tests/test_memory_loop_closure.py tests/test_experience_recall.py` **95 passed**（后续收紧前）。C3 仍缺 PatternDB 历史连续性、完整知识复用/晋升和跨消费者最终验收；C4/C5 未完成。

### C3 历史补导入恢复与 PatternDB 连续性接续（2026-09-23，局部完成）

- active 目标记忆补导入先确认原 cutover manifest 含目标记忆源；缺源/损坏明确拒绝，不以 `KeyError` 结束或发布空 receipt。独立 receipt 锁串行化核对、幂等 Store 写入与原子发布；半数行写入或全部行写入后中断，重试只补缺行，并发重试得到同一映射。
- 全局 PatternDB 不加入目标 cutover manifest，也不在 primary 正常召回中作为第二来源。新增显式 `--backfill-pattern-source`：按源文件字节摘要固定当前日志及 `.1`–`.3` 轮换文件，先发布 `pending` receipt；仅导入精确当前目标、结构有效且未污染的行，全部标为历史未验证 `note`，不伪造阴性/原语或跨目标知识。receipt 的 `experience_map` 保存 Experience ID、源路径、行号、行摘要/原时间；损坏行保留有位置的隔离诊断。同源重试幂等，源变更拒绝，中断可从 `pending` 继续。未操作真实目标。
- primary 组合召回回归确认：Store 经验 + registry 已登记卡可见；旧目标文件、旧 PatternDB 行和未登记卡不混入。知识草稿的人工审核晋升全链、M8 成本测量及其它 C3 消费者仍待验收，不能据此宣布 C3 完成。
- 定向验证：`python3 -B -m pytest -q -p no:cacheprovider tests/test_target_migration.py tests/test_experience_recall.py tests/test_distill_target.py tests/test_knowledge_audit.py tests/test_knowledge_promote.py` → **115 passed**；`python3 -B tools/target_migration.py --help` 成功；`git diff --check` 通过。未提交、未推送。

### C3 知识复用隔离全链接续（2026-09-23，局部完成）

- 使用隔离 Store 的真实 observation + 条件化 Experience 构造蒸馏证据视图；人工草稿沿现有 `knowledge/candidates/` 保存条件。晋升前其它目标的正常召回看不到候选卡或目标私有经验；调用现有 `knowledge_promote.promote()` 后 strict audit 通过、registry 登记，跨目标只出现知识卡引用，目标私有 Experience 仍不泄漏。这验证机械链路，不替代 AI 草稿质量或在线能力对照。
- PatternDB 中单个坏 UTF-8 行改为按行隔离；同文件后续合法行继续导入，并用源行字节摘要核对 receipt 映射。全局日志/轮换文件保持历史材料，不成为 primary 第二写源。
- 补充坏 JSON 标量/缺目标身份行的隔离诊断；其他目标的合法行只跳过、不导入。最终定向命令 `python3 -B -m pytest -q -p no:cacheprovider tests/test_target_migration.py tests/test_experience_recall.py tests/test_distill_target.py tests/test_knowledge_audit.py tests/test_knowledge_promote.py` → **116 passed**；`git diff --check` 通过。

### C3 primary 消费投影接续（2026-09-23，局部完成）

- `derive_owner_projection` 在 primary 上从 Store/当前证据/Recon 只读重建端点视图，不再由旧 `coverage_matrix.json` 的存在与内容决定已测/未测事实；即使 Store 没有端点，两个 authority 标志也阻止 Profile 回退。`read_matrix(current_only=True)` 排除旧矩阵历史行，不改变默认历史审阅视图。Context Pack、Checkpoint 与 Autopilot Closure 的 primary 读口也使用这一视图，旧矩阵端点不再伪装成当前 gap。
- Intel 的 `--repo-root` 现传入记忆上下文；primary 不从旧 Profile/journal 生成当前技术栈、端点或“已测 CVE”提示。Resume 和 Surface 在 primary 上不再加载旧 Profile；Surface 的 coverage 输入使用当前只读重建。隔离冲突/损坏旧文件样本通过，当前 Recon 未测端点仍可见。
- 相关模块定向回归 `tests/test_context_pack.py tests/test_checkpoint.py tests/test_autopilot_state_tool.py tests/test_runtime_state.py tests/test_resume_tool.py tests/test_intel_engine_primary.py tests/test_surface_primary_owner.py tests/test_coverage_matrix.py` → **715 passed**（含当前 Recon 未测端点断言）；原 Pack 测试依赖旧矩阵行保留的断言已改为当前来源语义。`git diff --check` 通过。C3 尚未完成：其它消费者与 Store-only 全链、旧责任退役和 C5 成本/能力对照仍需继续；未操作真实目标。

### C3 Hunt/Intel 与 Scope 接续（2026-09-23，局部完成）

- primary Hunt 收尾不再写旧 Target Profile；会话 journal 仍记录摘要，但发现数量和类别取 Store 投影，不把旧报告类别当当前事实。Intel continuation 遇到 Store 故障不再作为坏 legacy Queue 吞掉。
- 损坏旧 Profile、冲突旧报告、缺失 fenced Store、坏 legacy Queue 的隔离回归通过；Hunt/Intel 定向测试分别为 **10 passed**、**5 passed**。这不代表 C3 整链完成。
- Scope 是独立执行准入，不是建议性目标记忆。`recon_candidates.py`、`recon_host_verify.py`、`request_guard.py` 仍读旧 Profile 的 `scope_snapshot`；在确定独立 Scope 来源及迁移/拒绝规则前，不删除这份排除项以免扩大执行范围。Host 验证器曾在 `ScopeContext` 排除后又以目标域名匹配放行，并且未按实际 scheme/port 复核；现仅由 `ScopeContext` 判定，实际探测前再核 scheme/port/连接目标和 Host。候选筛选接受明确授权的 HTTP(S) 端口，实际请求仍按单一选定 scheme 准入。损坏、错目标或形状错误的旧 Scope 来源不发布完成 summary。无网络定向回归 `tests/test_recon_host_verify_scope.py tests/test_scope_context.py` **15 passed**；C4 退役 Profile 时必须先解决 Scope 来源，不能把“建议性 note 不授权”误用为“旧 Scope 可忽略”。

### C3 Recon Scope 分类接续（2026-09-23，局部完成）

- `recon_candidates.py` 的资产关系分类与相关资产关联改由同一 `ScopeContext` 判定；删除 `ScopeChecker` 加原始目标匹配的双重规则。`scope_source.py` 是过渡期唯一旧 Profile Scope 读取点，Host/Recon/Runtime 不再各自解析这份快照；错目标或非法 snapshot 明确拒绝，不将坏排除项当空集。外部链路候选仍保留为 context/review，不因未授权而丢弃。
- 资产关系分页游标绑定 `scope_hash`；Scope 更改或续页原始文件缺失时拒绝旧游标。Runtime 完整/快速读口重新核对已发布摘要的 Scope hash，Surface 不再把失效分类输出为当前 lead；原始文件仍保留供复核。隔离回归 `tests/test_recon_candidates_asset_relation.py tests/test_recon_candidates_scope.py tests/test_recon_host_verify_scope.py tests/test_scope_context.py tests/test_runtime_state.py tests/test_surface_primary_owner.py` **64 passed**（最终断言补入后重跑）；受保护的未跟踪 `tests/test_recon_candidates_asset_relation.py` 只运行、未编辑。独立 Scope 来源与 Profile 退役仍待 C4，C3 仍未完成。

### C3 Request Guard Scope 遥测接续（2026-09-23，局部完成）

- `request_guard.py` 的 preflight/record 复用 `scope_source.py` 的已加载 Profile 解析，不再自行筛掉坏字段或重新解释 `scope_snapshot`；Profile 只读一次，RPS/熔断设置读取路径及 advisory 契约保留。CLI allowlist 仍按原有覆盖语义使用，CLI 排除域名/类别改为追加到 Profile 排除项，不能把已排除目标误报为 `pass`；坏 Scope 报 `invalid/skip`，不生成通过判断。
- 定向回归 `rtk proxy python3 -B -m pytest -q -p no:cacheprovider tests/test_request_guard_tool.py tests/test_recon_host_verify_scope.py tests/test_recon_candidates_scope.py` → **25 passed**；`git diff --check` 通过。该工具只提供遥测，不代替实际请求准入。独立 Scope 持久化来源及迁移/拒绝规则仍未确定，Profile 排除项不能在 C4 直接删除；C3/C4 均未完成。

### C3 Store-only Case 续跑读口接续（2026-09-23，局部完成）

- `build_autopilot_state` → `_load_case_state_projection` → `target_case_state.summary` 的 primary 链路不再以旧 `case_state.json` 是否存在为前置条件；投影路径指向当前 Store。Store 中的未决假设在旧文件不存在时仍进入 `resume_case_state`，legacy 缺文件/损坏文件语义保留。
- 定向回归 `rtk proxy python3 -B -m pytest -q -p no:cacheprovider tests/test_autopilot_state_tool.py -k 'primary_case_projection_uses_store_without_legacy_file or case_state_work_routes_bootstrap_and_blocks_exhausted_closure or malformed_case_state_returns_structured_state_error'` → **3 passed**。其它 C3 消费者与 Store-only 全链仍需继续核验，不能据此宣布 C3 完成。

### C3 Resume/Autopilot 当前记忆判定接续（2026-09-23，局部完成）

- primary Resume 的 `canonical_sources` 仅保留真实 runtime 文件，不再把退休的 Queue/Case 文件存在性报为当前来源；legacy 的来源顺序及兼容行为不变。
- Autopilot 不再以空 Store 的只读投影 `available=true` 断言已有 hunt memory；Store 行动、Case 实体/假设、目标意图/经验及当前 Finding/端点仍使记忆可恢复。旧 Queue/Case 损坏文件在 primary 下不会改变该判定。
- primary Resume 的确认数量改从 Store 当前技术裁决取得；旧 journal 的 `confirmed/payout` 只保留在 legacy 历史展示，不给 Store 未裁决主张提权，也不显示没有当前依据的金额。
- 定向回归 `rtk proxy python3 -B -m pytest -q -p no:cacheprovider tests/test_autopilot_state_tool.py -k 'primary_resume_memory_requires_store_facts_not_legacy_owner_files or primary_case_projection_uses_store_without_legacy_file or case_state_work_routes_bootstrap_and_blocks_exhausted_closure'` → **3 passed**；`tests/test_resume_tool.py -k 'primary_resume_does_not_promote_historical_journal_result or primary_resume_ignores_retired_profile or loads_profile_journal_and_pattern_matches or canonical_queue_state_is_a_resume_source_without_profile'` → **4 passed**。C3/C4 仍未完成，未操作真实目标。

### C3 Context Pack 目标经验读口接续（2026-09-23，局部完成）

- primary Pack 复用 `load_goal_memory` 的 Store 查询，单次有界取最近 5 条经验；JSON 和默认文本均保留 kind、条件、重开条件、下一意图、证据引用、准确总数/余量和按 ID 展开命令。回归含一条绑定真实 operation 的条件化阴性结果及 7 条/5 条续页；续页命令绑定实际 `--repo-root` 与 revision 游标，可在隔离根直接运行；查询不改 Store revision。
- SQLite DB 从目标记忆和 evidence-summary 两条 `must_read` 来源排除，避免把二进制文件当可读材料；原有 evidence anchors/source summary 保留。primary 的 `do_not_load` 不再要求从旧 `findings.json` 读索引，而是指向 Store Finding ID 与证据引用；legacy 提示不变。Pack 的 `ai_override` 不再要求把选定 Skill 路由写入 Queue，原生 Skill 选择仍留给 AI；Queue/Store 路由逻辑退役仍属 C4。
- 首次定向回归发现 evidence-summary 第二条 DB 路径后已修；修正后 `tests/test_context_pack.py -k 'primary_context_pack_reads_conditional_memory_without_sqlite_must_read or primary_context_pack_exposes_one_store_revision_binding or primary_goal_memory_projection_uses_store_case_context or must_read_omits_absent_target_state_paths'` → **4 passed**。相关文件完整回归 `rtk proxy python3 -B -m pytest -q -p no:cacheprovider tests/test_context_pack.py tests/test_core_foundation_tools.py` → **152 passed**。C3/C4 尚未完成，未操作真实目标。

### C3 Checkpoint 条件记忆输出接续（2026-09-24，局部完成）

- 用户明确要求继续原 Trellis 任务，已恢复当前会话的任务指针；保持主线程实施，不新建任务。执行前 diff 与受保护测试指纹保存在 `/tmp/ccst-c3-checkpoint-memory-20260924/`，64 项既有工作区改动保留。
- 真实新进程 CLI 回归复现：`build_checkpoint` 调用 Context Pack 后重组字段，却丢弃 `active_goal` 与 `target_experiences`，空经验和 7 条经验两种情形均缺该字段。现在 primary Checkpoint 直接保留已查询的 Pack 意图和 5 条经验窗口；文本复用 `context_pack.format_target_experiences`，不另开查询或复制字段映射。条件化阴性的条件、重开条件、下一意图、证据引用、准确余量和绑定目标根的续页/展开入口均可见。
- 回归覆盖空经验、7/5/2 窗口、真实 operation 引用、损坏旧目标记忆、含空格的隔离根，以及实际 CLI 续页和按 ID 展开的精确条目集合。读取后 Store binding 不变，不生成旧 Queue 或 checkpoint witness；旧目标输出保留。未改变 schema、行动选择、显式 handoff、安装 runtime 或真实目标数据。
- 定向命令：`rtk proxy python3 -B -m pytest -q -p no:cacheprovider tests/test_checkpoint.py tests/test_context_pack.py -k 'primary_checkpoint_cli_preserves_goal_and_conditional_memory or primary_checkpoint_projects_store_actions_without_legacy_queue or checkpoint_without_recon_recommends_refresh_recon or primary_context_pack_reads_conditional_memory_without_sqlite_must_read or must_read_omits_absent_target_state_paths'`。初次行为回归为 **2 failed**（缺 `target_experiences`）；修复后 **6 passed**。本次不以局部通过替代 C3 全消费者/M8 或 C4/C5 验收，不提交、不推送、不归档。

### C3 Resume 完整分页与根绑定接续（2026-09-24，局部完成）

- 真实新进程回归复现：Resume 先读 20 条、再展示 5 条，却沿用原余量/游标。7 条时错误声称剩余 0，23 条时声称剩余 3 且续页跳过中间 15 条；首次定向结果 **2 failed、1 passed**。现由 `load_resume_summary` 明确请求 5 条，保留完整返回页，不再二次截窗。
- `load_goal_memory` 在分页元数据中提供一条 shell-quoted `recall_command`，绑定绝对 repo root、canonical target 和请求 limit。Resume、Context Pack 和 target-memory `show` 复用，避免各自漏传根；`show` 仍保留默认 20 条、原 cursor 和 ID 模板，增加可直接执行的续页命令。Resume 文本补齐经验 kind、operation 引用和作者，未改变领域写入、schema、行动选择或 legacy 输出。
- 根因是分页行集与元数据跨层脱节，兼有命令参数重复拼装遗漏；已有三轮恢复每轮最多 4 条，未触发窗口边界。新增 0/7/23 条回归在含空格的隔离根运行真实 Resume CLI，从文本提取续页/展开命令并执行，逐页核对余量和完整精确 ID 序列；同时保留三轮 no-echo 和 Pack/Checkpoint 回归，扩充现有 `show` 的实际命令执行检查。读取后 Store binding、损坏旧记忆原字节不变，不发布 witness。
- 最终验证：`rtk proxy python3 -B -m pytest -q -p no:cacheprovider tests/test_resume_tool.py tests/test_core_foundation_tools.py tests/test_context_pack.py tests/test_checkpoint.py -k 'primary_resume_memory_window_is_complete_and_root_bound or primary_three_round_pickup or target_memory_show_reports_bounded_store_history or target_memory_primary_selection_and_goal_are_store_owned or primary_context_pack_reads_conditional_memory_without_sqlite_must_read or primary_checkpoint_cli_preserves_goal_and_conditional_memory or loads_profile_journal_and_pattern_matches'` → **10 passed、348 deselected**，8.74 秒。未跑全量；C3 全消费者/M8、C4/C5 仍未完成。
- 执行前 diff 和受保护测试指纹位于 `/tmp/ccst-c3-resume-memory-20260924/`。不使用子代理、不提交、推送或归档，不修改真实目标数据、安装 runtime 或受保护测试。

### C3 日常记忆 CLI 与验证骨架接续（2026-09-24）

- `target_memory.py` 原先没有 `--repo-root`/`--json`，先前 monkeypatch 测试不能证明日常真实进程入口。新增真实子进程回归先因 argparse 缺参失败；现显式传递 root 到 Store、pointer 和 legacy helpers，不修改全局常量，支持选项放在子命令前后。JSON 保存返回原 Store receipt，show 返回共享投影；参数/内容错误结构化 exit 2。目标意图提交后 pointer 发布失败保留 receipt 与 failed selection，原 command/content/revision 重试不增加 revision。
- 新测试覆盖全部日常命令、带空格根、第二数据根隔离、错误零写入和幂等；首次实现后的失败为新测试错误要求 replay receipt 连 replayed 标记也完全相等，已按既有收据契约修正，未改变领域幂等语义。`rtk proxy python3 -B -m pytest -q -p no:cacheprovider tests/test_target_memory_cli.py tests/test_core_foundation_tools.py tests/test_stage_one_ux.py -k memory` → **17 passed、41 deselected**，2.57 秒。
- 骨架真实缺口是 `Store.family -> scaffold.vuln_class` 映射丢失，不是整个 validate 未接 Store。两种 family 回归先复现空字符串；修复后按 canonical family 核对（auth_bypass 在 Store 中规范化为 Authz），开放 family 保持原值，AI 判断字段仍空。`rtk proxy python3 -B -m pytest -q -p no:cacheprovider tests/test_decision_scaffold.py` → **12 passed**，0.49 秒。
- 此后继续推进，不把单批通过当作任务停点。候选截窗已定位为 primary 实际调用链，完整候选可访问性与 M8/其它消费者仍待处理；C3/C4/C5 未完成。不提交、推送、归档或修改真实目标/runtime。

### C3 记忆有界快照与局部成本证明（2026-09-24）

- `load_goal_memory` 原先调用全量 `case_context`，每个 Case 假设再读两组关联，仅用于一个 current_hypothesis；目标意图、Case 与经验分别读取，存在混合 revision。现 `TargetStore.memory_context` 在单读事务中读取意图、原 stable ID 序的一个 Case 前提和经验页；分页 SQL 与原 `experience_page` 共享，不新建事实源。记忆不再读取无关 private Case 材料；独立 Case readiness 的完整性检查保留。
- 全量 Case 禁用回归先失败，修复后包括并发写入、schema、CLI、分页和 Pack 在内的 focused check：`rtk proxy python3 -B -m pytest -q -p no:cacheprovider tests/test_core_foundation_tools.py tests/test_target_store.py tests/test_context_pack.py tests/test_target_memory_cli.py -k 'memory or experience_page or primary_goal_memory'` → **25 passed、223 deselected**，3.29 秒。并发写入真实提交，但返回的 goal/page/revision 保持旧快照一致。
- `research/measure_memory_query.py --baseline /tmp/ccst-c3-memory-query-20260924/tools/target_memory.py` 在同一隔离 fixture 比较保存的旧消费者与当前消费者，100/1000 条 Case 假设、窗口 5、15 次交错运行，完整 JSON 相等且 Store binding 不变。100 条：连接 4→2，SQL 233→18，Python 实际接收 SQLite 行 116→13，中位 4.477→2.059 ms；1000 条：SQL 2033→18，行 1016→13，中位 13.322→3.072 ms，峰值 Python 分配 932107→15627 字节。原始数据与基线 SHA 见 `research/memory-query-cost-20260924.json`。
- 成本结论仅适用于共享记忆查询：SQLite 内部扫描、Pack/Checkpoint/Resume 整链、外置证据 I/O、DB/WAL/备份成本及在线能力尚未在此测量，不据此关闭完整 M8 或 C5。执行前文件备份在 `/tmp/ccst-c3-memory-query-20260924/`。

### C3 目标意图无 revision 重试修复（2026-09-24）

- 新真实 CLI 回归复现 `set --goal --command-id` 省略 expected revision 时，第一次成功后原 argv 重试误报 content conflict；pointer 发布失败同样不能用原命令恢复。原因是消费者每次重算 revision，污染同一命令的内容身份。
- 可选 revision 的解析移到 `TargetStore.set_active_goal`：已提交命令复用 receipt revision−1，未提交命令捕获当前 revision，再执行原 CAS 与完整 command/entity/actor/content 校验。未放松并发控制，不改历史 receipt digest；原明确 revision 调用不变。后来已有新意图时重放旧命令只返旧收据，不回滚新意图。
- `rtk proxy python3 -B -m pytest -q -p no:cacheprovider tests/test_target_memory_cli.py tests/test_target_store.py tests/test_core_foundation_tools.py -k 'memory or goal_cli'` → **21 passed、117 deselected**，4.10 秒。保留 explicit/implicit revision 两种 pointer 恢复和更改内容冲突回归。

### C3 Checkpoint 未决行动与实际认领恢复（2026-09-24）

- 旧 primary 测试仅检查零写入，未核对行动 ID；补断言后复现 Store `WORK-1` 被输出中的临时建议 `A1` 替代。primary 现直接保留 Store 未决行动原 ID/状态/原因/metadata/command_hint，默认按 ID 展示 5 条并返回 total/remaining 和可执行完整查询。完整查询是新快照且含终态历史；没有伪造分页 cursor。
- primary 不再调用旧 lead/next/dead-end 或固定类型/priority 建议生成器，不自动选择未认领首项；已有 claim 即使位于窗口外仍显示为当前工作，blocked 不隐藏、cancelled 留在历史。Runtime wait 锁仍优先且不清掉实际未决列表。Resume 保留窗口与展开命令，也不重新把首项选作 current action。
- Autopilot 原 primary 字段映射遗漏 Store descriptive metadata，已改用已有 `action_queue.load_queue` 公共读口，删除重复映射。正常写入、claim/证据约束没有改动；旧生成器及 legacy 行为留待 C4。
- 定向回归先为 **2 failed**；最终 `rtk proxy python3 -B -m pytest -q -p no:cacheprovider tests/test_checkpoint.py tests/test_resume_tool.py tests/test_autopilot_state_tool.py -k 'primary_checkpoint or primary_three_round or primary_resume or primary_case_projection or checkpoint_without_recon_recommends_refresh_recon or bounded_proposals_preserve_lane_types or checkpoint_cli_syncs_durable_action_queue_idempotently'` → **16 passed、415 deselected**，10.01 秒。含 12/5/7 窗口、实际完整 CLI 展开、窗口外 claim、blocked 原因、cancelled 历史、三轮交接和 legacy 兼容。
- 执行前备份 `/tmp/ccst-c3-action-view-20260924/`。共享 Action owner 仍全量读取；其它 Surface/Coverage 原始候选可访问性及整链成本未由此证明。C3/C4/C5 仍未完成；持续按批准范围推进，不要求用户逐补丁确认。

### C3 蒸馏真实进程展开接续（2026-09-24）

- 既有蒸馏仅返回 Finding cursor、经验展开漏 repo root，Case 截取字符串也无完整读取命令；新增真实进程回归先复现缺 `next_command`。现两个窗口保留 Store binding/order/count/has_more，文本和 JSON 均给续页及 ID 展开；经验作者可见，Case 标记 preview 并给完整查询。
- 为现有 `finding_page/finding/case_state` 添加最薄 `target_store.py findings/case` 只读 CLI，复用 runtime admission，不增 schema/query model，不建库或回退 legacy。root/target 使用 shell quoting，Finding/经验沿各自 cursor 继续，ID/完整 Case 是新查询。未填 AI 草稿或自动晋升。
- `rtk proxy python3 -B -m pytest -q -p no:cacheprovider tests/test_distill_target.py tests/test_knowledge_promote.py` → **16 passed**，1.91 秒。覆盖 12/10/2 Finding/经验精确尾页、实际 ID/Case 展开、来源/条件、stale cursor 非零、未初始化零创建及原人工晋升流程。没有跑全量，没有真实目标或安装 runtime 操作。

- 本批 diff 复核另发现蒸馏把长 Finding/event ID 截断，导致展开缺少完整标识；已保留完整 ID/endpoint，claim 的 160 字截取显式标为预览。新增长 ID/endpoint 回归；最终 `rtk proxy python3 -B -m pytest -q -p no:cacheprovider tests/test_distill_target.py` → **7 passed**。`git diff --check` 与受保护测试 SHA 核对通过；未执行全量测试。


### C3 Surface/Coverage 完整访问与剩余消费者接线（2026-09-24）

- Surface 原展开提前消费但未展示 index 前 50 条、漏 repo root，小于 50 条时甚至没有展开入口。现从完整 index 首页开始，包含外部关系上下文，命令 shell-quote 绝对 root；默认文本和缓存保留完整命令，Surface CLI 增加显式 `--repo-root`。没有把 review pool 当作 index 页，也没有给旧快照伪造 cursor。
- 真实 CLI 进一步复现 Coverage `find-gaps`/`needs-triage` 仍直接读退休矩阵。两个普通入口现复用 `read_matrix(..., current_only=True)`，旧文件损坏不再阻断当前 Store 查询；有界输出提供 total/returned/remaining/truncated/order/expand_command，triage 增加 `--all`。Checkpoint 的 10 条 gap 窗口与文本有完整查询。
- 无有效 index 时 Coverage 原先只读 all.txt，会漏 API/browser/JS 输入；primary 现复用 Surface 的 `recon_source_iterators`，不自动发布 index。Surface index 的 Finding URL 改读 Store，manifest 绑定其 identity/revision，不再读取或 stat 退休 findings.json；Coverage fingerprint 覆盖同组真实来源。查询保持零领域写入。
- Coverage 改按 endpoint/class 身份顺序，triage 按 endpoint 顺序；route kind、参数存在、source count 和类别枚举位置不再决定首窗。更新对应旧排序断言，因为 R1 明确要求移除这些优先级替身；原始观察字段保留。Coverage build version=7、Surface projection schema=4 让旧派生缓存失效，不涉及 DB schema。
- Surface/Coverage 定向组：`rtk proxy python3 -B -m pytest -q -p no:cacheprovider tests/test_surface_primary_owner.py tests/test_coverage_matrix.py` → **143 passed**（新 Store index 失效用例加入前）；新增 `-k binds_store` → **1 passed**。随后跨消费者组 `tests/test_surface_primary_owner.py tests/test_native_judgment_boundary.py tests/test_checkpoint.py tests/test_context_pack.py tests/test_resume_tool.py -k 'primary or surface'` → **65 passed、2 failed**；两个失败是已改变的故障边界：Store 变动更早在 index stale 校验拒绝，preview 不再允许正常 Surface 查询。保留旧 projection 字节、真实排他锁阻塞、零 preview index 发布的断言并按新契约修订测试；两项重新验证 → **2 passed**。没有降低故障准入。
- 备份 `/tmp/ccst-c3-access-20260924/`。Surface 的旧 score/frontier/soft preference 和普通 legacy 分支仍存在；此次证明完整原始访问及接线，不据此宣称 R1/C3/C4 完成。

### C3/M8 恢复链成本与 Case 关联批量读取（2026-09-24）

- `case_context()` 原对每条假设读取两组关联；现同一事务批量读 actor/object links，保留完整结果、原 ID/actor 顺序、空引用、metadata、私密材料检查及 readiness。`tests/test_target_store.py tests/test_target_case_state.py -k 'case or hypothesis'` → **46 passed、85 deselected**，1.07 秒；包含 100 条假设的恒定 SQL 上界及精确关系核对。
- `research/measure_recovery_query.py` 复用已有计量代码，对同一临时 Store 的 recall、负结果 ID 展开、Pack、Checkpoint、Resume、蒸馏进行前后完整输出比较，100/1000 条 Case 假设，固定 12 行动、12 Finding、7 observation。前后各 15 次交错运行；parent 固定时钟避免 as_of 噪声，额外各 15 个真实新进程 Resume 使用正常时钟。原始数据见 `research/recovery-query-cost-20260924.json`，基线及 SHA 在结果中；备份 `/tmp/ccst-c3-recovery-cost-20260924/`。
- 1000 假设：Checkpoint SQL **5920→1924**、中位 **251.787→243.833 ms**；Resume SQL **6311→2315**、中位 **285.644→270.989 ms**；蒸馏 SQL **2115→117**、中位 **16.418→13.348 ms**。Pack 不读全 Case，SQL/连接/返回行数均未变。100 条时 Checkpoint/Resume 中位反而变慢；不能宣称稳定整链提速。连接数仍为 Pack 62、Checkpoint 170、Resume 200，Case/Action/closure 全量读取及反复验证仍是债务。
- 两种规模的 parent 输出完全相等，Store binding 不变。新进程 Resume 中位 **549.298/555.845 ms**；记录 JSON/文本字节，不把字节当模型 Token，也没有测在线重复探测、模型能力或 SQLite 内部扫描行数。
- DB 331776 字节起，100/1000 假设后为 **372736/720896** 字节，关闭连接后 WAL 均 0。SQLite backup 单次 **4.343/1.818 ms**，隔离文件复制恢复 **3.167/1.984 ms**；恢复后 binding、完整 Case、条件化经验、证据完整性相同。仅静默自包含 fixture 的单次备份/恢复，不代表并发 WAL 故障验收或真实目标恢复。
- C3 全消费者/业务全链、C4 旧责任退役和 C5 全面成本/能力验收仍未关闭。持续推进；未提交、推送、归档、修改真实目标/安装 runtime/受保护测试。

## 2026-09-24 C3：Runner claim 与真实 CLI 验证闭环

- `validation_runner` 的 request/native API 与 CLI 新增显式 `action_id/claim_token/command_actor`（CLI `--actor`）；复用 Store claim 校验，操作作者与观察 actor 分离。缺项、错误操作者/token、work、释放的 claim、endpoint/family 不一致均在请求或材料发布前拒绝。完整/partial summary 保留绑定；不自动完成。
- request-diff 的同 attempt 重放拒绝再次执行；登记可用已保存 summary 重试。native 同 argv 跨进程登记幂等，即使该行动已显式完成也不会重新执行或改变状态。原未绑定 summary 不新增默认绑定字段。修复 native 小数秒被截断导致 observation 早于 attempt 的错误。
- 真实 Store-only CLI 回归发现 preflight 漏接旧 Finding owner；`load_finding_prefill(..., target=...)` 现在统一 scaffold/preflight/apply 的 root/target/Store 读取，preflight 的报告归属查询也传目标。不存在通过生成旧文件来绕过。
- validate 只产生草稿及技术/交付裁决，测试明确随后调用 report CLI 登记产物。报告 CLI 原固定源码目录输出，现 Store 路径从输入 owner 根解析；保留 symlink/owner 约束。
- 新进程链：claim（公共领域 API）→ record-evidence --no-sync → 原 argv 登记 → scaffold → preflight（revision 不变）→ validate → report CLI → 显式 complete → 原 argv 幂等 → Checkpoint/Resume。全链临时根含空格，无 monkeypatch BASE_DIR、无真实网络，无旧领域文件。测试检查 operation/claim、观察 actor/小数秒、报告绑定和恢复后的完成引用。

验证：

1. 新 claim/故障/闭环 focused：19 passed、1 failed。失败是 preflight 漏接，修复后推进到报告步骤；中途错误断言“validate 已注册报告”按实际独立报告契约修正，未改变生产生命周期。
2. 完整真实 CLI 闭环：1 passed、118 deselected，2.42 秒。
3. `rtk proxy python3 -B -m pytest -q -p no:cacheprovider tests/test_validation_runner.py tests/test_validate_target_mode.py tests/test_decision_scaffold.py`：184 passed，6.09 秒。
4. `rtk proxy python3 -B -m pytest -q -p no:cacheprovider tests/test_finding_index.py -k 'primary or prefill or report'`：46 passed、48 deselected，1.71 秒。

修改前备份：`/tmp/ccst-c3-runner-claim-20260924/`。受保护测试 SHA256 仍为 `b590266d9cc8b07ce59af5cb8e0c9636ea3b4fbc962e1998b66a18a562dfbb85`。未提交/推送/归档，未改真实目标。

这是 C3 的一条工程闭环证据，非 C3/C4/C5 完成。仍需解决 Coverage 作者输入、Scope 独立来源、Surface 隐含排序、Pack/Resume 展开和退役清单。另观察到 validate 的 assessment identity 仍取含时间的 summary，前驱从当前 Finding 动态读取；命令级 apply/裁决部分失败的重放语义需继续验证，不能以 native 登记重放结果代替该项。

## 2026-09-24 C3：Pack/Checkpoint/Resume 完整材料入口

- Context Pack 将当前 Surface index 的 count/revision/首页完整查询与 Coverage 的 total/order/完整查询作为 `source_queries` 输出，Checkpoint/Resume 直接透传。文本共用渲染函数，明确 anchors 是预览而非分页，未伪造 returned/remaining。保留外部关系 URL，不插入过滤或首窗游标，不新增读取/缓存写入。
- `tests/test_surface_primary_owner.py::test_primary_pickup_preserves_surface_and_coverage_expansions` 用含空格 root、空集和 57 个内部 URL + 1 个外部 URL，分别运行三种真实 CLI 的 JSON/默认文本和每条完整查询；逐页核对所有精确 URL、index revision、Coverage 全集合与总数。Store binding/raw 不变，Checkpoint 不落盘 witness。
- focused：2 passed、6 deselected，8.49 秒；相邻 `tests/test_context_pack.py tests/test_checkpoint.py tests/test_resume_tool.py -k 'primary or surface'`：55 passed、264 deselected，13.10 秒。
- 备份 `/tmp/ccst-c3-pickup-access-20260924/`；`git diff --check` 通过。未声明 Surface 排序/全部窗口 R1/R8 完成。下一项继续核对 Scope 独立来源：当前 Profile snapshot 还包含 exclusions 和 request_guard 的速率/breaker 配置，不能仅移除 Profile 读取。

## 2026-09-24 C3：Validate 稳定命令、部分失败恢复与独立交付

### 实测根因与修复

- 原真实 CLI 重复 apply 同一 decision 再次返回 `updated`，会新建 assessment 并使已有报告 stale。新增回归首次运行失败（1 failed，1.51 秒），直接证明该缺口。
- 现以原 decision JSON、store_id 和所选 operation 的 Finding 关联观察构造稳定命令。scaffold 填 `store_preconditions.assessment_id/delivery_id`，首个裁决为 null；写后重复 apply、改运行时间、先 assessment 后 delivery 失败均重用原命令/前驱，Store 自身仍负责幂等、内容冲突与 CAS，不改 Store schema。修改裁决必须明确当前前驱；过时输入在报告/summary 写入前拒绝。
- summary 持有 `machine_decision.store_command` 作为可重放请求，含 Store 代次、命令 ID、证据与前驱。旧 primary summary 不猜前驱，明确要求重新生成 scaffold。未增加第二个裁决 owner 或新表。
- primary preflight 原只检查 operation 存在和首步方法，未验证归属/当前材料完整性。现要求完整 operation、该 Finding 的关联步中有 endpoint/method 匹配，并调用 `verify_operation`；外来 operation、部分材料、哈希变化均拒绝，零报告/裁决写入。多步证据不要求锚点是第一步。
- 评审只引用明确选定 operation 的关联观察，不再把同 Finding 下其他（可能 partial）的实验全部并入。测试增加另一条已绑定但 incomplete 的实验，当前完整证据仍可被正确评审。
- Store 技术判定现在只用 Gates 1–3、Q1/Q2/Q3/Q4/Q6；duplicate、known/documented、never-submit 对应 Gate4/Q5/Q7 只约束目的地。显式拒收产生 ineligible，待补报告门产生 deferred；技术门未通过仍 inconclusive。报告生成同时要求 confirmed 与 eligible，命令记录不替代模型的边界/影响判断。legacy 适配保留旧语义直到 C4 退役。

### 验证与边界

- 新重放/错误证明/真实 CLI：7 passed、118 deselected，3.38 秒；增加选择单 operation 与交付分离后 focused：14 passed、118 deselected，4.17 秒。
- 最终 `rtk proxy python3 -B -m pytest -q -p no:cacheprovider tests/test_validation_runner.py tests/test_validate_target_mode.py tests/test_decision_scaffold.py`：**197 passed，7.89 秒**。包括先后两处裁决故障注入、重试只提交未完成命令、时间独立重放、前驱显式更新、不变 Store revision、报告不被重复 apply 失效，以及 confirmed/ineligible 和 confirmed/deferred 的实际报告抑制。
- `git diff --check` 通过。受保护测试 SHA256 再核对为 `b590266d9cc8b07ce59af5cb8e0c9636ea3b4fbc962e1998b66a18a562dfbb85`。
- 修改前切片：`/tmp/ccst-c3-validation-replay-20260924/` 与 `/tmp/ccst-c3-validation-destination-20260924/`；此前本轮备份仍保留。没有提交/推送/归档、真实目标修改、安装 runtime 修改或在线模型调用。

C3/C4/C5 仍未完成：Scope 独立持久来源必须保留 Profile 的 out_of_scope/excluded_classes 和 request_guard 速率/breaker 设置；Coverage mark/triage 作者输入仍需归唯一领域表达；Surface `_SurfaceCandidateFrontiers`/score/soft preference 仍决定默认工作集，完整展开不等于 R1 已关闭；随后才能严格 Store-only 退役和 C5 全面成本/恢复验收。主线程已读取 ScopeContext/scope_source/request_guard 相关实现，尚未为这些待办改代码。

## 2026-09-24 C3：独立 Scope 来源与全部现有 ScopeContext 消费者

- `scope_context.py` 复用原有 schema-v1 parser/classifier，增加目标归属、四个速率/breaker 参数验证和 `state/<key>/scope.json` 原子发布。Store 只依赖该底层 owner，不反向依赖 Profile/runtime 适配器；静态依赖检查加入 Scope owner 本身，继续禁止旧 memory owner 依赖。
- `scope_source.py show/publish --manifest/--profile` 提供正常查看与显式导入/替换。primary 缺失、坏 JSON、错目标、symlink 或非私有文件均拒绝，绝不回 Profile/target-only。替换使用当前字节 SHA256；相同内容重放幂等，损坏 JSON 可凭当前字节摘要+有效备份显式修复。replace 前失败保留旧文件；replace 后目录 fsync 失败时，重试必须完成目录 fsync 后才能成功。
- fresh 初始化在既有 target exclusive lock 内发布 target-only Scope；重复 init 校验现有配置而不重置。已有 primary 缺 Scope 需显式发布，不自动采纳旧 Profile。本轮未对任何真实目标执行此操作。
- migration readonly preview 校验配置，隔离导入把旧 Profile 纳入 manifest/copy，单独发布 Scope 并在 receipt 绑定 `scope_sha256`；preview publish/promote 拒绝配置漂移。外部 HUNT_MEMORY_DIR 的相关 Profile 需导出到显式源，不能遗漏。Profile 其他字段保留为历史输入，不声称已迁移其全部责任。
- Recon 关系分类、Host verification、request_guard、Autopilot bootstrap/state、continuation、FFUF rotation 均读共同来源。排除先于候选 budget，变化使旧游标/续跑/轮转 completion proof 失效；缺 binding 不能继承旧轮转完成信息。显式 batch manifest/text 仍是单独的 Scope 输入。
- request_guard 仍为 advisory telemetry：保存四个限制，低正速率不再被 clamp 放宽，status 和执行遥测读口一致；配置无效在 telemetry 写入前返回错误。外部 memory_dir 调用显式传 repo_root。没有把遥测描述为全局主动请求准入。
- 新真实进程回归覆盖含空格 root 的 init/show/profile import/replay，Profile 不可用后的读取、预检/熔断，以及 FFUF 选取/登记/变更拒绝；其余覆盖归属/丢失/损坏/权限、原子失败/恢复、Recon 精确分页和 Host 选择、Autopilot 及续跑。网络入口仅替身核验，没有真实请求。
- 联合回归：`rtk proxy python3 -B -m pytest -q -p no:cacheprovider tests/test_scope_source.py tests/test_scope_context.py tests/test_request_guard_tool.py tests/test_recon_candidates_scope.py tests/test_recon_host_verify_scope.py tests/test_target_migration.py tests/test_target_store.py tests/test_hunt_initialization.py tests/test_autopilot_continuation.py tests/test_autopilot_bootstrap.py tests/test_autopilot_recon_rotation.py tests/test_autopilot_state_tool.py`：**503 passed，7.39 秒**。随后补缺 binding 拒绝与删除无调用方转换包装，定向 `tests/test_scope_source.py tests/test_autopilot_recon_rotation.py`：**32 passed，1.95 秒**。此前失败分别暴露 telemetry 提前建目录、Store 反向依赖以及测试把一页误当全集，均已修正。
- 备份：`/tmp/ccst-c3-scope-source-20260924/`；保护测试未编辑。没有提交/推送/归档、目标数据/安装 runtime/在线模型变更。

C3 仍未完成。下一项 Coverage 作者输入已开始读取：`mark_endpoint_kind` 和 `mark_cell` 写 matrix，而 primary current-only 从空投影重建，作者输入会丢失；旧 N/A 按既有契约只能作为建议，不能授权执行闭合。已确认不应把这些输入伪装为 execution observation，也不应塞进 Case object/hypothesis 的无关字段来绕过明确领域表达。尚未修改 Coverage 代码或 schema。Surface/FFUF 认知评分、C4 严格单 Store 退役和 C5 完整验收仍待完成。


## 2026-09-24 C3：Coverage 作者输入、历史导入与 v10 显式升级

- 确认 matrix 不能作为可重建投影和作者输入的双重 owner 后，在同一 Store 加入 `coverage_reviews`，仅保存 endpoint-kind/cell-status 评审及来源、作者、原因、时间、revision 和可选 Finding 关系。没有伪造 attempt/observation，也没有向 Case/Experience 添加无关字段。
- `mark-endpoint-kind` / `mark` primary 直接提交 Store，支持 `--actor/--command-id`，同命令重放幂等、内容冲突拒绝。可选 Finding 与评审原子提交；已有主张保持不变，新理由留在评审。primary mark 返回 advisory 评审和 receipt，不能冒充当前技术状态。
- 普通 read/rebuild/needs-triage/find-gaps 全部从当前 Store 取评审，不再依赖保存矩阵；删投影不会丢作者输入。分类可恢复，显式 untriaged 会重新出现；人工 tested_clean/n_a 不能闭合，闭合仍只来自 current_truth。Gap 输出保留相关评审理由，source snapshot 绑定 review IDs。
- 新 Store 为 v10；`upgrade-schema --backup` 复用原有 SQLite backup/身份/完整性验证、排他锁、事务/audit 升级协议，支持真实 v8/v9 结构。普通 query/init 不自动升级；v8/v9 的 Coverage review 入口提示显式升级。`upgrade-memory` 保留 v8→v9 入口，v9+ 目标记忆仍可用。没有升级真实目标。
- migration 只读 preview 和隔离 import 复用 Store normalizer 校验旧标注。非默认 cells 和作者分类作为 historical review 导入；默认空 cells 留在源。receipt 以 manifest/digest + review ID→JSON pointer 保留追溯；损坏、错目标、外部 URL 和新 Store 投影作为源均拒绝/隔离。
- `--backfill-coverage-source` 用既有活动 cutover manifest 显式补导入；receipt 写失败后重放不重复，历史输入不覆盖切换后的新评审。旧矩阵字节和有效原有证据状态均保留。
- 主回归 `rtk proxy python3 -B -m pytest -q -p no:cacheprovider tests/test_coverage_reviews.py tests/test_coverage_matrix.py tests/test_target_store.py tests/test_target_migration.py`：**306 passed，6.38 秒**。随后审查补齐 legacy 切换竞态拒写、去除重复评审投影、坏历史 endpoint 校验，并扩入真实 Pack/Checkpoint/Resume 材料入口：同命令加 `tests/test_surface_primary_owner.py`，**314 passed，24.20 秒**。
- 已核对相对本轮备份的三处产品 diff；`git diff --check` 通过。备份 `/tmp/ccst-c3-coverage-reviews-20260924/`。未提交、推送、归档或修改真实目标/安装 runtime/受保护测试。

Coverage 这一消费者缺口已闭合；C3/C4/C5 仍未完成。接下来删除 Surface/FFUF 默认工作集里的固定类别/词表价值排序，保留完整材料和机械 Scope/预算/续跑约束，然后继续严格单 Store 与旧责任退役。


## 2026-09-24 C3：Surface/FFUF 中性候选窗口

- FFUF pending batch 仅按 URL 排序；删除类别词表、根域优先、host/technology 多样性权重。Scope 排除、wordlist/scope binding、预算、完成登记和跨轮续跑保留。
- Surface 仍遍历完整 exact index，默认窗只保留字典序前 16 个 URL 与总数；删除 score/breakdown、来源优先和 shape 配额，`p1/p2/kill` 留空兼容字段。Browser/JS/source/scanner/memory 元数据保留，FFUF sample 按同一 URL 序合并并去重；不会重复计算余量。shape 仅用于导航。
- Projection schema 4→5 使旧排序缓存失效，发布/读回保留 `review_window` 的 order/total/returned/remaining/limit。默认 Surface 文本显示全 16 条，Autopilot/Pack 不再生成 score 文案；Autopilot 保留机械 cooldown 和明确恢复 focus 的显示规则。
- 命令/工具索引/recon-surface 契约已同步，备份 `/tmp/ccst-c3-neutral-selection-20260924/`。扩容脚本已改为验证尾项保留在完整 index；本批未运行 30 万行性能验收，不宣称性能收益。
- 验证 `rtk proxy python3 -B -m pytest -q -p no:cacheprovider tests/test_neutral_surface_selection.py tests/test_native_judgment_boundary.py tests/test_surface_primary_owner.py tests/test_scope_source.py tests/test_autopilot_recon_rotation.py tests/test_context_pack.py` → **166 passed，25.68 秒**。包含真实 CLI、缓存发布/读回、完整尾部可达、同 shape 多 variant、来源/严重性不影响默认窗、Scope 排除和 FFUF 跨轮穷尽。
- 继续检查 Autopilot 时删除了无意义 score=0，并修复文本直接索引旧 score 的消费路径；`rtk proxy python3 -B -m pytest -q -p no:cacheprovider tests/test_neutral_surface_selection.py tests/test_autopilot_state_tool.py tests/test_autopilot_bootstrap.py -k 'surface or recommended_targets' --tb=short` → **44 passed，223 deselected，1.67 秒**。中途 1 个 KeyError 已归因并修复，未改测试规避。
- 本批收口候选排序缺口，C3 全消费者、C4 旧责任退役、C5 工程成本和在线能力证据仍未完成。继续主线程实施；未提交/推送/归档、未操作真实目标或 runtime。


## 2026-09-24 接续：Skill 路由责任退役与 Checkpoint 类别来源修复

- 完成已接通消费者对应的 C4 Skill 子项：删除运行 `skill_catalog.py`、参数发现固定路由、Queue/Store 两处 Skill 文件/frontmatter/预设维度门槛；pivot/continuation 不继承旧路由，Checkpoint/witness 删除空壳。保留平台原生 Skill 加载、实验 `active_dimension`、Runner `tested_dimensions` 和证据/秘密/并发/预算约束。开放旧 metadata 不作 Skill 调用证明，迁移仍保留原处置键，不重写真实数据。
- 同步 commands/context-pack/js-read/hunt、docs/autopilot-lanes/architecture-contract、skills/README/runtime-protocol 和 backend 对应契约。`tools/`/`tests/` AST 检查无运行 catalog import；历史归档不恢复为当前 owner。备份 `/tmp/ccst-c4-skill-retirement-20260924/`。
- `rtk proxy python3 -B -m pytest -q -p no:cacheprovider tests/test_action_queue.py tests/test_target_store.py tests/test_primary_action_consumers.py tests/test_context_pack.py tests/test_direct_only_skill_contracts.py tests/test_target_migration.py --tb=short` → **391 passed，12.64 秒**。替换已退役的私有路由拒绝测试，新增无 Skill 文件时 Store-backed add/claim、旧字段不解释和 pivot 不继承的行为证明。
- 扩组首次另见 Checkpoint 无显式类别却生成 actor matrix gap。根因是 C3 Coverage 的完整缺口枚举被 `_evidence_vuln_classes` 当成已选方法；它原本接 gap 列表。现从已取得的同快照 observation records 与未决 Action 读取显式类别，普通 URL 或空 coverage cell 不再派生角色测试。扩充空目标回归同时覆盖 legacy/primary，保留有 IDOR 观察时 actor gap 的正向证明。
- `rtk proxy python3 -B -m pytest -q -p no:cacheprovider tests/test_checkpoint.py --tb=short` → **182 passed，8.40 秒**。初次新空 metadata 测试的断言也已按既有省略空字段格式修正。最终 `git diff --check` 通过。
- 严格 `runtime_store -> TargetStore` 与所有 None/legacy 分支尚未落地；已定位 migration `_legacy_sources` 仍调用普通 `load_queue`，必须先在同批保留明确的历史输入读口。C3/C4/C5 未整体关闭，不提交、推送、归档或操作真实目标。


## 2026-09-24 C4：严格 Store 接入与旧领域写入退役（接续中）

本段覆盖上一接续尚未记录的改动，阶段仍未完成，不用旧测试计数替代当前验收。

- Report、Case、Resume/Hunt、Runner/native registration、Coverage、Checkpoint、Validate、Surface 与 Intel 普通路径要求 Store。Report 删除 legacy 自动报告/Queue 补写，手工报告保留在 drafts；Case 删除 JSON writer，私密材料保留；会话 header 合并与 object status 保留已修复。
- Runner 删除 Ledger/Finding/Queue 补偿和登记后再次改写 Finding 的逻辑。Validate 只提交 Store assessment/delivery，registered report 路径不能被草稿覆盖。查询不恢复 Profile/旧 Finding/旧 Ledger。
- Probe 在网络前固定 Store/attempt 并持目标切换锁；raw 以 0600 写入，登记失败保留材料/attempt，不重发请求。共享 target_paths 统一本机字面别名归属，保留原始 URL，协议/端口与外部主机限制；CLI 对 StoreError 清晰退出。closure records 补传原有副作用标志，避免 summary 漏计。
- Scanner/Hunt 改用 index_scanner_material：category txt 和不完整 root claim 形成不可变 review 快照与 Store work Action，不捏造 method/operation/verdict。输出 scanner_candidates.json，旧 findings.json 不改。嵌套 sessions 归属到目标 Store，source_id 带完整 repo-relative 路径。直接 scanner 在网络/材料前检查 Store。Autopilot 保留 raw claim 可见性，不把它自动提升为队列工作。
- 删除 Finding 的整表 writer/upsert/status/provenance append/读取时迁移，保留 load_legacy_finding_index 只读历史入口与旧 provenance 验证；target_migration 已接新显式名称。
- 删除 Ledger record_entry、CLI record/from-probe、旧写入命令提示和旧跨目标 JSONL aggregate 分支；summary 继续读取统一 current_truth。历史 JSONL 诊断仍供迁移。
- 删除 Action save_queue/ingest_checkpoint/upsert、旧私有 resolve、hypothesis 自动 pivot/continuation、Coverage/unsafe-review 补写；公共 add/claim/resolve 继续由 Store 处理。Checkpoint 删除 40 个无正常调用方的提案/类别排序/队列转换/自动链路私有函数；显式 round/witness 保留。
- 生产模块清理无调用方 import/reexport；尚需完成相关旧公共行为测试迁移、私有测试退役和 CLI/spec 同步。此时旧测试文件仍引用删除 API，不能宣称全量可收集或 C4 完成。

已运行：Probe+Scanner 39 passed（12.04s）；Store+显式 migration+Scanner 168 passed（3.84s）；本批核心模块 F821 通过。迁移测试的 Case 输入改为固定历史文件，preview 检查直接用 Store 读取，不再调用严格普通运行接口。旧 API 顶层 import 导致的初次 collection 错误已在这组内修正；其他旧测试仍待迁移。

保护文件 SHA256 再核对为 b590266d9cc8b07ce59af5cb8e0c9636ea3b4fbc962e1998b66a18a562dfbb85。未提交/推送/归档，未操作真实目标/安装 runtime，未运行在线模型对照。C5 成本、WAL、全链及 R10 仍未完成。


## 2026-09-24 C4：Runner、Ledger、Queue 与 Context/Coverage 消费者回归迁移

接续记录此前未落盘工作与本轮结果；C4/C5 仍未完成。

- `test_validation_runner.py` 使用显式 Store fixture 与真实 native attempt/claim；删除已退役 Checkpoint 自动入队、按 URL 猜 Queue、跨 owner 补偿测试。保留 raw、partial、scope/auth、请求差分、故障回滚与真实 CLI 整链。新增 audit INSERT 故障验证元数据/关联/revision 全回滚，raw 保留，重试幂等；新执行不得覆盖技术/交付裁决或自动重开行动。
- `test_stage_one_ux.py` 记忆写入绑定临时 root；原 structured-json 写入明确拒绝。`test_evidence_ledger.py` 通过实际 attempt/operation 登记，旧 JSONL 只作历史诊断。
- `evidence_identity.observation_supports_coverage` 统一完整执行、error/truncation 与已知副作用未确认的闭合准入；Closure 和 actor matrix 同用。Store 保留未知 state_changing=None，native partial error 同时接受字符串与结构化错误。Ledger CLI 状态失败 stderr/exit 2。
- Queue 删除 `--from-evidence` 与自动推导；6 个并发 claim 只发一个新 permit，其余 resumed。resolve 的命令身份包含 actor/metadata，terminal 改内容拒绝，blocked 同内容幂等。Store 以只读 `command_receipt` 查询原审计收据，不建第二 owner。普通 work 的描述性 family 不被当成 HTTP 执行 family。测试覆盖显式证据归属、敏感/Runner-owned 字段、预算与真实完成引用。
- 前述验证：Runner/Ledger/current_truth **174 passed，8.36s**（`/tmp/ccst-c4-evidence-check2.txt`）；Queue/primary consumers **83 passed，1.70s**。Stage-one 的 8 项在上一组合通过。备份 `/tmp/ccst-c4-consumer-tests-20260924/`，包含旧测试、Action/Ledger 代码。
- `test_context_pack.py` 全部普通查询使用显式 Store fixture；人工 keyed facts 改为有条件/来源的 advisory note，角色矩阵用真实 observation，技术栈读发布的绑定 Surface 而非信任调用方字典。发现 Pack 写回示例未绑定 root、negative 缺必需参数；`_write_back_commands` 现统一输出 shell-quoted root、条件/重开/operation 引用和原生登记入口。含空格 root 的四条真实记忆 CLI 命令通过。`tests/test_context_pack.py` **111 passed，19.92s**（`/tmp/ccst-c4-context-check2.txt`）。
- Coverage 公共行为测试迁为 Store claims/reviews；无证据主张和人工 n_a/tested_clean 不授权闭合，review 在投影删除和窄化 Recon 后可恢复。历史格式只在显式 load 测试使用；路径/参数/类别/来源/身份、并发评审、别名仍有回归。删除没有当前读者的 compact summary writer、stat binding 及 Checkpoint/Autopilot 消费分支，保留正常完整只读投影和显式 matrix cache。`tests/test_coverage_matrix.py tests/test_coverage_reviews.py tests/test_surface_primary_owner.py` **154 passed，18.92s**（`/tmp/ccst-c4-coverage-check2.txt`），包含真实 Pack/Checkpoint/Resume 展开。
- Hypothesis 重放测试退役自动 activation/continuation/kill 与 Queue last_outcome 副本，保留 claim 的真实引用/预算/单维度/反伪造约束。发现空 selected_knowledge_refs 错误要求卡目录且显式 null 被放行：共享 Store 校验现接受缺省/空列表，拒绝 null/非列表，非空仍验证卡文件归属。新真实重放回归证明同 attempt 幂等、新 attempt 独立、明确 resolve 不生成子行动、无 hint primitive 可恢复；毒化旧 owner 后连续三次 Checkpoint 和新进程 Resume 保留条件与未决原 ID。`tests/test_autopilot_hypothesis_replay.py` **23 passed，2.15s**（`/tmp/ccst-c4-hypothesis-check4.txt`）；Store 核心 87 项在同批前次组合全部通过，组合唯一失败为新 fixture 的第二次观察时间早于 attempt，已修正后重验新文件。

下一步：Checkpoint 与 Autopilot state 旧测试族仍引用已删 API；Finding 等可收集文件也仍需旧 writer 回归迁移。未重新全仓 collect/full test，尚须完整静态调用图、CLI/spec/文档同步与 C5 查询/恢复/WAL 成本验收。没有提交、推送、归档、真实目标/安装 runtime 操作或在线模型对照。


## 2026-09-24 C4：Checkpoint 普通查询、Browser 材料与 State 接续断点

- Checkpoint 测试迁入显式 Store；普通查询不选行动、不回写记忆/覆盖/witness，真实 claims/gaps/actor matrix 仍可见。保留轮次预算、并发 claim/heartbeat、中断、证据失效和原子 witness。CLI 绑定 repo-root，新增 root claims/workflow/repo-source 材料窗口和完整展开入口。`commands/checkpoint.md` 同步。
- Browser importer 默认只导入材料；显式 enqueue 先检查 Store，再复用 add_material_review 登记不可变快照及 work，修复旧 helper 读取已删 path 造成的导入假失败。browser-js 契约及真实双模式/幂等回归同步。
- 最后组合：`rtk proxy python3 -B -m pytest -q -p no:cacheprovider tests/test_checkpoint.py tests/test_native_judgment_boundary.py -k 'not owner_read_budget' --tb=short` → 106 passed、1 deselected，14.31s（/tmp/ccst-c4-checkpoint-check7.txt）。owner_read_budget 仍待迁移与真实查询优化，未宣称通过。
- State 普通查询不信任调用方 Case 快照；CLI 传递 repo-root，空 Store 的 source 标签不再冒充 has_memory。closure source markers 改绑 Store ID/revision，保留真实材料/runtime/scope marker，删除 legacy owner marker；该最后修改尚待验证。
- State 测试迁移中，最近 /tmp/ccst-c4-state-check7.txt 为 60 failed、164 passed。主要剩余：旧 JSON 真源 fixture、已删 Finding writer/compact coverage loader、经验第二队列、按类型/命令隐藏持久 work。新增 marker 测试未运行。C4/C5 未完成，无全仓绿色结论。


## 2026-09-24 C4：Autopilot 当前事实、经验展示与 Coverage 候选闭合

- 删除 State 中经验文字的命令/证据路径解析、M1… 队列生成与自动 validate fallback；Gate/loop guard 不再把 memory_candidate_next 当 owner。兼容字段为空，默认经验复用 Context Pack 渲染，保留 conditions/reopen_when/next_intent/完整展开，不增加写入。
- 删除按 action type/category/command prefix 判断 substantive 的启发式；显式登记 work 全部按 active 状态可见，frontier head 使用创建时间/ID，不按业务类别或命令隐藏。Claim/证据/phase 锁保持。
- State 测试迁移到真实 Store claims/assessments/delivery、Case、work 完成产物、observations 和 current Coverage。旧 compact reader 私有测试替换为缓存删除/投毒后当前闭合，保留缺库/坏库、旧文件不可读、phase lock、显式轮次及损坏 raw 的失败回归。
- 发现并修复快速 Recon 的 findings_dir 未定义且仍探旧 findings.json：现在从 Store 有界查询 Finding 数量。Surface cache 在 Store revision 变化时仍提供当前输入 fingerprint，原料变化可重置旧 round guard。
- 同时间戳 observation 按登记 revision/step 稳定排序，避免 operation hash 决定当前身份；Coverage 对实际 Store observation 保留来源、计数和参数名，修复仅有 Store candidate 时被误作无来源网格项、Closure 错误 finish。新回归保留全部 19 类既有覆盖后登记 dead_end→candidate，验证同时间戳序列和重新打开的真实缺口。
- 验证轨迹：State check10 为 193 passed/30 failed，check11 为 219 passed/6 failed；完成迁移后 State+Store check12 为 311 passed/1 failed，最后失败暴露上述 observation 来源缺口。扩组 State+Coverage+reviews+Store check13 为 457 passed/1 failed（21.14s），唯一剩余是新测试自设 hunt_p1 先命中 next_action_pending，已改为 handoff 隔离验证闭合；定向 later_candidate_reopens 随后通过。没有跳过/xfail。
- `rtk proxy python3 -B -m ruff check --select F821` 对本轮 7 个生产模块与 State 测试通过；`git diff --check` 通过。全仓 collect-only：2286 tests collected，3.47s（/tmp/ccst-c4-collection-20260924.txt），无 collection error。未运行 full suite。
- 本轮切片备份 /tmp/ccst-c4-state-retirement-20260924/；旧消费者备份仍保留。C4 仍有 Finding/Validate/Resume/Runtime 等旧 writer 测试和文档残留；C5 owner_read_budget 及真实连接/读取成本未完成。未提交/推送/归档、未操作真实目标/安装 runtime、未做在线对照。


## 2026-09-24 C4：Runtime/Resume、Finding/Report 与 Validate 恢复闭环

- Runtime 的 tested endpoints 只来自真实 Coverage/观察；保存 Finding 主张不算执行。Resume 使用独立 root 的 Store 行动、主张、裁决和条件化 Experience；raw root claim 只有显式材料登记才变成审阅 work。默认文本保留未决行动页与 ID，不替 AI 选行动。
- Runtime/Resume 首次组合 64 passed、3 failed（`/tmp/ccst-c4-resume-runtime1.txt`）；修正 fixture 的闭合粒度、Checkpoint decision 和候选显示后，定向三项 3 passed、23 deselected。未把这两次表述为一次全组通过。
- Finding/Report 用显式主张身份、真实 operation/assessment/delivery/register_report 回归替代旧 writer 补偿。材料索引保留未知 family、缺 URL、幂等、不可变来源；报告分离 renderer type 与原始 family，并带评估/边界/观察引用。`tests/test_finding_index.py` 57 passed（`/tmp/ccst-c4-finding2.txt`）。
- Validate 全链暴露原生 query URL 被公开脱敏改变身份：Runner 现在用 digest-bound 私有 identity artifact 登记精确 endpoint，公开摘要仍去掉查询值。request-diff 与 native 共用消费边界；原生 anchor 不接受仅形状相同的空 query。登记前对比已发布 artifact bindings，损坏不成为新合法观察。
- Validate 先原子发布完整 AI 正文，再提交 assessment、delivery、report registration。各命令可独立重试；同 Finding/同裁决/同字节复用报告而不改 inode/mtime；跨 Finding、旧裁决、缺失/改字节均拒绝。报告生成不产生 delivery event，也不完成 Action。后续 /report 使用已登记 AI 正文。
- `rtk proxy python3 -B -m pytest -q -p no:cacheprovider tests/test_validate_target_mode.py tests/test_validation_runner.py --tb=short` → **157 passed，9.76s**（`/tmp/ccst-c4-validate-runner4.txt`）。前两次新增 fixture 错误已修正；SQLite 只读 WAL 空文件/SHM 属于引擎协调产物，文件快照仍检查 DB、非空 WAL、raw 与应用产物。
- `runner_witness.py` 已无领域调用；唯一剩余 repo-relative 文件定位并回 Report 后，删除整份旧 Ledger witness 验证实现。备份 `/tmp/ccst-c4-validate-retirement-20260924/`。

旧测试职责迁移（不是单纯减少测试数）：

| 退役测试职责 | 当前行为回归 |
|---|---|
| Finding/Queue/Ledger 跨文件同步、自动 resolve | `test_primary_*registration*` 的 Store 原子登记、显式 claim/proof completion；测试不再要求自动完成 |
| Validate owner sync 中断/重试 | `test_primary_validation_retries_only_uncommitted_judgment[assess/decide_delivery/register_report]`，正文保留、已提交裁决不重复 |
| 非交互身份/方法/类别/目标/operation 绑定 | `test_machine_binding_rejects_identity_changes_before_writes`、`test_primary_validation_preflight_rejects_invalid_proof_without_writes`、selected-operation 与 native-step-method 回归 |
| 未初始化/legacy 读取迁移与 quarantined finality | 普通 Validate 明确拒绝；`test_validate_store_admission_never_recovers_old_owner`；合法历史导入只由 `test_target_migration.py` 承担 |
| 报告归属、未登记文件、正文冲突、隔离 root | `test_machine_report_*` 加 native CLI→scaffold→preflight→validate→report→resume 整链 |
| 旧 method/class 由 Ledger 推断、跨 owner 补偿 | Store 显式 Finding method/family/target；未知 family 保留；不恢复旧推断 |
| 直接 JSON finality/provenance 防伪 | Store 当前完整 operation、assessment/delivery 前置 IDs、raw 损坏拒绝；旧 JSON 不再是普通输入 |
| 技术成立、known/duplicate/ineligible | `test_primary_validation_separates_technical_and_delivery_judgments`，确认与资格独立 |

C4 文档与静态调用图仍在收口；C5 开始单次内部 owner 复用，修改前四模块备份 `/tmp/ccst-c5-owner-reuse-before-20260924/`。不提交、不推送、不归档，不操作真实目标或安装 runtime；在线能力对照仍无预算。


### 2026-09-24 接续：C4 Scope/消费者回归与 C5 测量落盘（进行中）

- C5 同 fixture 交错前后测量已完成：`research/recovery-query-cost-owner-reuse-20260924.json`，脚本 `measure_recovery_query.py --baseline-consumers /tmp/ccst-c5-owner-reuse-before-20260924 --counts 100 1000 --iterations 15`。完整输出相等、Store revision 不变。100 hypotheses 下 Checkpoint 连接 174→142、读行 1045→818、median 243.65→191.91ms；Resume 206→174、1198→971、270.88→219.30ms。1000 条下 Checkpoint 3745→2618、296.92→251.55ms；Resume 3898→2771、313.22→265.79ms。Pack 63 连接/250 读行不变，median 有波动，不宣称 Pack 加速。
- DB 样本 389120/737280 bytes，静止 WAL 0；SQLite backup 1.04/1.88ms、copy restore 1.37/2.16ms，均为无并发 writer 的单样本。输出字节不是模型 Token；在线对照未执行。Case summary/seed 的全量 hypothesis 读取热点仍待收口。
- 首轮 C4/C5 全量：2223 collected；2077 passed / 146 failed，132.01s（`/tmp/ccst-c4-c5-full1.txt`）。多数失败来自被退役的 JSON fixture/私有符号；按公开业务职责迁移测试，不恢复正常 legacy fallback。
- 修正 Scope 初始化前边界：fresh target 从显式目标生成只读 Scope；已有独立 scope.json 使用当前配置；存在 legacy Profile 时要求显式导入；active/preview/fence/损坏校验不降级。纯 Recon artifact inspection 不再查询 Finding，Surface 从本次 owner projection 补 Finding 计数。受保护 asset relation 4 项通过，文件未改。
- Scope 组初次 90 passed / 10 failed；边界与 fixture 修正后扩大组 138 passed / 3 failed。后续 Bootstrap/Runtime/Case 修正通过；fresh Recon 的原始 URL 投影不能充当已保存记忆，移除 `has_memory` 的 legacy 分支与未测 URL 判据。
- Recall 迁到实际 Store hypothesis/negative/primitive/handoff，保留真实 raw observation refs、目标隔离、5/6/7 条分页与条件展示；嵌套 note 作为原文数据保存，不做隐式解包。OAST marker fixture 显式建库。Round/Recall/OAST 组合 44 passed / 1 failed，唯一为 preview 拒绝提示匹配，已修正。
- Round 删除无调用者的自动 Surface refresh/写回补偿，删除对公开 state/closure 无效的额外 Queue snapshot 读取。测试由旧 checkpoint→queue→surface 自动写回故障点改为当前 checkpoint 查询、快照、中断前/后 closure；保留轮次预算、已开始 lane 拒绝、真实 Store 并发漂移重读、进程间 claim/close 锁、显式 Surface refresh。旧测试备份 `/tmp/ccst-c4-round-retirement-20260924.py`。
- 压测结构检查器 `tests/skill-validator/check_autopilot_run.py` 迁到 Store Queue/operation 与 `verify_operation`，不再将旧 findings.json/ledger.jsonl 或裸路径当作当前执行事实。原始 root claims 不自动激活工作；缺失/变更 raw 拒绝。Round + run-contract **33 passed，10.07s**（`/tmp/ccst-c4-run-contract.txt`）；旧测试备份 `/tmp/ccst-c4-run-contract-retirement-20260924.py`。
- 旧测试职责映射：fact 覆盖→追加 note 保历史；自动优先级/关键词选择→显式 ID claim；自动 knowledge pull→保存 selected refs + 独立显式阅读遥测；旧 Profile→Store goal/experience 隔离；私有 witness/closed-cell 导出→唯一 current_truth/closure owner；旧记忆导入仍由 migration 独立 legacy 样本覆盖。离线知识评估使用临时目标根，避免读取真实目标或在 checkout 中初始化 eval.test。
- 合同/fixture 第一组 158 passed / 13 failed，修正 import、显式 root 与剩余新合同后第二组 137 passed / 6 failed。剩余 6 项正在修正（空蒸馏窗口预期、自定义 family 大小写保真、原生 actor/隔离 root、Capability fixture）。F821 当前通过。尚未跑第二次全量，不宣称工程闭合。


## 2026-09-24 C4 收口：单一 owner、末端消费者与全量回归

### 当前实现

- Case 复用 `_case_entities` 的同快照实体读取与全部私密材料检查；`case_summary` 用 SQL 计数，`case_object_refs` 供 seed 查询。`case_state(include_hypotheses=False)` 省略该键，默认完整历史和批量关系不变；Distill 使用实体视图，其公开输出不变。1001 条假设、完整关系、私密材料缺失/篡改回归已补。
- `autopilot_state` 不再在批量状态查询中执行 `migrate_legacy_list_storage`；显式批量 Recon 仍保留迁移入口。测试先证明查询字节/目录不变，再显式迁移并核对恢复。
- Disclosure 不再按标题类别读取跨目标 PatternDB 并自动贴“重复”标签；完整公开报告和顺序保留，提供绑定 root/target 的当前 recall 命令。`--no-mcp` 不再重载 client、搜索或读取目标技术栈。
- Knowledge evaluator 从直属 Store/fence 发现目标，fence 只作 hint，完整准入仍由 runtime owner 执行；CIDR 与目录身份受校验，Actions 分页计数，同 tag 多卡均保留信号。坏库/缺 fence/坏 fence/缺被接管库显式失败，不能作为零信号建议退役。末次复核修复 hint 提前打开 symlink/FIFO 的边界：先拒绝路径穿越，再以 `O_NONBLOCK|O_NOFOLLOW` 打开并确认 regular file，读取限4097字符。此处不复制完整 fence 准入协议。
- Runner candidate pool 读当前 Store，并扫描 native 嵌套 `validation/**/summary.json`。只有当前 refuted 或有效 report 所在 assessment 明确引用的 operation/step，才按 attempt + 已评审 artifact refs 退役旧候选。新 attempt/新材料/缺明确引用继续可见；删除 URL/lane/category 去重与旧 JSON closure 猜测。当前 raw 必须有效，查询前后 Store binding 漂移拒绝。
- `finding().assessment.evidence` 返回该 assessment 的明确引用；外层 evidence 保留全部关联。新增 `FindingNotFoundError`，Runner create 只处理真正缺失，不吞任意 StoreError。
- Surface 删除重复 Queue semantic 转换，只绑定当前 Store id/revision 与当前 raw 完整性；schema 6 使旧缓存失效。Checkpoint coverage witness 不再接受旧 Queue/Ledger 文件；State/Gate/Pickup 等提示改为当前来源。
- 删除无正常调用者的 `save_target_profile` 和 `PatternDB.save`/dedup/写入旋转，取消默认 PatternDB 导出。历史 read/match 保留且构造不建目录。历史测试输入集中在 `tests/legacy_fixtures.py`，未删除历史数据；calibration 遥测仍存在，文档不再称它参与当前 Surface 排序。
- 同步 runtime-protocol、Scope、lifecycle-state、transactional-target-state 与 autopilot-round/context-pack/surface/hunt/pickup/retrospect/validate 命令；settle 查询不再自动写 Queue/Surface，Validate 的显式 runtime/telemetry 写入继续说明。生命周期文档的未闭合 Markdown fence 已修复。

### 验证与修正轨迹

- Case/seed/Checkpoint/Pack：264 passed，32.59s，`/tmp/ccst-c5-case-query-check.txt`。
- Disclosure/knowledge/Runner/Surface 定向：27 passed，`/tmp/ccst-c4-late-consumers.txt`。
- 全量 full2：2220 passed / 2 failed；旧 Profile/Recon URL 不算已保存记忆、Pickup 只读文案两项已修且单独 2 passed。
- 全量 full3：2220 passed / 1 failed；唯一旧文档断言要求 settle 自动写回，已按当前只读契约修正。
- 最后 focused：66 passed / 1 failed；新负向 witness 测试实际先被更早的 target-owned gate 拒绝，错误匹配修正后该项 1 passed。没有绕过准入或改成接受旧证据。
- 最后全量：`rtk proxy python3 -B -m pytest -q -p no:cacheprovider --tb=short`，**2221 passed，140.34s**，`/tmp/ccst-c4-c5-full4.txt`。
- 全量后仅 knowledge discovery 读取边界增加产品逻辑；`rtk proxy python3 -B -m pytest -q -p no:cacheprovider tests/test_knowledge_eval_draft.py --tb=short`，**11 passed，0.56s**，包括真实子进程 symlink/目录 symlink/FIFO 非阻塞拒绝。没有在这一小改动后再次全量。
- 旧测试备份、各批切片与历史失败日志保留。新静态清点扩大到 tools + memory 的 **134 个模块、159 处 owner import、0 处普通入口退休 import 违规**，规则与源码 SHA256 在 `current-owner-callgraph-20260924.json`；静态导入不是完整动态调用图。直接路径/运行调用与唯一责任映射已写入 `writer-inventory.md` 当前节，旧表明确标历史。

C4 的正常消费者迁移与旧责任退役已取得离线工程证明。这个结论不等于真实目标升级/部署或 R10 完成。仍保留原始材料、显式历史读取/迁移、scope、私密材料、资源锁、runtime breadcrumb、journal 和 calibration 遥测；不把它们机械并入领域 Store。没有提交、推送、归档、真实目标操作或安装 runtime。

## 2026-09-24 C5：Case 查询成本与证据范围

`research/measure_recovery_query.py --baseline-case /tmp/ccst-c5-case-query-before-20260924 --counts 100 1000 --iterations 15 --output research/recovery-query-cost-case-summary-20260924.json` 的结果已保存；实际执行需使用任务 research 完整路径。每规模15次交错、完整公开输出相等、Store revision 不变。baseline 只还原旧 Case 读取，其他消费者是当前版本；不是完整旧 checkout。测量器重复 runtime admission 计数已修正，下面取修正后的重测结果。

| Case 假设数 | 查询 | Python 行物化 before→after | median ms before→after |
|---|---|---|---|
| 100 | Case summary | 104→5 | 2.79→2.10 |
| 100 | Case seed | 104→4 | 3.31→2.51 |
| 100 | Checkpoint | 820→621 | 194.72→196.20 |
| 100 | Resume | 973→774 | 223.08→224.41 |
| 100 | Distill | 154→54 | 10.00→9.25 |
| 1000 | Case summary | 1004→5 | 5.93→2.05 |
| 1000 | Case seed | 1004→4 | 8.13→2.43 |
| 1000 | Checkpoint | 2620→621 | 195.00→187.06 |
| 1000 | Resume | 2773→774 | 250.01→249.10 |
| 1000 | Distill | 1054→54 | 13.64→9.61 |

- summary/seed 各2连接、Checkpoint143、Resume175、Distill10，前后不变。1000条 summary Python peak 911310→14740 bytes；SQL COUNT 仍扫描匹配记录，不能把 Python 行物化数当成 SQLite 内部扫描次数。
- JSON 保留 p95、Python peak、进程 I/O、JSON/文本输出字节、新进程 Resume。输出字节不是模型 Token；固定父进程时钟，新进程使用实际时间与进程启动成本。
- 两规模 DB 为389120/737280 bytes，初始348160；静止 WAL 0。SQLite backup 1.427/1.647ms，copy restore 2.092/1.862ms；单样本、无活动 writer，恢复后 Store/Case/Experience/raw 验证相等。不是并发写入恢复压力测试。
- 上一批 owner 复用结果仍在 `recovery-query-cost-owner-reuse-20260924.json`，不与本批不同基线数字混算；小规模本批整链没有稳定加速，Pack 也没有稳定加速证据。
- 本批固定12 Actions/12 Findings/7 observations，只证明 Case 历史热点已消除；Action/closure 历史与材料读取成本须另测。Distill 为当前证据检查仍取完整 closure，不能称全部默认历史读取已消除。后续扩大独立领域历史样本的结果另段记录。
- 在线原生/旧版/目标版对照、模型 Token、真实请求、条件变更后的重复探测/有效发现没有执行；R10 与全部 M8 增强收益不标完成。


## 2026-09-24 C5 接续：材料校验连接热点

- 将测量样本扩为100/1000 Case、Actions、Findings、observations 与独立 raw 文件；保留单 operation 场景，不假称测了大量独立 attempt。加入 create-action/create-finding 登记耗时、同 operation 重放、打开 reader 后再提交一条 goal 命令保留 WAL，以及公开 Store backup/恢复校验。
- 第一轮整链扩容运行约8分钟仍在1000条样本，主线程主动中断为exit130，未产出完整结果，不能记为通过或性能数字。中断堆栈位于 current_truth→verify_operation→artifact_status→sqlite3.connect（`/tmp/ccst-c5-domain-measure.txt`）。源码确认每份 artifact 已在同一初始查询取出，却又独立开库读取。
- `verify_operation` 直接复用已有 `_artifact_status(conn, artifact)`，在一个只读快照内保留全部逐文件 hash、availability/provenance event 检查；不新增缓存或校验副本。调用点已核对 Store completion/registration/assessment、current_truth、Validate、Runner candidates、显式 migration 与检查器。
- 新回归 `test_operation_verification_checks_all_material_in_one_snapshot` 使用10份材料，断言1连接、完整artifact数、不授予semantic verification、末项篡改拒绝、Store binding不变；既有撤销/不可用/恢复检查保留。`rtk proxy python3 -B -m pytest -q -p no:cacheprovider tests/test_target_store.py tests/test_current_truth.py tests/test_validation_runner.py tests/test_validate_target_mode.py tests/test_runner_candidate_store.py --tb=short` → **262 passed，10.33s**，`/tmp/ccst-c5-operation-verify-check.txt`。此项发生在前述2221项全量之后，不冒充后者已覆盖新改动。
- 定向成本：复用 `measure_recovery_query.py --scale-domain-history --counts 100 1000 --iterations 15 --queries verify_operation --baseline-verification /tmp/ccst-c5-operation-verify-before-20260924/target_store.py`，结果 `operation-verification-cost-20260924.json`。同fixture15次交错，完整返回相同，revision不变；仅恢复旧verify方法，不是旧版本全量对照。

| 独立raw文件 | 连接 before→after | SQL语句 before→after | median ms before→after | p95 ms before→after |
|---|---|---|---|---|
| 100 | 101→1 | 707→107 | 82.58→10.58 | 93.17→13.19 |
| 1000 | 1001→1 | 7007→1007 | 812.26→100.51 | 883.91→108.67 |

- 1000条时进程读取字符数50101086→657182、读系统调用18159→3160；受页缓存影响read_bytes为0，不能称无I/O。Python peak1550408→1565670 bytes，未改善内存；省下的是重复连接/元数据检查，文件哈希仍按材料规模增长。
- 隔离100/1000样本DB573440/2539520 bytes，初始348160；两者WAL12392 bytes。backup1.83/4.37ms、包含raw的恢复copy8.11/62.10ms；恢复Store/Case/Experience及操作完整性相等。固定reader保留一次已提交写入，不是并发writer负载测试。
- knowledge discovery最后规范化repo root，兼容合法`state/..`参数，同时保留目录/fence symlink和FIFO拒绝；**11 passed，0.53s**，`/tmp/ccst-c4-knowledge-final.txt`。
- 补齐memory-gc旧PatternDB writer说明，并删除validation-evidence末尾多余fence。36份修改/任务Markdown围栏配对检查通过；受保护测试SHA256仍为`b590266d9cc8b07ce59af5cb8e0c9636ea3b4fbc962e1998b66a18a562dfbb85`。
- 优化后的完整扩大样本正在测量，结果另段记录；当前不能将定向约8倍速度推广为整链或在线能力收益。


### C5 扩大领域历史的完整测量（首个通过版本）

`measure_recovery_query.py --scale-domain-history --counts 100 1000 --iterations 15` 已通过，结果 `recovery-query-cost-domain-history-20260924.json`（日志 `/tmp/ccst-c5-domain-measure-after.txt`）。每组Case/Action/Finding/observation各100或1000，raw分别100或1000份，单operation；完整输出重复一致、Store不变、备份恢复语义相等。这是当前版规模测量；被中断的旧整链没有可比结果，不宣称整链加速倍数。

| 规模 | 查询 | 连接 | Python行物化 | median / p95 ms |
|---|---|---|---|---|
| 100 | Pack | 61 | 1174 | 206.77 / 254.20 |
| 100 | Checkpoint | 138 | 2715 | 372.01 / 427.89 |
| 100 | Resume | 169 | 3322 | 453.72 / 490.39 |
| 100 | 新进程Resume | — | — | 655.68 / 729.26 |
| 100 | Distill | 9 | 244 | 20.47 / 26.02 |
| 1000 | Pack | 61 | 10174 | 1547.96 / 1652.09 |
| 1000 | Checkpoint | 138 | 23415 | 3070.34 / 3440.58 |
| 1000 | Resume | 169 | 28522 | 3580.50 / 4142.84 |
| 1000 | 新进程Resume | — | — | 3748.54 / 4972.51 |
| 1000 | Distill | 9 | 2044 | 140.09 / 164.02 |

- Case摘要/seed保持2连接、5/4行；recall2连接12行、negative展开2连接5行。材料校验1连接，100/1000份median10.65/100.05ms；同operation重放1连接，22.64/228.23ms。
- Action创建median1.39/1.42ms，Finding创建1.41/1.37ms；100/1000观察的单次批量登记27.27/228.00ms。不同规模写入样本不是同命令重复性能，不比较“总登记耗时相同”。
- DB573440/2539520 bytes，WAL各12392 bytes；公开backup2.05/6.66ms，含raw的copy restore8.29/64.63ms，恢复语义相同。仍只有固定reader保留一次已提交goal，无活跃writer压测。
- 发现尚未关闭的M8缺口：1000条时Resume内部JSON680340 bytes，新进程CLI942716 bytes。源码`load_resume_summary`仍同时输出完整Finding/endpoint集合与重复owner_projection；默认文本却只显示少量预览。接下来收敛默认输出并给精确总量/余量和现有完整查询入口；不得仅截断不说明，也不把输出减少当成底层读量已降低。原始测量保留作修改前证据。


### C5：Resume 有界输出、完整展开和失败恢复成本

- `load_resume_summary` / `load_pickup_summary` 的默认 Finding、tested/untested endpoint 各取5条；新增 `domain_windows` 精确记录 total/returned/remaining/limit/order/expand_command。Finding按原Store ID序、端点按字典序，未加价值过滤。`owner_projection` 只保留来源/authority元数据，删除重复的完整集合。
- `full_domain_context=True` / `resume.py --json --full` 显式返回完整集合；缺少`--json`时参数错误。生成的命令绑定实际root、规范target、memory-dir并shell quote。默认文本显示真实总数、预览和剩余量，confirmed统计仍来自完整事实。Autopilot未测端点总数也读window，且复用本次Resume已读取的structured Finding summary，不再重复查一遍。
- 新真实CLI回归覆盖空集/61条Finding/61条已测/61条未测、含空格root、执行输出的完整命令、精确ID/端点、无重复owner数组与Store不变。Resume/Runtime/Autopilot组合：293 passed / 1 failed，23.49s；唯一旧措辞断言`last recon`改为真实来源`current coverage`，该项随后1 passed，0.36s。复用Finding读取后相关State/Checkpoint：59 passed、262 deselected，9.32s（`/tmp/ccst-c5-resume-reuse-check.txt`）。未重复全量。
- `resume-domain-window-cost-20260924.json` 保存100/1000档复测。baseline只加载旧Resume wrapper，其他消费者为当前代码；全文字段与`--full`完全相等，Store不变。内部JSON 77419→14426 bytes、680454→14471 bytes；当前真实CLI JSON19602/19647 bytes。这里只证明输出工作集变小且完整集合可达，不声称底层查询行数/所有历史访问已变成有界，也未重测整链延迟。
- `measure_failure_recovery.py` 通过实际SQLite `BEFORE INSERT ON audit` 触发器注入ABORT，对100/1000档各15次note命令测失败→重试→已提交重放。每次验证失败后的revision/receipt/entry均未提交，重试只增加1 revision，后续重放保留同一receipt且revision不变；不重发任何执行或网络动作。最初一次临时测量漏传必需note参数而TypeError，已修正测量器，未据此改产品代码。
- 成本结果 `metadata-failure-recovery-cost-20260924.json`：100档失败/重试/重放median1.34/1.35/1.12ms，p951.74/1.75/1.41ms；1000档median1.20/1.23/1.04ms，p951.54/1.60/1.40ms。SQL触发器setup与诊断读取不计时。这是本地note元数据事务恢复，不代表运行中进程被杀、活动并发writer或外部执行恢复的成本。
- `commands/pickup.md` 和事务契约已同步。脚本与结果均在当前任务research；未修改真实目标、安装runtime、保护测试，也未提交/推送/归档。

### 本次收口边界

- **工程/退役**：C4正常消费者单Store与旧writer退役已闭合；全量2221项通过发生在后续knowledge/verify/Resume修复之前，后续分别由11项、262项、上述293+1及59项有归属回归证明，不拼成新的全量计数。
- **离线成本证据**：保留历史100条/15次count基线；已补当前等价query/Case/owner复用、材料校验、默认Recall/Pack/Checkpoint/Resume/Distill、新进程恢复、输出完整展开、登记/重放/失败恢复与DB/WAL/备份恢复。每份报告明确基线、规模、样本数和未测边界，不混算不同baseline。
- **未关闭的成本**：当前Coverage/closure仍为完整事实核验读取，Finding/Action的完整内部投影仍随历史增长；未宣称所有默认内部读取已有界。当前材料数较大时CPU/hash、行物化和多层重复读取仍有成本。跨进程/整链最后时延样本是在Resume窗口修复前取得，不能将输出缩小换算成时延或Token收益。
- **在线能力**：未执行原生Claude/原版/目标版对照、真实请求、模型Token或条件变化下的重复试错/有效发现验证；R10与完整M8增强收益仍未完成。总体任务保持in_progress，不提交、不部署、不归档。

最终静态复核：`ruff check --select F821 tools memory tests`（另含两个研究测量脚本）通过，`git diff --check`通过；36份Markdown围栏配对和全部本日cost JSON解析通过。AST报告已按最终源码重新生成：134模块、159处owner import、0退休import违规；保护文件SHA256未变。已核对本批diff中的输出截窗、完整展开、错误传播、快照复用及无重复当前owner；不把这些检查写成新的全量测试。

## 2026-09-25 C5：恢复 Finding 读取优化的验收记录

会话 `01a0d66b-a3ab-7431-985b-5e059d95eb07` 的后续结果已恢复，不把未写入本日志误判为未执行。

- `finding_page` 批量读取本页 assessment/destination/evidence/report 关系；`finding` 共用同一投影。选定 assessment 的 operation 在本次查询的同一连接/快照内只校验一次，下一查询重新检查字节与事件，不跨查询缓存授权。
- Coverage 使用普通 Finding 主张页保留端点/参数，不为读取端点展开报告及交付裁决；当前 closure 仍经 `current_truth` 核验材料。
- 历史定向日志 `/tmp/ccst-c5-finding-read-check-20260925.txt` 为 **173 passed，5.87s**；之后另增跨 Finding 裁决隔离回归，原会话记录 **1 passed，90 deselected，0.47s**。这不是 174 项同时运行的新全量。此次 Coverage 接续回归已重新覆盖当前 Store 测试。
- `recovery-query-cost-finding-reads-20260925.json` 已产出：100/1000档各15次交错，完整公开输出相等、Store不变。baseline只还原原 Finding reader 与 Coverage assembly，不是旧checkout；样本为未裁决主张、一个operation与100/1000份材料，不能代替大量已裁决/已报告历史的规模测试。

| 规模 | 查询 | SQL before→after | median ms before→after | p95 ms before→after |
|---|---|---|---|---|
| 100 | Finding page | 409→13 | 2.01→1.48 | 2.42→1.89 |
| 1000 | Finding page | 4009→13 | 10.97→6.61 | 28.50→8.12 |
| 1000 | Coverage | 5136→1136 | 619.43→589.68 | 754.43→648.68 |
| 1000 | Pack | 19407→3415 | 1575.13→1604.40 | 1929.10→1858.79 |
| 1000 | Checkpoint | 45920→5944 | 3024.98→3000.78 | 3945.76→3267.25 |
| 1000 | Resume | 59134→7166 | 3740.37→3572.73 | 3983.41→4404.32 |

行物化数与连接数未降低；1000条Resume仍为27516行、167连接。Pack中位数及Resume p95未改善，因此只确认批量SQL热点收敛，不宣称整链稳定提速或完整M8完成。

### Coverage 端点查找接续

- 1000条独立临时样本的`cProfile`定位：一次Pickup调用构建5次Coverage，`_ensure_endpoint`调用10000次并扫描增长中的list。profile总时长14.27s含探针开销，不作为实际恢复延迟。
- 在`tools/coverage_matrix.py`中将评审/主张/观察/closure查找接到同一次构建的有序端点索引；Finding页逐页消费，删除无用全量副本。没有新持久缓存、schema变更、类别排序或少查证据。
- 首次定向回归为253通过、1失败：scanner入口会向list新增端点，早先构建的索引漏掉新增项。修正为scanner采集后从完整list重建索引，保留随后被观察引用的scanner advice；测试未放宽。首轮性能进程已中断（exit130），不采用未完成输出。
- 最终命令：`rtk proxy python3 -B -m pytest -q -p no:cacheprovider tests/test_coverage_matrix.py tests/test_coverage_reviews.py tests/test_current_truth.py tests/test_target_store.py --tb=short` → **254 passed，13.57s**；日志`/tmp/ccst-c5-coverage-check-final-20260925.txt`。覆盖1000+2主张分页、相同端点参数合并、评审保留、重复观察、精确闭合、scanner-only端点、损坏材料和Store不变。
- 改动前备份`/tmp/ccst-c5-coverage-before-20260925/`；受保护测试SHA256保持`b590266d9cc8b07ce59af5cb8e0c9636ea3b4fbc962e1998b66a18a562dfbb85`。`git diff --check`与3个修改Python文件的AST解析通过。
- 当前只读路径仍多次构建Coverage及完整Finding/Action投影；端点索引仅消除重复list扫描，不将这些未解决的内部读取标成有界。在线模型预算已询问、未获具体授权；无在线请求、部署、真实数据操作、提交或归档。

### Coverage 端点索引最终成本对照

```bash
rtk proxy python3 -B .trellis/tasks/09-20-native-first-practical-optimization/research/measure_recovery_query.py --baseline-coverage /tmp/ccst-c5-coverage-before-20260925/tools/coverage_matrix.py --scale-domain-history --counts 100 1000 --iterations 15 --queries coverage pack checkpoint resume resume_new_process --output .trellis/tasks/09-20-native-first-practical-optimization/research/recovery-query-cost-coverage-index-20260925.json
```

exit0，日志`/tmp/ccst-c5-coverage-cost-final-20260925.txt`。每档15次交错、完整公开输出相同、Store不变、备份恢复语义相同；测量器SHA256与当前文件相符。baseline只恢复本批前Coverage assembly，其他组件为同一当前版本，不与上节不同baseline的数字混算。

| 规模 | 查询 | median ms before→after | p95 ms before→after |
|---|---|---|---|
| 100 | Coverage | 55.34→53.04 | 71.28→73.31 |
| 100 | Pack | 194.55→183.28 | 233.76→208.79 |
| 100 | Checkpoint | 412.78→385.39 | 542.43→681.57 |
| 100 | Resume | 453.51→445.59 | 495.58→552.25 |
| 1000 | Coverage | 541.05→395.60 | 732.56→521.81 |
| 1000 | Pack | 1554.82→1220.98 | 1696.93→1491.94 |
| 1000 | Checkpoint | 2985.86→2331.91 | 4238.67→2690.96 |
| 1000 | Resume | 3596.85→2778.16 | 4036.62→2959.85 |

- 1000档Resume中位数下降约22.76%；100档Checkpoint/Resume/Coverage p95未改善，不能宣称所有规模稳定加速。Python peak亦未稳定改善，例如1000档Checkpoint为40828505→42770222 bytes。
- SQL、连接与行物化数不变；1000档Resume仍为7166语句、167连接、27516行。输出JSON14273 bytes完整相同，Coverage完整JSON2020301 bytes；不得把局部CPU改善写成全量历史读取已消失。
- 当前版新进程Resume各15次：100档median/p95为618.30/671.81ms、1000档2828.95/2949.94ms，输出19404/19449 bytes。这一新进程项只有当前版，没有对应旧进程对照，不据此计算跨进程加速比。
- DB为573440/2539520 bytes、WAL各12392 bytes；backup2.13/4.58ms、含raw恢复copy7.99/66.46ms，恢复语义相等。固定reader保留一条已提交写入，不是活动writer压力测试。
- 本次验收闭合的是Finding批量读取记录与Coverage索引热点。剩余：默认整链重复Coverage构建、完整Finding/Action内部展开、较大已裁决/已报告历史样本，以及另行授权的在线R10/M8能力对照。任务保持in_progress；2026-09-24的静态调用图是历史源码快照，不冒充本次重跑结果。


## 2026-09-25 C5：Finding 事实摘要与有界默认读取

- 新增 `finding_summary` / `finding_state_page`：SQL 聚合精确计数、稳定 ID 的待验证/待报告首项；默认只物化 5 条预览与最多 2 条窗口外 follow-up。当前裁决和历史报告存在性不冒充当前证据/交付授权；完整 `finding` / `finding_page` 与 `current_truth` 保留当前字节/事件核验。
- Resume 的默认 Finding 预览、计数与 follow-up 复用同一次摘要；`--json --full` 保留完整列表。runtime 计数不展开历史；Pack 保留全部计数及窗口外候选存在性；Autopilot 的历史终态端点过滤改读事实页。
- 第一组定向测试为 511 passed、2 failed（48.20s）：两个新增测试的 fixture/键名错误，不是旧测试退化。已修正目标证据关联、报告归属路径、`source_summary` 键；新增摘要检查及 Resume/Pack 检查各已单独通过。随后新增并发写入下的摘要快照测试，待最终定向组覆盖。不得把这些分次结果写成新全量。
- 本批备份：`/tmp/ccst-c5-finding-summary-before-20260925/`。完整输出与成本对照运行中，结果未取得前不宣称时延收益。
- 剩余离线项：Surface scanner 摘要入口、重复 Coverage 构建、Action 默认历史读取、较大已裁决/已报告历史成本。在线 R10/M8 尚无独立模型预算批准。继续实施，不提交/推送/部署/归档。


### Finding 摘要最终定向检查与成本

- 最终 `rtk proxy python3 -B -m pytest -q -p no:cacheprovider tests/test_target_store.py tests/test_resume_tool.py --tb=short`：**122 passed，12.47s**，日志 `/tmp/ccst-c5-finding-summary-check-final-20260925.txt`。包括空集、混合裁决、重裁决后的旧报告、窗口外 follow-up、完整展开、损坏原始证据/报告仍压制授权、游标失效和并发快照。
- 其他相关组之前为 511 passed（新增 fixture 的两个失败已修正）；不把分次数字拼成新全量。
- `recovery-query-cost-finding-summary-20260925.json`：100/1000 档各 15 次 before/after 交错，完整公开输出一致、Store 不变、备份恢复等价。baseline 是本批前四个消费者模块，尚不含随后 Coverage 组装复用；测量器指纹对应当时脚本，不是后续增加选项的脚本。

| 规模 | 查询 | median ms before→after | p95 ms before→after | 行物化 before→after |
|---|---|---|---|---|
| 100 | pack | 197.87→206.90 | 256.45→237.81 | 1174→1185 |
| 100 | checkpoint | 364.01→368.99 | 395.73→418.47 | 2609→2625 |
| 100 | resume | 453.09→423.97 | 649.38→619.62 | 3216→3037 |
| 1000 | pack | 1296.41→1226.48 | 1432.81→1811.46 | 10174→10185 |
| 1000 | checkpoint | 2378.33→2272.92 | 2898.14→2410.83 | 22409→22425 |
| 1000 | resume | 2843.18→2762.43 | 3032.71→3054.20 | 27516→25537 |

- 1000 档 Resume 连接 167→163、语句 7166→7119；中位数改善约 2.84%，p95 未改善。该样本全部未裁决，不能据此证明大规模报告历史收益。当前版新进程 Resume 1000 档 median/p95 为 2723.67/3379.60ms，仅当前版、不计算跨进程加速比。

### Coverage 同次组装复用（后续批次）

- `runtime_state` / `resume` / `surface` 增加私有组装入口；公共入口不接受调用者伪造的 Coverage。Checkpoint 与独立 Pack 各自捕获一次当前 Coverage，在内部传递，不创建持久缓存、不跨查询复用授权。
- `_build_autopilot_state` 私有结果同时返回原始 ranked Surface；无 Recon 或部分 Recon 时 Pack 复用真实 ranked 输入，不能伪造 unavailable 字典丢掉已有候选。公共 Autopilot 输出形状不变。
- Surface scanner 主张读取改为 `finding_state_page`，不加载随后丢弃的报告/证据关系。完整 Surface 候选集合不裁剪。
- owner projection / Resume 增加 Store binding 漂移检查；当前 truth 仍在授权入口重新采集 raw 字节/事件。没有用摘要生成当前交付权限。
- 第一组相关测试 **461 passed，43.80s**；补充 absent/partial/ready Recon 的单次 Coverage 构建回归后，最终命令 `rtk proxy python3 -B -m pytest -q -p no:cacheprovider tests/test_checkpoint.py tests/test_resume_tool.py tests/test_context_pack.py tests/test_runtime_state.py tests/test_autopilot_state_tool.py --tb=short` → **505 passed，44.49s**。日志 `/tmp/ccst-c5-assembly-check-final-20260925.txt`。新增测试初次未种 Finding，已修正 fixture，未改变断言或产品行为。
- 组装前备份 `/tmp/ccst-c5-assembly-before-20260925/`。包含 95% Finding 两次裁决、80% 历史报告、反证/未决主张的 100/1000 档成本对照正在执行；未取得最终输出前不记录提速结论。


### 已裁决/已报告历史的 Coverage 组装对照

- `recovery-query-cost-assembly-assessed-20260925.json` 完成（exit0）：100/1000 Finding；分别 190/1900 次裁决、80/800 份报告、95/950 个关联 operation，包含重裁决后的旧报告、反证和未裁决主张。
- 命令：`rtk proxy python3 -B .trellis/tasks/09-20-native-first-practical-optimization/research/measure_recovery_query.py --baseline-assembly /tmp/ccst-c5-assembly-before-20260925 --scale-domain-history --assessed-history --counts 100 1000 --iterations 15 --queries pack checkpoint resume resume_new_process --output .trellis/tasks/09-20-native-first-practical-optimization/research/recovery-query-cost-assembly-assessed-20260925.json`。
- 各 15 次交错，完整公开输出一致、Store 不变、备份恢复 Finding（含报告状态）/Case/Experience 等价。该基线已包含 Finding 摘要，因此不是与最初版本比较。

| 规模 | 查询 | median ms before→after | p95 ms before→after | 连接 before→after | 行物化 before→after |
|---|---|---|---|---|---|
| 100 | pack | 507.57→355.62 | 628.26→419.41 | 346→233 | 2431→1709 |
| 100 | checkpoint | 831.56→384.43 | 940.09→469.41 | 609→259 | 4832→2322 |
| 100 | resume | 1038.42→554.81 | 1115.14→616.46 | 733→386 | 5635→3131 |
| 1000 | pack | 4096.04→2756.88 | 4926.08→3001.41 | 2911→1943 | 22546→15704 |
| 1000 | checkpoint | 6752.51→2852.50 | 7405.57→2993.26 | 4884→1969 | 44297→20772 |
| 1000 | resume | 7969.49→4134.41 | 8795.68→5490.06 | 5863→2951 | 51220→27701 |

- 1000 档 Checkpoint/Resume 中位下降约 57.76%/48.12%。当前 truth 仍对所有当前闭合来源核验材料；没有减少授权语义或截断候选换数字。新进程结果只测当前版，不冒充 paired speedup。

### Action 有界默认读取与 Pickup 共享恢复

- `TargetStore.action_summary` 只物化 5 个 nonterminal 行、最多两个原有选择规则下的运行/下一行动，SQL 精确统计全部/pending 数和全部 active family；metadata 损坏（包含终态历史）仍失败。`load_queue` 完整历史及 closure 的完整查询保留。
- `action_page` 的状态/描述性 type 在 SQL 过滤、游标绑定；Intel 只展开终态 intel-advisory。初版误把描述性 type 当 Store kind（仅 work/execution），新增真实 fixture 揭示此错，已改为读取 action_context.type，与既有投影一致。Surface 只取各绝对 URL 的最后终态 ID/endpoint/status，稳定 ID 顺序保留 path 折叠的覆盖顺序，不把行动结果当 closure。
- Queue fingerprint 改为 target/store_id/revision。旧编码 witness 会显式 stale，需要重新读取；不重写历史，不接受公开调用者提供的替代快照。旧算法已把 Store revision 放入内容 hash，无关 Store 写入同样会失效。
- Pickup 私有组装复用 Checkpoint 内捕获的 Resume；默认及 --full 仍返回原有集合/窗口。Checkpoint 失败时仍给独立 Resume 与明确错误。缺 Recon、部分 Recon、就绪 Recon 都只构建一次 Coverage。
- 复用 Coverage 后，后续 source/health/closure 采集如与原 matrix 不同则拒绝输出；新增同 revision raw 损坏回归，避免互相矛盾的闭合授权。Store binding 漂移检查保留。
- `tests/test_action_queue.py tests/test_checkpoint.py tests/test_autopilot_state_tool.py tests/test_context_pack.py tests/test_resume_tool.py tests/test_runtime_state.py` 定向组：**573 passed，46.04s**，日志 `/tmp/ccst-c5-actions-pickup-check-20260925.txt`。之后 Surface/Intel/primary/shared_coverage 组 **39 passed，146 deselected，14.32s**；action summary 并发快照和 Intel 描述性 type 各有新增定向通过。初次 Intel 测试重复放同一 ID 导致既有扫描重复引用，改为单处 ID fixture，未改既有去重语义。
- 本批受保护文件 hash 未变。选定修改文件 `ruff check --select F821` 通过，`git diff --check` 通过。未运行新的全仓测试。
- Action/Pickup 独立成本对照正在运行：100/1000、15次、95% Findings 已裁决两次、80% 有报告、90% actions cancelled；baseline `/tmp/ccst-c5-actions-before-20260925/`，完整输出对照，不拿窗口缩小当收益。


### Action/Pickup 成本与最后边界修正

`recovery-query-cost-actions-pickup-20260925.json` 已完成（exit0），命令为此前组装命令改用 `--baseline-actions /tmp/ccst-c5-actions-before-20260925 --terminal-actions`，输出到同名 JSON。100/1000、各15次交错、完整输出一致、Store 不变、恢复语义一致。每档90% Action cancelled、95% Finding 两次裁决、80% Finding 有历史报告。

| 规模 | 查询 | median ms before→after | p95 ms before→after | 连接 before→after | 行物化 before→after |
|---|---|---|---|---|---|
| 100 | pack | 316.49→316.86 | 365.16→362.23 | 233→233 | 1709→1709 |
| 100 | checkpoint | 360.62→354.67 | 481.40→456.14 | 259→259 | 2322→2227 |
| 100 | resume | 517.76→389.81 | 641.01→443.61 | 386→261 | 3131→2256 |
| 1000 | pack | 2662.96→2664.89 | 3236.06→3204.22 | 1943→1943 | 15704→15704 |
| 1000 | checkpoint | 2906.77→2878.27 | 3545.63→3077.26 | 1969→1969 | 20772→19777 |
| 1000 | resume | 4284.37→2914.70 | 4515.96→3863.66 | 2951→1971 | 27701→19806 |

- Action 窗口本身主要减少物化，Checkpoint 中位只小幅改善；Pack 无明显改善。Pickup 1000档中位下降约31.97%，来自消除重复 Resume/Coverage 组装，不把它全部算作 Action SQL 收益。
- 之后复核追加两个精确语义修正：窗口外 active family 按原行动ID/字段出现顺序去重，不按字母排序；描述性 action type 使用 Python `str.strip` 的同等空白语义，避免 SQL 精确匹配漏掉合法带空白的历史 type。旧性能样本没有 active family/type，不用它证明这些边界；新回归覆盖真实 actor-matrix 类别和 Unicode 空白。
- 上述 family 顺序回归先复现失败（Authz/GraphQL 顺序反转），已在 Store 聚合根因修正，未改期望。Intel type 与并发 Action 快照回归单独通过。

### 当前证据查询共享元数据快照

- 已裁决大样本暴露 `_store_truth` 对每个 operation 重开只读连接。`closure_records(verify=True)` 现在从同一次事实查询的连接/快照内逐 operation 调用既有 `_verify_operation`；默认 `closure_records()` 仍是事实查询。完整 raw/事件核验保留，下一次 query 重新采集，不跨查询缓存。
- 验证结果显式返回 `invalid_operations`，`current_truth` 使用同一条 source/health/suppression 算法。删除“对象没有 verify_operation 就跳过检查”的隐式放行。截断前缀仍仅报告 damage，不能授权闭合。
- 新回归用30个operation验证恰好1个读连接、所有operation都核验、同revision损坏字节后历史保留但闭合压制、核验中提交revocation仍保持原快照而下次查询失效。
- 最终定向：`rtk proxy python3 -B -m pytest -q -p no:cacheprovider tests/test_current_truth.py tests/test_target_store.py tests/test_coverage_matrix.py tests/test_coverage_reviews.py tests/test_action_queue.py tests/test_checkpoint.py --tb=short` → **427 passed，21.36s**；日志 `/tmp/ccst-c5-truth-check-20260925.txt`。包含前述family/type修正。
- `ruff check --select F821` 与 `git diff --check` 通过。备份 `/tmp/ccst-c5-truth-before-20260925/`。最终真值读取对照运行中：`--baseline-truth .../tools/current_truth.py --scale-domain-history --assessed-history --terminal-actions --counts 100 1000 --iterations 15 --queries pack checkpoint resume resume_new_process`，每项会打印采样进度，最终 JSON 同时记录消费模块指纹。


## 2026-09-25 C5 最终离线验收

- 最后一组共享快照成本进程正常结束（exit0）：`recovery-query-cost-truth-snapshot-20260925.json`，日志 `/tmp/ccst-c5-truth-snapshot-cost-20260925.txt`。100/1000 档各15次交错，含两次裁决、历史报告及90%终态行动；完整公开结果相同、Store不变、备份恢复等价。
- 1000档Pack median/p95 2806.69/3743.71→1270.61/1761.39ms，连接1943→41；Checkpoint 3028.31/3502.10→1458.97/1543.64ms，连接1969→67；Pickup 2979.31/3365.38→1464.43/2089.73ms，连接1971→69、SQL17711→8201、行物化19806→17904。Pickup median下降50.85%，Python peak略升，不宣称内存改善。
- 当前版新进程100/1000档median为442.41/1594.06ms；只有当前版，不算paired加速。DB为983040/6782976 bytes，固定reader保留的WAL各12392 bytes；backup3.10/12.57ms、含raw恢复copy12.29/139.93ms。各一次恢复，无活动writer压力测试。
- 收尾把 `test_context_pack_reuses_exact_surface_projection` 的拦截改为实际使用的 `_load_surface_context`，删除Pack/Autopilot/current_truth三个模块无用import。该测试 **1 passed，0.65s**。最新427项共享契约组仍是上一节实际运行，不与这一项或此前505/573组拼成全量。
- 最后报告中的测量器/baseline hash完全匹配；最终产品代码还原上述三处import清理后，全部11个consumer hash与测量报告一致。因此没有把后改产品逻辑的成本冒充实测。
- `current-owner-callgraph-20260925.json` 刷新为最终源码：134模块、159处owner import、0退休接口违规。20260924报告保留历史原文。`writer-inventory.md` 新增当前默认读取链、唯一owner、完整展开/完整性边界及fingerprint兼容影响。
- `ruff check --no-cache --select F821`（本批消费模块、修改测试、测量器）、`git diff --check`通过；全部研究JSON、测量Python AST、四份更新Markdown围栏/尾部空白通过。9个错误Action过滤输入在读取文件系统前明确拒绝，无目标创建。受保护测试SHA256未变。
- `research/offline-acceptance-20260925.md` 汇总最终证据、复现命令与限制；`implement.md`、PRD状态及task notes已更新。历史 `--baseline-finding-summary` 模式依赖当时私有消费接口，不能在最终源码上直接重跑；旧脚本保存路径与完整环境要求已明示，不为历史实验加入产品兼容层。
- 已授权离线工作收口；完整Coverage/Surface候选事实及raw核验仍随实际数据量增长，SQL内部扫描不等于行物化计数，不宣称所有查询常数成本。R10/完整M8的真实模型Token、重复试错及能力收益仍未实测，只有另行授权的在线验收阶段未执行。此前预算已询问但未具体批准，不重复索要同一许可；任务保持in_progress，不提交/推送/部署/归档，不改真实目标或历史事故材料。


## 2026-09-25 在线验收续接：统一 4-8 / max

- 用户已批准不限美元的模型预算，随后指定所有在线测试使用 `claude-opus-4-8`、思考强度 `max`，并禁止协作子代理；由主线程运行实验进程。
- 4-6/high 的 native/current pilot 完成；4-8/high pilot 保留七阶段和最后阶段因参数变更终止的记录（`/tmp/ccst-online-pilot-opus48-20260925/superseded.json`）。它们均不计入正式样本。high/native 将安全检查也放入 findings 且自定义 safe case_id，原判分保留；不能直接把协议错误全部当作业务误判。
- 正式冻结前统一明确 findings/safe_checks 的含义与五个 case_id；oracle 的安全覆盖要求同一 URL、GET 和正确三身份返回，畸形报告条目保留为无效。实验脚本保存 argv、turns、usage、cost、API duration；增加 `--sample` 以主线程并行执行三个独立配对样本，组内轮换顺序不变。
- `rtk proxy python3 -B .trellis/tasks/09-20-native-first-practical-optimization/research/online_compare.py --offline-check`：5 tests passed，3.680s。三份设施 Python 的 `ruff check` 通过；修正了新设施测试里的三个分号风格错误。产品实现未改。
- 4-8/max 通路 pilot：`/tmp/ccst-online-pilot-opus48-max-20260925`；实际 argv 已保存为 `--model claude-opus-4-8 --effort max`，流返回模型标签 `claude-opus-4-8`。待阶段完成后运行正式 3×4×2 对照；R10/M8 尚未勾选。

- max pilot 原生第1阶段完成（1/1有效、证据完整、4/4安全对照、无误报）；第2阶段3.73s内把工具调用输出为普通DSML文本，0次真实工具调用、missing_report，保留不重试。正式实验按相同配置继续衡量该模型接入的实际完成率。
- 正式运行已启动：`/tmp/ccst-online-formal-opus48-max-20260925/shard-{0,1,2}`；各自 `--repetitions 3 --sample 0/1/2`。三个manifest的实验脚本/各版本源码hash完全一致，模型均4-8、effort均max；服务端口及工作目录独立。

- 正式失败保留：sample-1/pre_store/stage-1 为 missing_report（390.73s，39请求，28工具调用，最终输出会话总结而非报告）；sample-2/pre_store/stage-2 为 timeout（600.06s，40请求，21工具调用，无最终usage）。都不重试替换，不将已收到的越界响应冒充已交付发现；缺失成本/Token标为未知。正式仍在运行，未作最终组间结论。

- 23/24阶段已保留，最后legacy阶段运行中。current六阶段的主协议结果为1 complete、3 missing_report、2 timeout；sample-2/stage-2有单个fenced JSON可独立核验2项有效发现、3项安全对照，另存事后诊断，不修改主结果。native sample-2/stage-2同样按600s超时保留，说明超时口径一致。当前证据不能验收在线增强收益。
- current/sample-1/stage-1实际工具返回显示多次记忆CLI拒绝：缺target、缺conditions/reopen_when、缺operation-ref、operation-ref格式错误；随后改为建议性note。只记录可复核摩擦，不把安全证据门降级，也不在正式中途改产品。


## 2026-09-25 C5 在线对照最终结果（4-8 / max）

- 24/24正式阶段已全部结束，三个分片各保留8条scored记录。配置均为claude-opus-4-8/max；无整场重跑、失败替换或实验中产品改动。
- 主协议完成数native/legacy/pre_store/current：5/6、6/6、2/6、1/6；有效且证据完整发现8/10、10/10、4/10、1/10；安全覆盖16/20、20/20、6/20、4/20；已提交主张无oracle拒绝。缺报告不等于证明无发现。
- current样本2阶段2实际写成stage2-report.json，最终文本为说明加JSON；统一事后fenced-JSON核验支持2项发现、3项安全对照，作为补充不改主计分。
- 请求数205/215/175/133，工具调用120/213/183/159。5个超时阶段无最终usage，已知费用总计22.056922美元只是部分合计；不可把失败/未知当节省。只有current样本1阶段1与native、legacy质量可比，分别多132.01s/63.98s和898644/631074累计输入Token，无在线提效证据。
- 三个会话同时出现上游EOF；CLI的synthetic模型标签对应API错误事件，所有非synthetic标签均为claude-opus-4-8。汇总器初次严格模型标签断言拒绝，按原始is_api_error_message核实后明确区分并保留；未改正式实验/结果。标签不能独立证明上游权重身份。
- 汇总器完成24条argv/模型/脚本及源码manifest/server日志/oracle/raw证据核对，证据漂移0、被测源码改写0。完整两阶段没有current与基线同质量的样本；三个变体各一次轨迹，不声称统计显著或普遍能力变化。
- 验收报告online-acceptance-20260925.md、机器结果online-results-20260925.json、复算脚本summarize_online.py已落盘。PRD/implement/task同步：在线执行已完成，R10和完整M8收益未通过，整体in_progress；保留既有离线工程收益。

- 最终检查：4份实验Python Ruff/AST、任务JSON及更新Markdown围栏/尾空白/本地链接、git diff --check通过；受保护SHA256仍为b590266d9cc8b07ce59af5cb8e0c9636ea3b4fbc962e1998b66a18a562dfbb85。所有正式沙箱已退出，24条记录完整；没有新增产品代码或重跑无关全仓测试。

## 2026-09-25 获批后续：失败诊断、CLI 修正、v2 配对

- 用户对“归因→真实请求/工具/新进程预检→最小CLI/协议修正→小规模配对”的方案回复go。沿用不限额4-8/max授权，全程主线程，不派子代理。
- 执行前备份本轮产品/实验文件到 `/tmp/ccst-online-followup-20260925-before/`，保护既有未提交修改。原正式harness按manifest核对后冻结到原运行根 `harness-v1/`；冻结汇总器复算24场的机器结果逐字节相同，证据和源码漂移均0。旧复算文档已指向冻结脚本，v2不替换旧主分数。
- `diagnose_online.py`/`online-diagnostics-20260925.json`记录24流的调用ID、事件行号和工具区间并集。明确3个同时EOF、4条CLI摩擦、空文本/DSML/会话总结/文件命名失败。5个600s超时已配对工具区间仅2.022–7.306s，区间外时间没有被误称为SQLite或工具成本。
- `online_preflight.py`在 `/tmp/ccst-online-preflight-opus48-max-20260925` 完成2个独立进程的真实工具保存/恢复，删除原输入后恢复nonce一致。6个实际出站请求全部4-8、output_config.effort=max、adaptive thinking；仅记录允许列表元数据，不保存凭据、headers或请求正文。2+2工具调用，5.848/37.090s，费用0.043635美元；一次首字节约30.886s。只证明短闭环通路，不证明稳定性/上游权重。实际导出工具为Bash/Edit/Read，不能将六工具argv冒充六工具已提供。
- 产品修正限于 `tools/target_memory.py` 帮助与错误：set位置参数、一次解释negative全部要求、operation零基step示例、无登记证据时明确advisory note；退役参数不再推荐且继续拒绝。`commands/remember.md`改为实际Store Experience/journal语义，删除旧patterns/profile自动写入承诺；事务规范同步。不改变证据门、初始化或Store schema。
- `tests/test_target_memory_cli.py`：12 passed/3.11s。设施 `--offline-check`：7 passed/4.310s；之后新增重叠区间计时检查单独1 passed/0.006s。新实验脚本/修改测试Ruff通过，产品原有第9行unused re/F401由本轮前快照确认未变，保留为既存问题；git diff --check通过。没有运行全仓测试或将旧427项算本轮验证。
- v2只改变报告格式准入：精确文件优先，缺文件时允许纯JSON或唯一json fence带说明，畸形/歧义/损坏精确文件仍拒绝；不猜文件别名、不补造报告，oracle/raw/三身份门不变。预注册sample0 native→current，每组两阶段，原40请求/50 CLI turns/600s预算。新目录 `/tmp/ccst-online-pair-v2-opus48-max-20260925`，不覆盖旧目录、不重试替换。
- 四阶段结果：native1 complete，1/1发现+4/4安全，36请求、435.431s；native2 complete，2/2+3/3，但第41次请求429，预算门失败，206.043s；current1 complete，1/1+4/4，31请求、159.823s；current2 missing_report，0工具/0请求、14.964s。最后一场stdout第2行只有DSML普通text块，CLI仍success；失败发生在任何项目CLI/Store执行前。v2解析器正确拒绝，不能据此改产品证据逻辑。实际CLI num_turns最高59，与参数50的计数语义未独立核实。
- current1没有调用target_memory/remember，仅发现sqlite3相关工具输入；不能宣称本次在线验证了CLI摩擦减少。阶段1质量和预算相当，current相对native少5请求但多21工具、651126累计输入Token和1.685417美元，时间少275.608s；不是完整交接或整体提效证据。四阶段费用4.651195美元，usage齐全；不能用current2早退当收益。所有已交付主张均有oracle证据，重复主张单列不改成误报。
- `summarize_pair.py`逐条核对argv、模型/usage、server/oracle、raw、harness及源码；0证据漂移/0源码改写。返回1表示预注册扩样门槛未过，结果已保存于 `online-pair-v2-results-20260925.json`；逐事件诊断另存。未扩大其余变体。完整说明 `online-followup-20260925.md`，PRD/implement/task notes同步。
- 当前未解决的是4-8/max接入在真实恢复提示下稳定输出结构化tool_use；CLI流不足以区分模型生成和上游转换，需要该边界的新证据。R10/完整M8不关闭，任务in_progress。所有实验进程已退出；无提交、推送、部署、runtime安装、归档或真实目标修改。

### 2026-09-25 入口修正后的在线配对收口

- sample1/sample2 native/current 两阶段配对已结束，统一 `claude-opus-4-8`/`max`，原始主轨迹保存在 `/tmp/ccst-online-entry-opus48-max-20260925/`，机器结果为 `research/online-entry-followup-results-20260925.json`，文字报告为 `research/online-entry-followup-20260925.md`。
- primary 结果：native 4 阶段中 2 个完整、1 个超时、1 个缺报告；current 2 个完整但都超过 40 请求预算、2 个缺报告。有效主报告累计 native 5 项发现/10 项安全覆盖，current 3 项发现/7 项安全覆盖；未知 usage 不按零成本处理。
- sample1 current 阶段2实际使用 `target_memory.py handoff` 恢复持久化状态并完成 release-2 复核；阶段1仅读新增 `CLAUDE.md` 后继续做常规文件/文档检查，未调用 target-memory CLI。native 使用文件/笔记交接。无法宣称源码搜索或 SQLite 无效探索减少。
- sample2 三个早退阶段均为 0 工具/0 应用请求，发生在项目 CLI/Store 之前；按用户要求把 tool_use/DSML 视为渠道事故，主计分不改、不执行普通文本。
- 渠道补跑单列在 `/tmp/ccst-online-entry-channel-retry-20260925/`：native stage2、current stage1 retry、current stage2 各有一条完整轨迹；原始主结果不替换，补跑不形成预算有效的同阶段比较。
- 本轮只确认入口修正被一次真实交接使用；没有 R10 或完整 M8 在线收益证据。任务保持 `in_progress`，不提交/推送/部署/归档，不修改真实目标或 runtime。

### 2026-09-26 当前三项成本补证与预算观测配对

- 用户确认最小补验后，由主线程完成四个现有 research 脚本的修改；没有子代理、生产代码
  或真实目标/runtime 变更。执行前副本及旧 v2 harness 保存在
  `/tmp/ccst-m8-budget-before-20260926-15pjpji7/`，已匹配三份历史 manifest，旧分数不改。
- `measure_recovery_query.py` 补真实 recall/展开默认文本字节及字段/余量/游标核对、计量支持
  文件与三个遗漏消费者的指纹；已有输出明确拒绝。7 条/1 次检查通过，100/1000 档各15次
  三项补证完成：1000档 recall/展开/蒸馏 median 为2.169/1.615/286.825ms，连接2/2/8，
  行物化12/5/4963。全文相同、Store不变、恢复等价，14个消费者指纹匹配；无 before/after
  加速主张，蒸馏仍随规模增长。见 `m8-current-consumers-20260926.md` 与同名 JSON。
- 实验服务端和中立 recorder 提供累计/剩余预算，唯一上限仍为40；第41次仍429/失败，
  缺失或错误头显式未知且保留raw。manifest标注预算观测修订1，报告v2/三身份/oracle不变。
  `online_compare.py --offline-check`：11 tests passed，6.156s；覆盖39/40/41、重置、
  坏头/缺头和每调用恰好一个请求。已有测量输出拒绝检查也通过且文件哈希不变。
- 新根 `/tmp/ccst-online-budget-observation-20260926`，固定4-8/max，sample1按current→native
  各两阶段，共四场，全部正常退出且full_quality。native请求36/35，current40/38，无429、
  超时、渠道早退或补跑；每组3/3有效发现及完整证据、7/7安全阶段案例。
- 汇总器退出0，质量/预算前置门通过、源码改写0，argv/模型/流指标/server/oracle/raw一致。
  149个预算raw与receipt次序逐一匹配。current阶段1保存的Store handoff在阶段2工具返回
  再次出现；阶段2也读取文件交接，不能将恢复效果单独归因于Store。
- 同质量两阶段current−native：+7请求、+5阶段内重复、+22工具、+698048累计输入Token、
  +13915输出Token、+$1.085411，墙钟−25.638s；四场费用$4.211495且usage齐全。
  结果 `online-budget-observation-20260926.md` / `online-budget-observation-results-20260926.json`。
  不把四场完成当增强收益；本批不立即扩样，下一步先从现成轨迹定位额外Token/工具成本，
  再决定有依据的改进或四组独立重复矩阵。R10/完整M8及整体仍为in_progress。
- 预算字段的执行契约已补到 validation-evidence spec；Ruff仅发现测量器中改动前即有的
  三个F401（build_context_pack/build_checkpoint/load_pickup_summary），未清理无关问题。
  不运行产品全仓、不提交/推送/归档，历史测试数量不算本轮验证。

### 2026-09-26 报告输出重复的最小设施修订收口

- 复用四场预算观测轨迹完成调用/结果字节、重复工具和 message ID usage 审计；22 次净额外工具调用可逐项对账，但逐调用 Token 无法从流式 usage 重建。详见 `research/online-cost-attribution-20260926.md` 与同名 JSON。
- `online_compare.prompt()` 已取消“写入精确报告文件后再次全文回显”的强制要求；文件优先、缺文件 fallback、坏文件拒绝、oracle/三身份/预算门均不变。manifest 标记 `report_output_instruction_version=2`。
- 新配对 `/tmp/ccst-online-report-output-20260926` 的 native/current 两阶段四场均 `complete`、`full_quality=true`、预算有效、无 source drift；四场最终回复为 120/581/309/290 字节的短路径确认，报告文件仍被评分器读取。汇总 `expansion_gate_passed=true`。
- 新旧配对不可合并为独立样本；阶段间 Token/费用方向相反，不能归因于该提示修订带来效率收益。R10/完整 M8 保持未通过，不继续无依据扩样，不改生产代码、Store、真实目标或安全证据门。
- 复核命令：`rtk proxy python3 -B .trellis/tasks/09-20-native-first-practical-optimization/research/online_compare.py --offline-check` → **12 passed，5.689s**（本地回环端口需提升权限）；未运行全仓测试。


### 2026-09-26 独立矩阵中断恢复（进行中）

- 恢复会话 `01a0dc41-f81f-7011-bf2d-be717010ea59` 后重新激活原任务，用户 `go` 接续。
  实际进程已退出；24 场中九场已终结，第十场 legacy/sample1/stage2 只有部分轨迹。
- 模型二进制、frozen harness 两文件及四臂源码均与原 manifest 完全匹配；受保护测试
  SHA256 未变。原 status/progress/server 日志与 68 个阶段文件指纹保存于
  `/tmp/ccst-online-independent-resume-20260926-v8jr1x8l/`。
- 复用 `online_compare.py --resume`，保留旧九场及中断场，不改旧分数，只启动余下十四场；
  模型仍为 `claude-opus-4-8` / effort `max`，请求/时间预算不变。实际网络/namespace
  权限单独获批，未重复申请模型预算。旧实验脚本未修改。
- 现有 `summarize_pair.py` 补四臂与 interrupted 记录，`diagnose_online.py` 补未知耗时；
  保持原 oracle/raw/argv/usage 门，新增输出拒绝覆盖，部分账单不作零成本。
  定向恢复保留检查 1 passed / 0.002s；汇总/诊断回归 2 passed / 0.206s。
  未运行全仓测试，无生产源码、真实目标、runtime、提交/推送/归档变更。
- 本轮矩阵尚在运行，不以模型退出 complete 代替完整质量；R10/完整 M8 保持开放。


### 2026-09-26 固定两轮在线评估最终收口

- 两个冻结根均已结束并通过最终汇总核验：共 48/48 阶段有终结记录，未补跑、未替换结果、未发现源码或设施漂移。原始 JSON、progress/server/oracle/raw、报告、usage/未知成本和输入指纹均保留。
- 合并结果写入 `research/online-r10-fixed-results-20260926.json` 与同名 Markdown。两轮合计 native/legacy/pre_store/current 的完整质量为 2/12、2/12、3/11、2/11；pre_store 和 current 各有 1 个零执行阶段，按规则单列，不当作产品质量证据。
- 完整同质量阶段配对为 0，两个阶段同时完整配对为 0；因此没有条件性成本差值，固定评估只能支持“执行完成、在线增强收益未证实/证据受限”，不能主张 current 获胜或退化归因。
- 任务交付清单已更新，`task.json` 标为 `completed`（2026-09-26），并保留未证实收益的独立结论。停止继续扩样、渠道调查、补跑或真实目标/runtime 操作；不提交、不推送、不部署、不归档。
