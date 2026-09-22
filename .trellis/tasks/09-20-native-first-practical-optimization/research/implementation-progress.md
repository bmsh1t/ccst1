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
