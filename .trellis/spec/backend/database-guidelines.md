# 持久化与状态规范

## 当前事实

项目没有关系型数据库、ORM 或迁移框架。`requirements.txt` 也未引入数据库依赖。
持久化由仓库内 JSON、JSONL、Markdown 和扫描器原始 artifact 组成。因此这里的“数据库
规范”实际约束文件状态的 schema、所有权、写入原子性、并发和迁移。

## 状态分类与所有者

| 数据 | 位置 | 所有者/入口 | 语义 |
|---|---|---|---|
| canonical findings + mutation provenance | `findings/<target>/findings.json`、`mutation-events.jsonl` | `tools/finding_index.py` | 发现身份、validation/report 生命周期和计数；每次 owner mutation 有同 target/finding 的可回放 event；根目录临时 JSON claim 只能由该 owner 在 checkpoint 时归档为 candidate |
| runtime breadcrumbs | `state/<target>/session.json` | `tools/runtime_state.py` | 仅保存不可派生的 runtime v2 事实 |
| action queue | `state/<target>/action_queue.json` | `tools/action_queue.py` | 可继续执行的持久动作及终态 |
| validation case state | `state/<target>/case_state.json` | `tools/target_case_state.py` | actor/session/object、证据范围与待验证 backlog；缺失表示尚未建立 case，已有文件损坏必须 fail-fast |
| coverage matrix | `evidence/<target>/coverage_matrix.json` | `tools/coverage_matrix.py` | endpoint × 漏洞类覆盖投影；消费 valid exact Surface Index，并以 index generation 绑定 freshness；缺失表示尚未建立矩阵，已有文件损坏必须 fail-fast |
| checkpoint witness | `state/<target>/checkpoint_latest.json` | `tools/checkpoint.py`（唯一写 owner）；`tools/checkpoint_witness.py`（共享结构校验） | context-pack 已进入 checkpoint 的小型证明；同时拥有 `round_guard` 和无人值守轮次的有界 `round_progress` |
| Legacy JSON/SQL probe summaries | `findings/<target>/poc/json_inject/summary.json`、`findings/<target>/poc/sql_matrix/<lane>/summary.json` | `tools/autopilot_state.py`（只读） | 历史输入绑定和执行摘要仅供恢复/复核；不再有新 writer，checkpoint 只投影通用 AI evidence-review action |
| observation inventory + summary | `state/<target>/observations.json`、`observations-summary.json` | `tools/observation_inventory.py` | 完整中性 observation/lifecycle 是 body 事实；summary 是与 body/source 绑定的可重建计数和 bounded sample |
| exact surface index | `recon/<target>/surface/{index.jsonl,manifest.json,summary.json}` | `tools/surface_index.py` | raw URL exact identity/provenance/shape/page 派生索引；只对完全相同字符串去重，不拥有 finding/coverage |
| bounded surface projection | `state/<target>/surface-projection.json` | `tools/surface_projection.py` | 完整流式评分后的可重建注意力窗口；仅 exact input fingerprint hit 可参与 next-action |
| evidence ledger | `memory/evidence/<target>/ledger.jsonl` | `tools/evidence_ledger.py` | endpoint/角色/对象/variant 的追加式证据 |
| target memory | `memory/goals/targets/<target>.json` | `tools/target_memory.py` | lead、dead-end、next action 和可复用经验 |
| legacy target profile | `hunt-memory/targets/<target>.json` | `memory/target_profile.py` | resume/intel 的 scope、endpoint、finding 和 session 历史；缺失可创建，损坏必须 fail-fast |
| request telemetry | `hunt-memory/guards/<target>.json` | `tools/request_guard.py` | advisory rate/breaker 历史；缺失表示尚未采样，损坏必须 fail-fast，不是执行授权 owner |
| audit/journal/patterns | `hunt-memory/*.jsonl` | `memory/audit_log.py` 等 | 追加式跨会话日志，带轮换 |
| knowledge candidate draft | `knowledge/candidates/<slug>.md` | `tools/distill_target.py` | /distill 草稿卡（card-template 形态，maturity: draft）；人工 mv 即 promote，git log 即审计。原 lifecycle.jsonl 状态机已归档 |
| corpus projection | （纯函数，无落盘） | `tools/corpus_projection.py` | 案例白名单投影（normalize_report/dedupe_by_id），case_corpus 消费 |
| knowledge value review | `knowledge/governance/value-review.json` | `tools/knowledge_value_review.py` | 全 active 卡的可重建 advisory 复核投影，不是 runtime 状态 |
| local case corpus | `distill/corpus/{reports.jsonl,index.json,manifest.json}` | `tools/case_corpus.py` | 可选、gitignored 的规范化案例数据与 byte-offset 索引 |

`findings.json`、action queue、evidence ledger 和 target memory 含义不同。不得为了方便把
它们合并，也不得创建第二套 finding 生命周期。

## 场景：Evidence Ledger 当前闭合投影

### 1. Scope / Trigger

修改 Ledger result、summary、Surface ranking、Checkpoint proposal 或 Autopilot closure 时，
必须区分追加历史和当前闭合投影。

### 2. Signatures

```python
build_current_cell_projection(entries: list[dict]) -> dict
build_summary(repo_root, *, target, ...) -> dict
ClosureResolver(evidence_summary, matrix=None)
```

### 3. Contracts

- closure identity 是 `endpoint × vuln_class`；actor/object/method/variant 是证据维度。
- `closed_cells.endpoint` 保留 `canonical_endpoint_identity()` 的精确 query 和语义 SPA
  hash route。Coverage Matrix 可以按 `canonical_endpoint_path()` 聚合 route，但 Queue、
  Ledger 和 Finding 的终态只能匹配相同 exact endpoint identity；不得把 route projection
  当作 terminal proof。
- path-only legacy terminal 可以关闭同一 path-only candidate，但必须对 query-specific 或
  不同 SPA route 的 candidate fail-open。
- `tested_clean|tested_finding|dead_end|blocked_redline|not_applicable` 进入 `closed_cells`。
- 后续 `lead|signal|candidate` 清除同 cell 的旧闭合；`candidate` 另外进入
  `open_candidates`。原始 JSONL 不修改。
- `recent_entries` 仅用于展示和近期统计，不能 author closure。ClosureResolver 和 Checkpoint
  消费 `closed_cells`；Surface 只将其作为 advisory history。Autopilot 的 generic Surface review
  finality 只能由 exact Action Queue final outcome 授权，不得由 Ledger lane terminal 代替。
- Autopilot 的显式 closure/loop projection 必须读取
  `load_entries_diagnostic()`：保留 valid `entries` 供既有 reducer 使用，同时投影
  `status|invalid_count|invalid_rows|last_valid_offset`。`partial|unreadable` 只能 fail-open
  到 handoff/continue，不能伪装成 missing、finish 或 rotate；missing Ledger 仍表示空历史。

### 4. Validation & Error Matrix

| 输入 | 当前投影 |
|---|---|
| terminal | closed |
| terminal -> candidate | open candidate |
| terminal -> signal | open, non-candidate |
| terminal -> candidate -> terminal | closed by latest terminal |
| unknown/malformed result | 不改变最近一个 recognized projection |

### 5. Good/Base/Bad Cases

- Good：Ledger owner replay JSONL 后输出 current projection，consumer 只格式化或查询。
- Base：无事件时 `closed_cells=[]`、`open_candidates=[]`。
- Bad：consumer 遍历 raw rows 或 `recent_entries`，看到任意旧终态就闭合 endpoint。

### 6. Tests Required

- Ledger 覆盖 terminal/open/terminal 重放序列和 vuln-class 隔离。
- ClosureResolver 断言 `recent_entries` 单独存在时不闭合。
- Surface 与 Autopilot 断言旧 terminal 后的新 candidate 仍保留待办。
- Autopilot 断言 Ledger terminal 不会完成 generic Surface candidate；同 path 不同
  query 的 Queue/Finding terminal 不会完成或隐藏 candidate，exact Queue identity 仍可完成。

### 7. Wrong vs Correct

```text
Wrong: raw history contains tested_clean -> close forever.
Wrong: /api/x?foo=1 terminal -> strip query -> close /api/x?foo=2.
Correct: replay latest recognized endpoint × vuln_class result -> consume closed_cells.
Correct: use route identity for coverage and exact Queue endpoint identity for Surface terminal proof.
```

## 写入规则

### 替换型 JSON

- canonical 或多读者状态优先使用“同目录临时文件 -> flush/fsync -> `Path.replace()`”模式。
  真实范例：`tools/finding_index.py::_write_finding_payload()`、
  `tools/runtime_state.py::_write_json_atomic()`、
  `tools/checkpoint.py::_write_json_atomic()`。
- `hunt-memory/targets/<target>.json` 只有真正缺失时可投影为新 profile；JSON、schema 或读取
  损坏必须带路径失败，不能回落为空状态后覆盖历史。写入使用同目录临时文件、`fsync` 和原子替换。
- `hunt-memory/guards/<target>.json` 同样只有真正缺失时返回空 telemetry；坏 JSON、非 object、
  非法 `hosts/settings` 必须带路径失败。写入使用同目录临时文件、`fsync` 和原子替换；当前没有
  target lock，不能把它宣称为并发事务或执行授权状态。
- `findings.json` 的新增/更新必须调用 `upsert_finding(s)` 或
  `update_finding_status()`；coverage、runner、validator、report 不得直接覆盖整个文件。
- 源码支持的 finding 进入 `validation_status=rejected` 前，owner 必须校验本次传入的
  `validation_summary`：`result` 为 `rejected`，且 `source_guard` 的源码文件、1-based 行号和
  单行精确 quote 指向真实可执行 guard。缺失、注释、转述或不匹配引用必须在任何 owner
  写入前失败；该 cite-check 不替代 source-to-sink 控制流解释。
- 每次 canonical finding owner mutation 都必须在行上写入 `owner_provenance`，并向
  `mutation-events.jsonl` 追加同一 snapshot 的 `event_id`、target、finding ID、endpoint、
  漏洞类、lifecycle status、受限 evidence summary 和 fingerprint。`validated`、`rejected`、
  `generated`、`reported` 行只能在
  `verify_finalized_finding_owner_provenance()` 成功后被 reader 当作 closure/report input；
  直接 JSON finality edit 必须降级为 `validation_status=needs_owner_revalidation`、
  `report_status=not_generated`，并把原声明保存在 `claimed_validation_status` /
  `claimed_report_status`；不能由 rebuild、legacy migration 或通用 upsert 静默补 event 洗白。
- `findings/<target>/*.json` 中的独立 claim 不是第二套 finding schema，也不能直接被称为
  validated/report-ready。`autopilot_state` 只能只读提示其原始证据缺口；
  `checkpoint.py` 调用 `finding_index.reconcile_root_finding_claims()` 将其幂等归档为带显式
  incomplete rubric 的 canonical candidate，并同步 durable action。推荐 claim 使用
  `kind=finding_claim`、`schema_version=1`；无 discriminator 的 legacy claim 只有同时具备至少
  两个 identity 字段和 evidence-shaped detail 才兼容，未知 `kind`、错误 schema 或 off-target
  endpoint/target 必须忽略。匹配的 runner 必须传入该 canonical `--finding-id`，使 raw evidence
  回写同一 finding，而不是按自然语言 claim 另建状态。checkpoint 在 reconcile 后必须以
  `include_reconciled=True` 枚举所有 canonical root claim；每个缺证据 claim 都有一个幂等
  candidate-evidence-gap durable action，不能只处理本轮新增 claim。
- canonical finding 与 action queue owner 使用 target 级 `fcntl.flock` 包围完整
  read-modify-write，再通过同目录临时文件、`flush/fsync` 和 `Path.replace()` 原子替换；
  replace 失败必须清理临时文件并保留旧字节。调用方不能绕过 owner 自行执行 load/save，
  validation queue closure 也必须在同一锁事务内完成 identity 选择和 mutation。target memory
  的 `set`、append、handoff 和 checkpoint apply 使用同一 target-local mutation lock 包围
  read-modify-write，并通过同目录临时文件、`flush/fsync` 和 `Path.replace()` 原子替换；
  handoff 文件使用排他创建，不能覆盖同秒产生的另一个 handoff。该锁仍不宣称跨文件事务能力。
- runtime state 使用 target-local `session.lock` 包围完整 read-modify-write，并通过同目录
  临时文件原子替换；已有 `session.json` 损坏或不是 object 时必须 fail-fast，不能按空状态
  继续写入并覆盖诊断现场。
- validation case state 和 coverage matrix 同样使用同目录临时文件、`flush/fsync` 与
  `Path.replace()` 原子替换；replace 失败必须清理临时文件并保留原文件字节。case state
  的 actor/session/object/backlog mutation 另外由 `case_state_mutation_lock()` 包围完整
  read-modify-write；认证头不进入公共 JSON，而写入 `.private/case-state/...` 并以
  `private_ref` 关联，读取时只在内存合并。coverage matrix mutation 使用 target-local
  `coverage_matrix.lock`（`fcntl.flock`）包围每个完整 read-modify-write 事务；调用方必须
  通过 `save_matrix()`、`rebuild_matrix()`、`mark_endpoint_kind()` 和 `mark_cell()` 进入
  owner，不得绕过该锁。它只串行化同一 target 的 writer，不提供跨文件事务能力。
- observation owner 先原子替换完整 body，再按最终 body stat/revision 原子替换 summary；两步
  间中断由 binding mismatch 显示 stale/needs-sync。surface index 先发布完整 index/summary，
  manifest 最后发布；bounded projection 只有在完整 ranking 前后 input fingerprint 一致时才
  原子替换。旧派生文件可保留供诊断，但 reader 不得消费 stale 内容。

### 追加型 JSONL

- 每行必须是一个完整 JSON object；schema 校验在 owner 边界完成。
- 多进程共享日志使用 `O_APPEND + fcntl.flock`，并检查 partial write。真实范例：
  `memory/audit_log.py::AuditLog.log()`、`memory/hunt_journal.py::HuntJournal.append()`。
- finding mutation event 使用同样的 append/lock/fsync 边界。canonical JSON 已成功而 event
  append 失败时必须向上抛出，保留可诊断但 provenance-invalid 的行；只能通过再次调用同一
  owner API 重写该 finding 来恢复，不能由 consumer 手工回填字段。
- 大型长期日志使用 `memory/rotation.py` 的 10MB/3 backups 机制，不自行实现另一套轮换。
- evidence ledger 当前依赖个人顺序写入；不要在未升级 owner 的情况下宣称它支持并发追加。
- 正式卡 governance log 也以个人顺序使用为边界。追加前必须完整读取并 replay 现有事件，
  拒绝在损坏状态上继续写；事件写入后 `flush/fsync`。当前没有跨进程锁，不能宣称并发 writer
  安全，也不能通过编辑历史行纠错；使用显式补偿事件。

## Schema 与身份

- 新持久化对象必须有 `schema_version`，读取器需要明确缺失、旧版本和非法结构的行为。
- 目标身份统一经过 `canonical_target_value()`；目录统一经过 `target_storage_key()`。
  list target 使用“文件 stem + canonical path digest”，避免同名 list 共享状态。
- finding 身份由 `finding_index` 的 semantic key 管理；report ID 由
  `report_generator` 检查 finding、`INDEX.json` 和磁盘占用后分配。
- `owner_provenance` 的 `event_id`、`owner`、`operation`、`recorded_at`、`fingerprint` 与
  event 必须一一匹配；fingerprint 排除 provenance 自身。consumer 不得各自重算或只检查
  `validation_status`/`report_status`。
- 每个 root claim revision 是规范化 JSON 内容的稳定 SHA-256；canonical row 用集合式
  `claim_sources[{claim_id,source_file,revision}]` 保存全部来源/revision，标量
  `claim_id/claim_source_file/claim_revision` 仅作兼容投影。幂等判断使用 source+revision，
  不能让多个同 semantic claim 交替覆盖 trace。
- 新 validation writer 必须按 finding ID（无 ID 时按稳定 report identity）生成独立
  `<artifact-key>.validation-summary.json` / `<artifact-key>.submission-notes.md`。canonical row
  保存实际 `validation_summary` 路径和 `validation_summary_sha256`；shared provenance verifier
  同时验证 event fingerprint、summary 存在性和内容 digest。`findings/last-validate.json` 仅是
  convenience pointer，不是 canonical evidence。
- root claim discovery 必须排除上述 `*.validation-summary.json` 生成物，不能把 validation
  artifact 重新归档为 root claim。claim 同时带有流程/描述性 `type` 和明确 `vuln_class` 时，前者
  保留给流程/decision binding，后者保留为 coverage/evidence ledger 的 canonical 分类；不得让
  `type` 覆盖显式 `vuln_class`。
- active 知识卡来源由 `tools/knowledge_registry.py::parse_source_refs()` 统一规范化；
  `(type, corpus, id)` 在单卡内唯一，案例 ID 是非零十进制字符串。audit、resolver 和
  value review 不得自行实现另一套来源 parser。
- 正式卡 `event_id` 和 transition replay 归 `knowledge_lifecycle` 所有；candidate event 与
  formal-card event 不共享状态机。`value-review.json` 必须以 registry 的完整 active card ID
  集合为覆盖基线，不能成为决定卡片 active 状态的第二真相。
- 派生计数不能成为第二真相。runtime v2 从 recon artifact 和 finding index 动态推导
  readiness/count，只在 `session.json` 保存不可派生 breadcrumb。
- Surface destructive dedupe 的唯一 key 是经过既有逐行 trim 后仍完全相同的 URL 字符串。
  参数值/顺序、重复 key、percent encoding、scheme/port、path 大小写和尾斜线必须保留独立
  identity；`shape_id`、参数名 multiset 和 ordered signature 只用于统计/导航。

## 读取、损坏与迁移

- 缺失可选 artifact 通常返回空投影，让上层决定 `run_recon`、handoff 或补证据。
- inventory summary 或 surface projection 的 missing/stale/invalid 不能投影为零、clean 或
  exhausted。bootstrap 只能读 sidecar/stat 和 exact-hit bounded projection，不得回退解析
  monolithic inventory、扫描参数 URL 或隐式 refresh。完整 body/index/ranking 只由显式 owner
  命令或 recon finalizer 执行。
- append-only 日志允许跳过单条损坏行，但必须输出行号 warning；见
  `HuntJournal.read_all()`。
- `knowledge/governance/events.jsonl` 采用更严格语义：读取时可以收集其余合法行用于诊断，
  但任一坏行、重复事件或非法迁移都会使 audit/后续 append 失败，不能把损坏历史解释成
  可继续写入的状态。
- 本地案例 corpus 缺失是 `unavailable`，不阻断普通知识路由；三个 artifact 不齐也按
  unavailable 处理。文件 size/mtime/hash、schema、offset 或逐行 hash 不一致分别返回
  `stale`/`invalid`，查询不得返回 payload。只有显式 `build` 可以更新 corpus。
- canonical state 不应把损坏内容静默解释为“从未运行”。runtime state、action queue、validation
  case state 和 coverage matrix 仅在各自文件缺失时返回空投影；坏 JSON、非 object、owner 已定义的错误
  schema 或错误容器字段类型都必须抛出带路径错误。coverage matrix 的现有格式没有
  `schema_version`，本轮只严格校验其 `endpoints` 容器，不借修复损坏回落隐式迁移格式。
  checkpoint 等 consumer 不得吞掉这些错误后继续生成空状态 witness。
- 历史 finding list payload 由 `finding_index` 迁移为 canonical object。非终态 lifecycle 可以
  正常保留；无可信 event 的 finalized 声明只保留到 `claimed_*` 和证据指针，并降级为
  `needs_owner_revalidation`。迁移必须在 owner 内完成且可回归测试。
- 早期 writer 产生的 `{"findings": [...]}` object envelope 可由投影/owner 入口显式以
  `load_finding_index(..., allow_legacy=True)` 规范化到内存；该路径同样隔离无 provenance 的
  终态、拒绝 target/schema/容器错误、拒绝非 object 行，且不改写文件。默认读取以及
  report/validate witness 仍使用严格 canonical 校验；只有 owner mutation 在锁内重新签名后
  才能恢复生命周期终态。
- 历史 object payload 的普通 read 不会自动伪造 finality provenance。rebuild、legacy migration
  和通用 upsert 在 owner 签名前必须统一验证 existing finality；没有有效 event 的历史
  validated/generated row 在 canonical 行中显示 `needs_owner_revalidation`，runtime 派生动作可
  显示 `owner_revalidation_pending`。只有明确 `/validate` / status-owner transition 可以恢复终态。

## 多文件一致性

项目没有跨文件事务。现有流程采用“主状态 owner 成功 -> 派生/队列同步”的顺序，并让
非主同步返回 `skipped` 或可诊断结果。例如 report 先排他创建文件，再更新 finding 状态和
queue。新增跨文件流程必须明确：

1. 哪个文件是事实来源；
2. 中断发生在每一步时如何重放；
3. 同一 finding/action 的幂等键；
4. 派生同步失败是否可恢复，不能静默丢失主结果。

当前已证明的有界重放入口是：checkpoint CLI 的 root claim -> Finding -> Queue、
`validation_runner.sync_runner_artifacts()` 的 Ledger -> Finding -> Queue、
`report_generator.process_findings_dir()` 的 report file -> Finding -> Queue -> Index，以及
`autopilot_round.settle_round()` 的 checkpoint -> Queue -> Surface -> round closure。相同公共操作在
任一已提交边界后重跑必须补齐后续 owner/投影且不复制 identity；ambiguous、owner write error 或
仍 stale 的 Surface 保持可见的 partial/handoff，不能授权 `finish`。这些保证由
`test_checkpoint_root_claim_replays_each_durable_boundary`、
`test_runner_reconciliation_replay_repairs_each_owner_without_duplicates`、
`test_report_generator_retry_reconciles_interrupted_cross_owner_flow` 和
`test_settle_round_replays_each_durable_boundary` 的故障注入矩阵约束。

无人值守 round 的停滞计数属于现有 checkpoint witness 的 `round_guard`；只有显式 round
closure record 可以递增，相同 blocker fingerprint 连续三次封顶，相关证据变化或非前提型
handoff 清除。fingerprint 只哈希 coverage 语义，不包含 `last_updated` 等 rebuild 时间戳；
普通 `/autopilot` 和只读 closure 不递增。封轮计算忽略仍为 active 的当前 round recovery
投影并读取 underlying post-round Closure；`next_action_pending`、`coverage_high_value_gaps` 与既有
prerequisite blockers 共用同一 guard。fingerprint 同时绑定 bounded Surface candidate/review
identity；阈值处只有在无 authoritative durable work 时才旋转到 target-owned adjacent candidate，
没有 continuation 则 non-exhaustive blocked。

案例 corpus 以 `reports.jsonl` 为数据面，`index.json` 和 `manifest.json` 为匹配该版本的
校验/查询 artifact；build 在 staging 中完成后再替换三个文件，reader 必须在查询前验证三者
一致。正式卡 active 状态则由 registry 控制运行时加载、governance log 控制历史追溯；audit
负责验证两者一致，不存在跨文件事务或隐式双写。

Surface 派生链以 raw recon/inventory 为事实来源：recon finalizer 可以按
`exact index -> full stream rank -> inventory summary -> bounded projection` 重建；任一步失败都
不得删除 raw artifact 或写 tested-clean。index/projection 输入在构建期间变化时拒绝发布，用户
重跑即可。输入 manifest 绑定普通文件身份和目录结构，但不绑定目录时间戳，也不包含 finalizer
之后写入的 `recon_manifest.jsonl` 等控制文件，避免已发布 projection 因收尾写入立即 stale。
`action_queue.json` 与 Evidence Ledger 是语义 fingerprint 例外：Queue 的 claim、runner
`last_outcome`、`next_question` 和时间戳更新不使 projection stale；会改变 Queue action
语义（包括 active endpoint/action identity 或 final endpoint/status）的更新必须使其 stale。
Ledger 只按 owner 的 closed-cell projection 和读取诊断参与 fingerprint；不改变 closed-cell
meaning 的追加记录不使 projection stale。raw Queue/Ledger records 仍完整保留在 manifest
items 和各自 owner 文件中，target binding 与 exact-hit 校验不变。bootstrap、full state 和
context-pack 只复用同 fingerprint 投影，不形成多写者。

## 场景：Autopilot durable continuation

### 1. Scope / Trigger

修改 Surface/Coverage 输入、Action Queue 领取、Case State 启动投影、无人值守 lane
预算或 Target Memory 写入时，必须保持同一 owner 链，避免上下文重启后跳过长尾或重复执行。

### 2. Signatures

```text
python3 tools/action_queue.py claim --target <target> [--json]
begin_round(repo_root, target, *, max_lanes) -> dict
record_round_lane(repo_root, target, *, lane, max_lanes) -> dict
record_round_lane_result(repo_root, target, *, lane, status, decision, evidence_ref, next_action) -> dict
python3 tools/checkpoint.py --target <target> --record-round-closure --json
```

### 3. Contracts

- Coverage rebuild 流式消费 valid `surface/index.jsonl` 的 `target_owned=true` URL；原有
  scope、weight、route-template、raw artifact 和 finding owner 不变。source fingerprint
  包含 Surface `input_fingerprint`、`index_binding` 和 row count。
- Action Queue 在现有 target lock 内选择并 claim。已有 `running` 永远先于 queued/report/
  advisory；queued claim 原子转为 `running` 且 attempts 只加一次，重复 claim 返回 `resumed`。
- Case State 只投影无秘密 summary/top action；active backlog/open hypothesis 阻止 exhausted，
  损坏 canonical file 进入结构化 state error。
- `checkpoint_latest.json.round_progress` 保存 round ID、原始 `max_lanes`、唯一
  `claimed_lanes`、派生计数、budget flag 和与 claimed 顺序一致的 `lanes[]`。每条 lane 在目标
  工作前原子写 `status=started`；终态只保存 `completed|blocked`、单行有界 `decision`、
  `evidence_ref`、`next_action` 和时间戳，不保存 raw response、prompt 或凭据。
- Checkpoint mutation 与 Closure 只读投影共同调用 `tools/checkpoint_witness.py` 的结构校验器；
  reader 仅可为历史 completed evidence 修复启用显式兼容开关，不能放宽预算、派生计数、lane
  顺序、时间戳或终态字段校验。
- Heartbeat 不是第二套 action owner；terminal lane 的 unresolved `next_action` 必须在 closure 前
  写入其既有 owner 或 Action Queue。heartbeat 只保证该 write-back 前中断时仍可恢复决定。
- 缺少 `lanes[]` 的旧 active witness 将 claimed ID 规范化为 unfinished `started`。started replay
  不增加预算；terminal replay 不发起目标工作；相同 terminal result 幂等，冲突改写拒绝。
  `completed` 必须引用可定位 evidence；任一 started lane 存在时 round closure 必须失败。
- Target Memory 文件缺失可建立默认对象；已存在的坏 JSON/shape 必须报错，写入必须原子替换。

### 4. Validation & Error Matrix

| 条件 | 结果 |
|---|---|
| Surface missing | Coverage 保留 legacy 输入；不得伪造 index generation |
| Surface stale/invalid | 旧 Coverage fingerprint 失效；closure 不得把旧投影当完整覆盖 |
| Coverage source fingerprint mismatch | Closure returns `coverage_stale` and requires a rebuild; a stale full matrix is not a valid fallback for a stale projection |
| Recon phase input sampled | Manifest gate exposes bounded totals and continuation; only explicit `closure_blocking=true` residuals hold Closure |
| Phase artifact changed after manifest record | Rebuilt gate returns `partial` with `artifact_changed_since_record` |
| Queue 已有 running | `claim` 返回同一 ID、`claim_status=resumed`，不领取第二项 |
| Case State 损坏 | bootstrap/closure 返回 exit `2` 和 `state_read_error` |
| round witness 损坏或预算字段矛盾 | round begin/claim 返回 exit `2`，不得新建空预算覆盖 |
| lane ID 重放 | `already_claimed` 且 claimed_count 不变 |
| terminal lane ID 重放 | `already_completed|already_blocked`、`allowed=false`，不得重复目标请求 |
| terminal result 同值重放 / 冲突重写 | `already_recorded` / exit `2` 且保留原结果 |
| completed 缺可定位 evidence_ref | exit `2`，lane 保持 started |
| closure 尚有 started lane | exit `2`，round 保持 active |
| budget 已满 | `allowed=false,status=budget_exhausted`，不执行新 lane |

### 5. Good/Base/Bad Cases

- Good: 第 6 个以后 API Surface 进入 Coverage；中断后恢复 running action、started lane、terminal
  decision/evidence/next action 和剩余 lane 预算。
- Base: 没有 Surface Index/Case State/Target Memory 时保持 legacy recon 和首次默认状态。
- Bad: 只检查启动前五项、把 running 排在 queued 后、由 prompt 重新从零计 lane，或把 claimed
  直接当 completed 后继续/结束。

### 6. Tests Required

- Surface-only 长尾进入 Coverage，index rebuild 使旧 matrix/projection stale。
- Queue claim/resume 保留 attempts/notes/evidence，runtime wait 不破坏 queue。
- Action Queue 的 `validated`/`reported` 终态必须携带仓库内可定位且已存在的 evidence ref；
  空值、自由文本或不存在的路径不得关闭队列动作。canonical `/validate`、report 和 runner
  调用方必须先写出对应 summary/report artifact，再执行该 owner mutation。
- Case backlog/hypothesis 覆盖 bootstrap、compact projection、loop guard、closure 和坏 JSON。
- Round begin/claim/start/result/idempotent conflict/terminal replay/exhausted/unfinished closure/
  new-round、legacy normalization 及损坏 witness 全部用 `tmp_path`；另以多进程超额 claim、
  同值 terminal writer 和反复中断/封轮循环验证 lock + atomic replace。
- Target Memory replace failure 保留旧字节并清理临时文件；CLI 不输出 traceback。

### 7. Wrong vs Correct

Wrong: `next -> execute -> resolve` 只靠模型记忆，并按本轮局部变量判断 `max_lanes`；claimed ID
被误当作已完成 lane。

Correct: `claim/start -> execute -> terminal heartbeat`，每个 substantive lane 先由 checkpoint
witness 原子领取，结果引用既有 evidence owner；final closure 同时要求没有 started lane，并只
消费 owner 的 `round_progress.budget_reached`。

## 场景：Spray preflight、run 与敏感证据契约

### 1. Scope / Trigger

修改 `spray_orchestrator.sh`、四种 Spray adapter、request spec、审计字段或恢复逻辑时，
必须保持 `tools/spray_contract.py` 的唯一共享契约。preflight/run 是执行卫生和证据，
不是 finding、action queue 或 target memory 的第二状态机。

### 2. Signatures

```text
tools/spray_orchestrator.sh URL --mode MODE --users FILE --passes FILE [flags]
prepare_run(mode, *, config_binding, request_shape) -> RunContext
append_attempt(context, event) -> event
finish_run(context, *, status, stop_reason, counters, exit_code) -> summary
```

`--dry-run` 生成 preflight；无人值守 live 使用 `--preflight FILE --i-understand`；恢复使用
`--resume RUN_DIR`。

`spray_orchestrator.sh` anchors the default `SPRAY_REPO_ROOT` to its checkout,
so invoking it from another cwd remains restart-safe; an explicit environment
override is retained for isolated workspaces and tests.

### 3. Contracts

- 必需 env：`SPRAY_TARGET_URL/MODE/USERS_FILE/PASSES_FILE/DELAY/JITTER/CONTINUE_ON_HIT`；
  Shell 另传 `SPRAY_DRY_RUN/I_UNDERSTAND/INTERACTIVE_CONFIRMED/INSECURE/PREFLIGHT/RESUME`。
- binding 包含 URL、mode、去重后 users/passwords SHA-256、config digest、`user_count`、
  `password_count`、`total_attempts`、有效的 `max_users`/`max_attempts`、delay/jitter 和
  continue-on-hit；默认上限为 100 个用户和 1000 次总尝试，AI shortlist 同时绑定 companion
  metadata digest。preflight `schema_version=1` 且 24 小时过期；输入或限制漂移必须 fail-fast。
- `spray-shortlist.txt/.jsonl` 必须为 `0600`，metadata 顺序与 password digest 一致；已知
  candidate-pool/ranked alias 在共享契约拒绝，不能只依赖 Agent 文档。
- HTTP/OAuth 默认验证 TLS；显式 insecure 进入 config binding。带 secret-like query key 的目标
  URL 在任何请求前拒绝。
- live 输出 `recon/<key>/spray/<run-id>/{run.json,attempts.jsonl,summary.json}`；
  token、cookie、响应正文和 TREVOR HOME 只进 `.private/spray/<key>/<run-id>/`。
- `attempts.jsonl` 只保存 password hash prefix、分类和无秘密元数据；`summary.json` 是完成、
  stop、中断或错误 marker。
- resume 只接受缺失 summary、`interrupted` 或 `error`；其他 status 是终止状态，必须新建
  preflight。每个 live/resume run 持有非阻塞文件锁，避免并发重复。
- TREVOR 只能消费 private 目录内由 canonical users/passwords 写出的 `0600` 去重副本，不能把
  与 binding 语义不同的原始文件直接传给上游。

### 4. Validation & Error Matrix

| 条件 | 行为 |
| --- | --- |
| URL 不是 http/https、嵌入凭据、输入空或数字非法 | 任何请求前 fail-fast |
| unattended live 缺 preflight、过期或 binding 漂移 | fail-fast，不隐式选“最新” |
| preflight run 已存在但未显式 resume | 拒绝，提示 `--resume` |
| resume 越出当前 target spray 目录、manifest/JSONL 损坏或 run ID 不一致 | fail-fast |
| resume 已 completed/stopped run 或另一个 runner 已持锁 | fail-fast，重新评估后新建 preflight |
| candidate alias、shortlist metadata 缺失/漂移或密码文件权限宽于 0600 | fail-fast |
| SIGINT、guard stop、provider 非零退出 | 写明确 summary，不表示 clean/no findings |

### 5. Good / Base / Bad Cases

- Good：dry-run 零认证请求，live 使用同 binding，中断后跳过已记录 attempt。
- Base：人工交互 live 保留兼容，但仍使用同一 run/audit/private 契约。
- Bad：把 candidate pool 直接 live、重用过期 preflight、把 token 写入 stdout/attempts，或把
  进程非零解释成零发现。

### 6. Tests Required

- `test_spray_contract.py`：binding、过期/漂移、权限、shortlist metadata、终止状态、并发恢复和损坏 JSONL。
- localhost HTTP/OAuth：dry-run 请求数为 0，CSRF/CookieJar、特殊字符编码、明确/模糊/
  rate-limit 分类、private secret 与 resume 不重复。
- fake/current TREVOR：module/CLI、分类、脱敏、隔离 HOME、no-loot 和非零 summary。

### 7. Wrong vs Correct

```python
# 错误：只要 fail regex 消失就声明有效凭据。
credential_valid = not fail_regex.search(body)

# 正确：无明确 success 证据时停在模糊候选，交还 AI 复核。
classification = "valid_session" if success_signal else "ambiguous_candidate"
```

## 场景：大体积派生状态的可验证分页与缓存失效

### 1. 触发范围

`observations.json`、Surface index 或 projection 的 reader 需要在不重读完整正文的前提下判断
快照是否仍可用，或按 cursor 访问长尾数据时，必须遵循本节；不能为了性能把前 N 条当作完整
攻击面。

### 2. 签名

- `page_inventory(repo_root, target, *, status="", kind="", source="", limit=50, cursor="")`
- `page_surface_index(repo_root, target, *, limit=50, cursor="", shape_id="", source="", target_owned=None)`
- `build_surface_input_manifest(repo_root, target, *, memory_dir=None)`

### 3. 契约

- inventory owner 写入 `page_order: "first_seen_id"`，并按 `(first_seen, id)` 固定正文数组物理顺序；
  sidecar 的 `inventory_binding` 至少绑定 `size`、`mtime_ns`、`ctime_ns`、`st_dev`、`st_ino` 和正文
  digest。后续 streaming cursor 只从 byte offset 扫到下一页所需 observation。
- legacy/未知物理顺序的 inventory 仅可走兼容完整读取分页；page reader 不得借此改写 body 或 sidecar。
- Surface input/index binding 同样记录文件身份字段。即使替换后的文件 size 相同并恢复 mtime，只要
  inode/ctime 变化，manifest/projection 必须成为 `stale`，不能消费旧候选。
- 过滤分页只有在后方存在下一条**匹配**记录时才返回 `next_cursor`；byte EOF 前的非匹配行不构成下一页。

### 4. 校验与错误矩阵

| 条件 | 行为 |
| --- | --- |
| cursor 的 target/filter/revision 不匹配 | fail-fast；调用方从新快照开始 |
| sidecar/body binding 或 projection manifest 不匹配 | 返回 `stale/needs_sync`，不把旧数据投影为零或 clean |
| legacy body 没有 `page_order` | 兼容完整读取，不写入目标状态 |
| filtered final page 后只有非匹配行 | `next_cursor == ""` |

### 5. Good / Base / Bad

- Good：owner sync 后的 30 万 observation 使用 byte cursor 继续访问，前一页不重载完整 JSON。
- Base：首次 page 为得到 `total_matching` 可以完整流式计数；以后的同一快照 cursor 不重复计数。
- Bad：只比较 size/mtime 后继续使用旧 projection，或按文件 EOF 生成必然为空的 follow-up page。

### 6. 必需测试

- 原子同尺寸替换并恢复 mtime 后，summary/projection 必须 stale。
- 流式 cursor 遍历所有匹配 ID 一次且不调用完整 snapshot loader；legacy 分支不写文件。
- source/shape 过滤后的最后一条匹配记录不返回空 cursor。

### 7. 错误与正确做法

```python
# 错误：同尺寸且 mtime 被恢复的替换会伪装成 cache hit。
fresh = stat.st_size == binding["size"] and stat.st_mtime_ns == binding["mtime_ns"]

# 正确：派生 reader 还要验证文件身份，并在不匹配时 fail closed。
fresh = (
    stat.st_size == binding["size"]
    and stat.st_mtime_ns == binding["mtime_ns"]
    and stat.st_ctime_ns == binding["ctime_ns"]
    and stat.st_dev == binding["st_dev"]
    and stat.st_ino == binding["st_ino"]
)
```

## Scenario: Recon collector 原子发布与失败保留

### 1. Scope / Trigger

修改 `tools/recon_engine.sh` 的并行 collector、profile、raw artifact 或
`recon_manifest.jsonl` 时适用。目标是缩短 wall time，但 collector 失败、中断或缺工具不能清空
上一次可恢复的事实。

### 2. Signatures

```text
bash tools/recon_engine.sh TARGET [--quick|--normal|--deep|--full]

recon_collector manifest row:
{schema_version, record_type, target, target_key, mode, collector,
 status, artifact, count, duration_seconds, note, recorded_at}
```

### 3. Contracts

- 裸入口为 `full`；`hunt.py --recon-only` 默认传 `--normal`，显式 quick/deep 原样覆盖。
- 每个 collector 写同目录临时文件；只有 `rc=0` 才替换 canonical artifact。
- timeout 或带部分输出的失败将旧 artifact（含 `.txt.gz`）与新输出做 exact union 后发布；
  unavailable、skipped、无输出 error 保持旧 artifact 不变。
- 父进程等待全部独立 collector 后，单写 manifest 和合并文件；后台进程不得并发追加 manifest。
- 状态只使用 `ok|partial|unavailable|error|skipped`；`ok + count=0` 表示已运行零结果，不能与缺工具
  或超时混同。
- URL reader/merge 必须同时接受当前 `.txt` 和 post-run `.txt.gz`；参数顺序、重复参数、编码、端口、
  path 大小写等 exact identity 不得因合并而归一化。
- `urls/js_files.txt` 保留完整 inventory；`js/deep_candidates.txt` 只保存多类别有界消费视图。
  Recon 生成的 deep-JS action 使用稳定 `source_id` 和候选内容 `generation`：同一未执行动作原地
  更新，同一已终态 generation 不重复加入，新 generation 必须生成新的可执行动作。

### 4. Validation & Error Matrix

| 条件 | 行为 |
| --- | --- |
| collector `rc=0` | 原子替换 canonical artifact，删除同名旧 gzip |
| collector `rc=124` | `partial`；合并旧事实和本轮 partial 输出 |
| collector 缺失 / profile 不适用 | `unavailable/skipped`；旧 artifact 保留 |
| collector 非零且无新输出 | `error`；旧 artifact 保留 |
| 子进程没有写 status sidecar | 父进程记录 `error`，不能复用旧 sidecar |
| plain 缺失但 gzip 存在 | count、merge、Surface provenance 从 gzip 读取 |

### 5. Good / Base / Bad Cases

- Good：gau 本轮超时，旧 gzip 与本轮 partial URL exact union 后继续进入 `urls/all.txt`。
- Base：首次运行缺少 amass，记录 `unavailable + count=0`，其它 collector 正常合并。
- Bad：启动 collector 前执行 `: > gau.txt`，随后工具超时，导致上轮 raw URL 永久丢失。

### 6. Tests Required

- Shell 语法和 wiring：profile 校验、父进程 wait、独立 sidecar、临时 artifact 发布。
- focused regression：缺工具、skip、timeout、带/不带 partial 输出、旧 plain/gzip 保留。
- Surface/inventory：gzip/plain provenance union 与 exact URL variant identity。
- JS/queue：候选按类别有界；相同 generation 幂等，新 generation 在旧动作终态后重新入队。
- 全量 pytest；涉及 runtime prompt 时另跑 runtime staging/doctor。

### 7. Wrong vs Correct

```bash
# Wrong: 运行前破坏 canonical 数据，失败后只能得到空文件。
: > "$artifact"
collector -o "$artifact" || true

# Correct: 临时写入；按退出状态替换、合并或保留旧 artifact。
tmp=$(mktemp "$(dirname "$artifact")/.collector.XXXXXX")
collector -o "$tmp"
mv -f "$tmp" "$artifact"
```

## Scenario: detached phase lock 与 manifest 输入 no-op

### 1. Scope / Trigger

- 适用于父编排进程以新 session 启动 recon/scan 长任务，或 Action Queue 文件被 Surface
  input manifest 追踪的路径；防止父进程终止后锁提前释放，以及空 sync 误打 stale。

### 2. Signatures

- `runtime_phase_lock(repo_root, target, phase, include_fd=True) -> (lock_path, fd)`
- `subprocess.Popen(..., pass_fds=(fd, ...), start_new_session=True)`
- `save_queue(repo_root, target, queue) -> Path`：语义无变化时返回原路径但不替换文件。

### 3. Contracts

- 实际长任务继承父进程预留的 phase lock fd；父上下文只关闭自己的 fd，不能对共享
  open-file-description 执行 `LOCK_UN`。
- queue/action 顶层 `updated_at` 不参与 no-op 判断；action metadata 中同名证据字段仍参与。
- no-op 保留磁盘字节和 inode；真实 priority/status/metadata/action 变化仍原子替换并更新时间。
- Surface manifest 忽略 findings owner 的 `.locks` 目录；只含该控制目录的 findings 根等价于
  不存在业务输入，首次建锁不能改变 fingerprint。
- Surface manifest 对 Queue/Ledger 保留原始 `items` metadata，但 fingerprint 使用上述语义
  projection；因此 Queue claim/runner write-back/timestamp-only replacement 不会制造 stale，
  Queue endpoint/status 或 Ledger closed-cell meaning 改变会制造 stale。缺失、空文件和只含
  非终态 lead 的 Ledger closure meaning 相同；首次创建 Ledger 目录/文件不能单独制造 stale。

### 4. Validation & Error Matrix

| 条件 | 行为 |
| --- | --- |
| 父进程退出、子进程仍持继承 fd | phase 保持 active，阻止重复启动 |
| 最后一个 fd 关闭 | flock 自动释放 |
| checkpoint 语义无变化 | queue 不替换，Surface projection 继续 valid |
| metadata/priority/status 变化 | `updated += 1`，原子替换 queue；Surface 仅在语义 projection 变化时 stale |

### 5. Good / Base / Bad Cases

- Good：slash 调用父进程被终止，detached recon 继续运行且仍持 recon/scan 预留锁。
- Base：普通 direct phase runner 自己持锁，退出时自动释放。
- Bad：父上下文显式 `LOCK_UN` 后再关闭 fd；继承子进程仍运行但 lock 已消失。

### 6. Tests Required

- 子进程继承 fd 后父上下文退出，`runtime_phase_is_active()` 仍为 true；子进程退出后为 false。
- hunt Popen 收到当前 phase lock `pass_fds`。
- 相同 checkpoint 二次 ingest 为 `added=0, updated=0`、inode 不变且 projection 为 valid。
- projection 发布后首次创建 `findings/<target>/.locks/findings.lock` 仍保持 valid。
- projection 发布后首次写入非终态 Ledger lead 仍保持 valid；首个 closed-cell 使其 stale。
- metadata-only 更新必须计为 updated 并持久化，不能被时间戳过滤误吞。

### 7. Wrong vs Correct

```python
# Wrong：父进程一死，detached child 仍运行但锁被释放。
with runtime_phase_lock(root, target, phase):
    subprocess.Popen(command, start_new_session=True)

# Correct：实际长任务继承 fd；include_fd 上下文退出时不显式 LOCK_UN。
with runtime_phase_lock(root, target, phase, include_fd=True) as (_, fd):
    subprocess.Popen(command, start_new_session=True, pass_fds=(fd,))
```

## Scenario: repository-root seam and worker auxiliary state

### 1. Scope / Trigger

- 适用于工具或 worker 需要读取仓库配置、recon 输入或写入 findings/state 的场景。
- 模块级 `BASE_DIR` 只保留默认 checkout；显式 root 必须覆盖同一执行链上的辅助状态。

### 2. Signatures

- `operation(..., repo_root: str | Path | None = None)`：在最高共享边界接收可选 root。
- `main(... --repo-root ROOT)`：仅在 CLI 自己选择仓库相对路径时暴露。
- `GlobalRateLimiter(state_path=...)`：worker 传入 root-owned lock path。

### 3. Contracts

- `repo_root=None` 保持既有 checkout-relative 默认行为；传入 root 后，配置、recon、findings、
  cursor、checkpoint 和 worker auxiliary state 不得回写默认 checkout。
- 已有 `evidence_root`、`recon_root`、`memory_dir`、`findings_dir` 或 `out_path` 的模块继续使用
  窄路径参数，不添加同义 `repo_root`。
- import-only 的 `BASE_DIR` 只用于 `sys.path` bootstrap，不接受伪 root 参数。

### 4. Validation & Error Matrix

| 条件 | 行为 |
| --- | --- |
| 无 root 参数 | 输出路径和 schema 与历史调用一致 |
| 显式 root | 所有可变 artifact 与 worker lock 位于该 root |
| 输入 artifact 在 root 外 | 作为调用方显式输入读取；不得将其复制为 root 内第二真源 |
| import-only 模块 | 不新增 `repo_root` 参数 |

### 5. Good / Base / Bad Cases

- Good：worker 从 `ROOT/recon/<target>` 读取 URL，并把 `ROOT/hunt-memory/audit/parallel_lock.json`
  作为限速器状态。
- Base：默认 CLI 未传 `--repo-root`，继续写当前 checkout。
- Bad：主 findings 写入 ROOT，但限速器或 cursor 仍写模块 `BASE_DIR`。

### 6. Tests Required

- 每个 repo-root-dependent 边界使用 `tmp_path` 断言输出位于 root。
- worker 测试同时断言 recon 输入和 auxiliary lock 位于 root。
- classification contract 覆盖全部候选模块，并断言窄路径/import-only 模块没有 cosmetic root 参数。
- 至少一次全量测试确认默认调用、schema 和现有 CLI 兼容。

### 7. Wrong vs Correct

```python
# Wrong: 主输出隔离了，worker 限速状态仍污染 checkout。
GlobalRateLimiter(test_rps=1.0)

# Correct: 所有可变 worker 状态绑定同一个显式 root。
GlobalRateLimiter(state_path=Path(repo_root) / "hunt-memory/audit/parallel_lock.json", test_rps=1.0)
```

## 测试要求

- 使用 `tmp_path` 构造完整读写往返，不读取真实 `state/`、`recon/` 或目标记忆。
- 覆盖缺失、旧 schema、非法 JSON、重复写、碰撞和中断恢复。
- 改动 target/finding/report 身份时，必须同时检查所有生产者和消费者。
- 改动 finding lifecycle/provenance 时，必须覆盖 owner API round-trip、event/row fingerprint 或
  operation/timestamp 不匹配、直接 JSON finality reject、以及 owner-backed validated/generated
  行在 report/runtime/surface/runner 中的正向消费。
- 改动 root claim 时，必须覆盖普通 status JSON、未知 kind、off-target scheme-less identity、
  source revision replay、同 semantic 多来源稳定 union、incomplete identity 补齐、非空冲突，及
  重复 checkpoint 后所有 reconciled claim 仍各有一个 durable evidence-gap action。
- 改动 validation artifact 时，必须在同一目录连续写至少两个 finding，验证不同 summary/notes
  路径、digest mutation reject 和 report path cross-finding ownership。
- 改动 action queue 时，必须覆盖 missing、坏 JSON/shape/schema、atomic replace failure 保留旧
  字节，以及 CLI stderr 路径诊断和 exit `2`。
- 改动 validation case state 或 coverage matrix 时，必须覆盖 missing、坏 JSON/shape/schema、
  atomic replace failure 保留旧字节，以及 checkpoint 等 consumer 对损坏状态的显式失败。
- 改动 Surface/inventory 派生层时，必须覆盖 sidecar/projection missing/stale/corrupt/target
  mismatch/body binding、atomic replace failure、构建 input race、exact variant identity、
  provenance union、cursor revision/filter mismatch 和读取零 lifecycle mutation。大规模测试只在
  `/tmp` synthetic fixture 中写入；opt-in 外部语料只读并只输出聚合指标。
- 改动知识来源、正式卡 lifecycle 或案例索引时，覆盖 corpus missing/stale/invalid/dangling、
  非法/终态迁移、replacement/archive 一致性和 active registry 全量集合等价。迁移行为测试使用
  synthetic corpus 与临时治理日志，不读取本机 `distill/corpus/`；另保留一个只读的当前仓库
  lifecycle audit 回归，断言每张 active 正式卡都有 adopted event。
