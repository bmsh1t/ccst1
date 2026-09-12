# Recon and Surface Contracts

> Recon 输入、派生 Surface、coverage 和排序契约。

## Scenario: Scanner 原始语料、消费视图与完成态

### 1. Scope / Trigger

- 修改 recon URL 产物、`vuln_scanner.sh` 输入、Autopilot broad scan、scanner
  summary 或完成态消费者时适用。
- 目标是保留完整攻击面，同时避免把历史语料数量直接放大成通用 scanner 工作量。

### 2. Signatures

```bash
python3 tools/hunt.py --target <target> --scan-only --quick
bash tools/vuln_scanner.sh <recon_dir> [--quick|--full] [--skip <modules>]
```

正常出口的 `summary.json` 至少包含：

```json
{
  "input_contract": "live-priority-targets",
  "raw_url_count": 19000,
  "parameter_url_count": 4,
  "ordered_scan_count": 3
}
```

### 3. Contracts

- `recon/<target>/urls/all.txt` 和 collector 原始文件是完整证据语料，不删除、
  不覆盖参数值、顺序、重复参数、编码等变体。
- 常规 broad scanner 的 `ordered_scan_targets.txt` 只由 `priority/*.txt` 与
  `live/urls.txt` 按顺序合并并 exact 去重；参数 lane 独立消费
  `urls/with_params.txt` 的派生视图。
- General Nuclei consumes only the origin-deduplicated bounded derivative of
  that ordered list: quick/standard/full default to 50/100/200 origins, with
  `BB_NUCLEI_MAX_TARGETS` as an explicit override. `summary.json` must retain
  available/selected/truncated counts. This is a bounded breadth sensor, not
  exhaustive coverage; raw or long-tail paths require an AI-selected,
  evidence-backed targeted input.
- The integrated CVE lane covers low-to-critical templates on those bounded
  origins. It excludes only DoS/brute-force tags, local `code` templates, and
  external interactsh callbacks by default; headless/JavaScript/fuzz/intrusive
  labels are not category-level skips. Rate, concurrency, and timeout caps are
  the execution controls; scanner output remains advisory until exact replay
  and impact validation.
- Explicitly state-changing Scanner probes, including upload canaries and HTTP
  method tampering, require `ALLOW_UNSAFE_HTTP_TESTS=1`. Without the opt-in they
  are skipped, recorded under `manual_review/unsafe_skipped.txt`, and remain
  reviewable rather than clean; HTTP method alone is not a universal effect
  classifier.
- `commands/autopilot.md` and `agents/autopilot.md` are controller prompts,
  not embedded playbooks. Guard their UTF-8 sizes at 20 KiB and 32 KiB while
  separately testing required runtime references and rejecting embedded payload
  tables; do not use line count as a prompt-cost proxy.
- bounded Surface/projection 是默认 AI 窗口，不是能力上限；长尾通过 index
  分页、raw 查询或证据驱动的专项列表继续消费。
- findings 目录创建后立即删除旧 canonical summary 和临时 summary；consolidation
  先生成 `findings.json`，成功后再以 `summary.json` 作为最后发布的 completion marker。
  finding index 或 summary 序列化失败都必须非零退出；历史 raw evidence 不随之删除。
- 任一 Nuclei lane 非零退出时，该 lane 必须显示 `incomplete`，不得同时显示
  `clean`。`hunt.py` 使用既有 `scan_failed / run_vuln_scan_failed` breadcrumb，
  Dashboard 显示 `Failed`，不能把已执行失败显示成 `Skipped` 或成功。
- Surface 必须从当前 target 的 canonical `findings/<target>/summary.json.manual_review[]`
  建立完整中性索引。只接受位于该 target findings 根目录内、实际存在且包含非空行的
  文件；summary 中的重复、缺失、空、绝对或越界路径必须忽略，行数以实际文件为准。
- 完整 ranked Surface 保留全部合法 manual-review 条目；小型 projection 只保留总数、
  canonical summary 路径和最多 8 个文件/每文件 3 行的预览。默认 Scanner Findings 文本
  显示同一有界预览，不能依赖 workflow-lead top-K 才可见。
- 未识别 manual-review 文件只是证据索引，不得自动成为 workflow lead、Candidate、
  Coverage 结论或 Queue 动作。`unsafe_skipped.txt`、`open_200_api.txt` 和
  `standard_public_metadata.txt` 继续使用各自已有的专用 handler。
- Incomplete scanner runs still pass successful lane outputs through the canonical
  `finding_index` owner as unvalidated candidates. They do not publish `summary.json`
  or `scanner_pass.json`, so partial evidence stays reviewable without claiming
  scanner completion or tested-clean coverage.
- Recon's configured soft budget is advisory telemetry, not a phase-stop or
  completion verdict. A completed run records `run_budget.status=ok` and may set
  `soft_budget_status=advisory_exceeded`; only interruption, parent/tool timeout,
  or an actually incomplete run records `run_budget.status=partial` and blocks
  Closure through the existing `recon_artifacts` projection.
- 常规 quick breadth 使用既有 single-target runtime lock；Deep、raw URL 数量或
  scanner-negative 不能自动触发第二次 broad nuclei。明确组件、CVE、路径或行为
  证据可触发独立 targeted templates，但不得伪装成常规 scanner completion。
- `exposure/host_ranking.jsonl` is a rebuildable advisory view over cached Host,
  port, API, JS, browser, collision, AI-asset, relation, and technology signals.
  It retains every observed Host and changes only deterministic ordering; raw
  Recon artifacts remain authoritative and the view never creates Queue actions
  or expands Scope.
- Each `recon_phase` row in `recon_manifest.jsonl` also carries one bounded
  `gate` object with `status`, `evidence_refs`, `coverage_gaps`, and `next_focus`.
  The gate distinguishes complete, partial, and blocked execution without
  replacing the phase's original `status`; it is advisory input for Claude and
  never creates a second state owner or turns missing evidence into clean.
  Readers must rebuild the gate from the current record `status` and artifact
  ownership; the persisted gate is historical metadata and cannot override a
  newly missing artifact or failed phase status.
- Bounded phases persist `gate.bounded` with `input_total`, `selected`,
  `remaining`, `continuation`, and `closure_blocking`.  The raw input remains
  authoritative; `remaining` is a resumable residual, not a reason to discard
  the unselected rows.  Only an explicitly owner-backed, closure-blocking
  residual resumes through its owner continuation. Advisory residuals remain
  non-executable, but Closure requires their exact `review_token` in the current
  snapshot-bound global review; an explicit defer produces `blocked` with
  `can_claim_exhausted=false`, never a normal exhausted terminal. They do not
  become tested-clean or implicit Queue actions. The writer builds this gate from the
  complete manifest record through the shared gate owner; readers still rebuild
  it against current status and artifact ownership before use.
- WAF breadth keeps its cursor in the existing `live/waf_context.json` summary.
  The cursor binds `next_offset` to the canonical target-owned URL input SHA-256;
  matching input resumes the next bounded Host batch and changed input restarts
  at offset zero. Only a published exit-zero JSON list whose URL identities match
  the selected Host batch exactly advances the offset; missing, malformed,
  duplicate, foreign, or short output is partial even when the process exits zero.
  Result ordering is irrelevant. A partial raw artifact may contribute a
  detection to the derived hits/context only when that row has a URL identity in
  the current selected batch; malformed and batch-external rows remain diagnostic
  raw bytes and never enter the Observation Inventory. Partial, error, skipped, and
  unavailable runs preserve it. A successful batch
  with positive `remaining` is `closure_blocking` and resumes through the existing
  Recon frontier; completed and non-success states are non-blocking. The
  quick/normal batch caps remain unchanged.
- Scanner `summary.json.lane_coverage` records `input_total`, `selected`,
  `remaining`, `execution_kind`, and continuation for bounded XSS, SQLi, SSTI,
  Nuclei/CVE, SSRF, Open Redirect, and IDOR lanes. Positive remaining input uses
  the same global-review token contract as advisory Recon residuals; candidate-only
  depth is retained and cannot be reported as scanner-tested.
- `tools/graphql_audit.sh` writes by default under
  `findings/<target_key>/graphql/<run-id>/`, publishes a bounded `run-summary.json`
  with target identity, operation ID, signal list, and artifact digests, and sends
  positive signals through `finding_index.upsert_finding()`. The resulting row is
  always `candidate` with an incomplete GraphQL evidence rubric; introspection,
  suggestions, batching, status codes, and tool output never become validated or
  report-ready without canonical protocol replay and `/validate`.
- Gate records include a small `artifact_binding` for concrete artifacts.
  Readers compare the stored binding with the current file generation and
  downgrade the gate to `partial` with `artifact_changed_since_record` when a
  phase artifact was replaced or appended after the recorded result.

### 4. Validation & Error Matrix

| 条件 | 结果 |
|---|---|
| 缺少 live data / ordered input | 非零退出，本轮无 `summary.txt/json` |
| killed / stopped / timeout / non-zero | incomplete，不得解释为零发现或完成 |
| 任一已启动 Nuclei lane 非零退出 | 记录失败标记、非零退出且不发布 summary |
| canonical finding index 写入失败 | 非零退出且不发布 summary |
| Recon soft budget exceeded but run reaches normal end | `run_budget.status=ok`, advisory telemetry only |
| Recon parent/tool interruption or timeout | `run_budget.status=partial`, preserve artifacts, handoff |
| summary 序列化/落盘失败 | 清理临时文件、非零退出，不发布 canonical summary |
| 正常到达 consolidation | 写入新 summary，计数 raw/parameter/ordered 三类输入 |
| raw corpus 从 1 增至 19K、live/priority 不变 | `ordered_scan_count` 不变 |
| 需要历史长尾或专项 CVE | 分页/查询 raw corpus 并构造专项输入，不扩大默认 broad input |
| manual_review 路径缺失、空、绝对或越出 target findings 根目录 | 不进入 Surface 索引 |
| 未识别但合法的 manual_review 文件 | 进入中性索引/预览，不生成 workflow lead 或执行动作 |

### 5. Good / Base / Bad Cases

- Good：19K historical URL 保留在磁盘，3 个 live/priority target 只产生 3 个
  ordered scanner target；AI 仍能按 shape/source 查询长尾。
- Base：没有 `all.txt` 或 `with_params.txt` 时对应计数为 0，正常 live quick scan
  仍可完成。
- Bad：`nuclei -l recon/<target>/urls/all_historical.txt` 作为默认 broad scan，或
  后台任务被 kill 后沿用旧 summary 宣称 `0 findings / scanner complete`。

### 6. Tests Required

- `tests/test_vuln_scanner_script.py`：19K raw fixture 下断言 raw=19000、parameter
  为原始参数行数、ordered 仅等于 live/priority exact 去重数，且 raw 文件未改变。
- 同文件预写旧 summary 后在 consolidation 前退出，断言 summary 被清理、
  `findings.json` 保留。
- 注入 summary JSON 写入失败，断言脚本非零退出且 canonical/temp summary 均不存在。
- 注入 Nuclei 非零退出或 finding-index 写入失败，断言脚本非零退出且不发布 summary。
- `tests/test_recon_engine_script.py` 与 `tests/test_runtime_state.py`：软预算超限仍可调度
  后续阶段并投影为 advisory；真实中断才投影为 partial。
- `tests/test_autopilot_state_tool.py`：command/agent/rule 同时固定 wrapper、专项扩展和
  incomplete 语义。
- `tests/test_surface_tool.py`：canonical summary 新增未知 manual-review 文件后，断言
  完整 ranked 索引、有界 projection 和默认文本可见；同时覆盖空、缺失、重复、绝对及
  越界路径，并固定未知条目不进入 workflow leads。
- `tests/test_vuln_scanner_script.py`：upload and method-tampering fixtures must
  prove the explicit opt-in gate skips requests, preserves the review artifact,
  and leaves the approved path unchanged.

### 7. Wrong vs Correct

#### Wrong

```text
raw historical corpus -> general nuclei -> killed -> 复用旧 summary -> complete
```

#### Correct

```text
raw corpus -> Surface/专项消费者
live + priority -> ordered_scan_targets -> quick broad scanner -> 正常 consolidation -> summary
```

## Scenario: Intel Advisory 完整性与版本闭环

### 1. Scope / Trigger

- 修改 `intel_sources` 分页、target memory CVE 历史或 Intel continuation 时适用。

### 2. Signatures

- `fetch_nvd_for_components(components, repo_root, *, max_components=20, max_seconds=120) -> dict`
- `fetch_osv_for_components(components, repo_root, *, max_workers=4) -> dict`
- `fetch_github_advisories_for_components(components, repo_root, *, max_workers=4) -> dict`
- `_nvd_summary_version_boundary(summary, component) -> dict`
- `inventory_source_binding_matches(binding, path) -> bool`
- `prioritize_advisories(advisories, memory, *, now=None) -> dict`

### 3. Contracts

- NVD 必须根据 `totalResults` / `startIndex` 读取全部页；中途失败或游标异常返回
  `partial`，不能把首屏结果标记为完整 `ok`。
- NVD 的组件与分页共享默认 120 秒总预算；每页最多 200 条，并以组件首页优先的轮询队列
  继续后续页。单页 transport timeout 不得超过剩余预算；POSIX 主线程且没有调用方 alarm 时，
  同时使用墙钟 timer 中断慢速响应。单页超时记录 `partial` 并继续其它组件；总预算耗尽或收到
  HTTP 403/429 才停止剩余 NVD 查询。已获取或 stale cache 页必须保留，使 KEV、EPSS 和最终
  artifact 仍可继续；`attempted_queries` 只统计实际进入首页查询/缓存读取的组件。
- 可选 `NVD_API_KEY` 只通过请求 `apiKey` header 使用，不得进入 cache query、artifact 或日志。
- NVD 缺少 `configurations` 时，只允许从以组件名开头的明确数字分支句提取
  `<branch>.x before <fixed>`。观测版本必须是同长度的纯数字点分版本且命中同一分支，才可
  判定 `affected/not_affected`；其它情况保持 `unknown`。解析结果复用 `fixed_versions` 和
  `affected_ranges`，不能另建 summary-only 排序状态。
- `tested_cves` 是无组件/版本的 legacy 历史，只能关闭无版本 advisory。
- 有版本 advisory 的终态复用归 action queue 的 advisory + component + version
  disposition 所有；target memory 的 CVE-only 标签不能越过该绑定。
- continuation 只消费终态 `type=intel-advisory`。存在 `advisory_id`、`component`、
  `version` metadata 时三个字段必须精确匹配；无结构化 binding 的 legacy action 才按
  CVE/GHSA、组件名和完整版本 token 回退，`1.2` 不得命中 `1.20`。
- continuation 检查 inventory raw source 时复用 inventory owner 的 size/mtime/format/path/
  SHA-256 binding；同尺寸覆盖并恢复 mtime 仍必须返回 `run_intel`。
- Intel continuation 是建议性补充：可以替换 `continue_last_focus`、`resume_untested` 和
  `handoff`，但不得抢占 `hunt_p1`/`hunt_p2`；Intel 候选仍保留在 `priority_frontier` 供 AI 取舍。
- OSV 与 GitHub component query 默认最多 4 路并发，不截断 eligible components；合并顺序、
  cache/stale/error 统计必须保持原始 component query 顺序。NVD 继续遵循其分页和限速契约。
- KEV 不只是已有 advisory 的 enrichment：对已观测/声明组件匹配的 KEV-only CVE 也必须生成
  `applicability=unknown` 的 advisory lead，再进入 EPSS 和统一排序；不能因 NVD 延迟丢失已加入
  KEV 的供应商漏洞。

### 4. Validation & Error Matrix

| 条件 | 结果 |
|---|---|
| `totalResults` 大于当前页 | 从下一 `startIndex` 继续读取 |
| 后续页失败或响应游标不一致 | source=`partial`，保留已取页和错误原因 |
| NVD 总预算耗尽 | source=`partial`，停止剩余 NVD 查询并保留已取页 |
| 单个 NVD 请求超过墙钟截止 | source=`partial`，跳过该页并继续其它组件 |
| NVD 403/429 且存在 stale cache | 使用 stale 页、停止后续组件并返回 `partial` |
| legacy CVE 命中且 advisory 有版本 | `already_tested=false`，继续版本适用性闭环 |
| legacy CVE 命中且 advisory 无版本 | 保持兼容，`already_tested=true` |
| 其它类型终态 action 含相同 CVE/组件/版本文本 | 不关闭 Intel advisory |
| 结构化 metadata 任一 binding 字段不匹配 | 不回退文本、不关闭 advisory |
| raw source 同尺寸换内容并恢复 mtime | SHA-256 mismatch，返回 `run_intel` |
| OSV/GitHub 某个并发 query 失败 | 保留其它 query 结果并按输入顺序输出 `partial/error` 统计 |
| KEV 有 CVE 但 NVD 当前无对应记录 | 合并为 `source=kev`、`kev_only=true` 的候选，并继续 EPSS enrichment |
| 摘要为 `WordPress 6.9.x before 6.9.5`，观测 `6.9.4` | `affected`，fixed=`6.9.5` |
| 同摘要观测 `6.9.5` | `not_affected` |
| 分支不匹配、prerelease、其它产品或插件句中仅提到组件名 | `unknown` |
| NVD 已有 `configurations` | 保留结构化数据，不用摘要解析覆盖 |

### 5. Good / Base / Bad Cases

- Good：三条 NVD 结果分两页返回，artifact 保存三条且 source 为 `ok`。
- Good：多个组件都有多页时，先获取每个组件首页，再按原组件顺序继续第二页；下一轮复用已缓存
  页面继续推进。
- Good：五个 OSV/GitHub query 以最多 4 路并发执行，结果仍按 component 输入顺序合并。
- Good：Fortinet KEV-only CVE 在 NVD 延迟时仍进入统一 advisory，并带有 KEV/EPSS 信号。
- Good：明确的 WordPress 多分支 before 边界只匹配观测版本所在分支，并进入现有 applicability 评分。
- Base：NVD 响应没有分页字段时，把当前合法响应视为单页；单个 OSV/GitHub query 时退化为顺序执行。
- Bad：`totalResults=101`、只读取首屏后仍返回 `ok`；旧版本测试关闭新版本；或所有终态
  action 只要文本含相似版本就关闭 advisory。
- Bad：把 `Example plugin for WordPress 6.9.x before 6.9.5` 当成 WordPress core 边界。

### 6. Tests Required

- `tests/test_intel_sources.py` 覆盖 NVD 多页合并、partial 语义、摘要 branch-before 边界、
  跨组件轮询、墙钟截止、缓存续跑、产品/分支保守回退、OSV/GitHub 并发上限和保序。
- `tests/test_intel_engine.py` 覆盖 versioned 与 unversioned memory closure。
- `tests/test_intel_continuation.py` 覆盖 action 类型、metadata、legacy token、组件版本、raw
  source digest binding 和 continuation 抢占优先级。

### 7. Wrong vs Correct

```text
Wrong: any final action containing `1.2` -> close advisory for component `1.20`
Correct: CVE-only memory -> history; exact intel-advisory+component+version binding -> closure
Wrong: summary contains component name + any `before` -> mark affected
Correct: component-leading numeric branch sentence + exact observed branch/version -> applicability
```


## Knowledge Routing and AI-Guided Surface Contracts

- Promotion rules for security-capability optimization from labs, authorized
  tests, public research, disclosed reports, CTFs, and project retrospectives:
  - Ordinary reusable knowledge does not become a new Skill.
  - Small practical gaps are fixed in `context_pack.py`, knowledge cards, hypothesis
    seeds, and regression tests.
  - Repeated high-value patterns may be promoted to knowledge-card enhancements.
  - Rare, transferable techniques are the only candidates for new Skills.
  - Content that is noisy, redundant, ineffective, or overfit to one lab is discarded.
- Skill distillation must pass a concrete value gate before any new Skill is
  considered:
  - First test whether the model likely already knows the knowledge. Common
    vulnerability basics, common payload families, and easily searchable
    explanations do not justify a Skill.
  - Score the candidate by scarcity, real-world frequency, transferability,
    source quality, and reproducible evidence quality.
  - If the model knows the individual facts but tends to miss the order,
    connector, or decision point, prefer a compact decision tree in a knowledge
    card or `hypothesis_seeds` instead of a new Skill.
  - If the idea is rare but low-frequency, keep it as a prompt/context note until
    repeated evidence proves it deserves stronger promotion.
  - High-quality sources include unexpected CTF solutions, top conference talks,
    high-signal disclosed reports, and deep technical posts with explicit trigger
    conditions and boundaries. Strip all target-bound details before storing.
- Context assets must be layered by runtime value, not by volume:
  - Core knowledge cards are decision aids for route selection, evidence gates,
    stop conditions, and coverage; keep `context_pack.py` bounded to 1-2 cards.
  - Context Pack keeps `selected_skill`, `skill_route`, and `knowledge_cards` as
    compatibility recommendations. They do not enter `must_read`, represent an
    AI selection, or bind Checkpoint Queue actions. Shared runtime, target state,
    Ledger, and evidence-specific tool/artifact refs remain mandatory inputs;
    Claude explicitly loads the chosen Skill/Card and records the actual route
    when claiming a substantive action.
  - `skills/runtime-protocol.md#shared-knowledge-recall` owns the recall decision
    for natural-language and Autopilot entries. Reuse a matching in-session Pack;
    otherwise call the existing `context_pack.py --target TARGET --focus FOCUS`.
    Read selected Skill/Card contents that are not already in context before the
    boundary-specific action. Changed target, focus, or material evidence requires
    reassessment, not a new loading-state owner. Autopilot still bootstraps and
    follows owner-selected initial work before substantive recall; pure explanation
    does not require target setup or card loading. Deferred recall and explicit
    `/kb` remain available beyond the default recommendation budget.
  - Reference/anchor checks and CLI-versus-state candidate parity are deterministic
    tests, not proof of model discovery or reading. Live acceptance requires actual
    lookup/read tool results before the relevant action; a path mention, fake-model
    response, unavailable login, or zero-token run is not a passing observation.
  - 新增 signal-only 路由必须覆盖“精确信号 + 宽泛背景”回归，并让精确信号卡先于
    同源的通用卡进入预算；否则 1-2 卡上限会把已命中的专用上下文静默挤掉。显式 focus
    仍可优先于只存在于 target memory/recon 的背景信号。
  - Context Pack 的 `knowledge_card_recall[]` 必须按稳定候选顺序投影 selected/deferred Card，
    每项包含 `file`、`id`、`status`、`rank` 和有界 `reason`。reason 只解释现有 focus、路由、
    fallback 与 Card/case-router 预算，不创建第二套路由状态，也不改变 `knowledge_cards` 或
    `deferred_knowledge_cards` 的选择语义。
  - `hypothesis_seeds`、`alternative_angles` 和 `knowledge_card_recall[]` 只提供有界建议与诊断；
    Context Pack 保留三者，Checkpoint 保留有界 seed/recall 投影，但不得因建议存在而生成 Queue
    动作或已选择的 activation hypothesis。ViewState 等专项投影必须读取原始 `source_summary`
    证据信号，不能把 seed 文本当成证据 owner。
  - 已观察 API path 的祖先前缀补漏只处理同目标、去除 query/fragment 的路径：
    每个 seed 最多 3 个非根前缀、每轮最多 12 个候选，API 文档优先，management
    候选需要框架证据。保留 `seed_refs` 和派生字段，并用 soft-404/响应结构门禁；
    不从一条 API path 扩展出通用目录字典。
  - Distilled cards are router / recall assets. They may point to
    structured `source_refs`, but should not inline report bodies, target domains,
    payload dumps, credentials, or PII.
  - For Opus 4.8-class models, methodology prose that has no A/B-proven
    incremental value should not become default context. Prefer precise technical
    details, on-demand references, real-case pointers, evidence gates, stop
    conditions, and regression tests.
  - Active cards use frontmatter `source_refs` as their only machine-readable case
    source. Parse it through `tools/knowledge_registry.py`; do not restore the old
    Markdown `source_report_ids` footer as a second source of truth. Historical
    archive notes may retain that footer as inert provenance text.
  - A v1 source ref is a unique `corpus-report` object for
    `hackerone-disclosed-reports` with a non-zero decimal string `id`. Treat it as
    a local gitignored case-library pointer. Query it only after the current
    evidence matches the card's trigger signals and a real case shape or
    report-writing precedent is needed.
  - Source resolution has three explicit audit modes: `off`, `if-present`, and
    `required`. Missing optional corpus is a reported `skipped` capability in
    `if-present`; stale/invalid corpus and dangling refs are errors whenever
    resolution is enabled; `required` also turns a missing corpus into an error.
  - `tools/case_corpus.py` ordinary `get`/`from-card`/`search` queries must use
    manifest size/mtime plus index validation and the selected line's digest;
    they must not re-hash the complete `reports.jsonl` on every request. Full
    data/index hashes belong to explicit `status`/audit checks.
  - `knowledge/governance/value-review.json` must contain exactly one row per
    active registry card. Its card path, layer, load, maturity, trigger tags,
    source count/strength and overlap IDs must agree with the current card and
    registry; duplicate IDs or stale projections are hard audit errors.
  - Candidate lifecycle events must keep typed `corpus-report:<id>` evidence
    references exactly aligned with their corpus source objects. A source ID
    without a matching evidence reference (or an extra malformed reference) is
    an audit error.
  - Formal-card lifecycle is separate from candidate lifecycle and finding state.
    `knowledge/governance/events.jsonl` records append-only adoption, review,
    replacement, retirement, and restoration; the active registry remains the
    runtime loading authority. `knowledge/governance/value-review.json` is an
    advisory all-active-card review projection, not routing or lifecycle state.
    Lifecycle regressions must also audit the checked-out registry/event log so
    fixture-only transition tests cannot miss an active card without an adopted event.
  - Reviewed Candidate runtime hints are a separate advisory projection, not a
    formal-card route: only reviewed rows with explicit human `recall_signals`
    may match current focus/evidence; pending, terminal, current-target, legacy
    rows without signals, and corrupt lifecycle input produce no hint. The
    projection is capped at one row, excludes source targets/evidence refs, does
    not enter `must_read`, card budgets, Action Queue, Finding, or Closure, and
    reports pool/match/selected counts for diagnosis.
  - Candidate corroboration uses a `corroborated` append-only event in the same
    lifecycle owner. It may add a target-memory source with evidence to pending
    or reviewed candidates only when the target is independent; status and the
    Markdown staging snapshot do not change. Duplicate targets, missing evidence,
    terminal candidates, or invalid lifecycle history fail before append.
- Lab or target execution is only a pressure test for project capability. Passing
  a lab, reproducing a public case, or finishing one authorized target is not
  itself an acceptance signal; the reusable output is the route gap, evidence gate,
  seed gap, stop condition, or de-noising regression that generalizes beyond that
  source.
- Skill changes require validation before acceptance:
  - Run `skill-creator/scripts/quick_validate.py` for every changed Skill and
    periodically for the full `skills/*/SKILL.md` set.
  - CVSS 示例只要同时给出 score 与 vector，就必须用标准公式回归逐行计算 score，
    并校验 severity 阈值；禁止手工维护互相漂移的“分数 + 向量”表。
  - For capability claims, keep a reproducible A/B task suite that compares the
    current Skill/context-pack route against a no-Skill keyword baseline.
  - A useful Skill should improve route precision, de-noising, evidence gates,
    stop-condition guidance, or required safety checks; a lab pass alone is not
    proof of improvement.
  - When slimming a default-loaded Skill, preserve a deterministic post-slim
    regression that asserts enhanced signal coverage, no route/card gaps, and a
    bounded line-count ceiling. Move payload/bypass/tool bulk into on-demand
    references; do not delete decision signals just to reduce line count.
- `context_pack.py` currently returns only the first six deduplicated
  `hypothesis_seeds`; when enhancing one vulnerability lane, merge related
  trigger/evidence/stop-condition guidance into compact high-signal seeds instead
  of appending many near-duplicate sentences.

## Scenario: Skill 与知识统一只读治理

### 1. Scope / Trigger

修改 `skills/*/SKILL.md`、Context Pack 主路由、知识 registry、正式卡 lifecycle、候选
lifecycle 或全卡价值矩阵时，必须用统一治理入口证明这些既有 owner 没有漂移。该入口只做
组合和有界投影，不创建新的状态 owner。

### 2. Signatures

```bash
python3 tools/capability_governance.py [--repo-root PATH] [--strict] [--json] \
  [--source-mode off|if-present|required] [--corpus-dir PATH] [--matrix-path PATH]
```

```python
audit_governance(
    repo_root,
    *,
    strict=False,
    source_mode="if-present",
    corpus_dir=None,
    matrix_path=None,
) -> {
    "ok": bool,
    "sections": {
        "knowledge": dict,
        "lifecycle": dict,
        "candidates": dict,
        "value_review": dict,
        "skills": dict,
    },
    "advisories": {"trigger_collisions": list, "trigger_collision_error": str},
}
```

`tools/context_pack.py` 的 `SKILL_CATALOG` 是全部仓库 Skill 的 route-mode owner；
`SKILL_PATHS` 和 `SKILL_TEST_DIMENSIONS` 只能从其中的 `primary` 项派生。

### 3. Contracts

- 命令只调用 `audit_repository()`、`audit_lifecycle()`、`audit_candidates()`、
  `audit_matrix()` 和 Skill catalog 检查；不得增加 `--fix`、`--apply`、自动晋升、maturity
  修改或持久化报告。
- JSON 固定暴露五个 section；为保持有界，统一入口不得输出 lifecycle 的全量 `states`，
  但必须保留 counts、errors、advisories 和 owner path。
- 任一 section `ok=false` 时顶层 `ok=false`、进程退出 `1`。`--strict` 还将 knowledge
  warning 变成失败；trigger collision 始终只是 advisory，不能因 `--strict` 阻断。
- `source_mode=if-present` 且本地 case corpus 缺失时，knowledge/candidates section 保留
  `skipped: source-resolution` 并继续成功；stale/invalid、dangling ref 或 `required` 缺失仍失败。
- route mode 固定为：`primary`、`direct-only`、`reference-only`、`report-only`。只有
  `primary` 可进入 Context Pack 主路由；reference/report/direct-only 不得被通用 focus 隐式选择。
- primary 为 `bb-methodology`、`bug-bounty`、`credential-attack`、`triage-validation`、
  `web2-recon`、`web2-vuln-classes`。显式选择只认 focus 的首个规范化 Skill ID；随后出现的
  `candidate`/`validation` 不得吞掉它。Skill ID 只是在混合 focus 列表中后置出现时，继续走
  原有隐式路由顺序，避免把漏洞类别信号误当成 route override。
- registry trigger 以 trim + casefold + 内部空白收敛后投影碰撞，输出排序后的 trigger 和完整
  capability IDs；碰撞不改变 registry、Context Pack 预算或运行时选择。
- Claude Code CLI 的项目级常驻契约是 `CLAUDE.md`；`runtime-protocol.md` 是共享路由/写回
  契约，`bb-methodology` 是开始/换目标/停滞/选路时的按需决策 Skill，专项 Skill 是按证据
  选择的执行契约，知识卡只提供候选模式/证据门/停止条件，工具和现有状态 owner 负责确定性
  执行、生命周期与恢复。Claude 当前主会话保留最终路线判断权。
- Claude Code CLI 自动加载项目 `CLAUDE.md`；Context Pack 的 `must_read` 包含
  `runtime-protocol`、目标状态、Ledger 和证据专用引用，不包含推荐的 primary Skill/Card。
  `selected_skill`、`skill_route` 和 `knowledge_cards` 字段继续提供有界兼容推荐。根
  `SKILL.md` 只用于旧单文件直装，不由正式 `install.sh` 安装，也不进入 Context Pack。

### 4. Validation & Error Matrix

| 条件 | 结果 |
|---|---|
| structure/lifecycle/candidate/value-review 任一 owner 报错 | 对应 section `ok=false`，exit `1` |
| Skill 缺失、额外、重复 path、非法 mode 或 primary 无 dimensions | skills `ok=false`，exit `1` |
| knowledge 只有 warning，不带 `--strict` | 成功并保留 warning |
| knowledge 只有 warning，带 `--strict` | knowledge `ok=false`，exit `1` |
| `if-present` corpus 缺失 | 两个 owner 显式 `skipped`，整体可成功 |
| `rce`/`jwks` 等 trigger 命中多 capability | 排序 advisory，整体仍可成功 |
| focus=`credential-attack candidate validation` | 选择 `credential-attack` |
| 混合漏洞 focus 中后置出现 `credential-attack` | 保留既有漏洞类别路由 |
| Context Pack 默认构建 | `CLAUDE.md` 不重复列入；推荐的 primary Skill/Card 不进入 `must_read` |
| staged `install.sh` | 安装模块化 `skills/bug-bounty/SKILL.md`，不以根 `SKILL.md` 覆盖 |

### 5. Good / Base / Bad Cases

- Good：一次 strict 命令显示 `57/57` value review、12 个 Skill、6 个 primary 和 trigger collision。
- Base：本地 case corpus 未安装，输出 skipped，但其它治理 owner 继续检查。
- Bad：为方便汇总复制 registry/lifecycle parser，输出全量 lifecycle states，或让 collision 自动改路由。
- Bad：把 focus 任意位置出现的 Skill ID 都视作显式 override，破坏既有混合 focus fixture。

### 6. Tests Required

- `tests/test_capability_governance.py`：五个 section 分别失败都 exit `1`；strict warning、optional
  corpus skipped、只读文件快照、12/12 catalog、6 primary 和 collision advisory 均有断言。
- `tests/test_context_pack.py`：六个 primary 首词显式可达且优先于 validation；既有 skill/route
  fixtures必须全量通过，证明混合 focus、隐式顺序和卡片预算未回归。
- `test_command_and_autopilot_state_recall_share_candidates` covers the shared
  focus routes, selected/deferred candidates, recall diagnostics, and advisory
  budget using isolated local state. `tests/test_context_pack_docs.py` checks
  shared entry references without locking complete prose sentences. Live
  discovery, read ordering, and continuation reuse are reported separately.
- `tests/test_knowledge_value_review.py`：checked-out matrix 必须 `cards == registry_cards == 57`。

### 7. Wrong vs Correct

```text
Wrong: duplicate parsers + auto-fix/apply + collision changes runtime route
Correct: existing audit owners -> bounded read-only sections -> hard failures + advisory collisions

Wrong: any occurrence of `credential-attack` -> explicit Skill override
Correct: first normalized focus token is a primary Skill -> explicit override; otherwise preserve old routing
```

## Scenario: Context Pack historical pattern recall

### 1. Scope / Trigger

When Context Pack is built from a valid ranked Surface, it may expose the existing
cross-target pattern suggestions as bounded advisory context.

### 2. Signatures

```python
build_context_pack(...)["historical_patterns"] -> list[str]
build_context_pack(...)["source_summary"]["historical_patterns"] -> int
```

### 3. Contracts

- Surface remains the pattern-recall owner: it loads the target profile only for
  episodic/technology context, calls `PatternDB.match(..., calibrated=True)`,
  excludes the current target, and returns at most three
  `memory.pattern_suggestions`. Current findings and endpoint test state come
  from `runtime_state.derive_owner_projection()`; the legacy profile is a
  compatibility fallback only.
- Context Pack excludes a current-target suggestion, strips cross-target
  provenance labels, then deduplicates and projects the first three reusable
  lessons. It does not read `patterns.jsonl`, rerank patterns, expose historical
  target domains, or use them as evidence/finality.
- Formatted output labels the suggestions advisory and requires current-target evidence.

Candidate advisory (`reviewed_candidate_hints` family) was retired with the
knowledge-governance state machines (2026-09-11, zero-B): the pack no longer
carries candidate-hint fields, and `historical_patterns` stays the only
cross-target advisory channel. New cross-target knowledge enters via `/distill`
draft cards promoted into `knowledge/cards/`.
or formal-card selection.

### 4. Validation & Error Matrix

| Input | Context Pack result |
|---|---|
| missing Surface memory | `historical_patterns=[]`, count `0` |
| current-target suggestion | omitted |
| cross-target `target: lesson` suggestion | target prefix removed |
| duplicate suggestions | first occurrence retained |
| more than three suggestions | first three retained |
| stale Surface projection | existing Surface refresh/rebuild path runs before recall |

### 5. Good/Base/Bad Cases

- Good: valid Surface provides calibrated cross-target suggestions; Context Pack shows
  three advisory lines after knowledge/reference routing.
- Base: no target profile or matching pattern produces an empty list.
- Bad: Context Pack scans `hunt-memory/patterns.jsonl` or treats a historical payout as
  current-target evidence.

### 6. Tests Required

- `tests/test_context_pack.py` asserts current-target exclusion, provenance
  stripping, dedupe, the three-item limit, advisory formatting, and the
  source-summary count.
- Candidate routing tests also assert English and Chinese explicit signals,
  reviewed-only filtering, corrupt/legacy fail-closed behavior, one-item cap,
  and formal-card budget non-regression.
- PatternDB/Surface owner tests retain responsibility for calibration, tech-stack match,
  current-target exclusion, and corrupted-row behavior.

### 7. Wrong vs Correct

```text
Wrong: historical pattern -> candidate/finding/terminal state
Correct: historical pattern -> bounded advisory recall -> current-target evidence action
```

- Endpoint→漏洞类型的语义打分不得把路径段和参数名简单拼成一个
  regex blob 后统一匹配，尤其是依赖“查询语义”的 lane（如 SQLi）。
  资源名里的 `order`、`select`、`report` 可能只是 REST path 命名，
  不是查询入口；应把 path-only 强信号和 observed-params 强信号分开打分。
  最少保留一组“真查询面 + 假资源名”的回归对照，例如：
  - Good: `/rest/products/search?q=test` 允许命中 SQLi query semantics
  - Bad: `/rest/order-history`、`/address/select` 不能仅靠路径词被抬进
    SQLi 的前排 coverage gap
- Discovery 阶段产出的高价值 queue item 不得只给“去测某 endpoint × 某漏洞类”
  这种抽象 TODO；必须尽量同时附带**最小验证路径**，并与 `/validate`
  使用同一套 evidence rubric。
  - Good: coverage-gap 同时给出 “Validation path: two-actor replay /
    exact replayable request / baseline-vs-perturbation / bounded synchronized
    replay ...”
  - Bad: 只有 “test this for IDOR/SQLi/Race” 而没有下一条可执行证据动作
  - 目标：让 discovery→candidate→validate 是同一条链，不让代理在发现后
    再重新猜“下一步该怎么证明”
- AI/工具职责统一遵守[质量规范](../quality-guidelines.md#ai-与工具边界)；本分册只定义
  Recon 和 Surface 的具体证据、排序与 continuation 契约。
- 对 browser-observed / ranked surface，AI 的优势应用在“生成最小 replay 草案”，
 不是只输出排序结果。
  - Good: `Continue top ranked surface ... Replay draft: capture exact browser baseline;
    prefer POST replay; reuse observed params; follow source hints; focus Authz evidence`
  - Bad: 只有 `continue top ranked surface <url>`，没有 method、参数、角色差异、
    baseline、验证方向
  - 数据来源优先级：browser 真实请求形态 > JS method/param hints > source-intel
    hypotheses > semantic relevance tie-break
  - 目标：把 AI 的归纳/联想能力落到“下一条可执行 replay”上，而不是停留在描述层
- Ranked surface 里的无扩展页面路由（如 `/orders`、`/order-summary`）不能因为
  raw GET 返回同一份 SPA HTML 就判 clean。case_state 存在时也应优先
  browser-state-first：用 MCP/浏览器捕获 owner/peer 真实 XHR、对象 ID 和状态，
  再把底层 API 交给 `validation_runner.py authz-role-replay` 或
  `idor-actor-pair`。页面路由是链路入口，不是最终 replay 目标。
- AI/operator-confirmed endpoint kind is allowed to change direct coverage
  applicability, but auto hints are not. For example, `route_prefix_candidate`
  only stays a hint; after Claude explicitly marks `/rest/admin` as
  `endpoint_kind=route_prefix`, coverage may mark that prefix row `n_a` for
  direct replay while keeping concrete child handlers such as
  `/rest/admin/application-configuration` testable. Rebuilds must preserve
  final endpoint kinds even for findings-only endpoints.
- Report actions are phase-closure assets, not the steering wheel. If any
  active non-report action remains (validation, ranked-surface, coverage,
  action-gated review, secondary sweep, case-state work), `action_queue next`
  should select that work before report. Checkpoint `next_action` and handoff
  summaries must mirror the final `recommended_executable_action`, not stale
  `autopilot_state.next_action` values such as `report_finding`.
- Surface review ordering must preserve evidence quality before score hints.
  `surface.py` should build the Claude-facing review pool from evidence-rich
  sources first (cross-evidence convergence, browser-observed XHR/API,
  JS/source hypotheses, scanner candidates, target-memory continuations), then
  use score-only items only as fallback when no actionable evidence exists.
  Recon/memory-only facts such as non-standard port, tech-stack overlap, or
  "untested" are useful in P1/P2 compatibility output, but must not crowd the
  Claude-facing review pool when browser/source/JS/scanner/parameter/intel
  evidence exists. `autopilot_state.py` must preserve that review-pool order;
  do not re-sort by `score`, because score is only an advisory hint and can
  otherwise push generic paths such as challenge helpers ahead of real
  browser/source evidence.
- Large Surface processing has three separate contracts:
  1. **Completeness**: raw recon plus the full observation inventory retain every
     target-owned observation. Only exact URL strings may be destructively
     deduplicated across sources; query value/order, duplicate key, encoding,
     scheme/port, path case, and trailing slash remain distinct.
  2. **Derived review**: `surface_index.py` performs external sort/provenance
     union, then `surface.py` scores every unique target-owned row and maintains
     stable bounded P1/P2/review frontiers. Shape is grouping/navigation after
     scoring, never a pre-ranking sample or deletion key.
  3. **Control plane**: bootstrap reads shared control facts, fast recon stat,
     inventory summary, and only an exact-hit bounded projection. It never scans
     large URL/inventory bodies, refreshes cache, mutates lifecycle, or treats a
     missing/stale projection as no attack surface.
- P1/P2/review top-K and summary samples are attention windows. Overflow and
  untouched rows remain open until an owner-backed action changes their state.
  Long-tail access uses revision-bound cursor paging; page/list reads never imply
  reviewed/tested-clean or automatically enqueue/route a Skill.
- Full and streaming ranking must remain behaviorally equivalent for candidate
  identity, stable order, score, score breakdown, reasons, review reason, FFUF
  sample, evidence convergence, and target ownership. An intentional signal bug
  fix (for example hostname leakage or unbounded short-token matching) requires
  its own before/after regression rather than being hidden inside a performance
  change.
- Recon finalization may build derived Surface artifacts best-effort, but raw
  recon success is independent. Finalizer failure leaves cache missing/stale and
  must be recoverable by explicit refresh; it cannot delete raw artifacts or
  write false closure. Projection/index publication requires manifest-last or
  atomic replace plus a before/after input fingerprint race check.
- Replay 草案应尽量同时提供 Evidence Ledger 记录骨架，但只作为命令草案，
  不自动写入：
  - Good: `Ledger skeleton: python3 tools/evidence_ledger.py record --target ...
    --endpoint ... --method ... --vuln-class ... --result signal --replayed ...`
  - 记录默认使用 `--result signal`；执行后按实际证据改成
    `tested_clean` / `tested_finding` / `candidate`
  - browser-observed surface 应带 `--browser-observed` 和对应
    `recon/<target_key>/browser/...` evidence-ref；JS/source 推断出的
    method/vuln_class 可作为草案字段，但必须在 replay 后按事实修正

## Scenario: 大规模 Surface 派生视图与只读 Bootstrap

### 1. Scope / Trigger

修改 `/autopilot` 启动态读取、recon URL 来源、observation inventory、surface ranking、
context-pack/checkpoint 消费或 recon 收尾流程时，必须应用本契约。目标是在大语料上缩短控制面
启动时间，但不能通过截断、模板单样本或固定 regex 路由缩小攻击面。

### 2. Signatures

```bash
python3 tools/autopilot_bootstrap.py --json -- <target> [mode flags]
python3 tools/surface.py --target <target> [--refresh] [--json]
python3 tools/surface_index.py build|status|page --target <target> [...]
python3 tools/observation_inventory.py summary|sync|list|page|touch --target <target> [...]
python3 tools/surface_finalizer.py --repo-root <repo> --target <target> --json
```

持久化签名：

- 完整事实：`recon/<target>/...`、`state/<target>/observations.json`；
- exact 派生索引：`recon/<target>/surface/{index.jsonl,manifest.json,summary.json}`；
- 小型派生视图：`state/<target>/observations-summary.json`、
  `state/<target>/surface-projection.json`。

### 3. Contracts

- Bootstrap 只读取共享 control facts、fast recon stat、inventory summary 和 exact-hit bounded
  projection；不得逐行读取大型 URL、解析 monolithic inventory、同步 owner 或执行 ranking。
- URL 仅以完全相同的 trimmed raw string 做 destructive dedupe。query value/order、duplicate key、
  encoding、scheme/port、path case 和 trailing slash variant 必须保留独立 exact row。
- Index 合并 provenance 并保存稳定 first-seen sequence；shape/ordered signature 只做导航，不能在
  scoring 前删除 variant。所有 target-owned exact row 都经过同一 scorer。
- P1/P2/review frontier 是 bounded 注意力窗口；overflow 和 inventory 中未展示的 observation 仍为
  `untouched`，不能推导 tested-clean、exhausted、finding 或 Skill route。
- Projection 必须绑定所有 ranking 输入，且仅在 ranking 前后 manifest fingerprint 一致时原子发布。
  full state、context-pack/checkpoint 只复用 exact hit；bootstrap/full state 遇到
  miss/stale/invalid 返回 `prepare_surface_context`，closure 保持
  `surface_projection_pending`，不得用 fallback ranking 驱动 hunt 或 finish。
- Observation body 是 lifecycle owner；summary 在 body replace 成功后发布并绑定 body/source。
  `page` cursor 绑定 target、filter 和 body revision，读取不写 lifecycle。
- Recon finalizer 是 best-effort 派生步骤。失败保留 raw recon 和已有 owner state，后续显式
  `surface.py --refresh` 可恢复。

### 4. Validation & Error Matrix

| 条件 | 正确行为 |
|---|---|
| projection missing/stale/corrupt/target mismatch | 不消费旧候选；bootstrap 返回 refresh action |
| inventory summary missing 或 body/source binding mismatch | 返回 `needs_sync`，保留旧计数仅供诊断，不投影为零 |
| index 行损坏或输入在构建中变化 | fail-fast，不发布新 manifest/projection |
| external sort/atomic replace 失败 | 清理临时文件；旧可读派生物或 raw artifact 保留 |
| cursor target/filter/revision 不匹配 | exit `2`/抛明确错误；调用方从第一页重启 |
| finalizer 失败 | recon 仍成功，记录 recoverable failure，不写 closure |
| high-priority finding/runner/queue 存在 | bootstrap 直接返回对应 action，不打开大型 artifact |

### 5. Good / Base / Bad Cases

- Good：30 万 exact URL 全部进入 index/scorer，内存只保留 bounded frontier；warm bootstrap 只读小型
  projection 并在 slash 超时窗口内返回。
- Good：同 URL 跨 API/param/browser/scanner 来源只有一行且 provenance 完整；不同参数顺序仍为两行。
- Base：旧 target 尚无 sidecar/projection，bootstrap 返回 refresh/sync 语义，显式 owner 完成一次迁移。
- Bad：读取 `with_params.txt[:8000]`、每个 shape 只保留一条，或按 auth/payment/upload 互斥分桶后
  声称完整攻击面。
- Bad：cache miss 时回退到无界 slash ranking，或把 top-K 外 observation 自动标 reviewed/parked。

### 6. Tests Required

- Bootstrap：巨大占位 URL/inventory 的 open/read/rank/sync trap、零 target-write、优先级 parity。
- Index/ranker：exact identity/provenance/sequence、所有 parser-sensitive variant、off-target、probe、
  FFUF/browser/JS/source/scanner/intel/memory/ledger/queue 的 materialized/streaming parity。
- Sidecar/projection：missing/stale/corrupt/target mismatch/body binding、atomic failure、input race、
  cache hit 复用和删除后重建。
- Cursor：status/kind/source filter、全量恰好一次可达、revision/filter reject、读取前后字节不变。
- Scaling：仅在 `/tmp` 生成 30 万 URL 与百 MB inventory，校验末行强信号、exact identity、untouched
  lifecycle、RSS/耗时和 source byte preservation；外部 opt-in 验收只输出聚合指标。
- Runtime：staged install 和 slash-command wiring；tracked 产品面不得包含靶场/外部 target 数据。

### 7. Wrong vs Correct

#### Wrong

```python
# 首 N 条和 shape 单样本都可能永久饿死文件尾部或 parser-sensitive variant。
candidates = [first_per_shape(url) for url in urls[:8000]]
return sorted(candidates, key=score, reverse=True)[:16]
```

#### Correct

```python
# raw/index 保存完整 exact identity；每行评分后只压缩注意力 frontier。
for sequence, row in iter_surface_index(repo_root, target):
    if row["target_owned"]:
        frontiers.add(score_candidate(row), sequence)
publish_projection(frontiers, exact_input_manifest)
```

## Recon Phase Manifest and Lossless Analysis Inputs

### 1. Scope / Trigger

Use this contract whenever `tools/recon_engine.sh` changes phase execution,
recon artifact generation, URL denoising, JS analysis, parameter extraction, or
Claude-facing recon next-step wording. Recon is a collection and handoff layer,
not a vulnerability judgment layer.

### 2. Signatures

- `bash tools/recon_engine.sh <target-domain|ip|cidr|list-file> [--quick|--normal|--deep]`
- `python3 tools/hunt.py --target <target> --recon-only [--quick]`
- `python3 tools/openapi_semantics.py --target <target> --repo-root <root>
  [--max-platform-hosts N] [--timeout SEC] [--max-response-bytes N] [--json]`
- Per-target phase ledger: `recon/<target_key>/recon_manifest.jsonl`
- CIDR continuation: `BBHUNT_CIDR_OFFSET=<non-negative integer>` with
  `live/cidr_pages/<offset>.{txt,httpx.txt}`, `live/cidr_continuation.json`, and
  canonical `live/httpx_full.txt`.
- Lossless analysis views:
  - `recon/<target_key>/urls/js_files_analysis.txt`
  - `recon/<target_key>/urls/with_params_analysis.txt`
  - `recon/<target_key>/js/request_targets.txt` (target-owned active JS URLs only)
- Host-aware port evidence:
  - `recon/<target_key>/ports/open_host_ports.txt` (canonical `host:port` rows)
  - `recon/<target_key>/ports/open_ports_all.txt` (legacy port-only projection)
- FFUF evidence views:
  - `recon/<target_key>/dirs/ffuf_results.jsonl.gz`
  - `recon/<target_key>/dirs/ffuf_summary.json`
- AI-selected focused FFUF run:
  - `ffuf -u '<evidence-backed-template-with-FUZZ>' -w '<run-dir>/wordlist.txt' ... -s -json`
  - `recon/<target_key>/focused_fuzz/<run_id>/dirs/ffuf_results.jsonl.gz`
  - `python3 tools/recon_adapter.py --recon-dir <run-dir> --summarize-ffuf ...`
  - `python3 tools/target_memory.py lead|dead-end '<evidence and decision>' --target <target>`
- OpenAPI semantic facts:
  - `recon/<target_key>/api_specs/{operations,auth_boundary_candidates,platform_metadata,errors}.jsonl`
  - `recon/<target_key>/api_specs/{spec_urls,public_operations,unauth_api_findings}.txt`
  - `recon/<target_key>/api_specs/{summary.json,summary.md}`

### 3. Contracts

- `recon_manifest.jsonl` is append-per-phase within one recon run. Non-CIDR and
  CIDR offset `0` starts reset it; CIDR offset `>0` is the same bounded run and
  preserves/appends the ledger. Each row must include `record_type=recon_phase`, `target`,
  `target_key`, `mode`, `phase`, `status`, `artifact`, `count`, `note`, and
  `recorded_at`.
- Every active request input must pass `tools.target_paths.url_belongs_to_target()`
  (or its host-equivalent contract) before DNS, HTTP, WAF, port, authenticated
  bulk-tool, or OpenAPI candidate fetching. Raw CT/Chaos/JS/API evidence may keep
  off-target values for review context, but those values never become direct
  request targets.
- `js_files_analysis.txt` is lossless discovery evidence. Active bundle curl,
  xnLinkFinder, and LinkFinder consume only `js/request_targets.txt`; quick and
  normal build the inventory/candidate view but defer active per-bundle analysis.
  Deep/full retain the active extraction behavior.
- Chaos is an optional passive collector. Missing `CHAOS_API_KEY` records
  `unavailable` without blocking Recon; malformed responses are collector errors;
  parsed values pass the same target ownership filter as every other subdomain
  source. OpenAPI external `servers` remain contextual facts and never expand
  fetch scope.
- Current-run active tools write temporary output first. A failed, timed-out,
  missing, or skipped command may leave prior canonical bytes in place only when
  the manifest status/note says `partial`, `error`, `skipped`, or `unavailable`;
  preserved bytes are not counted as a fresh `ok` result. HTTPX, WAF, puredns,
  naabu, and nmap derived summaries are rebuilt from current output (or the
  explicit CIDR page union).
- Successful collector replacement archives the prior raw collector bytes under
  `recon/<target_key>/history/collectors/<run_timestamp>/` before publishing the
  current generation. The archive is retention-only and never becomes default
  scanner input; failure to archive leaves the prior collector artifact in place
  and records an error.
- Runtime numeric settings are validated before recon I/O. HTTP crawling and
  DNS/port tools use the shared bounded rate settings, and direct httpx/naabu/nmap
  phases have hard per-phase timeouts in addition to the outer process timeout.
- The canonical port artifact retains host identity. Runtime, Observation
  Inventory, Surface, and Autopilot prefer `open_host_ports.txt` and fall back to
  `open_ports_all.txt` only for legacy fixtures; a current empty preferred file
  does not resurrect stale legacy bytes.
- FFUF/config probes normalize the join boundary once, strip query/fragment from
  the base used for path joins, and must never emit an accidental `//path`.
- Surface exact URL identity and the complete index remain unchanged. Bounded
  P1/P2/review frontiers reserve representatives across normalized route shapes;
  same-shape ties retain the legacy score-descending, first-seen order.
- CIDR offset `0` clears prior host/probe pages and canonical `httpx_full.txt`.
  Offset `>0` preserves them, writes only `<offset>.httpx.txt`, then rebuilds
  `httpx_full.txt` as a deterministic deduplicated union. `urls.txt` and status
  views must always derive from that canonical union, never only the newest page.
- Manifest `status` describes execution state only (`ok`, `partial`, `skipped`,
  `seeded`, or a tool-specific partial status). It must not encode attack-surface
  value, vulnerability confidence, or tested-clean semantics.
- Filtered URL files (`*_filtered.txt`) are priority views only. Any phase that
  extracts further surface from filtered URLs must append raw backstop data and
  deduplicate while preserving filtered-first order.
- Filtered URL views may reject invalid web schemes, collapse fragment/cache or
  tracking duplicates, and retain a bounded sample per `surface_shape`; every
  rejected row must remain in the raw artifact and have a reviewable reason.
- `coverage_matrix.json` remains the canonical Coverage owner. High-frequency
  checkpoint/autopilot readers may use its stat-bound `coverage_matrix-summary.json`
  projection; a missing, stale, or malformed projection must fall back to the
  canonical matrix and must not turn omitted default cells into tested-clean state.
- `js_files_analysis.txt` must be built from `js_files_filtered.txt` followed by
  raw `js_files.txt`; `with_params_analysis.txt` must be built from
  `with_params_filtered.txt` followed by raw `with_params.txt`.
- Recon summary and command docs should route the next step through `/surface`,
  `context_pack.py`, browser/source/JS enrichment when useful, and optional
  scanner quick as a breadth sensor. They must not imply scanner-negative equals
  completion.
- FFUF must keep one result-only JSONL/JSONL.GZ full artifact plus one bounded
  compact summary; do not duplicate the full result set into normalized hits and
  URL inventories. `ReconAdapter` owns FFUF decoding and safe projection.
- FFUF observations are AI review evidence, not bulk coverage input. Do not merge
  them into `urls/all.txt`, assign vulnerability classes, add score, or treat a
  random-miss/control signature match as an exclusion.
- SPA/WAF controls must use the same FFUF request/auth/redirect semantics as the
  main job. Controls and bounded heavy response signatures expose facts to AI;
  `-sf`, status/path filters, or automatic WAF/fallback verdicts must not hide
  unexecuted wordlist surface.
- High-frequency runtime/status readers may consume `ffuf_summary.json` only;
  parsing legacy giant root JSON is an explicit adapter operation.
- Baseline FFUF remains the automatic, fixed, bounded breadth sensor. Focused
  FFUF is optional and AI-selected; a zero-result baseline must not trigger it.
  The AI must have one concrete browser/JS/source/API/recon-backed template,
  one bounded deduplicated wordlist, an authentication context, a rate, and a
  stop condition before execution. Do not add a focused-fuzz wrapper, candidate
  extractor, score, or automatic surface/queue/coverage expansion.
- Every focused run must use an isolated `<run_id>` directory and preserve its
  wordlist, raw JSONL/JSONL.GZ, compact summary, and target-memory `lead` or
  `dead-end` decision. Different templates or auth shapes require different
  runs; focused artifacts must not overwrite baseline artifacts.
- Review the saved wordlist, result URL, response signature, and random-miss
  control together. FFUF may encode `input.FUZZ`, and `-ac` calibration can
  influence that raw field, so it is not sufficient as the sole provenance
  signal.
- `tools/openapi_semantics.py` is the only owner of derived `api_specs/*` content.
  It unions validated and raw API candidate files with exact URL deduplication,
  parses OpenAPI 3.x/Swagger 2 JSON or YAML, and exact-merges resolved operations
  into `urls/api_endpoints.txt`; validated views must never replace raw candidates.
- Operation identity is `(method, resolved_url)`. Records preserve source specs,
  parameters and `declared_required|explicit_public|anonymous_optional|unspecified`
  security status. Conflicting duplicate declarations remain explicit conflicts.
- `auth_boundary_candidates.jsonl` and `public_operations.txt` are discovery facts.
  `unauth_api_findings.txt` stays empty until runtime anonymous/authenticated role
  or object differential evidence is validated by the canonical finding owner.
- Platform probes cover Firebase init and OAuth authorization/protected-resource
  metadata. `BBHUNT_OPENAPI_MAX_PLATFORM_HOSTS` defaults to `20`; `0` removes the
  host budget. The budget limits requests only and must not truncate `live/urls.txt`.
- Runtime, Surface and Autopilot are consumers: they count artifacts and emit one
  aggregated soft lead. They must not duplicate the parser, mutate the action
  queue, alter P1/P2 scoring, or infer a vulnerability from schema declarations.

### 4. Validation & Error Matrix

- Tool missing or phase incompatible with target kind -> record `skipped`; do not
  create a tested-clean or dead-end conclusion.
- Invalid `BBHUNT_CIDR_OFFSET` -> exit `2` before resetting prior pages. A valid
  continuation cursor with remaining hosts must have `next_offset>0`; malformed
  JSON/UTF-8, target mismatch, or a reset-loop offset is projected as `invalid`.
- Phase ran but produced zero artifacts -> record `partial` or `ok` with
  `count=0` and a note that explains the execution boundary.
- A command exits non-zero with current bytes -> record `partial`; exits non-zero
  without current bytes -> record `error` (or `unavailable`/`skipped` when that is
  the actual boundary). If one port scanner succeeds while another fails, the
  port phase is `partial`, not a false full success or an all-or-nothing error.
- Invalid numeric settings -> exit `2` before creating the target recon tree or
  sending a request. A missing Chaos credential is `unavailable`; malformed
  Chaos JSON is `error` and does not publish a new collector artifact.
- Filtered file exists but raw contains extra JS/parameter URLs -> analysis input
  includes both, filtered first.
- Empty GitHub org extraction -> emit one numeric `0`, not duplicated fallback
  output that corrupts Claude hints or manifest counts.
- Summary next-step wording -> points to evidence pack and optional scanner quick,
  not a mandatory scanner-first flow.
- FFUF succeeds with zero observations -> `dir_fuzz=ok`, `count=0`; any host,
  compression, control, or parse failure -> `partial` while preserving valid
  result lines; missing tool/live URL/wordlist -> `skipped`.
- Baseline returns zero observations -> continue AI evidence review; do not
  schedule focused fuzz unless independent evidence supports a template and
  bounded wordlist.
- Focused FFUF or gzip fails -> preserve valid partial JSONL.GZ and summarize
  with `--attempted 1 --failed 1`; do not overwrite the baseline summary.
- Random miss matches a focused response signature -> expose the match to AI;
  do not silently discard the result or declare it fallback/WAF noise.
- `input.FUZZ` disagrees with the result URL after `-ac` -> retain the raw row
  and review URL + response + saved wordlist + control; do not infer the tested
  candidate from `input.FUZZ` alone.
- OpenAPI candidate fetch/parse failure, oversized body, missing YAML parser, or
  metadata network/5xx failure -> write `errors.jsonl`, publish `partial`, and
  continue Recon; common metadata 4xx is a miss, not an error.
- No schema/metadata hit -> publish `empty`; invalid CLI budgets/timeouts -> exit
  `2` before writing. Unexpected writer failure -> fail the semantic phase while
  preserving raw Recon artifacts.
- `.validated` exists but raw contains another schema URL -> fetch each exact URL
  once from their union. Never treat `.validated` as the complete corpus.
- Operation security declaration exists -> create a candidate with
  `requires_runtime_validation=true`; never write `unauth_api_findings.txt`.

### 5. Good/Base/Bad Cases

- Good: `127.0.0.1:9 --quick` records `subdomain_enum=skipped`,
  `port_scan=seeded`, and `js_analysis=skipped`; Claude can see what was not
  attempted.
- Good: `js_files_filtered.txt` contains one bundle and raw `js_files.txt` has a
  second bundle; `js_files_analysis.txt` contains both once.
- Base: a domain has no live hosts; recon records low-signal/partial HTTP
  probing but preserves artifacts for future browser/source/scope changes.
- Good: CT/Chaos contains unrelated SANs, raw JS contains third-party/private
  URLs, or API candidates include an external host; those values remain reviewable
  evidence while active inputs contain only target-owned URLs.
- Good: a partial nmap/naabu/httpx run publishes current bytes and a non-`ok`
  status; stale prior projections are not counted as current evidence.
- Good: a Surface fixture dominated by query variants of one route still returns
  multiple normalized route shapes in bounded review while exact index rows remain
  complete and legacy/index ranking stays equivalent.
- Good: CIDR pages `0` and `4096` remain present after continuation; their probe
  rows appear once in canonical `httpx_full.txt`, and the cursor advances again.
- Bad: offset `4096` truncates the manifest or canonical probe file, or derives
  live/status views from only `4096.httpx.txt`.
- Bad: JS analysis chooses filtered URLs when non-empty and silently ignores raw
  JS files.
- Bad: final recon output says only `Next: Run vulnerability scanner`, training
  Claude to treat scanner output as the hunt steering wheel.
- Good: cached browser evidence contains `/rest/admin/application-version` and
  `/rest/admin/application-configuration`; AI runs one bounded
  `/rest/admin/FUZZ` wordlist under an isolated run and records the result path.
- Base: the baseline FFUF summary is empty and no concrete sibling/template
  evidence exists; AI chooses another discovery lane without focused fuzz.
- Bad: merge a generic API dictionary after baseline misses, write focused
  output into baseline `dirs/`, or promote every 200 response into coverage.
- Good: global bearer security plus an operation-level `security: []` produces
  distinct required/public facts and one Surface workflow lead requiring a
  controlled differential.
- Base: no schema is found and all three metadata paths return 404; summary is
  `empty`, raw candidates/live hosts remain unchanged, and Recon continues.
- Bad: parse only `.validated`, infer auth bypass from `security: []` or HTTP 200,
  write a finding/action directly, or delete external-server operations.

### 6. Tests Required

- `tests/test_recon_engine_script.py` must assert manifest writer presence,
  non-judgment wording, CIDR offset/page preservation plus canonical union,
  filtered-first raw-backstop helper usage, and AI-first summary next-step wording.
- The same suite must cover target-owned active inputs, optional/malformed Chaos,
  invalid numeric settings, hard timeout wiring, host-aware nmap/naabu projection,
  HTTP partial-output status, and mixed port-scanner aggregation.
- `tests/test_runtime_state.py` and `tests/test_autopilot_bootstrap.py` must assert
  pending/complete/invalid CIDR cursor projection and bounded `state.recon` fields.
- `tests/test_recon_adapter.py` must cover JSONL/GZ streaming, sensitive-field
  projection, bounded heavy signatures, controls, paging, stale summaries, and
  explicit legacy fallback. Surface/runtime tests must prove FFUF stays unranked
  and does not expand coverage.
- Autopilot doc tests must assert fresh flow keeps browser/source/JS truth before
  scanner quick.
- `tests/test_focused_fuzz_docs.py` must assert baseline/focused/AI-decision
  semantics in the Skill and both autopilot entries; removal of legacy `/tmp`,
  generic API-dictionary, and `seq 1 10000` examples; preservation of root,
  nested, authenticated `-request`, path/query/body/header, adapter paging, and
  target-memory write-back capabilities.
- A low-cost local smoke such as `bash tools/recon_engine.sh 127.0.0.1:9 --quick`
  should exit 0 and write `recon/<target_key>/recon_manifest.jsonl` plus both
  `*_analysis.txt` files when recon_engine behavior changes.
- `tests/test_openapi_semantics.py` must cover OpenAPI 3 JSON/YAML, Swagger 2,
  security overrides/empty requirements, local refs, server/parameter resolution,
  duplicate merge, atomic writes, body limit, partial errors, idempotency and
  metadata host overflow without changing `live/urls.txt`.
- Recon/runtime/Surface/Autopilot/coverage tests must assert call ordering,
  recoverable phase status, exact counts, one soft lead, zero scoring/finding
  promotion, and demotion of the three standard public metadata paths.
- Surface frontier tests must cover route-shape diversity, first-seen ties, and
  category reservation only after a representative is actually admitted.

### 7. Wrong vs Correct

#### Wrong

```bash
JS_FILES_FOR_ANALYSIS="$RECON_DIR/urls/js_files_filtered.txt"
[ -s "$JS_FILES_FOR_ANALYSIS" ] || JS_FILES_FOR_ANALYSIS="$RECON_DIR/urls/js_files.txt"
echo "Next: Run vulnerability scanner"
```

#### Correct

```bash
build_filtered_first_backstop \
  "$RECON_DIR/urls/js_files_filtered.txt" \
  "$RECON_DIR/urls/js_files.txt" \
  "$RECON_DIR/urls/js_files_analysis.txt"
record_recon_phase js_analysis "$JS_ANALYSIS_STATUS" \
  "recon/${RECON_TARGET_KEY}/js/endpoints.txt" "$JS_ENDPOINTS" \
  "JS input uses filtered-first ordering plus raw js_files.txt backstop"
echo "Next: Build the AI evidence pack, then choose the highest-value hypothesis"
```

#### CIDR Wrong

```bash
BBHUNT_CIDR_OFFSET=4096 bash tools/recon_engine.sh TARGET --normal
# newest page overwrites live/httpx_full.txt
```

#### CIDR Correct

```text
offset 0 resets -> each offset owns one page -> deterministic page union
-> canonical httpx_full.txt -> urls/status views -> next_offset continuation
```

#### OpenAPI Wrong

```text
validated candidates only -> security: [] -> unauth_api_findings.txt -> action queue
```

#### OpenAPI Correct

```text
validated + raw exact union -> bounded fetch -> operation/security facts
-> api_endpoints exact merge + runtime counts -> one soft evidence lead
-> anonymous/authenticated role-object differential -> canonical validation
```

#### Focused FFUF Wrong

```bash
# Baseline miss is not evidence for a broad second dictionary.
ffuf -u 'https://target/FUZZ' -w ~/wordlists/api-endpoints.txt -o /tmp/ffuf.json
```

#### Focused FFUF Correct

```bash
RUN_DIR='recon/<target_key>/focused_fuzz/<run_id>'
ffuf -u 'https://target/api/v2/FUZZ' -w "$RUN_DIR/wordlist.txt" \
  -mc all -ac -rate 20 -t 5 -s -json \
  | gzip -c > "$RUN_DIR/dirs/ffuf_results.jsonl.gz"
python3 tools/recon_adapter.py --recon-dir "$RUN_DIR" \
  --summarize-ffuf --attempted 1 --succeeded 1
python3 tools/target_memory.py lead \
  "Focused fuzz evidence: $RUN_DIR/dirs/ffuf_summary.json; next: <replay>; stop: <condition>" \
  --target target.com
```

## Coverage Matrix Endpoint Triage Contracts

### 1. Scope / Trigger

Use this contract whenever `tools/coverage_matrix.py` stores endpoint-level
classification for recon/browser/JS/source URLs. Endpoint kind is a Claude /
operator judgment, not a regex verdict. Tool heuristics may only emit
`auto_hints` and prioritization weights.

### 2. Signatures

- `python3 tools/coverage_matrix.py needs-triage --target <target> [--limit N]`
- `python3 tools/coverage_matrix.py mark-endpoint-kind --target <target> --endpoint <path-or-url> --kind <kind> [--reason <text>] [--source ai_triage|manual|operator]`

Allowed `kind` values:

- `untriaged`
- `api_endpoint`
- `page_route`
- `static_asset`
- `public_metadata`
- `route_prefix`
- `realtime_endpoint`
- `external_chain_context`
- `unknown`

### 3. Contracts

- Fresh or rebuilt endpoints default to `endpoint_kind="untriaged"`.
- Regex/path features are stored under `auto_hints`, for example
  `api_like_path`, `static_asset_shape`, `public_metadata_path`, or
  `has_query_params`.
- `auto_hints` are not verdicts. They must not mark a vulnerability class
  `n_a`, remove an endpoint from the matrix, or replace Claude's judgment.
- `mark-endpoint-kind` stores `endpoint_kind`, `kind_source`,
  `kind_reason`, and `kind_triaged_at`.
- Rebuild must preserve endpoint kinds whose `kind_source` is
  `ai_triage`, `manual`, or `operator`.
- Any later pass that recomputes `auto_hints` after rebuild, such as
  scanner-pass metadata merge, must pass the full endpoint universe so
  relationship-based hints like `route_prefix_candidate` are not erased.
- Clearly bogus parser artifacts such as minified-JS property-chain pseudo
  URLs may still be dropped before matrix insertion.

### 4. Validation & Error Matrix

- Unknown `kind` -> fail-fast with valid kind list.
- Unknown `source` -> fail-fast with valid source list.
- Existing endpoint with final `kind_source` -> rebuild preserves it.
- Existing endpoint with old auto-derived kind and no final source -> rebuild
  resets it to `untriaged` plus `auto_hints`.
- Scanner-pass metadata merge on `/rest/admin` plus
  `/rest/admin/application-configuration` -> keeps `route_prefix_candidate`.
- Static/public metadata shape -> low priority is allowed, but cells stay
  `untested` until Claude/operator marks them clean, blocked, or N/A.

### 5. Good/Base/Bad Cases

- Good: `/orders` is stored as `untriaged`; Claude observes SPA fallback and
  XHR `/rest/order-history`, then marks `/orders` as `page_route` with a
  reason.
- Good: `/.well-known/jwks.json` gets `auto_hints=["public_metadata_path"]`
  but remains untriaged until Claude decides whether it is normal metadata,
  chain context, or sensitive exposure.
- Base: `/assets/app.js` is low priority and untriaged; it may still be useful
  for source-map, endpoint discovery, or secret review.
- Bad: a regex marks `/rest/admin` as `route_prefix` and sets all cells `n_a`
  before Claude sees status/body/browser evidence.

### 6. Tests Required

- Rebuild tests must assert static/public/API-like paths produce `auto_hints`
  while `endpoint_kind` remains `untriaged`.
- Triage tests must assert `needs_endpoint_triage()` lists untriaged endpoints
  with hints and status counts.
- Persistence tests must assert `mark_endpoint_kind()` survives rebuild.
- Scanner-pass tests must assert advisory metadata does not erase
  `route_prefix_candidate`.
- Regression tests must assert minified-JS pseudo URLs are dropped without
  dropping real dotted paths such as `.well-known` metadata.

### 7. Wrong vs Correct

#### Wrong

```json
{"endpoint": "/rest/admin", "endpoint_kind": "route_prefix", "cells": {"Authz": {"status": "n_a"}}}
```

#### Correct

```json
{"endpoint": "/rest/admin", "endpoint_kind": "untriaged", "auto_hints": ["api_like_path"]}
```

Then Claude decides and persists:

```bash
python3 tools/coverage_matrix.py mark-endpoint-kind --target target.com --endpoint /rest/admin --kind api_endpoint --reason "Admin API path confirmed by response/body/browser evidence"
```

## Scanner Pass Advisory Contracts

### 1. Scope / Trigger

Use this contract whenever `tools/vuln_scanner.sh`,
`tools/scanner_pass_writer.py`, or `tools/coverage_matrix.py` exchange scanner
coverage feedback.

### 2. Signatures

- `python3 tools/scanner_pass_writer.py --target <target> --findings-dir <dir> --recon-dir <dir>`
- `tools/coverage_matrix.py rebuild` consumes `findings/<target>/scanner_pass.json`

### 3. Contracts

- `scanner_pass.json` records scanner-touched `(endpoint, vuln_class, module)`
  pairs only as advisory context.
- Pre-created category directories are not scanner-touched evidence; a module
  needs at least one regular file in its category directory before
  `scanner_pass_writer.py` records it.
- Broad scanner-negative results must not become `tested_clean`.
- `coverage_matrix.py` may attach `scanner_swept`, `scanner_module`, and
  `scanner_pass` metadata to an `untested` cell.
- Only deterministic validation runners, evidence ledger resolution, or
  explicit operator `mark` commands may close a cell as `tested_clean`.
- Scanner-positive output is still only `lead` / `signal` / `candidate` until
  validated with exact replay and evidence rubric.

### 4. Validation & Error Matrix

- Missing `scanner_pass.json` -> no matrix status changes.
- Empty pre-created scanner category directory -> no scanner pass row.
- Unknown `vuln_class` in scanner pass -> warn and leave cell untested.
- Untested cell + scanner pass row -> status remains `untested`, metadata gets
  `scanner_swept=true`.
- Existing `tested_finding`, `tested_clean`, or `n_a` cell -> preserve status.

### 5. Good/Base/Bad Cases

- Good: SQLi scanner touched `/search?q=x`; matrix keeps SQLi cell
  `untested` with `scanner_swept=true`; Claude decides whether a targeted
  diff runner is still worthwhile.
- Base: scanner did not run XSS in quick mode; no XSS cell is closed.
- Bad: directory existence or scanner-negative summary marks every endpoint ×
  class as `tested_clean`.

### 6. Tests Required

- `tests/test_scanner_pass.py` must assert scanner pass metadata does not mark
  cells clean.
- `tests/test_scanner_pass.py` must assert pre-created empty scanner category
  directories do not create advisory module rows.
- Coverage rebuild tests must assert final statuses are preserved over
  scanner-swept metadata.

### 7. Wrong vs Correct

#### Wrong

```json
{"SQLi": {"status": "tested_clean", "evidence_ref": "scanner_pass.json#vuln_scanner.sqli"}}
```

#### Correct

```json
{"SQLi": {"status": "untested", "scanner_swept": true, "scanner_module": "vuln_scanner.sqli"}}
```

## Surface Ranking Hint Contracts

### 1. Scope / Trigger

Use this contract whenever `tools/surface.py`, `tools/surface_weights.py`, or
shared high-value signal helpers rank, demote, or label discovered hosts/URLs.

### 2. Signatures

- `python3 tools/surface.py --target <target>`
- `python3 tools/recon_candidates.py --target TARGET` publishes the rebuildable
  `recon/<target_key>/exposure/host_ranking.jsonl` attention view; it retains every
  observed host and never changes scope, Coverage, Finding, or Queue state.

### 3. Contracts

- Path/host/title regexes are ranking hints only.
- Low-priority host output must be phrased as a hint, not a kill/exclusion
  verdict.
- Docs/status/blog/static/CDN-looking hosts may be deprioritized, but must
  remain revisitable when browser, auth, Cloudflare clearance, source, secret,
  webhook, OAuth/JWKS, CDN, or integration evidence changes.
- Surface ranking may suggest where to start; it must not claim a host, URL, or
  lane is out of scope, tested clean, or not applicable.

### 4. Validation & Error Matrix

- 403-only host + CF bypass active -> emit refresh/bypass hint, not low-priority
  host hint.
- Docs/static/status-looking host -> low-priority hint only.
- New target-owned browser/source evidence for a low-priority host -> ranking
  can promote it back to P1/P2.

### 5. Good/Base/Bad Cases

- Good: `docs.example.com` appears under "Low-priority host hints" with a
  reason and can be revisited if source/secret/OAuth context appears.
- Bad: display "Kill List (skip)" and train Claude to ignore a target-owned
  host permanently.

### 6. Tests Required

- Surface tests must assert low-priority host hints do not remove ranked target
  URLs.
- Formatting tests should prefer "low-priority hint" language over "kill" or
  "skip" wording.

### 7. Wrong vs Correct

#### Wrong

```text
Kill List (skip):
- docs.example.com — likely docs/static/support host
```

#### Correct

```text
Low-priority host hints (not exclusion):
- docs.example.com — possible docs/static/support host
```

## Scenario: 通用 case-router 与可选案例来源

### 1. Scope / Trigger

新增或修改 `layer=case-router` 的知识卡时，必须把“加载/路由职责”和“案例来源”分开。历史上一批
router 卡来自 HackerOne corpus，但项目同时服务通用渗透测试；任何单一平台/corpus 都不能成为
case-router 准入条件。

### 2. Signatures

```yaml
- id: CARD_ID
  kind: card
  file: knowledge/cards/CARD_ID.md
  layer: case-router
  load: on-demand
  purpose: route|connector|bypass|validate
```

```yaml
# frontmatter：来源可选
source_refs: []
```

### 3. Contracts

- `case-router` 只表示明确 signal 命中时按需加载，硬门是 `load=on-demand`、触发信号、证据门、
  停止条件和返回既有 Skill/evidence/finding lifecycle。
- `source_refs` 是可选溯源信息，不是 card maturity、active 状态或 route 权限。没有可核对来源时必须
  保持空列表，禁止猜测 ID。
- 现有 v1 `corpus-report/hackerone-disclosed-reports` resolver 仅用于历史本地案例查询；已有引用继续
  严格校验，缺本地 corpus 不阻断普通 context-pack 路由。
- 新卡不得为了满足来源门而降级到错误 layer，也不得扩展第二套 finding/action/evidence owner。

### 4. Validation & Error Matrix

| 条件 | 正确行为 |
|---|---|
| case-router 使用 `load!=on-demand` | knowledge audit error |
| `source_refs: []` | 合法，正常按信号路由 |
| source_refs 非空但 schema/ID 非法 | knowledge audit error |
| source_refs 指向可用 corpus 中不存在案例 | strict source audit error |
| 本地可选 corpus 缺失 | source resolution `unavailable/skipped`，路由继续 |

### 5. Good / Base / Bad Cases

- Good：Cognito 产品边界卡使用 case-router/on-demand、空 source refs，并由明确 Identity Pool 信号触发。
- Base：已有蒸馏卡保留真实 report refs，仅在需要案例形状时按需查询。
- Bad：为了让新卡通过审计虚构 HackerOne report ID，或声明整个项目依赖 HackerOne。

### 6. Tests Required

- knowledge audit fixture：case-router + empty refs 通过；非法非空 refs 仍失败。
- governance：core/default budget 不增长，case-router 必须 on-demand，所有 cards 唯一登记。
- context-pack：新 signal 命中新卡，最多一个 case-router，overflow 进入 deferred 而不是丢失。
- index/template 文档必须明确 case-router 与单一 corpus 无绑定。

### 7. Wrong vs Correct

#### Wrong

```text
layer=case-router -> 必须伪造一个 HackerOne source_refs -> 才能 active
```

#### Correct

```text
signal -> on-demand case-router -> evidence/stop gate -> existing Skill lifecycle
                            \
                             optional verified source_refs
```

---

## Scenario: 参数发现批次与可恢复 cursor

### 1. Scope / Trigger

- 修改 `tools/param_discovery.py`、`/param-discover`、参数 raw artifact 或其
  Action Queue 投影时适用。
- 目标是让 GET/POST 的默认深度预算保持有界，同时把未完成的 URL 留为可显式续跑的工作。

### 2. Signatures

```python
discover_parameters(
    *, target, urls=None, methods=("GET",), max_urls=5,
    resume=False, ...
) -> dict
```

```text
python3 tools/param_discovery.py --target TARGET --method GET|POST|BOTH
  [--max-urls N] [--resume]
```

### 3. Contracts

- 每种 method 每次最多执行 `max_urls` 个输入；默认值为 5。`PUT/PATCH/DELETE`
  不由该入口加入；POST 表单抓取也只处理本批输入页。
- `recon/<target_key>/params/summary.json` 保留 `batch_id`、`resumable` 和
  `cursor.methods[method]`：`input_url_digest`、`accepted_url_digest`、`total`、
  `next_index`、`remaining`、`complete`。cursor 是 summary 的派生续跑事实，不是新状态 owner。
- `--resume` 必须复用相同 target、source、method、认证 `session_id` 和输入摘要；
  成功后从 `next_index` 取下一批。输入变化或已完成 cursor 不得重新发起请求。
- 新批次的 summary 先把旧 `summary.json` 归档为 `summary.batch-*.json`，raw tool
  输出使用 batch/全局序号命名，不覆盖旧文件。参数列表/POST form 投影只追加合并，原始
  失败与旧 summary 保留。
- 工具非零/timeout 时该 URL（或 POST 批次）不推进 cursor，summary 为 `partial`/`blocked`；
  失败工作必须可由后续 `--resume` 重试，不能投影为 `tested_clean`。
- 非正 `max_urls` 直接报错并在任何 summary、queue 或 raw 输出写入前退出。

### 4. Validation & Error Matrix

| Condition | Result |
|---|---|
| `--resume` 无 summary、summary 损坏、target/source/method/auth/input digest 不匹配 | `ValueError`/exit 2，旧 artifact 零写入 |
| `max_urls` 非整数或 `<=0` | `ValueError`/exit 2，旧 artifact 零写入 |
| 输入超过本批预算 | 写 cursor，状态 `partial`，Action Queue hint 带 `--resume` |
| 工具失败或 timeout | 保留失败 run，cursor 停在失败前，状态非完成 |
| cursor 全部 complete 且重复 `--resume` | 返回现有 summary，不产生新批次或请求 |

### 5. Good / Base / Bad Cases

- Good：7 个 GET URL、预算 3 的三次调用依次执行 `0..2`、`3..5`、`6`，旧批次和
  raw 输出均可回放。
- Base：输入只有 5 个 URL 时一次完成；显式 `--max-urls 8` 可在一次调用覆盖 8 个。
- Bad：每次从序号 1 重跑并覆盖 `x8_GET_1.txt`，失败 URL 被 cursor 跳过，或把 5 个
  URL 的预算误用于默认 PUT/PATCH/DELETE。

### 6. Tests Required

- `tests/test_param_discovery.py`：默认/显式预算、GET/POST batch cursor、summary/archive
  保留、重复 resume no-op、输入/auth 变化零写入、损坏 summary、失败重试和非正预算。
- `tests/test_action_queue.py`：partial cursor 的 queue action 保留 `--resume` hint，
  metadata merge 仍幂等且拒绝敏感字段。
- `git diff --check`、`python3 -m compileall -q tools/param_discovery.py`。

### 7. Wrong vs Correct

#### Wrong

```text
urls[:5] -> run -> overwrite summary/output -> failure still advances cursor
```

#### Correct

```text
stable input digest -> bounded batch -> atomic summary + cursor -> explicit --resume
```

---

## Scenario: 框架信号复用既有知识 owner

### 1. Scope / Trigger

新增框架、协议或产品特征的知识路由时，先判断它是独立攻击边界，还是既有漏洞类型的触发信号。
Next.js、Spring、ASP.NET 等框架名本身不构成新的 finding 类型，也不应默认扩张 Skill 数量。

### 2. Signatures

```python
# tools/context_pack.py
DISTILLED_TOKEN_TO_CARDS = (
    (FRAMEWORK_BOUNDARY_RE, ("EXISTING_OWNER_CARD",)),
)
```

```yaml
# 只有独立 query/protocol boundary 才登记 signal-only reference 卡
- id: BOUNDARY_CARD
  kind: card
  layer: reference
  load: signal-only
```

### 3. Contracts

- 框架特征能够由现有漏洞 owner 表达时，必须路由到现有卡和 Skill；不得新增
  `hunt-nextjs`、`hunt-springboot`、`hunt-aspnet` 一类固定框架 Skill。
- 路由信号必须指向具体边界，而不是普通技术栈标签。例如 `/_next/image` 指向 SSRF fetch gate，
  `/_next/data` 指向 IDOR identity diff，Actuator 指向管理响应形态，ViewState 指向完整性和真实消费，
  legacy auth 指向同账号策略差异。
- OData、LDAP/XPath 等现有 owner 无法准确表达的独立 query context，才允许新增
  `reference + signal-only` 卡；卡只保存边界、最小证据和停止条件。
- HTTP 200、operator 可用、格式可识别、端点可达只能形成 Signal。Candidate 必须由现有
  evidence/finding owner 按可复现影响晋升。
- `context_pack` 仍遵守最多 1-2 张卡的预算；未选卡进入既有 deferred 路径，不创建第二套路由状态。

### 4. Validation & Error Matrix

| 条件 | 正确行为 |
|---|---|
| 普通 `Next.js homepage` | 不加载 SSRF/IDOR 专项卡 |
| `/_next/image` 且出现 fetch/URL 边界 | 加载 `ssrf-url-fetch`，HTTP 200 保持 Signal |
| `/_next/data` 且出现对象/身份边界 | 加载 `api-idor`，要求 anonymous/owner/peer/cross-tenant 对照 |
| 普通 `Active Directory login` | 不加载 LDAP/XPath query 卡 |
| LDAP filter/DN/XPath parser 或 query error | 加载 `ldap-xpath-query-boundaries` |
| 同一信号命中多张卡 | 按既有预算选 1-2 张，其余进入 deferred |

### 5. Good / Base / Bad Cases

- Good：`/_next/image?url=` 命中 SSRF owner，seed 明确要求唯一 OAST 或 upstream/internal 差异。
- Good：LDAP filter error 命中 query boundary 卡，但登录页只有 AD 品牌字样时不加载。
- Base：只观察到 Actuator 路径 200，保持 Signal，先排除登录页、Whitelabel 和 SPA fallback。
- Bad：看到 `Next.js` 就加载 SSRF/IDOR，或为每个框架复制一个 `hunt-*` Skill。

### 6. Tests Required

- `tests/test_selective_knowledge_distillation.py`：框架正向信号命中既有 owner，并携带 negative gate。
- 同文件必须覆盖普通 Next.js homepage 和普通 Active Directory login 的负向路由。
- knowledge audit 验证新增独立边界卡为 `reference + signal-only`，且 core/default 预算不增长。
- context-pack 回归断言 `knowledge_cards <= 2`，deferred 行为不丢失。
- collision 回归必须覆盖具体正向、近似和宽泛负向信号，并断言 `knowledge_card_recall` 排序、
  reason、去重和预算在重复构建时保持稳定。

### 7. Wrong vs Correct

#### Wrong

```text
framework keyword -> dedicated hunt-* Skill -> HTTP 200 -> Candidate
```

#### Correct

```text
specific boundary signal -> existing owner / signal-only reference
                         -> negative gate + reproducible evidence
                         -> canonical evidence/finding lifecycle
```

---

## Scenario: 跨组件结构化值的测试前视图差异召回

### 1. Scope / Trigger

当 Context Pack 看到尚未验证的表面证据同时表明“可写结构化输入”、“安全敏感字段”和
“存储/转发/校验后由第二组件消费”时，必须在测试前把它路由到既有
`view-differential` Card。这样模型能生成最小 A/B 验证，而不是只能在已经观察到 parser
差异后复核。该路由不新增 Lane、状态 owner 或固定输入字典。

### 2. Signatures

```python
# tools/context_pack.py
def _has_json_view_differential_candidate_signal(text: str) -> bool: ...

# Existing owner and budget path
_select_cards_and_deferred(blob, skill, ranked, gaps, goal_memory, focus, repo)
```

### 3. Contracts

- 前置候选必须同时满足：JSON/API/request body 等结构化边界、role/tenant/permission/status/
  amount 等安全敏感字段、以及存储/转发/校验与 read-back/consumer/worker/backend/admin/
  permission 的跨组件关系；任一条件缺失不得加载该 Card。
- 同一规则同时用于显式 `focus` 和聚合后的 target evidence `blob`，但只是知识召回和验证假设，
  不能写入 finding、覆盖完成态或 action queue 终态。
- 已观察到的 raw `\\ud800`-`\\udfff` 未配对 escape、重复 JSON key、规范化/截断和
  parse/serialize 差异可直接命中该 Card；有效 high+low surrogate pair 不是该信号。
- `view-differential` 与 `type-confusion` 等同层 Card 仍复用既有 selected/deferred 预算；
  不因主动召回创建第二个预算或绕过 `knowledge_card_recall[]`。
- 具体字段和值必须由目标 schema 和基线请求派生。示例角色名不能成为 router 条件或固定测试
  向量；Card 只要求 baseline、单变量候选、近似负例和最终影响对照。

### 4. Validation & Error Matrix

| 条件 | 正确行为 |
|---|---|
| 可写 JSON role 字段先持久化，再由 permission/admin API 读取 | 测试前加载 `view-differential` 并生成视图对照假设 |
| 普通 JSON API 响应或普通 profile `role` 字段 | 不加载 `view-differential` |
| `\\ud888` 等未配对 escape 与消费侧截断证据 | 直接加载 `view-differential`，不误路由 `upload-parser` |
| 有效 surrogate pair 表示普通昵称 | 不加载该 Card |
| 同时命中 scalar/object 与 view 差异信号 | 选择一个 case-router，另一个进入 deferred |
| 两侧严格 parser 在入口拒绝输入 | 记录测试结果/停止，不把错误响应提升为 Candidate |

### 5. Good / Base / Bad Cases

- Good：从 API 文档或 read-back 路径看到可写租户字段被 worker 和权限接口消费，先构造
  baseline、单边界变体和 read-back 对照。
- Base：已有未配对 surrogate 或重复键分叉证据时，加载 Card 并确认实际库版本、配置和
  Content-Type。
- Bad：看到任意 JSON、角色字符串或单个 `400/500` 就加载 Card，或用示例角色名枚举所有字段。

### 6. Tests Required

- `tests/test_context_pack.py` 必须覆盖英文和中文的测试前正向信号。
- 同文件必须覆盖普通 JSON、普通 role 字段、有效 surrogate pair 的负向路由。
- 同文件必须断言 raw 未配对 escape 不被 `upload-parser` 抢占，case-router overflow 进入
  `deferred_knowledge_cards`，且 Card 预算稳定。
- `python3 tools/knowledge_audit.py --strict` 和完整 Context Pack 回归必须通过。

### 7. Wrong vs Correct

#### Wrong

```text
ordinary JSON -> always load parser Card
observed parser difference -> only then think about view differential
```

#### Correct

```text
structured input + sensitive field + multiple processing views
  -> bounded view-differential hypothesis
  -> baseline + one variant + negative control + read-back
  -> evidence/finding owner decides final result
```

---

## Scenario: Generic asset-relationship Scope projection

### 1. Scope / Trigger

Use when public registry, RDAP/WHOIS, certificate, passive-DNS, ASN/origin,
supplier, mapping-provider, or public-browser evidence is normalized into
`asset_relation_observations.jsonl`. This is a bounded Recon projection, not a
collector, target-set editor, Browser Surface owner, or direct validation lane.

### 2. Signatures

```bash
python3 tools/recon_candidates.py --target TARGET [--asset-input INPUT.jsonl] \
  [--asset-limit N] [--asset-cursor CURSOR]
```

Observation identity remains `(asset_type, value, relation)`. Required fields are
`schema_version=1`, `kind=asset-relation-observation`, `asset_type`, `value`,
`relation`, and `source`. Optional recursion metadata is `entity_ref`,
`parent_ref`, numeric `ownership_pct` in `0..100`, and integer `depth` in `0..4`.

### 3. Contracts

- Raw `exposure/asset_relation_observations.jsonl` is lossless evidence. Candidate
  limits only bound `asset_relation_candidates.jsonl`; invalid rows are summarized.
- `recon_candidates.py` is the only normalizer/merge owner. Candidate provenance is
  merged without changing its identity; entity/parent refs are bounded unions, the
  highest ownership percentage and shallowest depth survive.
- Candidate `scope_status` is tool-derived only: `excluded` precedes `in_scope`, then
  high-confidence `scope-review`, `external-chain-context`, and `unknown`.
  Only `domain`, `hostname`, `url`, `ip`, and `cidr` values may call target ownership
  helpers. A `related` value never makes the candidate value `in_scope`.
- Primary target ownership and explicitly supplied profile scope are both active;
  target-profile exclusions win. Relationship evidence remains context until the
  target set explicitly proves ownership.
- Candidate and `asset_relation_summary.json` use atomic replacement. Summary carries
  target identity, candidate byte size, and a source-bound continuation cursor;
  a cursor is rejected when the observation source changes. Recon reruns retain the
  last usable projection until a complete rebuild publishes a replacement, so a
  failed rebuild cannot erase prior review context; the phase record remains
  `partial` and consumers must not treat that projection as a fresh completion.
- Runtime projects the small summary in both full and fast paths. Surface emits a high
  `asset-scope-review` lead only for pending high-confidence Scope Review; Checkpoint
  persists it through the existing Action Queue. Other relationship rows stay medium
  advisory context and never enter P1/P2 or direct network execution.

### 4. Validation & Error Matrix

| Condition | Result |
|---|---|
| Invalid percentage/depth/text/timestamp | invalid input row; raw line remains and summary records warning |
| Relative path, ASN, organization, or malformed host | `unknown`; do not call `url_belongs_to_target()` |
| Explicitly excluded candidate or related target | `excluded` / no Scope Review promotion |
| Candidate target does not match summary target, or byte size mismatches | summary invalid; fast/bootstrap state reports warning and consumes no review count |
| High-confidence target-linked controlling/certificate/registrant or multi-source relation | `scope-review` -> durable `workflow-lead-review` |
| Medium/low external relationship | `external-chain-context`; visible but does not block closure |

### 5. Good / Base / Bad Cases

- Good: a high-confidence certificate relation to an external hostname creates a
  Scope Review action, then remains non-executable until an explicit target update.
- Base: a supplier hostname remains external chain context and closure may finish
  after unrelated durable work is resolved.
- Bad: scan every returned provider host, classify an organization/relative path as
  target-owned, silently drop raw observations, or use target text in `related` to
  grant direct scope.

### 6. Tests Required

- `tests/test_recon_candidates.py`: legacy merge, optional metadata bounds, raw-byte
  preservation, domain/IP/CIDR/list/exclusion disposition, related-list truncation,
  and invalid/mismatched summary handling.
- `tests/test_runtime_state.py`: fast inspection remains stat/sidecar based and
  projects valid summary facts without scanning candidate JSONL.
- `tests/test_surface_tool.py`, `tests/test_checkpoint.py`,
  `tests/test_action_queue.py`, and `tests/test_autopilot_state_tool.py`: high review
  is durable/selectable and blocks closure; advisory context does not.

### 7. Wrong vs Correct

#### Wrong

```text
mapping result -> add hostname to P1 -> active request -> report
```

#### Correct

```text
raw public observation -> bounded candidate + derived Scope status ->
Scope Review Action Queue -> explicit target-set proof -> active work
```

---
