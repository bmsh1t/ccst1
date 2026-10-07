# F11 owner 与 CLI 契约核验

研究日期：2026-10-07。仅静态读取源码；未运行测试、运行态 CLI、目标请求或迁移。本主题使用定位搜索与定点源码读取；另一研究主题使用 fast-context。仅写本文。

## 1. 当前 owner 与恢复字段

- `tools/target_store.py:2916-2924`，`runtime_store()`：只接纳已初始化的 primary Store；legacy 明确报 `target is not initialized; use explicit init or legacy import first`。读取、经验写入不会初始化或回退读取旧 JSON。
- `tools/target_memory.py:219-305`，`load_goal_memory()`：`store.memory_context()` 是目标记忆 owner；旧 JSON 形状只是兼容读投影。返回 `source.kind="store"`、`source.store_id`、`source.revision`、`source.experience_window`、`target_path`（Store 路径）。不要把旧 `memory/goals/targets/<target>.json` 或 sessions 记录当当前事实来源。
- `tools/target_memory.py:346-375`，`set_active()`：`set TARGET` 只选择已初始化目标；有 `--goal` 才通过 Store 修改目标。`active.json` 新写内容精确为 `schema_version`、`target`、`updated_at`（361-362 行），只是选择指针，不拥有目标状态/验证结果。旧 `--mode/--phase/--hypothesis/--skill/--knowledge` 参数显式拒绝。
- `tools/target_memory.py:578-619`，`show()`：`show TARGET` 或无参数使用选择指针；JSON 原样返回上述 Store 投影。当前 `target.current_handoff` 与 `target.next_actions` 来自最新 handoff；历史意图不是待执行 Action。
- `tools/target_store.py:2281-2302`，`memory_context()`：记忆是 advisory，不决定 Case readiness。`current_hypothesis` 来自 `experience_case_context.why_now`；普通 `lead` 写 hypothesis 经验，不等于写 Case premise。
- `tools/target_store.py:2944-2972`，当前 Finding 查询是 `findings --target TARGET [--id FINDING_ID | --cursor CURSOR] [--limit N]`；**本 CLI 没有 `--json`，默认打印 JSON**。`--id` 与 `--cursor` 互斥；列表默认 10 条。
- `tools/target_store.py:2483-2561,2759-2776`：Finding 含原始 claim 字段及 `assessment`、`deliveries`、`reports`、`evidence`、`technical_conclusion`、`evidence_integrity`、`destination_decision`；单条扩展还有 `assessment.evidence`、`delivery_events`、`revision`。`reports[]` 包含 `artifact_ref/artifact_sha256/artifact_size` 与实际 assessment/delivery 绑定。**没有 `validation_summary` 或 `validation_summary_path` 这一 Finding 字段。**
- `tools/validate.py:1707-1717`：应用调用返回 `summary_path`、`report_path`、`submission_notes_path`、`validation_sync` 等。`validation_summary_path` 是实际 summary JSON 内的字段（737-755 行），不是 Store Finding 字段。恢复应查询 Store 的 Finding/assessment/report 关系，并使用该次调用返回的 per-finding `summary_path`；不要依赖 repo-global `findings/last-validate.json` 或想象 Store 的 summary 路径字段。

## 2. target_memory 实际写入与拒绝边界

入口：`tools/target_memory.py:398-455,514-530,658-711`；底层：`tools/target_store.py:1722-1747`（`remember()`）。

| CLI | Store kind | 必要条件与含义 |
| --- | --- | --- |
| `lead --target TARGET TEXT` | `hypothesis` | 文本非空；`--conditions` 缺省 `unknown`；证据可选。是待验证假设，不自动建 Action。 |
| `next --target TARGET TEXT` | `handoff` | 文本非空；未给 `--next-intent` 时沿用 TEXT；是 advisory next intent，不是 Queue action。 |
| `dead-end --target TARGET TEXT` | `negative` | 必须有非 unknown 的 `--conditions`、非空 `--reopen-when` 和至少一个 `--operation-ref OPERATION_ID:STEP`。 |
| `handoff --target TARGET SUMMARY` | `handoff` | summary 非空；`--conditions`、`--next-intent`、可重复 `--operation-ref` 可选；不会把 summary 自动当 next intent。 |
| `note --target TARGET TEXT` | `note` | 无登记证据时保存未证实观察的现成入口。 |
| `pattern --target TARGET TEXT` | `primitive` | 必須引用登记观察；conditions 缺省 unknown。 |

- `--target` 省略时用活动选择指针；**show/set 的 TARGET 是位置参数**，不是 `--target`。所有 target_memory 子命令均接受 `--repo-root`、`--json`（731-735 行）；`--command-id` 可用于幂等重试，`--actor` 缺省 operator。
- `--operation-ref` 可重复；按最后一个冒号拆 `OPERATION_ID:STEP`，STEP 为从零开始的 observation index（54-57,388-395 行），**不是 artifact 路径、request 路径、Finding ID 或整个 summary 路径**。
- Store `_references()` 拒绝空列表（在需要证据时）、不精确的字段结构、重复引用、负数/non-int step（`tools/target_store.py:491-505`）；operation ID 也须为 bounded identifier，非路径（465-469 行）。`experience_observations` FK 绑定本 Store 已有 observation（280-285 行）：跨目标/不存在 operation 或 step 拒绝。
- `remember()` 不做“operation 必须 complete”或“原始 bytes 再校验”的额外 gate，不能在文案中发明这一 CLI 前置限制；它保存带条件的经验，不能替代 assessment。`dead-end` 的显式条件比底层 `remember()` 更严格；文字不能把某个条件下的 negative 升级为全局绝对结论。
- `--structured-json/--kind` 是退休写法，显式报错；`--evidence-ref` 路径也是退休写法，错误要求 `--operation-ref`（417-420 行）。未登记证据时改写为 note 或保留假设，不伪造 operation 引用。
- `--command-id` 原 argv/actor/content 相同重试返回 `receipt.replayed=true`；同 ID 不同内容拒绝（`tools/target_store.py:772-794`）。target_memory 成功 JSON 为 `{target, receipt}`，`receipt.entity_id` 是经验 ID。

### 文案可复用的有效语法

前提：TARGET 已初始化，OPERATION_ID:0 确为该 Store 已登记观察；占位值必须换成实际返回值。

```bash
python3 tools/target_memory.py show TARGET --json
python3 tools/target_store.py findings --target TARGET
python3 tools/target_store.py findings --target TARGET --id FINDING_ID

python3 tools/target_memory.py lead --target TARGET \
  --conditions 'peer session; same tenant; JSON representation' \
  'Hypothesis: compare the saved control and peer response'
python3 tools/target_memory.py next --target TARGET \
  'Compare the existing control with the saved peer response'
python3 tools/target_memory.py dead-end --target TARGET \
  --conditions 'peer session; same tenant; JSON representation; recorded deployment' \
  --reopen-when 'role, tenant, representation or deployment changes' \
  --operation-ref OPERATION_ID:0 \
  'No peer read was observed under these recorded conditions'
python3 tools/target_memory.py handoff --target TARGET \
  --conditions 'saved response only; impact not established' \
  --next-intent 'Compare existing control before another experiment' \
  --operation-ref OPERATION_ID:0 \
  'Candidate remains unconfirmed'
```

`/target` 是 AI 命令表面；实际语法应以这里的 Python CLI 为准。完整重试时可加固定 `--command-id`，不同经验应使用不同 ID。

## 3. 当前 validation 输入、登记与 assessment 链

- `commands/validate.md:89-188` 已有主要正确链路，可直接引用而非重复定义 schema：Store Finding → 已登记的 runner witness → scaffold → AI 判断 → preflight → apply。
- `tools/validate.py:915-937`，`load_finding_prefill()` 只读 `runtime_store(...).finding(id)`，将 `family/endpoint/claim` 用于预填；目录必须匹配所选 owner。`migrate_legacy` 参数仍在签名，不代表当前路径读写旧 Finding JSON。
- `tools/validation_runner.py:1190-1308`，`record_native_evidence()` 只登记**已经执行**的材料，不发请求；必须已有 primary Finding，真实 `attempt_id` 可由 JSON 字段或 `--attempt-id` 给出。schema-v1 必需 `source`、带时区的 `generated_at`、AI `result`、`observed_difference`、非空 `runs`。完整 run 必有 request/response 的非空同目标原始 artifact；锚点 URL/method 精确匹配 Finding，锚点 actor 明确，多锚点须 `subject_step`。缺失响应/error/truncation 只能 `partial`。
- 状态改变事实用 `--state-changing --redline-checked`；只读用 `--no-state-changing`。缺省 None，不应在指导中谎称 parser 强制二选一；明确 state-changing 而未 redline checked 会拒绝（`tools/validation_runner.py:693-703,1412-1417`）。已认领 Action 才附 `--action-id ACTION_ID --claim-token CLAIM_TOKEN --actor OPERATOR`，操作者应是 claimant；登记不完成 Action。操作 ID 输出为 `store_operation_id`（498 行），不是输入文件路径。
- `tools/validate.py:1471-1519` / `tools/decision_scaffold.py:71-122`：scaffold 预填 target/finding/endpoint/method/class、runner summary refs 和报告路径；impact、gates、seven_question_gate、evidence.summary、report.content 仍需 AI 填写。保留 `store_preconditions.assessment_id/delivery_id`；null 意为此前无判断。
- `tools/validate.py:1106-1180`：preflight 必须 witness 属同目标/Finding，包含 Store operation，operation complete 且有 observation；必须关联该 Finding 的 endpoint/method，并验证现有原始 artifacts。assessment 只引用选择的 operation 上与 Finding 关联的 steps。不靠 runner 的 candidate/tested_clean/dead_end 标签决定技术裁决。
- `_primary_validation_command()` 把 Store generation、整份 decision、证据 refs 绑定到稳定 assessment/delivery command ID；新决定须重新 scaffold，旧 predecessor 拒绝；原决定重复可恢复 assessment 已提交而 delivery 未提交的情况。
- `tools/validate.py:791-842`，`_sync_primary_validation()`：调用 `store.assess()` 与 `store.decide_delivery()`，不写 Finding JSON；技术判断映射 confirmed/inconclusive，目的地判断 independent eligible/ineligible/deferred。这个机器入口**不表达 refuted**，虽底层 Store.assess 支持它。
- `tools/validate.py:1674-1717`：AI 正文先原子落盘，再保存 summary、分别提交 assessment/delivery；满足 report_ready 才登记 report。报告或提交失败保留已有内容并允许原决定重试；没有自动外部提交或 Action 完成。

### 文案可复用的 validation 命令

TARGET/FINDING_ID 已存在；native-observations.json 保存实际已执行证据，真实 attempt ID 在材料中或显式参数中。若证据早已登记，跳过第一步。

```bash
python3 tools/validation_runner.py record-evidence --target TARGET \
  --finding-id FINDING_ID --evidence-json /tmp/native-observations.json \
  --attempt-id ATTEMPT_ID --no-state-changing --json
python3 tools/validate.py --target TARGET --finding-id FINDING_ID \
  --scaffold --json > /tmp/validate-decision.json
```

AI 填完上述判断/正文/evidence.summary 后：

```bash
python3 tools/validate.py --target TARGET --finding-id FINDING_ID \
  --decision-json /tmp/validate-decision.json --preflight --json
python3 tools/validate.py --target TARGET --finding-id FINDING_ID \
  --decision-json /tmp/validate-decision.json --json
```

`--preflight` 成功 `status=preflight_ok`；错误 exit 2、`status=preflight_invalid` 和 errors。应用结果保留 `summary_path`，再以 Store Finding 查询确认 assessment/evidence/delivery/report。`validate.py` 没有 `--repo-root`，隔离根用 `--findings-dir ROOT/findings/TARGET_KEY`；target_store/target_memory/validation_runner 各有自己的 repo-root flag。

## 4. 最小指导改动与已知缺口

1. 活跃 validator 的输入、查询和 resume 文案改为上述 Store query 与“本次调用返回的 summary_path”；删除依赖旧 Finding JSON 的状态写回/读取以及虚构 `validation_summary` 字段。`agents/validator.md:38,60,66` 存在这三类旧引用。
2. 复盘/退路保持原推理方法，只补全 dead-end 三项实参和真实 observation 来源；next/handoff 明确 advisory，不能写成 Queue owner 或自动排队。
3. `commands/validate.md:237-239` 的“selected finding's recorded summary path”容易误读成 Store 字段；若该链落入最终范围，最小澄清是使用该次 invocation 返回并保留的 per-finding summary path。Store 自身没有 summary locator，不应为文案新增字段或 registry。
4. `commands/validate.md:108-110` 说 scaffold 绑定“latest owner-bound run”比实际代码强：`decision_scaffold._latest_runner_run()`（49-68 行）只找本 Finding 目录最新 summary，核对其 finding_id；真正 Store operation/完整性绑定在 preflight。文案不应把 scaffold 当验证成功。其 missing-witness warning（117-121 行）仍只有 request-diff 且命令不完整，但这是生产输出，F11 不改 feature；必要时用指导覆盖 native registration 选择即可。

## 5. 现有定向验证抓手（未执行）

- `tests/test_target_memory_cli.py:26-76`：临时 Store + registered operation，真实子进程覆盖 lead/next/dead-end/handoff 的 Store kind、幂等 receipt 和无旧 JSON 写入。
- 同文件 `test_memory_cli_explains_failed_negative_and_recovers_as_advisory_note`（107 行）：缺必要实参错误后可 note，且不生成 handoff/next intent。
- 同文件 `test_handoff_operation_refs_are_bound_atomic_and_idempotent_across_processes`（177-225 行）：多 refs、同命令幂等、无效/跨目标引用原子拒绝。
- `tests/test_validate_target_mode.py:704-734`：已有 native label 不决定 gate/无需重跑；`test_candidate_admission_keeps_operation_guards`（780-802 行）：partial/unbound/tampered 仍拒绝。
- 实施后可选最小验证：用现有 tmp_path Store fixture 执行最终指导的实际 argv，断言 kind/conditions/reopen_when/operation refs 与 no-write rejection；不要只做关键词快照，也无需新 registry/全套测试。
