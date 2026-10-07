# 错误处理规范

## 分层策略

错误处理按“入口解析 -> 核心逻辑 -> 持久化/外部工具 -> CLI 出口”分层：

- **入口解析**：用户参数错误应在执行任何目标动作前返回稳定、可展示的错误。
  `tools/autopilot_args.py` 把未知 flag、冲突 cadence 和无效 auth file 转为结构化
  `errors`，`autopilot_bootstrap` 据此停止。
- **核心逻辑**：可被其他模块调用的函数使用 `ValueError` 或领域异常表达非法状态，不能
  `print()` 后继续。`RuntimePhaseBusy` 是目标 phase 锁冲突的领域异常范例。
- **验证边界**：`tools/validate.py` 只接受显式 `--decision-json`；缺失判断不能以默认肯定
  gate 代替。scaffold/preflight 只读现有 Store，全部 binding 通过前不得发布报告或提交裁决；
  普通验证永不隐式初始化/迁移 legacy payload。
- **持久化**：写入失败必须清理临时文件并继续向上抛出，不能返回成功。原子 writer 在
  `except` 中只做清理，不吞掉原始异常。
- **CLI 出口**：`main(argv)` 捕获预期的 `KeyError`/`ValueError`，错误写 stderr，返回稳定
  非零码；`if __name__ == "__main__"` 使用 `raise SystemExit(main())`。

## 可恢复错误

以下情况允许就近降级，但必须符合数据含义：

- 可选 recon/browser/source artifact 不存在：返回空投影或 unavailable，交给状态层决定
  下一步，不能把缺失当作 tested-clean。
- Context Pack 本地 JSON 读取健康见下方“本地 intel 材料诊断”；坏材料不能折叠为成功空结果。
- bootstrap 发现 inventory summary 或 surface projection missing/stale/invalid：返回结构化
  `needs_sync`/`prepare_surface_context`，保持零 target-write，不能为“兜底”加载大型 body 或
  执行 ranking。recon 成功后的 surface finalizer 是明确的 best-effort 派生；失败必须保留 raw
  recon、输出 warning，并让后续显式 refresh 恢复。
- bootstrap 读取损坏的 canonical state 时返回 `stop_state_error` 和有界错误类型/原因；不得
  输出 traceback、覆盖损坏文件或继续目标动作。已有历史 probe summary 读取失败必须保持 partial，不能伪装为空。
- bootstrap 的 runtime compare 遇到 `OSError`/`ValueError` 时返回 `stop_runtime_error`；参数
  gate 仍优先，错误不得触发 target state 读取或自动 runtime sync。
- 可选 `distill/corpus/` 缺失时，case resolver 返回结构化 `unavailable`，普通
  `/kb`/知识路由继续；启用来源解析后发现 stale/invalid corpus、坏 offset/hash 或 dangling
  ref 时必须返回不可用结果，不能返回部分 payload 或伪可信摘要。
- append-only 日志单行损坏：跳过该行并在 stderr 输出文件/行号 warning。
- 非主链 telemetry 或 session summary 失败：保留主结果，输出 warning 或
  明确诊断。领域登记失败必须返回可重试的 partial/error，不能假装 Queue 同步成功。`HuntJournal.log_session_summary()` 是 best-effort 范例。
- capability profile 探测失败：返回 advisory unknown profile，不能阻断 target state；
  runtime drift 和参数错误仍是 blocking gate。
- subprocess cleanup 的 `communicate()`、process-group lookup、SIGTERM 或 SIGKILL
  异常必须保留 bounded stderr 诊断并返回失败语义；不得把空 stdout/stderr 当作
  `finished=true`，也不得静默跳过强制终止路径。

## 不可恢复错误

- 无效 target、非法状态迁移、缺少必需文件、schema owner 无法写入、知识 registry 不可
  解析等错误必须 fail-fast。
- 显式 Surface/index refresh 遇到 external sort 失败、坏 index 行、输入构建 race 或 manifest
  不匹配必须 fail-fast 且不得发布新 manifest/projection；不能退回首 N URL、stale cache 或
  materialized 全量 set 来伪装成功。
- `validate.py` 的 non-TTY 无 `--decision-json`、decision target/finding/endpoint/vuln class
  不绑定、四 gate/Q1-Q7/impact/evidence/report 任一缺失或 evidence ref 不可定位，均是写入前
  的参数/契约错误：stderr 输出恢复动作、返回 `2`，且不得创建 report、summary、ledger、queue、
  runtime 或 canonical finding mutation。
  `decision.cvss` 是可选的外部交付字段；缺失不得制造错误或默认分值。
- Action Queue 的普通入口必须通过 Store 准入。未初始化、legacy、preview、坏库或 fence
  冲突均 fail-fast；只有已初始化且没有行动的 Store 才表示空队列。
- 不允许 broad `except Exception: pass`。只有明确标注的 best-effort 派生、清理或日志
  路径可捕获 broad exception，并且必须保留可诊断结果。
- 当前 Store 或证据损坏不能伪装为空状态。显式历史 reader 的诊断不提供运行时 fallback。
- 正式卡 governance log 有坏 JSON、重复 `event_id` 或非法 replay 时，audit 和后续 append
  都必须 fail-fast；诊断包含行号/card/event。修复使用新的补偿事件，不静默跳过后继续改写
  lifecycle。

## CLI 约定

- stdout 用于机器可消费结果或最终摘要；stderr 用于 progress、warning 和错误。
- 成功返回 `0`；没有可执行对象但不是数据损坏时可返回 `1`；参数/状态契约错误通常返回
  `2`。具体工具必须在测试中固定自己的语义，不能让调用方靠字符串猜测。
- 支持 `--json` 的 CLI 应保持字段稳定，错误同样结构化；Claude-facing bootstrap 尤其不能
  输出半结构化混合文本。
- `autopilot_state.py --projection-only` 只允许缩小 loop-check/closure 的序列化结果，必须保留
  schema、目标身份和命令消费者实际读取的完整字段；不带该参数的 full JSON/text 诊断入口
  必须继续可用，canonical state 损坏仍返回结构化 error，不能因投影缩小而变成空结果。
- `python3 tools/validate.py --target <target> --finding-id <id> --decision-json <file> --json`
  是唯一 non-TTY validation signature。decision 先完整验证，再经既有
  Store assessment/delivery/report 命令写回；不得接受 stdin EOF、自然语言确认或直接 `findings.json` edit
  作为替代输入。
- `python3 tools/action_queue.py ...` 遇到 queue read/write 的 `OSError`/`ValueError` 时写 stderr
  并返回 `2`；不得把损坏 queue 当作没有 action 后继续 checkpoint 或 handoff。
- `target_case_state.py` 与 `coverage_matrix.py` 只从 Store 派生当前事实；可重建缓存缺失可重算，
  Store 或必需私有材料损坏则显式失败。checkpoint 不得吞掉故障后伪造空 Case/已闭合覆盖。
- `surface.py`、`surface_index.py` 和 `observation_inventory.py` 的 schema/cursor/race/owner
  错误写 stderr 并返回 `2`。page cursor 的 target/revision/filter 不一致是明确错误，调用方从
  新 snapshot 重启，不能猜 offset 后继续。
- case resolver 的 `available|unavailable|stale|invalid|ok|not-found` 是机器契约；调用方按
  `status` 分支，不匹配 `reason` 文本。完整案例只允许显式单 ID `--full`，失败结果的
  `payload` 保持为空。
- 错误消息必须包含失败对象和可执行恢复动作，例如目标、candidate ID、文件路径或允许的
 状态集合；不要只输出 `failed`。
- Evidence runner 在任何网络 I/O 或 Action Queue 写入前必须校验绝对 HTTP(S) URL 属于当前
  canonical target；请求 cap 只限制采样量，若已完成所需样本，恰好耗尽 cap 仍按该 lane 的
  `tested`/`complete_no_hit` 或 `candidate` 语义收束，不能误降级为 `partial`。

## 直接执行与导入

项目工具既会作为 package 导入，也会直接执行。跨 `tools` 导入按现有模式处理：

```python
try:
    from tools.target_paths import target_storage_key
except ImportError:  # 兼容 python3 tools/example.py
    from target_paths import target_storage_key
```

只捕获 `ImportError`/`ModuleNotFoundError`，不能用 broad exception 隐藏模块自身初始化错误。

## 测试矩阵

- 合法输入 -> 预期输出和退出码。
- 缺参数/未知参数/非法状态 -> 无副作用、非零退出码、可操作错误。
- 缺失可选 artifact -> advisory/empty，不误报完成。
- JSON 损坏/半写 -> reader 行为明确，旧可读状态不被破坏。
- 写入中断 -> 临时文件被清理，原文件仍可读。
- best-effort 同步失败 -> 主结果保留且 warning/status 可见。
- non-TTY validate 缺/坏 decision -> exit `2`、所有 target-owned state 保持未创建或字节不变。
- legacy-only finding 的 machine binding -> exit `2`；旧 payload 不迁移，报告和领域事实不创建。
- Store/fence/schema 损坏 -> owner 抛恢复错误、CLI exit `2`；事务失败 -> 元数据和 audit 全回滚。
- Case 私有材料/已登记证据损坏 -> 当前授权失败；原始历史保留。可重建 Coverage 文件不是 owner。
- 报告发布失败 -> 无部分正文；裁决或报告登记中断 -> 正文及已提交收据保留，原命令可幂等重试。
- Surface/inventory 派生：missing/stale/corrupt summary/projection -> 不消费；atomic failure/race ->
  旧字节保留或无新 manifest；cursor snapshot 变化 -> fail-fast；recon finalizer failure -> raw
  artifact 保留且可由显式 refresh 重建。

## 本地 intel 材料诊断

### 1. Scope / Trigger

Context Pack 读取 browser forms/page_js_map/summary、JS hypotheses 和 source routes JSON。

### 2. Signatures

`build_context_pack(...)["source_summary"]` 输出 `local_intel_status`、
`local_intel_invalid_count`、`local_intel_diagnostics`（path/status/error）。

### 3. Contracts

每个源区分 missing/ok/invalid/unreadable。合法空对象、空集合为 ok；缺失字段保留
可选语义，已提供集合必须符合对象/对象列表类型。坏源进入 JSON 与文本 unknowns，
读取不改变源文件或 Store revision。

### 4. Validation & Error Matrix

- FileNotFoundError → missing；其余 OSError（包括目录占位）→ unreadable。
- 坏 UTF-8/JSON、非对象根或错误集合形态 → invalid，保留路径与原因。
- 有坏源且有好源 → partial；只有坏/缺源 → unavailable；有好源且无坏源 → ready。
- 全部缺失 → unavailable 且错误计数为零，保持可选材料兼容行为。

### 5. Good/Base/Bad Cases

Good：空 routes 为 ready、0 条；损坏 routes 为 unavailable、显式错误。
Base：尚未收集的源是 missing。Bad：解析异常静默返回 `{}` 并显示成功零结果。

### 6. Tests Required

`tests/test_context_pack.py` 验证缺失/合法空、坏编码/JSON/集合结构、读取错误、
JSON/text 展示路径及 Store binding 不变；与 Finding focused tests 同批验证。

### 7. Wrong vs Correct

`except error: return {}` → 返回空数据并附明确源健康，汇总保留错误与 unknowns。

## 披露查询失败与成功缓存保全

### 1. Scope / Trigger

`disclosure_search` 的 provider 查询、成功 cache 和 Markdown 输出；独立于 Intel/Store。

### 2. Signatures

`write_disclosed_patterns(target, repo_root=None, *, output_path=None, cache_ttl_hours=72,
no_mcp=False) -> Path`；两个查询 helper 返回 `QueryResult(reports, successes, errors)`。
provider `search_disclosed_reports(...) -> list[dict]` 不变，坏 search 结构抛 `HackerOneAPIError`。

### 3. Contracts

cache 只保留 `target/same/similar/coverage_status/cached_at_ts`。仅所有实际请求完整成功
才保存，包括合法零结果；没有计划的 similar 请求不算失败。任何请求失败均不改旧 cache
bytes/mtime/时间，program 失败后 keyword 成功仍为 partial。partial 有新报告只展示新材料，
无新报告或全部失败可展示一份有效旧快照，不混合。no-mcp 完全跳过 cache/client/inventory。
Markdown 分开显示 query status、material source/query time/stale 与 coverage；Generated at
只是文档生成时间。直接调用 renderer 未传查询事实时不推断 complete 或成功零结果。
cache/Markdown 复用 `write_text_atomic`，独立原子发布；写失败上抛且 CLI 不打印成功路径。

### 4. Validation & Error Matrix

- fresh 成功 cache → cached，不查询／刷新时间；完整成功空列表 → complete/no_mcp_coverage。
- 部分请求失败 → partial；无成功请求或 client 缺失 → unavailable。诊断包含请求标识、
  错误类型及单行原因，每条最多 500 字符；错误状态不另行持久化。
- 缺失／错误 provider envelope、非列表 nodes 或坏条目 → 请求失败。report/team 只允许
  缺失、null、对象，`[]/false/0/""` 不能当缺失；合法无 report 节点和可选字符串继续兼容。
- cache 编码／JSON／结构／目标／时间错误 → 可见诊断，不当健康旧材料；上游同时失败
  保留原字节。仅缺少 coverage_status 的历史 cache 按桶推导；已提供字段只接受 covered /
  no_mcp_coverage，mcp_unavailable、partial 或错误类型均不算完整成功快照。
- TTL 或 cache 时间非有限 → 拒绝；时间 0／数字字符串保持 cache 兼容，有限 TTL≤0
  强制刷新。历史错误写成成功空结果的材料不推测恢复，不新增迁移。
- 单文件 publication 失败 → 保留对应旧完整文件；Markdown 失败不回滚已写成功 cache，
  不宣称跨文件事务。正常生成 unavailable 文档仍返回 CLI 0，不等同于上游查询成功。

### 5. Good/Base/Bad Cases

Good：上游全失败仍显示旧报告及原时间／过期说明。Base：全部成功且零报告可替换旧快照。
Bad：把异常转成空列表，再写新时间；或把坏类型的假值当作无 report。

### 6. Tests Required

`tests/test_disclosed_pattern_dedup.py` 验证 total/partial 有无旧 cache、fallback 恢复、
完整成功零结果、TTL hit/强制刷新、no-mcp、不合法 TTL/响应/cache、真实 provider→owner
接线及 publication failure；断言旧 bytes/mtime/时间、报告归属、诊断和 CLI 不伪报成功。
mock 查询传输而非整个 owner；保留表顺序、recall 命令及 Store binding 不变。

### 7. Wrong vs Correct

`except Exception: return []` → 保留成功数与有界诊断，仅 complete 允许发布成功 cache；
`report or {}` → 在真假值判断前验证对象／null 类型。
