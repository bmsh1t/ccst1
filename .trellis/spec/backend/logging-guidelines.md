# 日志规范

## 日志通道

项目没有统一 logging framework，当前约定按用途分三类：

1. **CLI stdout**：最终结果、JSON payload 或用户明确请求的摘要。
2. **CLI stderr**：阶段进度、降级原因、warning 和错误；例如
   `tools/vuln_scanner.sh` 的阶段进度或 `tools/evidence_ledger.py` 的降级 warning。
3. **持久 JSONL**：需要跨会话审计、查询或重放的结构化事实；例如
   `hunt-memory/audit.jsonl`、`hunt-memory/journal.jsonl`、evidence ledger。

不要把关键状态只写到控制台，也不要为了调试把每个循环项永久写入日志。

## 持久日志字段

新 JSONL 事件至少应包含：

- `schema_version`
- UTC `ts`
- 所属 `target`/`target_key` 或明确的全局作用域
- 事件/action/result 类型
- 可追溯的 source/evidence/session/finding ID（适用时）
- 错误或降级原因（适用时）

字段由 owner schema 统一生成/校验。真实范例是
`memory.schemas.make_audit_entry()` + `validate_audit_entry()`，消费者不得在各处重新定义
同一事件结构。

## 级别语义

- **progress/info**：阶段开始/结束、输入数量、输出路径、选中的确定性分支。避免在高频
  内循环逐项打印。
- **warning**：可恢复降级、损坏的单条 JSONL、可选工具缺失、best-effort 同步失败。
  warning 不得伪装成功，也不能把缺工具算作 tested-clean。
- **error**：当前命令无法履行契约，写 stderr 并返回非零。
- **debug**：仅用于临时本地排查；提交前删除，或转成有明确开关和大小边界的 artifact。

## 并发、轮换与体积

- 多写者 JSONL 使用 `fcntl.flock` 和 `O_APPEND`；检查 partial write。
- `audit.jsonl`、`journal.jsonl`、`patterns.jsonl` 使用 `memory/rotation.py`，默认 10MB、
  保留 3 份备份。
- journal 的普通追加、命令判重、GC 轮换/清理与 reset 行过滤共用
  `HuntJournal.locked()` 的稳定 sidecar 锁，不能仅锁可能被轮换的 live inode。
- 大响应、扫描器 stdout/stderr 和 raw request/response 应写目标 artifact，并在结构化日志
  中只保存路径和摘要，不能整块复制进 session JSON 或 prompt。
- 输出到 Claude 前使用项目已有的 bounded projection/output cap，不把无界日志注入上下文。

## 内容边界

应记录：

- 入口参数的非敏感形态、目标 key、分支决策、工具/phase、异常类型和 artifact 路径；
- baseline/variant、角色/对象、状态变化和证据引用；
- 被跳过/阻塞的具体原因和下一条恢复动作。

不应记录到通用日志或知识层：

- cookie、Authorization header、API key、私钥、一次性 token、密码；
- 完整个人数据或第三方响应正文；
- 仅对一个目标有效的答案、域名和攻击 payload。

目标专属敏感证据保存在目标 artifact；内部 Runner/Browser/Case/Spray 工具输出可保留
分析所需原值，不能把这些输出视为公开安全日志。目标记忆保存传入正文及 operation 引用，
不自动遮盖参数；无需重复整份请求。通用卡片/公开交付仍遵循各自发布规则。

## 示例

- `memory/audit_log.py::AuditLog.log()`：校验、锁、append 和 partial-write 检查。
- `HuntJournal.iter_entries()`：按文件顺序逐行解析/校验；完整消费后汇总坏行数量与首条位置，
  沿用按文件指纹去重的 warning。`read_all()` 是同一 reader 的 list 包装，`query()` 保持列表 API。
  Resume 完整消费该流，只保留本目标计数、最后 session 与三条 guard；不以 tail 窗口代替精确统计。
- `tools/evidence_ledger.py::record_evidence()`：记录方法、actor、object、variant、result 和
  red-line 状态。
- `tools/autopilot_bootstrap.py`：stdout 输出单行稳定 JSON，不混入进度文本。

## 常见错误

- 在 stdout 同时输出 progress 和 JSON，导致 Claude/脚本无法解析。
- 捕获异常后不记录原因，后续只能看到空状态。
- 在循环中打印每个 URL/每个 payload，拖慢扫描并淹没关键决策。
- 只保存总结、不保存 raw evidence 路径，导致 finding 无法复现。
- 把凭证或目标正文写进跨目标 patterns/knowledge。
- 将流式 reader 的部分消费当完整审阅；未读完不能宣称坏行诊断或目标统计完整。

Journal 读路径修改用合成混合目标、乱序时间戳、空文件及坏行比较新旧结果和 stderr；
Resume 的完整返回须等价，不能省略旧 guard、改变文件顺序语义或重写任何日志。

## Scenario: remember 已提交经验后的 journal 恢复

### 1. Scope / Trigger

Store.remember 成功而 journal 失败时，经验已经可召回；补日志不能再保存一份经验。
此项只修操作日志恢复，不新增记忆 owner、索引或 Store schema。

### 2. Signatures

`HuntJournal.append_once(entry: dict) -> bool`：True 为本次追加，False 为已存在。
`HuntJournal.append(entry) -> None` 保持原接口；绑定命令的 entry 使用同一判重实现。
`HuntJournal.locked()` 不可重入，锁内轮换/清理直接调用既有 rotation 原语。
`remember_finding(...) -> dict`；已提交后日志失败抛 `RememberJournalError(OSError)`，
其 `.summary` 保留结构化 partial；CLI 返回 2。

### 3. Contracts

- journal schema v1 新增成对可选 `command_id/store_id` 非空字符串，旧无绑定行仍合法。
- 判重键为 canonical target + store_id + command_id，扫描 live 与所有现存数字备份。
  内容按落盘 JSON 表示比较；ts/session_id 不参与比较，保留第一次写入的值。
- 普通 append、append_once、memory_gc 的 journal rotate/purge、reset 的 journal
  read/filter/rewrite 共用 `.journal.jsonl.lock`，sidecar 不存收据或记忆。
- 成功写入先 fsync；短写只撤回本次产生的不完整尾部。完整写入后报错保留整行，
  重试验证并同步已有行，不再追加。读日志原有 warning/跳过坏行行为不变。
- `journal_saved` 为本次追加，`journal_replayed` 为已经存在，`journal_status` 为
  appended/already_present/unconfirmed；partial 保留 experience_saved、原 store_receipt、
  command_id/store_id 与 recovery。无显式 command ID 时也必须返回生成的 ID。
- 恢复使用原解析后输入和同 ID；from-validate 要保留相同源或显式传原字段，不重跑网络。
  没有 notes/technique/refs 的日志追加保持原准入，不能传经验条件或 command ID。

### 4. Validation & Error Matrix

| 情况 | 行为 |
|---|---|
| 同 ID、同内容的完整绑定行 | already_present；Store revision 与旧行字节不变 |
| Store 已提交、没有绑定行 | 补写；Store receipt 为 replay，不重复经验 |
| 同绑定 severity/tags/正文等改变 | JournalConflictError；partial，原经验及日志保留 |
| 保留日志有坏编码/JSON/schema/残尾或重复绑定 | JournalIntegrityError；不猜补齐，不改坏字节 |
| 写入/同步失败 | unconfirmed partial、原收据和重试 ID；CLI JSON 无 traceback |
| 旧无绑定行或绑定已被显式清理 | 不猜归属；首次补绑定附 journal_recovery_note |

### 5. Good / Base / Bad Cases

Good：首次日志故障后同 ID 重试补齐一条，经验 revision 不变。
Base：普通正常重放不追加日志。Bad：看到 Store replay 就跳过日志，或把日志失败说成经验未保存。

### 6. Tests Required

本任务 research/remember-journal-check-20261021.py 在固定提交临时源码副本叠加明确改动，
覆盖真实 Store/CLI、故障补写、短写、完整写后报错/fsync、JSON 往返、轮换/清理、
同命令多进程、旧 schema/损坏、跨目标/Store 与 journal-only 内容冲突。
仅执行 reset 的合成 journal block，不执行真实 reset 或项目 tests/。

### 7. Wrong vs Correct

`if not receipt['replayed']: journal.append(entry)` → 提交后不论 replay 都调用
`journal.append_once`，携带同一 Store/command 绑定；失败保留已提交收据。

## Scenario: 外部认证工具 emitted-event JSONL

### 1. Scope / Trigger

当 shell command 调用 TREVORspray 等外部认证工具，而上游只提供文本/混合 stdout 时，不能用
`tee *.jsonl` 把原始文本伪装成结构化逐 attempt 日志。必须由单一 adapter 转成 emitted-event
JSONL，并明确它与项目 built-in HTTP/OAuth 的逐请求日志粒度不同。

### 2. Signatures

```text
python3 tools/_spray_trevor.py

required env:
  AUDIT_LOG
  SPRAY_MODE=o365|okta
  SPRAY_TREVOR_BIN
  SPRAY_TARGET_URL
  SPRAY_USERS_FILE
  SPRAY_PASSES_FILE
  SPRAY_DELAY
  SPRAY_JITTER
optional env:
  SPRAY_CONTINUE_ON_HIT=true|false
```

### 3. Contracts

- adapter 使用 `subprocess.Popen` 合并 stdout/stderr、逐行转发内部原始输出，并返回外部工具原退出码。
- 每条上游 emitted line 对应一个完整 JSON object，稳定字段为：`schema_version=1`、UTC `ts`、
  `mode`、`tool=trevorspray`、`event`、`user`、`classification`、`credential_valid`、
  `token_issued`、`aadsts_code`、`pwd_sha256_prefix`、`raw`。
- AADSTS code 优先于文本关键词；只有响应 JSON 顶层 `access_token` key 才能设置
  `token_issued=true`。claims 片段或 raw substring 不算 token。
- 内部 console 与 JSONL `raw` 保留 emitted line 的原值（仅去行尾换行）；JSONL 文件0600、
  运行目录0700。密码关联仍使用短 hash/attempt key，不以原文替换身份键。通用错误 stderr
  的已有遮盖规则不变，这些内部原始证据不能自动进入跨目标知识或公开交付。
- 未识别行必须记录 `classification=unknown`，不能丢行或伪装成功。

### 4. Validation & Error Matrix

| 条件 | 正确行为 |
|---|---|
| 缺 required env / mode 非 o365/okta | stderr + exit `2`，不启动工具 |
| 外部工具启动失败 | 写 `tool_error` JSONL，stderr，exit `127` |
| 外部工具输出未识别文本 | 写 `attempt_result/unknown`，继续消费 |
| 外部工具非零退出 | 保留已写事件，再写 `process_exit`，返回同一 exit code |
| claims 中出现 `access_token` | `token_issued=false` |

### 5. Good / Base / Bad Cases

- Good：AADSTS50076 输出变成 `valid_password_mfa`，内部 console 与 JSONL raw 一致且原值可核验。
- Base：heartbeat/未知错误仍写一条 unknown emitted event，供后续 AI 复核。
- Bad：`trevorspray ... | tee attempts.jsonl` 产生不可解析混合文本，或 raw claims 字符串误判 token。

### 6. Tests Required

- `tests/test_spray_orchestrator.py`：离线假进程的合法 JSONL、原值 stdout/落盘、hash/binding、
  0600/0700 和跨目标 OAuth redirect 拒绝；不使用真实凭据调用。
- AADSTS/Okta 分类表；顶层 token、嵌套 claims、plain text token 三类边界。
- shell structural test：O365/Okta 只通过 adapter，禁止重新出现 `tee -a "$AUDIT_LOG"`。

### 7. Wrong vs Correct

#### Wrong

```bash
trevorspray ... 2>&1 | tee -a "$AUDIT_LOG"
```

#### Correct

```bash
export SPRAY_MODE="$MODE"
export SPRAY_TREVOR_BIN="$(command -v trevorspray)"
python3 "$SCRIPT_DIR/_spray_trevor.py"
```
