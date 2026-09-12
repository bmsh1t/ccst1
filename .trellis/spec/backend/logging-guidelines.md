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

目标专属敏感证据只能进入 gitignored 的目标 artifact，通用卡片和 target-memory 摘要使用
脱敏内容和 `evidence_ref`。

## 示例

- `memory/audit_log.py::AuditLog.log()`：校验、锁、append 和 partial-write 检查。
- `memory/hunt_journal.py::read_all()`：损坏行 warning 后继续读取其他事件。
- `tools/evidence_ledger.py::record_evidence()`：记录方法、actor、object、variant、result 和
  red-line 状态。
- `tools/autopilot_bootstrap.py`：stdout 输出单行稳定 JSON，不混入进度文本。

## 常见错误

- 在 stdout 同时输出 progress 和 JSON，导致 Claude/脚本无法解析。
- 捕获异常后不记录原因，后续只能看到空状态。
- 在循环中打印每个 URL/每个 payload，拖慢扫描并淹没关键决策。
- 只保存总结、不保存 raw evidence 路径，导致 finding 无法复现。
- 把凭证或目标正文写进跨目标 patterns/knowledge。

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

- adapter 使用 `subprocess.Popen` 合并 stdout/stderr、逐行转发脱敏输出，并返回外部工具原退出码。
- 每条上游 emitted line 对应一个完整 JSON object，稳定字段为：`schema_version=1`、UTC `ts`、
  `mode`、`tool=trevorspray`、`event`、`user`、`classification`、`credential_valid`、
  `token_issued`、`aadsts_code`、`pwd_sha256_prefix`、`raw`。
- AADSTS code 优先于文本关键词；只有响应 JSON 顶层 `access_token` key 才能设置
  `token_issued=true`。claims 片段或 raw substring 不算 token。
- passlist 明文、access/refresh/id token、Okta sessionToken、client secret 和 Bearer value 在
  console 与 JSONL `raw` 中都必须脱敏。密码只有在 emitted line 可关联 passlist 值时保存短 hash。
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

- Good：AADSTS50076 输出变成 `valid_password_mfa`，密码/token 全部脱敏，console 与 JSONL 一致。
- Base：heartbeat/未知错误仍写一条 unknown emitted event，供后续 AI 复核。
- Bad：`trevorspray ... | tee attempts.jsonl` 产生不可解析混合文本，或 raw claims 字符串误判 token。

### 6. Tests Required

- fake executable：合法 JSONL、实时脱敏 stdout、密码不落盘、退出码 0/非零。
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
