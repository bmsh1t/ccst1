# Evidence Runners

这些工具是可选的证据执行平面，不是 `/autopilot` 或 `/validate` 的主脑。

## 原则

- Claude 负责选择 hypothesis、攻击面、链路方向、影响判断和报告价值。
- 工具只负责稳定 replay、diff、raw evidence、ledger 和可复现输出。
- runner 输出是证据，不是最终结论；是否继续、降级、链式扩展或报告仍由 Claude 判断。
- 不要为了清队列而运行 runner；只在它能减少漂移、补足证据或复现复杂步骤时使用。
- MCP/browser/source/JS 观察帮助 Claude 选择真实实验；已有完整执行材料可直接登记，不为接入状态而重复请求。

## Native Evidence Registration

已通过浏览器、probe、curl、raw sender 等执行的实验，先按 `/hunt` 契约保存
canonical Candidate，再登记已存在的原始材料。该入口不执行命令、不发请求、不造 diff；
多步、不同方法、多字段身份上下文、multipart/binary 都不必改写为请求对。

`--evidence-json` 使用现有 schema-v1 summary 的观察字段：

```json
{
  "schema_version": 1,
  "source": "browser",
  "generated_at": "2026-09-16T10:00:00Z",
  "result": "tested_finding",
  "observed_difference": "Control and repeated test-owned transition produced the recorded state difference.",
  "runs": [
    {
      "url": "https://TARGET/api/orders/1",
      "method": "GET",
      "actor": "owner",
      "artifacts": {
        "request": ".private/validation/TARGET/control.request.txt",
        "response": ".private/validation/TARGET/control.response.txt"
      }
    },
    {
      "url": "https://TARGET/api/orders/1",
      "method": "POST",
      "actor": "peer",
      "object_scope": "other_object_same_org",
      "variant": "replay",
      "artifacts": {
        "request": ".private/validation/TARGET/transition.request.bin",
        "response": ".private/validation/TARGET/transition.response.bin"
      }
    }
  ]
}
```

```bash
python3 tools/validation_runner.py record-evidence --target TARGET \
  --finding-id FINDING_ID --evidence-json /tmp/native-observations.json \
  --state-changing --redline-checked --json
```

- `generated_at` 写原实验时间，必须含时区；`source` 写实际采集工具。
- URL、方法、类别从指定 Finding 读取；`runs` 必须含其精确 endpoint/method 对应的
  执行步骤。多步实验仍选一个 Finding 锚点，其余输入/状态读回/OOB 记录留在同一材料中。
- 每步 `artifacts.request/response` 指向已有、非空、同目标的原始文件；可附加
  `screenshot`、`callback`、`trace` 等引用。登记只保留引用和 SHA-256，不复制原始材料。
  若 probe JSON 已同时包含 request/response，两项可引用同一个原文件；使用采集返回的
  真实路径，不照抄示例路径或另拆文件。
- `actor` 使用 Ledger 现有角色词汇（如 anonymous/owner/peer/low_role/admin/cross_tenant）；
  锚点步骤必须明确角色。`object_scope`、`variant` 可省略，默认 unknown/replay；
  具体账号、会话和业务条件保留在原始证据，不在摘要中写凭据。
- `result` 是 **AI 对已执行材料的判断**：tested_finding/candidate/tested_clean/dead_end/partial。
  输出固定标注 `assessment_source=ai`、`lane=native_evidence`，不伪装成自动语义判定。
  `tested_finding` 只产生可交给 `/validate` 的 Candidate，七问、四 gate 和报告标准保持不变。
- 已知缺失响应、截断或执行错误必须是 `partial`：保存已获得材料，退出 1，不升级 Finding。
  完整实验至少保留输入/输出，不把截图或假设文字单独当执行证明。
- 发生过状态改变时使用 `--state-changing --redline-checked`，只读实验可用
  `--no-state-changing`；这些记录不追认或扩大原实验的执行许可。
- 同一材料重复登记复用 operation/path；Ledger → Finding → Queue 同步失败时
  返回非零并保留 `sync.status=partial`，修复原因后重跑登记即可，不重发请求。
  版本化 Queue 仍需预先 claim，登记只写观察，继续/停止仍由 Claude resolve。

登记成功后按 `/validate` 的 scaffold → 判断 → preflight → apply 流程继续。
现有 `replayed` 字段表示材料来自已执行实验；此命令本身只做登记，来源由
`native-evidence:<source>` 明确区分。无需修改 witness、报告 schema 或另立生命周期。

## 常用 runner

### Request diff (shared evidence primitive)

Claude chooses the exact baseline/variant pair and one active input dimension;
the runner only validates scope/auth facts, replays both requests, stores raw
evidence privately, and writes the existing Ledger/Finding/Queue projections.
`classifier` is a signal label, not a fixed input generator. Query, form, JSON,
XML/text, header/cookie, and path pairs can use the same contract. Unsupported
multipart, compressed, protobuf, and gRPC wire bodies return `manual_required`
without being marked clean. Use a canonical `vuln_class` when the pair must
close a Ledger family; an unclassified pair remains reviewable evidence.

```json
{
  "schema_version": 1,
  "baseline_request": {
    "method": "POST",
    "url": "https://TARGET/api/search",
    "headers": {"Content-Type": "application/json"},
    "body": {"filter": {"name": "SAMPLE"}}
  },
  "variant_request": {
    "method": "POST",
    "url": "https://TARGET/api/search",
    "headers": {"Content-Type": "application/json"},
    "body": {"filter": {"name": "PAYLOAD"}}
  },
  "active_dimension": "body:/filter/name",
  "evidence_shape": "request_diff",
  "classifier": "sqli",
  "expected_signal": "CHECK_FN",
  "repeat": 2
}
```

```bash
python3 tools/validation_runner.py request-diff \
  --target TARGET --request-spec REQUEST_SPEC.json --repeat 2
```

Request specs must preserve the observed wire shape. Encode query/path/form
values structurally (for example with the request builder or `urlencode`), keep
JSON as JSON, and never paste a manually double-encoded value into a second
layer. The runner records the exact pair; it does not rewrite malformed input
or infer a vulnerability from an encoding-only response change.

Only explicit `expected` assertions are mechanically checked. A confirmed
`declaration_intent=hazard` becomes `tested_finding` (a candidate, not a final
finding); a confirmed `clean` declaration becomes `tested_clean`. Undeclared or
unmet expectations remain `candidate`, including equal responses. Claude judges
business meaning through the existing seven-question/four-gate validation.
Each successful response is saved immediately; a later transport failure keeps
those artifacts and returns `partial`, never clean or report-ready.


### Request smuggling capability gate

`sender_semantics.py --require ...` reports whether a local sender can preserve
the required byte-exact and connection-reuse semantics; the AI builds the raw
probe from the observed wire shape. An unsupported sender capability is a
handoff, not evidence of a vulnerability.

## 相关状态工具

### Target case state

只在 actor/session/object/private marker 连续性有价值时使用。`case_state_seed` 只读对象线索，
不代选身份、标记私有数据、生成测试路线或登记命令。

```bash
python3 tools/target_case_state.py summary --target <target> --json
python3 tools/target_case_state.py next --target <target>
python3 tools/case_state_seed.py --target <target> --json
```

### Evidence ledger

用于查看已记录证据，避免重复验证同一个已经关闭的事实。它是记忆，不是攻击面过滤器。

```bash
python3 tools/evidence_ledger.py summary --target <target>
```

### Checkpoint / action queue

用于长会话收束、恢复、交接。它们给 Claude 提示，不替 Claude 排优先级。

```bash
python3 tools/checkpoint.py --target <target>
python3 tools/action_queue.py ingest-checkpoint --target <target>
python3 tools/action_queue.py next --target <target>
```

如果 queue 建议和当前 browser/source/recon 证据冲突，Claude 可以跳过、重排、覆盖，前提是写清理由和下一条证据动作。
