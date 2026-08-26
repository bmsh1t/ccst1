# Evidence Runners

这些工具是可选的证据执行平面，不是 `/autopilot` 或 `/validate` 的主脑。

## 原则

- Claude 负责选择 hypothesis、攻击面、链路方向、影响判断和报告价值。
- 工具只负责稳定 replay、diff、raw evidence、ledger 和可复现输出。
- runner 输出是证据，不是最终结论；是否继续、降级、链式扩展或报告仍由 Claude 判断。
- 不要为了清队列而运行 runner；只在它能减少漂移、补足证据或复现复杂步骤时使用。
- MCP/browser/source/JS 观察可以先帮 Claude 找真实请求形态，再交给 runner 做重复验证。

## 常用 runner

### Anonymous exposure

用于匿名访问 admin/config/account/API 暴露的最小证明。只有 body-backed 敏感/配置/密钥形态才应升级。
该 lane 的 `tested_clean` 只表示没有观察到公开暴露证据，不代表受保护资源的匿名
Authz 已验证；匿名请求写入 Ledger 时使用 `baseline`，不使用 `unauth_denied`。

```bash
python3 tools/validation_runner.py authz-public-exposure \
  --target <target> \
  --url <exact-url> \
  --browser-observed
```

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

### SQLi / NoSQLi result diff

旧命令仍保留，作为 `request-diff` 的 SQLi 兼容 wrapper。不要把 quote-only
shrinkage 当发现；需要稳定 DB/parser/boolean/union/result-expansion 等强信号。

```bash
python3 tools/validation_runner.py sqli-result-diff \
  --target <target> \
  --url '<exact-url-with-param>' \
  --param <name> \
  --baseline-value '<baseline>' \
  --variant-value '<controlled-perturbation>' \
  --repeat 2 \
  --browser-observed
```

### IDOR / Authz actor pair

用于 owner/peer 两个上下文可复现时的对象访问验证。case state 可以降低手工拼 header 的漂移，但不是前置门槛。

```bash
python3 tools/validation_runner.py idor-actor-pair \
  --target <target> \
  --from-case-state \
  --object-ref <object_ref> \
  --repeat 2 \
  --browser-observed
```

或显式传入请求上下文：

```bash
python3 tools/validation_runner.py idor-actor-pair \
  --target <target> \
  --url '<same-object-url>' \
  --owner-header 'Authorization: Bearer <owner-token>' \
  --peer-header 'Authorization: Bearer <peer-token>' \
  --expect-marker '<owner-private-marker>' \
  --repeat 2 \
  --browser-observed
```

### Marker replay

用于 RCE/SSTI/template/command-injection 等需要惰性 marker 的安全证明。marker 必须是低影响、可解释、可重复的 inert 输出。

```bash
python3 tools/validation_runner.py marker-replay \
  --target <target> \
  --url '<exact-url>' \
  --expect-marker '<inert-marker>' \
  --vuln-class RCE \
  --repeat 2 \
  --browser-observed
```

For a stronger marker claim, add a target-owned neutral control. The runner
records baseline absence and rejects weak or naturally present markers without
turning the observation into `tested_clean`:

```bash
python3 tools/validation_runner.py marker-replay \
  --target <target> \
  --baseline-url '<neutral-control-url>' \
  --url '<marker-request-url>' \
  --expect-marker '<unique-inert-marker>' \
  --vuln-class RCE
```

The neutral control must finish with a successful, non-truncated response. An
error or truncated control keeps the replay as a `candidate` signal so it
cannot become either `tested_finding` or `tested_clean`.

### Workflow sequence

Use only an imported HAR/browser Network artifact with at least two ordered,
same-target business requests. The runner performs one remove/repeat perturbation,
refreshes declared short-lived tokens, keeps raw traffic private, and writes a
bounded result to the Action Queue.

```bash
python3 tools/workflow_sequence.py \
  --target <target> \
  --evidence-ref evidence/<target>/browser/<capture>/requests.json
```

The workflow runner records raw traffic, budgets, and response differences; a
response difference remains a candidate until AI reviews impact and replayability.

A step-level `token` declares exactly one source: `regex` (body capture group),
`response_header`, `cookie` (`Set-Cookie` name), or a bounded dotted `json_path`.
Send the extracted value through `header` or a body `placeholder`; token source
URLs and redirects remain target-scoped. Example:

```json
{
  "token": {
    "url": "https://api.TARGET/session/refresh",
    "json_path": "$.data.csrf",
    "header": "X-CSRF-Token"
  }
}
```

### Timing SQL

Use after a time-shaped SQL signal, never as a default sweep. Samples are
interleaved baseline/variant pairs with a lane-global request cap. Median/MAD and
WAF/429/transport classification keep a single slow response from becoming a
finding.

```bash
python3 tools/timing_sql_runner.py \
  --target <target> --url '<target-url-with-param>' \
  --param <name> --variant-value '<controlled-delay>' \
  --repeat 5 --max-requests 20
```

### Request smuggling capability gate

`smuggling_executor.py` reports whether a local sender can preserve the required
byte-exact and connection-reuse semantics. `disposition=manual_required` is the
expected result for unsupported H2/desync variants; it is not evidence of a
vulnerability.

## 相关状态工具

### Target case state

只在 actor/session/object/private marker 连续性有价值时使用。

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
