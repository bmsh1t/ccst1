# Evidence Runners

这些工具是可选的证据执行平面，不是 `/autopilot` 或 `/validate` 的主脑。

## 原则

- Claude 负责选择 hypothesis、攻击面、链路方向、影响判断和报告价值。
- 工具只负责稳定 replay、diff、raw evidence、ledger 和可复现输出。
- runner 输出是证据，不是最终结论；是否继续、降级、链式扩展或报告仍由 Claude 判断。
- 不要为了清队列而运行 runner；只在它能减少漂移、补足证据或复现复杂步骤时使用。
- MCP/browser/source/JS 观察可以先帮 Claude 找真实请求形态，再交给 runner 做重复验证。

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

Promotion is fact-based: a stable material diff promotes to `tested_finding`
when the SQLi probe-shape detector confirms the diff form, or when the declared
active dimension is a credential boundary (e.g. `header:authorization`) that
the two requests actually differ in. Whether a boundary diff is a real
authorization violation stays with the 7-Question/4-gate AI review.


### Request smuggling capability gate

`sender_semantics.py --require ...` reports whether a local sender can preserve
the required byte-exact and connection-reuse semantics; the AI builds the raw
probe from the observed wire shape. An unsupported sender capability is a
handoff, not evidence of a vulnerability.

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
