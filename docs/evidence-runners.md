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

```bash
python3 tools/validation_runner.py authz-public-exposure \
  --target <target> \
  --url <exact-url> \
  --browser-observed
```

### SQLi / NoSQLi result diff

用于只读 baseline vs 单变量 perturbation。不要把 quote-only shrinkage 当发现；需要稳定 DB/parser/boolean/union/result-expansion 等强信号。

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
