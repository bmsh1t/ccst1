---
description: 查看和维护目标的中性 recon observation inventory。用法：/observations <target> [--stale|--status untouched|reviewing|reviewed|parked]
allowed-tools: Bash
---

# /observations

该命令解决 recon 结果跨 session 被遗忘的问题。它只回答“发现了什么、是否审阅过、
是否长期未触达”，不判断漏洞类别、攻击价值或下一项 Skill。

先同步当前 artifact，再读取有界摘要：

```bash
python3 tools/observation_inventory.py sync --target <target>
python3 tools/observation_inventory.py summary --target <target>
```

需要查看明细时再使用有界列表：

```bash
python3 tools/observation_inventory.py list --target <target> --status untouched --limit 50
python3 tools/observation_inventory.py list --target <target> --stale --limit 50
```

Claude 审阅某项后可更新 lifecycle：

```bash
python3 tools/observation_inventory.py touch --target <target> <observation-id> \
  --status reviewed --notes "<review evidence and disposition>"
```

允许的状态只有 `untouched|reviewing|reviewed|parked`。`reviewed` 只表示看过原始
observation，不等于 `tested_clean`、dead-end、Candidate 或 Validated Finding。
具体执行动作写入 action queue，角色/对象/响应差异写入 Evidence Ledger。

禁止根据列表顺序自动选择漏洞路线，也禁止把全部 observation 无界注入上下文。
`summary` 与 `/surface` 中的 sample 只是中性、稳定、有界的回忆入口。
