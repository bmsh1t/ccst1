---
description: 查看和维护目标的中性 recon observation inventory。用法：/observations <target> [--stale|--status untouched|reviewing|reviewed|parked]
allowed-tools: Bash
---

# /observations

该命令解决 recon 结果跨 session 被遗忘的问题。它只回答“发现了什么、是否审阅过、
是否长期未触达”，不判断漏洞类别、攻击价值或下一项 Skill。

`summary` 只读取小型 `state/<target>/observations-summary.json` 及相关文件 stat，不解析
大型 `observations.json` 正文。首次使用、source/body 变化、sidecar 损坏或绑定不匹配时会返回
`missing|stale|invalid`/`needs_sync`；这不等于零 observation。此时显式同步一次，再读取摘要：

```bash
python3 tools/observation_inventory.py sync --target <target>
python3 tools/observation_inventory.py summary --target <target>
```

需要查看少量兼容明细时可使用有界列表：

```bash
python3 tools/observation_inventory.py list --target <target> --status untouched --limit 50
python3 tools/observation_inventory.py list --target <target> --stale --limit 50
```

需要稳定遍历长尾时使用 `page`。把上一页的 `next_cursor` 原样传入下一页；同一 snapshot
每个匹配 ID 恰好可达，inventory revision 变化后旧 cursor 会 fail-fast，必须从新快照开始：

```bash
python3 tools/observation_inventory.py page --target <target> --status untouched --limit 50
python3 tools/observation_inventory.py page --target <target> --kind url --source param \
  --limit 50 --cursor <next-cursor>
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
`summary`、`list`、`page` 和 `/surface` 中的首屏都只是中性、有界的注意力入口；
`remaining`/overflow 仍是未审阅攻击面。只有显式 `touch` 才能改变 lifecycle。
