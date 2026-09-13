---
description: 从当前目标的原始证据直接写知识卡草稿（target-scoped 直写流程）。用法：/distill <target>
---

# /distill

从**当前目标**的原始证据（Evidence Ledger / Findings / Case State）蒸馏可复用知识。
这是 target-scoped 直写流程：机器出有界证据视图 → **AI 直接写完整草稿卡** → 人工审核晋升。

> 原生能力审计（2026-09-13）：旧"出题→三元组→渲染"中转已退役——三元组协议
> （pattern/trigger/action）无法保留独立的前提/反例/停止条件（实测），强制 Claude
> 在写 Markdown 前先写一遍 JSON 只是格式中转。机械保护（脱敏红线、target-owned
> refs）已迁入 knowledge_audit 的正式审计边界，在晋升门检查。

与相邻命令的分工：

| 命令 | 作用域 | 问题 |
|---|---|---|
| `/distill` | target-scoped | 当前目标打完了，什么经验值得沉淀成卡？ |
| `/intel` · `disclosed-researcher` | target-scoped 横向 | 别人在同类目标上什么模式拿过赏？ |
| `/retrospect` | session-scoped | 本轮会话的分流决策（lead/next/dead-end 写回 + 沉淀建议） |

## 流程（AI 直写，机器只出证据视图）

> 谁思考：草稿卡的全部内容（触发信号、前提、验证路径、反例、停止条件）是
> **AI 判断**——机器只拉证据、出有界视图，以及在晋升门做脱敏/可溯源校验。

```text
① AI 运行证据视图（机器拉证据，出有界视图）：
   python3 tools/distill_target.py evidence --target <target> --json

② AI 读 view，按 knowledge/card-template.md 直接写完整草稿卡：
   knowledge/candidates/<slug>.md（frontmatter maturity: draft）
   —— source_refs 用 target-evidence 契约：
      {type: target-evidence, target: <target>, refs: [<视图里的真实路径>]}
   —— 正文包含完整判断单元：触发信号 / 前提条件 / 最小验证 /
      反例与误判边界 / 停止条件；不写裸 IP 和凭据形态文本

③ 人工审核通过后晋升（机器登记 + strict audit）：
   python3 tools/knowledge_promote.py --id <slug>
```

## 机器 gate（晋升时 strict audit 强制）

- **脱敏红线**（`knowledge_audit._audit_card_scrub`）：卡正文判断段含裸公网
  IPv4 或 credential 形态文本 → 硬错误（保留地址/占位符/权限声明语法豁免；
  evidence 路径行不在判断正文范围）
- **可溯源**（`knowledge_audit._audit_target_evidence_refs`）：`source_refs` 的
  refs 必须指向声明 target 名下（`evidence/<target>/`、`findings/<target>/`、
  `state/<target>/` 前缀）且磁盘真实存在的文件
- **section 契约**：Quick Recall / 触发信号 / 思路分支 / 证据 / 常见误判 /
  下一步等 v2 section 完整
- **登记边界**：未登记的卡 Pack 不可见；document-unregistered 是硬错误

## 生命周期（git 即状态机）

草稿写入 `knowledge/candidates/<slug>.md`（frontmatter `maturity: draft`）后：

- **promote** = 人工审核通过后运行
  `python3 tools/knowledge_promote.py --id <slug>`（mv + registry 登记 + strict audit
  + Pack 目录可发现四步一条命令完成，失败原子回滚）。**裸 `mv` 不等于 promote**。
- **reject** = `rm knowledge/candidates/<slug>.md`
- **review** = 人眼看草稿（触发可观察？验证最小？误判边界清楚？前提/反例/停止
  条件完整？）；内容审核归人工，promote 命令只负责机械步骤
- promote 时把 frontmatter `maturity` 改为 `tested`/`proven`（有可复跑证据才可改）

没有第二个状态机；`git log` 就是治理审计。
