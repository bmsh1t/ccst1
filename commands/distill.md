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

## 入库三问（AI 判断，写卡前先过）

一条经验只有**三个问题全部指向"是增量"**才值得成卡：

1. **模型见过吗？**——公开知识/训练数据（教科书技巧、公开靶场的漏洞清单、
   框架文档级的怪癖）→ 见过，不是增量，不写卡。
2. **从当前证据可推理吗？**——模型拿到现场证据（响应、报错、行为差异）
   能当场推出同样结论 → 能推，不是增量，不写卡。
3. **需要真实成本才知道吗？**——实际打目标才换来的死路、文档没写的
   环境怪癖、能省掉重复探测的坑 → 只有这类是真增量，写卡。

①② 的即时判据：先让模型盲答该知识点（不看材料）。答得出来 = 见过或
可推，不入库；答不出或答案不稳，才进入 ③（真实成本）判定。AB 评测和
pull 数据是复审手段，不是第一道筛。

典型反例：公开靶场（juice-shop 等）的漏洞结论（模型见过）；"报错暴露
SQL 片段说明可注入"（可推理）；公开 writeup 里的编码 bypass 集（见过且
可推——材料在手边时"觉得有价值"的错觉会压过自检，先盲答再判）。
典型正例："该目标的 WAF 对 XX 编码放行"（真实成本）；"方案 A 在此环境
下因 YY 死路，直接走 B"（省重复探测）。

## 机器 gate（晋升时 strict audit 强制）

- **脱敏红线**（`knowledge_audit._audit_card_scrub`）：卡正文判断段含裸公网
  IPv4 或 credential 形态文本 → 硬错误（保留地址/占位符/权限声明语法豁免；
  evidence 路径行不在判断正文范围）
- **可溯源与可复现**（`knowledge_audit._audit_target_evidence_refs`）：
  `source_refs` 的 refs 必须指向声明 target 名下且磁盘真实存在的文件；
  **git 仓库内还必须不被 gitignore 命中**（git-tracked 卡引用 clone 后
  不存在的文件 = 可复现契约违反）。raw evidence（gitignored）由
  promote 自动迁移为 `knowledge/distill-digests/` 下的脱敏 digest
  （最小事实：method/path/status/body_sha256/actor 指纹 + raw_sha256
  绑定；无 headers、无 body——真实目标响应可能含 PII）。溯源链到
  digest 为止：本机有 raw 时用 raw_sha256 双向校验，没有就到此为止。
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
