---
description: 从当前目标的原始证据蒸馏知识卡草稿（target-scoped 直线流程，出题-收卷协议）。用法：/distill <target> [--typology pattern|target-vuln|failure|bypass]
---

# /distill

从**当前目标**的原始证据（Evidence Ledger / Findings / Case State）蒸馏可复用知识。
这是 target-scoped 直线流程：机器出题 → AI 提三元组 → 机器脱敏渲染草稿卡 → 人工 mv。

与相邻命令的分工：

| 命令 | 作用域 | 问题 |
|---|---|---|
| `/distill` | target-scoped | 当前目标打完了，什么经验值得沉淀成卡？ |
| `/intel` · `disclosed-researcher` | target-scoped 横向 | 别人在同类目标上什么模式拿过赏？ |
| `/retrospect` | session-scoped | 本轮会话的分流决策（lead/next/dead-end 写回 + 沉淀建议） |

## 流程（两段式，机器不能伪造认知）

> 谁思考：①③机器（拉证据/脱敏渲染/可溯源校验）；②三元组（pattern/trigger/
> action + evidence_refs）是**AI 判断**——机器只出题，不代提。

```text
① AI 运行出题（机器拉证据）：
   python3 tools/distill_target.py prompt --target <target> --typology <t> --json

② AI 读 question，从证据里提三元组（当前会话的认知）：
   {typology, pattern, trigger, action, evidence_refs}
   —— evidence_refs 必须来自题目视图里的真实路径，不得编造

③ AI 写三元组到文件并收卷（机器脱敏 + 渲染）：
   python3 tools/distill_target.py commit --target <target> \
     --triple-json /tmp/triple.json --json
```

## 类型学（四选一）

- `pattern`：可复用模式（信号 → 验证路径 → 停止条件）
- `target-vuln`：目标特征 → 漏洞倾向
- `failure`：失败教训（误判边界 / 死路）
- `bypass`：绕过关系（A 被挡 → B 成立 / 链跳板）

## 机器 gate（收卷时强制）

- **脱敏红线**：三元组正文含裸 IPv4、`password/secret/token/api-key =` 形态文本 →
  拒绝写入（email/长 token 由 scrub 自动替换 `[email-redacted]`/`[token-redacted]`）
- **可溯源**：`evidence_refs` 必须指向目标名下真实存在的文件
  （`evidence/<target>/`、`findings/<target>/`、`state/<target>/` 前缀）
- **字段完整**：pattern/trigger/action 三字段非空

## 生命周期（git 即状态机）

草稿写入 `knowledge/candidates/<slug>.md`（frontmatter `maturity: draft`）后：

- **promote** = 人工审核通过后运行
  `python3 tools/knowledge_promote.py --id <slug>`（mv + registry 登记 + strict audit
  + Pack 目录可发现四步一条命令完成，失败原子回滚）。**裸 `mv` 不等于 promote**：
  未登记的卡在 Pack 不可见，audit 的 document-unregistered 是硬错误。
- **reject** = `rm knowledge/candidates/<slug>.md`
- **review** = 人眼看草稿（trigger 可观察？action 最小？误判边界清楚？）；内容审核
  仍归人工，promote 命令只负责机械步骤
- promote 时把 frontmatter `maturity` 改为 `tested`/`proven`（有可复跑证据才可改）

没有第二个状态机；`git log` 就是治理审计。
