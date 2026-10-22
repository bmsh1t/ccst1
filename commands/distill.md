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

Store 视图中的 `windows.findings` / `windows.experiences` 给出准确余量、
`next_command` 和 `expand_command`；`case_expand_command` 展开完整 Case 元数据。
命令已绑定真实数据根和目标，直接执行；游标因 revision 变化失效时重新生成视图，
不猜 offset。按 ID/完整 Case 展开是新查询，原始私密会话材料不会输出到 Case JSON。
`windows.ledger` 描述已采集 observation 的尾部预览；源被截断时总量/余量为 unknown。
其 `next_command` 从完整 operation 历史第一页开始浏览，按 operation ID 升序，
不是这 40 条 observation 的下一页。使用返回的 operation cursor 继续，按 `--id`
展开有序 observations、原件引用及当前 `artifact_health`；元数据页本身不验证原件。
隔离根调用格式：`python3 tools/distill_target.py --repo-root ROOT evidence --target TARGET --json`。

经验正文同时保留精确版本、`review_state`、适用条件、来源健康和纠错/依赖引用。
受挑战、来源失效或待复核的旧经验是复盘素材，不能省略警示后当成当前成立的方法。

新增内容按完整判断单元而非单点标签评审：模型见过吗、从允许的现场证据可推理吗、
需要真实试错成本才知道什么差分？组合链的状态依赖、顺序、失败切换与反例须一起问，
不能因为节点各自常见而丢失新连接。公开或可推理且无差分的不新增。

盲答先登记模型/配置、问题、允许材料和判据；模型看不到待评正文/答案，保存原答。
完整稳定命中且没有新差分的不新增；答不出或不稳仅进入成本与迁移性复核，不自动通过。
没有运行批准就记 not-run，草稿不登记。既有合同迁移与旧知识复审另记，不以模型会答删除旧卡。

跨目标复核：同形态是否能识别/行动，是条件差异还是单站特例，比现有知识多什么？
单站失败只约束其身份/对象/状态；中危不进短表不等于删除目标经验或拒绝报告。

晋升前按 `knowledge/promotion-rules.md#审核回执` 写 `<slug>.review.json`，绑定最终草稿字节；
正文或盲答材料变化须重审。审核回执只记录准入证据，不是第二注册表。

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
