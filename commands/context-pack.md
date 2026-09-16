---
description: 为当前目标装配最小上下文包，避免全量读取 Skills、知识库和日志。用法：/context-pack [target] [focus]
---

# /context-pack

装配当前目标的最小上下文包。

这个命令不执行测试、不扫描目标、不写目标记忆。它只读取本地目标记忆、
surface 排名、覆盖矩阵、findings 索引、Evidence Ledger，以及 browser/JS/source
的小型证据索引，提供来源、目录和写回入口；Claude 决定本轮需要哪些信息。

## 必读规则

```text
rules/context-loading.md
```

## 用法

```text
/context-pack
/context-pack target.com
/context-pack target.com api-idor
/context-pack target.com auth-hidden
/context-pack target.com missing-param
/context-pack target.com path-pattern
/context-pack target.com graphql
/context-pack target.com sqli
/context-pack --target target.com --focus upload
/context-pack --target target.com --focus race
```

## 默认流程

先按 `skills/runtime-protocol.md#shared-knowledge-recall` 判断复用或刷新；需要查包时运行：

```bash
python3 tools/context_pack.py --target <target>
```

有 focus 时追加 `--focus <focus>`，不要丢弃用户输入或当前证据对应的边界。
如果用户没有传 target，工具会读取 `memory/goals/active.json` 的当前目标。

工具会：

1. 读取目标层：`memory/goals/active.json` 和 `memory/goals/targets/<target>.json`。
2. 只读调用 surface review pack，提取 AI Review Pool、advisory score hints、Workflow Leads 和 target memory 线索。
3. 读取覆盖矩阵未处置格的有界预览，不按关键词过滤。
4. 读取 `findings/<target>/findings.json` 索引。
5. 读取小型 browser/JS/source 证据索引：
   - `recon/<target>/browser/xhr_endpoints.txt`
   - `recon/<target>/browser/api_endpoints.txt`
   - `recon/<target>/browser/browser_params.txt`
   - `findings/<target>/js_intel/hypotheses.json`
   - `findings/<target>/source_intel/routes.json`
6. 读取 Evidence Ledger 摘要：`memory/evidence/<target>/ledger.jsonl`。
7. 从 `knowledge/capabilities.yaml` 发布知识卡目录；Skill 发现使用 Claude Code 原生目录。
8. 输出证据锚点、已记录的 Actor Matrix 缺口、未知项、矛盾点和 owner 写回入口。

`knowledge_cards`、`deferred_knowledge_cards`、
`knowledge_card_recall`、`hypothesis_seeds`、`alternative_angles` 是空兼容字段，
不表示已加载知识，也不会生成假设或测试路线。Claude 可直接运用已有知识；需要补充时
按目录读取完整判断单元，不要求先跑 Pack 才能思考或选择方法。

## 输出与使用

```bash
python3 tools/context_pack.py --target TARGET --focus '当前需要回答的边界问题'
python3 tools/context_pack.py --target TARGET --json
```

文本与 JSON 均提供知识卡目录、目标事实和证据锚点。短卡按需全文读；长卡读取完整的
相关机制，包括前提、证据门、反例与停止条件，再按需展开来源。`knowledge/index.md`
仍是可直接读取的目录，不是额外必过步骤。

## Skill / Focus 路由

`focus` 记录当前证据要回答的问题，不触发关键词自动选路。Skill 的选择与加载由 Claude
通过原生 Skill 工具完成；知识卡路径来自 registry。本命令不维护另一张固定映射表。

## 纪律

- Context Pack 不推荐主 Skill；Claude 通过原生 Skill 工具按需加载。
- 上下文窗口限制新增读取量，不限制知识访问；已读且未变的内容复用当前会话。
- Context Pack 不生成动作安全门禁。
- 结束前必须加入 `rules/coverage-gate.md`。
- 上下文包不是结论或必过步骤；它是可按需读取的事实和引用视图。
- 目录或观察不自动生成动作；Claude 选择假设后通过现有 owner 创建或激活 Queue action。
- 每次 substantive lane 在 Action Queue claim 时由 Claude 显式选择 `skill_route`；
  `required_dimensions` 必须写入对应 metadata。首次选择不是 override；替换 action
  owner 已有 route 时必须记录 `skill_override_reason`。
- browser 证据默认只读 `recon/<target>/browser/` 的 XHR/API/params/form/page-JS 小索引；
  不默认加载 `evidence/<target>/browser/...` 的原始 requests/console/storage。
- Actor Matrix 缺口不是结论；它只是提醒哪些角色/对象/replay 还没有结构化记录。
- 工具推荐不是强制路线，也不是固定工具清单；Claude 必须说明选择原因并把实际 route 写回 Action Queue metadata。
