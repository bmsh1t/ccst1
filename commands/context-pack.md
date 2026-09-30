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

1. `memory/goals/active.json` 仅用于选择目标；意图、笔记和条件化经验读取当前 Store。
2. 只读调用 Surface review pack，提取中性 URL 窗口、来源、余量与完整展开入口。
3. 读取覆盖矩阵未处置格的有界预览，不按关键词过滤。
4. 查询 Store Finding 主张、技术裁决和交付状态。
5. 读取小型 browser/JS/source 证据索引：
   - `recon/<target>/browser/xhr_endpoints.txt`
   - `recon/<target>/browser/api_endpoints.txt`
   - `recon/<target>/browser/browser_params.txt`
   - raw JS/source paths surfaced as `must_read` references
6. 从 Store observation 和当前材料完整性检查生成只读证据摘要。
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
- Skill 由 Claude 通过平台原生工具按需加载。Queue claim 不登记或校验 Skill 路由，
  不要求 `required_dimensions`；实验使用 `active_dimension`，实际执行由 Runner 记录 `tested_dimensions`。
- browser 证据默认只读 `recon/<target>/browser/` 的 XHR/API/params/form/page-JS 小索引；
  不默认加载 `evidence/<target>/browser/...` 的原始 requests/console/storage。
- Actor Matrix 缺口不是结论；它只是提醒哪些角色/对象/replay 还没有结构化记录。
- 工具推荐不是强制路线，也不是固定工具清单；Claude 必须说明选择原因并把实际 route 写回 Action Queue metadata。
