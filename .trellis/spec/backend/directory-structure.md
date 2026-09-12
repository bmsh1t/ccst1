# 后端目录结构

## 项目形态

本项目不是传统 Web 服务，而是面向 Claude CLI 的安全测试插件。Markdown 命令负责
Claude 侧编排，Python/Shell 工具负责确定性执行、证据保存和状态投影。新增文件应落到
现有职责层，不能因为调用方便就把状态写入、路由判断和展示逻辑堆进同一个入口。

## 目录职责

| 路径 | 职责 | 真实示例 |
|---|---|---|
| `commands/` | Claude slash-command 契约和人工流程入口 | `commands/autopilot.md`、`commands/kb.md` |
| `agents/` | 可选 Claude specialist 的职责边界 | `agents/autopilot.md`、`agents/validator.md` |
| `skills/` | 领域执行方法和按需参考资料 | `skills/web2-recon/SKILL.md`、`skills/cicd-security/SKILL.md` |
| `rules/` | 全局约束、状态模型和工具/AI 边界 | `rules/hunting.md`、`rules/tool-ai-boundary.md` |
| `knowledge/` | 小型知识卡、payload pack、playbook、capability registry 和正式卡治理产物 | `knowledge/capabilities.yaml`、`knowledge/cards/api-idor.md`、`knowledge/governance/events.jsonl` |
| `tools/` | 可独立调用、可测试的确定性 CLI 与共享模块 | `tools/autopilot_state.py`、`tools/evidence_ledger.py` |
| `memory/` | append-only journal、审计、schema 和目标记忆实现 | `memory/audit_log.py`、`memory/schemas.py` |
| `tests/` | pytest 行为、跨层契约和 runtime staging 测试 | `tests/test_finding_index.py`、`tests/test_claude_runtime_integration.py` |
| `templates/` | 报告、计划等可复用模板 | `templates/phased-surface-validation-plan.md` |
| `docs/` | 工具索引、证据 runner 等操作文档 | `docs/tool-index.md`、`docs/evidence-runners.md` |
| `mcp/` | 可选外部 MCP 客户端，不能隐式接入 `/autopilot` | `mcp/hackerone-mcp/` |

以下目录是运行产物或目标状态，不是通用源代码：`recon/`、`findings/`、`reports/`、
`evidence/`、`state/`、`targets/`、`hunt-memory/`、`memory/evidence/` 和
`memory/goals/`。测试必须通过 `tmp_path` 或隔离 staging root 写入，不能依赖本机历史
目标数据。

大型 Surface 的事实与派生文件必须分层：原始 recon URL 和
`state/<target>/observations.json` 是完整性数据；`recon/<target>/surface/{index.jsonl,
manifest.json,summary.json}`、`state/<target>/observations-summary.json` 和
`state/<target>/surface-projection.json` 是可删除重建的索引/sidecar/cache。派生目录不能反向
成为 finding、action、coverage 或 observation lifecycle owner。

`distill/corpus/` 是可删除、gitignored 的本地案例数据面，不是仓库知识权威，也不能默认
进入 Claude context。其 `reports.jsonl`、`index.json`、`manifest.json` 只能由
`tools/case_corpus.py build` 生成；测试必须使用 synthetic corpus。

Claude CLI `/autopilot` 的当前主入口是 `commands/autopilot.md`，并在当前 Claude 会话内
inline 执行。目标状态、checkpoint 和恢复统一走现有 canonical owner；不要新增第二套
controller 或 session/state 语义。

## 模块组织规则

1. **状态所有者优先**：跨工具共享的 schema、身份算法或 mutation API 放在拥有该状态的
   模块，例如 finding 写入归 `tools/finding_index.py`，目标路径归
   `tools/target_paths.py`，知识注册表解析归 `tools/knowledge_registry.py`。
2. **CLI 薄封装**：复杂模块使用 `build_parser()`/`main(argv)` 暴露命令，核心逻辑保持为
   可导入函数。`tools/action_queue.py` 和 `tools/knowledge_audit.py` 是现有范例。
3. **直接执行兼容**：`tools/*.py` 需要同时支持 `python3 tools/x.py` 和从测试中
   `import tools.x` 时，可使用项目现有的 `try: from tools... except ImportError: from ...`
   模式，不新增全局路径黑魔法。
4. **共享规则不复制**：命令文档描述控制流，工具实现稳定解析/落盘；不要在多个 Markdown、
   Python 和 Shell 文件中各维护一份 storage-key、状态迁移或 capability 解析算法。
5. **新增知识资产先登记**：正式卡片、payload pack 和 playbook 必须登记到
   `knowledge/capabilities.yaml`，并通过 `tools/knowledge_audit.py --strict`。
6. **知识状态分层**：卡片来源 frontmatter 解析归 `tools/knowledge_registry.py`，本地案例
   查询归 `tools/case_corpus.py`（规范化投影在 `tools/corpus_projection.py`）。
   候选晋升走 `/distill` 直线流程（`tools/distill_target.py` 出题-收卷；草稿在
   `knowledge/candidates/`，人工 `mv` 进 cards 即 promote——git 即生命周期，
   无第二个状态机；原 candidates/lifecycle 状态机 2026-09-11 随
   09-11-simple-efficient-refactor 零-B 归档）。
7. **治理投影不是路由状态**：`tools/knowledge_value_review.py` 生成的全卡矩阵只承载人工/AI
   advisory 复核；active/load/layer 仍由 registry 决定，maturity 证据由正式卡事件校验。
8. **大型 Surface 分层**：exact URL identity/provenance/page 归
   `tools/surface_index.py`，bounded cache 归 `tools/surface_projection.py`，完整 observation
   与 summary sidecar 归 `tools/observation_inventory.py`，控制面路由归
   `tools/autopilot_state.py`。consumer 只能调用 owner API，不能自行扫描大文件或复制
   fingerprint/schema。

## 命名约定

- Python 模块、测试文件和函数使用 `snake_case`；测试文件使用 `test_<owner>.py`。
- Skill/知识卡/capability ID 使用小写短横线，例如 `cloud-control-plane-pivots`。
- 目标磁盘目录不得自行清洗字符串，统一使用 `canonical_target_value()` 和
  `target_storage_key()`。
- JSON/JSONL 持久化对象包含 `schema_version`；时间字段使用 UTC ISO-8601。
- 目标级状态文件使用明确所有者名称，例如 `action_queue.json`、`session.json`、
  `checkpoint_latest.json`；不要创建含义重叠的 `state2.json` 或 `final_new.json`。

## 新功能落位示例

- 新增一个确定性 replay runner：实现放 `tools/`，行为测试放 `tests/`，操作说明放
  `docs/evidence-runners.md`，产出的原始证据写目标作用域目录。
- 新增一个知识路线：先判断是现有卡增量还是新卡；正式卡放 `knowledge/cards/`，登记
  registry，再在 `tools/context_pack.py` 增加 signal 路由和回归测试；如含案例来源，使用
  结构化 `source_refs`，按需通过 case corpus resolver 查询，不能内联报告正文。
- 新增 slash command：命令契约放 `commands/`；如果需要状态读写，调用现有 owner API，
  不在 Markdown 内拼接另一套 JSON writer。

## 禁止模式

- 把目标专属响应、token、域名或实验答案写入 `skills/`、`rules/`、`knowledge/`。
- 在消费者中重新实现 target key、finding identity、report identity 或 YAML 解析。
- 让 scanner、regex 或 score 直接成为最终漏洞判断和完成判断。
- 为单一调用创建无真实复用价值的 `utils.py`；共享抽象必须有明确状态/契约所有权。
