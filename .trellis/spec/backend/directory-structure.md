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
| `skills/` | 领域执行方法和按需参考资料 | `skills/src-hunter/modules/web2-recon.md`、`skills/src-hunter/modules/cicd-security.md` |
| `rules/` | 全局约束、状态模型和工具/AI 边界 | `rules/ccst/hunting.md`、`rules/ccst/tool-ai-boundary.md` |
| `knowledge/` | 小型知识卡、payload pack、playbook、capability registry 和发布审核回执 | `knowledge/capabilities.yaml`、`knowledge/cards/api-idor.md`、`knowledge/reviews/<id>/` |
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

Finding、Action 和实际执行的 observations 归 `state/<target-key>/metadata.sqlite3` 中的
TargetStore。Recon 的中性材料清单及审阅状态仍归 `observation_inventory.py` 管理的
`state/<target-key>/observations.json`，两种 observation 不可混同。
原始 recon URL 和完整 inventory 必须保留；`recon/<target-key>/surface/{index.jsonl,
manifest.json,summary.json}`、`state/<target-key>/observations-summary.json` 和
`state/<target-key>/surface-projection.json` 是可重建的索引/sidecar/cache。派生目录不能
反向成为 Finding、Action、Coverage review 或 observation 的事实 owner。

`distill/corpus/` 是可删除、gitignored 的本地案例数据面，不是仓库知识权威，也不能默认
进入 Claude context。其 `reports.jsonl`、`index.json`、`manifest.json` 只能由
`tools/case_corpus.py build` 生成；测试必须使用 synthetic corpus。

Claude CLI `/autopilot` 的当前主入口是 `commands/autopilot.md`，并在当前 Claude 会话内
inline 执行。目标状态、checkpoint 和恢复统一走现有 canonical owner；不要新增第二套
controller 或 session/state 语义。

## 模块组织规则

1. **状态所有者优先**：跨工具共享的 schema、身份算法或 mutation API 放在拥有该状态的
   模块，例如 Finding 创建归 `tools/target_store.py` 的 `TargetStore.create_finding()`，
   目标路径归 `tools/target_paths.py`，知识注册表解析归 `tools/knowledge_registry.py`。
2. **CLI 薄封装**：复杂模块使用 `build_parser()`/`main(argv)` 暴露命令，核心逻辑保持为
   可导入函数。`tools/action_queue.py` 和 `tools/knowledge_audit.py` 是现有范例。
3. **直接执行兼容**：`tools/*.py` 需要同时支持 `python3 tools/x.py` 和从测试中
   `import tools.x` 时，可使用项目现有的 `try: from tools... except ImportError: from ...`
   模式，不新增全局路径黑魔法。
4. **共享规则不复制**：命令文档描述控制流，工具实现稳定解析/落盘；不要在多个 Markdown、
   Python 和 Shell 文件中各维护一份 storage-key、状态迁移或 capability 解析算法。
   入口保留何时读取、执行及消费回执的触发点；捕获/登记/失败恢复细则引用
   `docs/evidence-runners.md`，认知读取/写回时机引用 `skills/runtime-protocol.md`。
5. **新增知识资产先登记**：正式卡片、payload pack 和 playbook 必须登记到
   `knowledge/capabilities.yaml`，并通过 `tools/knowledge_audit.py --strict`。
6. **知识状态分层**：卡片来源 frontmatter 解析归 `tools/knowledge_registry.py`，本地案例
   查询归 `tools/case_corpus.py`（规范化投影在 `tools/corpus_projection.py`）。
   `/distill` 产出 `knowledge/candidates/` 草稿；`tools/knowledge_promote.py` 负责审核后
   发布正式卡、登记 registry、保存回执并 audit。`tools/knowledge_review.py` 校验正文与
   审核原件的字节绑定；移动文件或 maturity 标签本身不构成已审核发布。
7. **治理投影不是路由状态**：`tools/kb_review.py` 只展示 registry、maturity 和已记录的 pull
   事实；零 pull 不代表未使用。`tools/knowledge_retire.py` 显式更新退役状态并保留正文；
   可见性归 registry，当前发布审核有效性归 `knowledge_review.py`。
8. **大型 Surface 分层**：exact URL identity/provenance/page 归
   `tools/surface_index.py`，bounded cache 归 `tools/surface_projection.py`，Recon inventory
   与 summary sidecar 归 `tools/observation_inventory.py`，控制事实投影归
   `tools/autopilot_state.py`，调查路线由 Claude 选择。consumer 调用 owner API，不复制
   fingerprint/schema。

## 命名约定

- Python 模块、测试文件和函数使用 `snake_case`；测试文件使用 `test_<owner>.py`。
- Skill/知识卡/capability ID 使用小写短横线，例如 `cloud-control-plane-pivots`。
- 目标磁盘目录不得自行清洗字符串，统一使用 `canonical_target_value()` 和
  `target_storage_key()`。
- JSON/JSONL 持久化对象包含 `schema_version`；时间字段使用 UTC ISO-8601。
- Store 领域事实不再另建 JSON writer；外置 owner 文件使用明确名称，例如 `scope.json`、
  `session.json`、`checkpoint_latest.json`。旧 `action_queue.json` 仅供显式历史读取/迁移，
  不作缺库 fallback；不要创建含义重叠的 `state2.json` 或 `final_new.json`。

## 新功能落位示例

- 新增一个确定性 replay runner：实现放 `tools/`，行为测试放 `tests/`，操作说明放
  `docs/evidence-runners.md`，产出的原始证据写目标作用域目录。
- 新增共享知识：先判断是既有卡复审还是新候选，走上述发布/审核 owner；Context Pack
  通过 registry 展示目录，由 Claude 选择相关方法，不增加关键词选路。如含案例来源，
  使用结构化 `source_refs`，按需通过 case corpus resolver 查询，不能内联报告正文。
- 新增 slash command：命令契约放 `commands/`；如果需要状态读写，调用现有 owner API，
  不在 Markdown 内拼接另一套 JSON writer。

## 禁止模式

- 把目标专属响应、token、域名或实验答案写入 `skills/`、`rules/`、`knowledge/`。
- 在消费者中重新实现 target key、finding identity、report identity 或 YAML 解析。
- 让 scanner、regex 或 score 直接成为最终漏洞判断和完成判断。
- 为单一调用创建无真实复用价值的 `utils.py`；共享抽象必须有明确状态/契约所有权。
