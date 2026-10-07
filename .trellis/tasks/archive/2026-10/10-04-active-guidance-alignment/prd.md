# F11：活跃验证与复盘指导对齐

## 目标与用户价值

让活跃 validator 和复盘指导可以按现有 CLI 正确读取、恢复与保存目标事实，避免退休
JSON owner、缺参数示例和无证据的负面经验建议误导后续会话；不改变验证或沉淀的判断方法。

## 背景与证据

- 以下漂移锚点为实施前 HEAD `e0ee593` 的规划证据。
  审计项 F11 / P2：`/tmp/ccst-audit-2026-10-02/AUDIT.md:100-106`。这是静态确认的
  操作指导漂移，不是已观测模型执行错误写入。
- `agents/validator.md:38-41,56-67` 仍把旧 Finding/target-memory JSON 当作输入、
  写回和恢复来源；`:49-52,86-89` 把 KILL 与 dead-end 写回直接相连。
- `rules/retrospective.md:20-25,36-55,110-116` 含旧输入、默认 refresh 和不完整写回；
  直接消费者 `commands/retrospect.md:127-134` 重复不完整命令。
  `commands/autopilot.md:282-293` 只引用分类标准，并明确禁止由建议自动写状态。
- 当前契约见 `tools/target_memory.py:219-305,398-455,658-735`；Finding 当前投影见
  `tools/target_store.py:2483-2561,2944-2972`，validate 返回路径见
  `tools/validate.py:1707-1717`。具体字段、实参和测试出处已存入 `research/`。
- F10 已于 `6245fb0` 修复，归档/日志已完成；F11 最终计划获用户 `go` 批准后激活。

## 要求与范围

### R1：只对齐活跃输入、写入与恢复契约

- 产品改动限于 `agents/validator.md`、`rules/retrospective.md`、`commands/retrospect.md`。
  使用现有 Store 查询读取 Finding/assessment/delivery/report 关系及目标经验；旧 JSON
  只能标为显式历史材料，不能作为缺库回退或当前状态写入位置。
- validator 的间接写入必须对应 `validate.py` 的真实职责：Store 判断及 report-local
  产物，不声称写旧 Finding JSON 或 session validation progress。当前 Finding 没有
  `validation_summary` 字段；使用 selected Finding ID 读取关系，summary 使用该次
  validate 返回并保留的 `summary_path`，不得从 `last-validate.json` 绑定别的 Finding。
  不将此改写为 validate 完全不触及 session；现有 runtime 工作流元数据更新不变。
- 保留 `memory/goals/active.json` 的目标选择作用，不把它当领域事实源。
- 复盘规则与现有 `/retrospect` 的按需读取契约一致：先读 memory/checkpoint，缺口才展开
  对应 owner；默认收集不执行 `coverage_matrix.py rebuild`，不改变 Coverage 引擎。

### R2：写回示例可执行且保持条件化语义

- 活跃 exact-command 示例显式绑定 TARGET，沿 `commands/target.md:48-56` 的现成写法。
  dead-end 必须包含非空适用条件、重开条件和同目标已登记的 `OPERATION_ID:STEP`；STEP
  从零开始，不能拿 artifact 路径、Finding ID 或虚构执行替代。
- KILL 只是不报告该 candidate，不自动等于技术反驳或已证实 negative。缺已登记证据时，
  可明确建议 `note` 保存未验证观察，或保留假设/缺失证据，不隐式降级写入或伪造观察。
- next/handoff 是 advisory intent，不创建或完成 Queue Action。仅在操作者明确要求时
  执行目标写回；Autopilot 的 presentation-only 边界不变。
- 保留 PASS / KILL / DOWNGRADE / CHAIN REQUIRED、现有输出结构、可选 Burp 流程和
  目标/知识库/Skill/Rules/remember 分流方法。Q1–Q7/四门仍只由
  `skills/triage-validation/SKILL.md` 定义，不复制或改写。
- 不重复维护路由表中的半截命令；表格可指向同文的完整示例。实际要保留的示例必须完整。

### R3：以真实 CLI 回归证明指导契约

- 在现有 `tests/test_target_memory_cli.py` 扩展定向测试；借用
  `tests/test_recon_ranker_contract.py:18-105` 的 R17 模式，从批准范围内文档提取真实命令，
  在临时 Store 中通过真实子进程执行。不新增测试框架、指导注册表或文案关键词门禁。
- 只替换文档中的 fixture 占位值并注入隔离根/输出选项；不得由测试补上遗漏的业务实参。
  不复制整套 validation/report fixture 或另建生产 query/writer。

## 验收条件

- [x] AC1（R1）：文档中的 Store/经验列表查询在当前、合法空和缺库 fixture 下分别返回
  真实当前事实、合法空结果和显式失败；`findings --id` 查询不存在的 ID 应失败而不是
  返回空成功。旧 JSON 投毒不进入当前结果；读操作不改 Store
  binding、选择指针或原始文件，也不创建缺失的 Store。
- [x] AC2（R1）：selected Finding ID 查询返回其实际 assessment/evidence 等关系；恢复
  指导不宣称 Store 有 summary 定位字段，不从全局 latest 指针恢复其他 Finding。
  本轮产物路径按实际 `validate.py` 返回值逐项核对，不重新执行完整验证链。
- [x] AC3（R2/R3）：从最终文档提取的 lead/next/dead-end/handoff 及无证据 note 示例
  可在隔离 Store 执行；negative 的 statement、conditions、reopen_when 和 operation/step
  引用准确保存，另一进程 show 能读回；advisory 不生成 Action。
- [x] AC4（R2/R3）：从有效 dead-end 示例分别移除条件、重开条件或操作引用，均明确
  拒绝且无写入；保留现有 malformed/foreign/missing-step 回归，无需重建同类测试。
- [x] AC5（R1/R2）：差异复核确认判断方法、分流输出、用户明确写入边界与 Autopilot
  presentation-only 约束未变；没有新增 owner、fallback、schema 或运行时功能。

## 范围外

其他审计项、全仓历史文案清理、`commands/validate.md` 的扩展润色、生产 Python 改动、
新功能/架构重构/依赖/指导注册表/关键词门禁、真实目标操作、全局安装/同步、未经确认的
数据迁移、集中工程验收和历史任务批量归档。CLI 测试不证明模型遵循指导或线上能力。

## 规划产物与批准边界

本任务为轻量指导与既有测试对齐，采用 PRD-only；不新增 design.md/implement.md。
`research/owner-cli.md` 和 `research/tests-reference-chain.md` 保存查证依据，
implement/check JSONL 只载入有关规范与研究。现有规范已经定义 Store/negative 语义，
不为相同契约重复建文档；收尾时核对规范并按需补充本次测试索引。

创建、规划、实施和三步提交收尾均已获批准。实施与定向检查完成，证据见 `validation.md`；
工作提交为 `3c83280`，本任务已归档，会话日志另立提交；集中验收尚未启动。
