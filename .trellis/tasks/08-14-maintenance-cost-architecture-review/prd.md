# 项目维护成本与架构复核

## Goal

以当前工作树为主、`HEAD` 为归因对照，对项目现有架构和维护成本做一次证据化只读复核，回答：

1. 当前架构是否清晰、可维护，主要数据流和 owner 边界在哪里；
2. 哪些维护成本已经通过近期修复下降，哪些仍是实际热点；
3. 剩余问题是否值得现在治理，以及最小、收益明确的治理顺序是什么。

本任务只产出审核报告，不修改功能代码，也不以文件行数或抽象偏好推动重构。

## Background

- 上一轮全仓审核基线及报告位于
  `.trellis/tasks/archive/2026-08/08-14-full-project-architecture-quality-audit/`，本轮复用其架构图、
  finding 格式和验证证据，不从零重复审核。
- 上一轮发现的 scanner 上传审批、AuthSession 跨目标隔离、显式缺失 auth file、target profile
  持久化和 request guard 持久化已经分别由 `a2cca49`、`6a59128`、`6a6e661`、`17e58b2`
  等提交处理；本轮将其列为已解决债务并抽查当前契约，不重新打开已闭合问题。
- 已知剩余线索包括多 owner 最终一致性、协调器耦合、Legacy 双入口、knowledge trigger collision
  advisory 和依赖可复现性。这些是待复核线索，不预设为缺陷。
- `commands/hunt.md` runtime drift 已明确排除治理；可作为当前运行状态记录，但不得执行同步、
  修改模板或与本轮架构建议混合。
- 当前工作树除本任务规划文件外包含用户已有的 `shenhe.md` 删除及 5 个未跟踪文件；不得修改、
  回退、暂存或提交这些内容。

## Requirements

1. 建立当前架构和主数据流地图，覆盖入口/协调器、Scope/Auth、Recon/Surface、Knowledge、
   Validation/Evidence、Ledger/Finding/Queue/Checkpoint、持久化 owner、Runtime、Legacy 和测试边界。
2. 从以下维度评估维护成本，并给出 `低 / 中 / 高` 评级、原因和 `file:line` 证据：
   - 修改局部性与协调器耦合；
   - 状态 owner、持久化、恢复与跨文件收敛；
   - 依赖方向、重复实现和第二真相源；
   - 测试定位、故障注入和回归信心；
   - runtime、知识治理和文档同步成本；
   - Legacy 兼容与发布/依赖可复现性；
   - 运行诊断、错误可见性和人工介入成本。
3. 对每个正式热点说明影响、触发条件、当前缓解、治理收益和最小方向；仅凭代码体积或理论风险
   不得判为高成本。
4. 明确区分：已解决债务、当前行为问题、advisory、结构性技术债、测试缺口和无需治理项。
5. 所有结论标注来源 `HEAD` / `WORKTREE` / `BOTH`；若审核期间工作树变化，重新核验受影响证据。
6. 对既有 P2 线索逐项给出“现在处理 / 随改随治 / 暂不处理”的判断，并用实际收益而非整洁偏好排序。
7. 输出最小增量治理建议；不得建议数据库、事件总线、Mutation Coordinator、全局 writer 抽象、
   全仓协调器拆分或无使用证据的 Legacy 删除。
8. 审核只读生产代码；仅允许写当前 Trellis 任务的规划和 `research/` 报告。

## Acceptance Criteria

- [x] `research/baseline.md` 记录起止 `HEAD`、工作树路径清单、近期修复提交和归因规则。
- [x] `research/architecture-map.md` 给出入口、模块职责、owner 和端到端数据流，并标明关键边界。
- [x] `research/maintenance-review.md` 给出各维度 `低 / 中 / 高` 评级、证据、优点、热点和残余风险。
- [x] 上一轮正式 finding 均被追踪到已修复、仍存在或无法确认，不把已闭合问题继续计入当前成本。
- [x] 多文件最终一致性、协调器耦合、Legacy 双入口、trigger collision、发布可复现性均有明确治理判断。
- [x] 每个 P0-P2 当前问题或高成本热点均有可点验的 `file:line`、调用链或目标验证证据。
- [x] `research/validation-results.md` 记录静态门禁、最小相关测试、既有完整测试证据及失败归因。
- [x] 最终建议按收益和依赖排序，且明确哪些内容不应现在做。
- [x] 起止工作树对比证明没有修改、回退、暂存或提交用户已有内容和生产代码。

## Out of Scope

- 修复审核发现、修改功能代码、重构或新增抽象。
- 同步或修复 `commands/hunt.md` runtime drift。
- 删除、移动或退役 Legacy 入口。
- 对真实目标运行 scanner、浏览器、验证器或任何外部网络请求。
- 重新运行全量测试；复用近期 `3390 passed` 证据，并只运行足以验证当前判断的聚焦检查。
- 读取 `.env`、`.private/`、真实凭据或目标响应内容。
