# 全仓审核执行计划

## Phase A：固定基线

- [x] 记录 `HEAD`、分支、ahead/behind、tracked/untracked/staged 状态和 diff stat。
- [x] 将 27 项现有改动按 runtime、状态、知识、scanner、测试、文档和新增工具分类。
- [x] 写入 `research/baseline.md`；只记录路径和摘要，不复制敏感内容。

## Phase B：建立架构与契约地图

- [x] 阅读 README、CLAUDE、SKILL、PRODUCT、关键命令和 Trellis backend 契约。
- [x] 定位主入口、legacy 入口、owner API、consumer、派生缓存、外部命令和测试套件。
- [x] 按 command -> evidence -> state -> finding/report 数据流写入 `research/architecture-map.md`。
- [x] 对每个状态对象列出 schema、identity、writer、lock、atomicity、replay 和 corruption 行为。

## Phase C：逐工作流静态审核

- [x] Runtime/Autopilot：命令契约、bootstrap、drift、finish/continue、子进程与双入口边界。
- [x] Scope/Auth/Path：目标规范化、off-target、redirect、凭据来源、argv/log 泄露和路径逃逸。
- [x] Recon/Surface/Context：完整性语料、派生索引、fingerprint、预算、fallback 和 coverage owner。
- [x] Knowledge：registry、trigger collision、排序、召回原因、candidate/lifecycle 和治理投影。
- [x] Validation/Evidence：runner 输入、raw evidence、Ledger/Finding/Queue 收敛和 lifecycle 单调性。
- [x] Persistence/Concurrency：锁、临时文件、`fsync`/`replace`、损坏 JSON、重复执行和直接 writer。
- [x] External/Legacy：shell/Python wiring、超时、退出码、依赖、optional integration 和兼容入口。
- [x] Docs/Packaging：tool index、requirements、runtime 模板、实际 CLI 参数和安装路径一致性。

## Phase D：测试有效性审核

- [x] 建立核心 invariant -> 测试映射，标记无测试、只测 helper、只测 mock 和生产入口脱节。
- [x] 抽查断言是否能在删除/破坏被测行为后失败，识别 tautological 或 fixture 自证测试。
- [x] 核对负向、损坏输入、失败注入、重复恢复、并发和跨 owner wiring 覆盖。
- [x] 将真实缺口与低收益覆盖建议分开记录。

## Phase E：只读验证

- [x] 运行 `git diff --check` 并记录基线归因。
- [x] 运行 `runtime_doctor.py --fail-on-drift`，区分 critical drift 与 advisory drift。
- [x] 运行 `capability_governance.py --strict` 和 `knowledge_audit.py --strict`。
- [x] 运行状态 owner、重放、runtime、知识召回等针对性测试。
- [x] 在目标检查稳定后运行完整 `pytest -q`；若成本或环境阻塞，记录已覆盖范围和残余风险。
- [x] 所有命令不得访问真实目标或外部网络；结果写入 `research/validation-results.md`。

## Phase F：候选复核与报告

- [x] 为每个候选追踪实际 caller、owner 和失败影响，排除规范允许行为及 advisory 误报。
- [x] 对 P0/P1 要求最小复现或等价的确定性调用链证据；缺证据则降级或移入未证实线索。
- [x] 为正式问题添加 `HEAD` / `WORKTREE` / `BOTH` 标签和 `file:line`。
- [x] 形成 `research/audit-report.md`：findings -> advisories/技术债 -> 测试缺口 -> 治理批次 -> 残余风险。
- [x] 结束前重取工作树摘要；若基线变化，重新验证受影响 findings。
- [x] 检查报告无凭据、真实目标内容、重复问题、无证据结论或按行数驱动的重构建议。

## 验收与回滚点

- 审核只写 `.trellis/tasks/.../research/`；任何生产代码变化都视为越界并停止。
- 测试失败不授权修复；只记录和归因。
- 用户工作树发生并发变化时不回滚，更新基线后继续。
- 若完整测试可能访问外部目标或依赖本机秘密，跳过该测试并记录原因。
