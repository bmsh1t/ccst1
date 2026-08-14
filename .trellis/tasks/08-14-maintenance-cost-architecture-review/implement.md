# 项目维护成本与架构复核执行计划

## Phase A：固定增量基线

- [x] 记录 `HEAD`、分支关系、staged/tracked/untracked 路径和 diff stat。
- [x] 从上一轮审核提取架构地图、findings、advisories、测试证据和残余风险。
- [x] 将 `a2cca49`、`6a59128`、`6a6e661`、`17e58b2` 等近期提交映射到旧 findings。
- [x] 写入 `research/baseline.md`，不读取或复制敏感内容。

## Phase B：增量架构复核

- [x] 核对当前主入口、Legacy 入口、核心协调器和 runtime 边界。
- [x] 核对 Scope/Auth -> Recon/Surface -> Knowledge -> Validation/Evidence ->
  Ledger/Finding/Queue/Checkpoint -> Report/Memory 数据流。
- [x] 为核心状态列出 owner、writer、identity、原子性、损坏输入和重放/重建契约。
- [x] 识别实际逆向依赖、第二真相源、重复实现和需要跨模块同步的修改点。
- [x] 写入 `research/architecture-map.md`，所有关键判断附当前 `file:line`。

## Phase C：维护成本评级

- [x] 按 PRD 七个维度给出 `低 / 中 / 高` 评级和实际维护后果。
- [x] 追踪上一轮 findings：已修复、仍存在、被其他提交改变或无法确认。
- [x] 复核多 owner 最终一致性、协调器耦合、Legacy 双入口、knowledge collision 和发布可复现性。
- [x] 将当前行为问题、advisory、结构债、测试缺口和无需治理项分开。
- [x] 对剩余事项给出“现在处理 / 随改随治 / 暂不处理”及最小增量方向。
- [x] 写入 `research/maintenance-review.md`。

## Phase D：最小验证

- [x] 运行 `python3 tools/runtime_doctor.py --fail-on-drift`，只记录 drift，不同步。
- [x] 运行 `python3 tools/knowledge_audit.py --strict` 和
  `python3 tools/capability_governance.py --strict`。
- [x] 运行覆盖 upload approval、AuthSession target isolation、missing auth file、target profile 和
  request guard 持久化的聚焦测试；不访问外部网络。
- [x] 记录近期完整测试结果及其时间边界，不重复全量测试。
- [x] 写入 `research/validation-results.md`。

## Phase E：报告自检与收尾

- [x] 检查每个 P0-P2 或高成本热点均有当前 `file:line` 和可验证影响。
- [x] 检查报告没有把文件大小、advisory 或理论风险当成行为缺陷。
- [x] 检查建议没有引入无收益的大型抽象或全仓重构。
- [x] 重取工作树快照并复核发生变化的路径。
- [x] 运行 `git diff --check` 和 Trellis task validation；确认只新增本任务产物。
- [ ] 提交本任务审核产物并按 Trellis 流程归档；不得包含用户已有未提交文件。

## 回滚点

- 任何生产代码或用户文件变化均视为越界，停止并先确认来源。
- 检查失败只记录和归因，不授权修复功能代码。
- 当前行号与旧报告冲突时，以当前工作树证据为准，不强行保留旧结论。
