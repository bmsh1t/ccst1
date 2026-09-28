# 设计：拒绝混合证据快照，保留有界恢复

## 目标与决策

针对 `research/findings.md` 的 F1，Closure 在组装任何可复核 digest 前，必须证明 Coverage
与它再次取得的 current truth 相匹配。架构和能力优先：复用已有判定，不用删读取或吞错
换效率；同时保留现有最多两次装配机会，不以一行 guard 为由损失恢复能力。

## Owner 与数据流

1. 在既有 `tools/coverage_matrix.py` 定义 `CoverageEvidenceChangedError(StoreError)`，
   `require_matching_truth()` 在原三项比较失败时抛该子类，消息保持不变。
   这个类型只区分“本次装配输入已经变化”；它不是新状态 owner，也不是通用重试策略。
2. `load_closure_projection()` 取得 `truth` 后立即调用同一 guard，再读取 witness、构造
   Closure 与 digest。不同事实不得继续混合；直接调用者收到可识别的异常。
3. `autopilot_state.main()` 和 `autopilot_round._closure_snapshot()` 使用各自**已有**的
   两次循环：仅捕获 Closure loader 抛出的新异常，第一次继续重建完整 state/closure，
   第二次原样抛出。原 owner-marker 漂移分支不删除；不扩大到其他错误或整个系统的重试。
4. Checkpoint 的复核/封轮写入入口不吞该异常，沿原 ValueError 错误边界退出，在写 witness
   前终止。CLI 最终失败保持非零码 2，稳定的证据损坏继续保留原诊断和恢复材料。

## 保持不变

- `_closure_coverage_snapshot()` 的时间归一化、所有 hash/schema/global-review basis。
- Store、raw evidence、Coverage、Surface、Checkpoint 各自的状态与写入归属。
- full/bounded 展示差异、完整展开入口、待办与已完成 lane 的恢复/幂等含义。
- 正常读取的采集次数和内容；新 guard 只比较已经取得的输入，不再次查询或散列大文件。
- `require_matching_truth()` 的现有调用者仍可按 StoreError/ValueError 捕获；只给需要有界
  重试的两个 Closure 入口更精确的异常类型。

## 兼容与风险

直接 `load_closure_projection()` 遇到同轮证据/Store 代际不一致将抛异常，而非返回带
`state_snapshot_stale` 的混合快照。该行为变化是明确的完整性修复，不隐藏在重构名下。
CLI/coordinator 仍可重读一次；持续变化显式失败，不发复核依据、不自动封轮、不重放执行。
仅变化检测异常可重试；缺库、损坏 schema、权限/I/O 等错误不因此获得静默重试。

## 文件边界

- 产品：`tools/coverage_matrix.py`（一致性异常归属）、`tools/autopilot_state.py`
  （guard 和既有 CLI 恢复循环）、`tools/autopilot_round.py`（既有协调器恢复循环）。
- 测试：`tests/test_closure_snapshot_stability.py`、`tests/test_checkpoint.py`、
  `tests/test_autopilot_state_tool.py`、`tests/test_autopilot_round.py`。
- 规范：transactional-target-state 与 lifecycle-state 的现有快照/恢复章节。
- 不修改 Surface/Resume/Checkpoint 产品实现、存储 schema、部署或第四批内容。

只有复现证明的接口行为变化才更新旧测试预期；不会通过缺字段绕过 guard 或 mock 掉
真实 SQLite/证据验证来消除失败。无数据迁移；回滚本任务独立代码提交即可。
