# 第三批：Coverage 与 Closure 事实契约核查

## Goal

修复已复现的 Coverage → Closure 混合证据快照，保证复核所依据的事实一致，同时保留
已有的有界恢复和完整材料访问。优先级是架构与能力 → 效率 → 维护成本；不做无证据重构。

## Confirmed Facts

- 本地基线已快进到 `7c05aa9`；未 push，两份旧日志的暂存补丁与工作区字节保持不变。
- F1：`tools/autopilot_state.py:3526,3549-3553` 两次读取间发生 raw 字节变化时，Coverage
  与 Closure 的健康状态相反，却返回 digest 且未标记 stale。损坏和恢复两个方向均已复现；
  未观察到错误耗尽判定。完整命令、结果及 owner 图见 `research/findings.md`。
- `coverage_matrix.require_matching_truth()`（`tools/coverage_matrix.py:997-1002`）已能识别
  该不一致；Checkpoint/Pack/Surface 已使用它，Closure 漏用。事实来源仍是 Store/current_truth。
- Coverage 保留 `as_of`、Closure 去除采集时间是合法设计，不需要改 hash 或统一展示。
- CLI/coordinator 已有最多两次装配循环（`autopilot_state.py:4439-4480`、
  `autopilot_round.py:49-88`）；不能为了少写代码让新的检测绕过既有恢复机会。
- 用户已以 `go` 批准方案实施；全程不使用子代理，提交另行确认。

## Requirements

- R1（架构）：Closure 使用已有 owner 的一致性规则；不再为不同的两次事实装配可复核
  digest，不新增状态 owner、比较算法或统一快照框架。
- R2（恢复）：直接读取拒绝不一致；CLI/coordinator 对该可区分的变化最多重新装配一次。
  持续变化显式失败，普通 Store/I/O 故障不被当成竞态重试，不重放外部执行。
- R3（完整性）：检测失败发生于复核/封轮 witness 写入前；稳定损坏保留既有诊断且不能
  授权闭合，原待办、lane 进度、证据与完整展开入口保持可恢复。
- R4（兼容与效率）：稳定输入的跨时间/full/bounded 判断和 digest 不变，真实变化继续使
  旧复核失效。正常态不增加采集/查询；不改 schema、hash、展示窗口或部署。

## Acceptance Criteria

- [x] AC1（R1）：真实临时 Store/raw 文件在两次读取之间损坏或恢复，revision/marker 不变，
  直接 Closure 均拒绝不一致，不返回混合 digest。
- [x] AC2（R2）：CLI/coordinator 瞬时变化后可重新装配成功；持续变化恰在两次尝试后失败；
  普通 StoreError 不获得新重试。直接 loader 的 Store 代际竞态预期同步为明确异常。
- [x] AC3（R3）：复核/封轮失败前后 witness 与 Store binding 不变；稳定 partial 继续抑制
  闭合，完整材料、待办和 lane 恢复/幂等回放回归通过。
- [x] AC4（R4）：时间/full/bounded 稳定性、真实变化失效、原 marker handoff/恢复通过；
  正常路径不多读，schema/hash/展示不变，无新依赖或无关修改。

## Out of Scope

- 第四批 scanner 摘要和部署规则、真实扫描、数据迁移、个人 runtime、旧暂存日志。
- 未经最终方案批准修改产品；自动提交、push 或引入新依赖。
- 文件系统事务、所有潜在 TOCTOU 窗口以及未复现的其他跨视图疑点。
