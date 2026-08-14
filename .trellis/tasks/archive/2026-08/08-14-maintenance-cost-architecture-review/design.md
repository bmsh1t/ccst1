# 项目维护成本与架构复核设计

## 1. 审核边界

本任务是上一轮全仓审核后的增量复核。当前工作树是主对象，`HEAD` 用于判断问题来自已提交实现
还是未提交改动。复用上一轮已经建立的入口、owner 和数据流地图，只对近期修复影响和剩余热点做
增量追踪。

本任务使用 inline 方式执行，不使用子代理。审核仅写当前任务目录下的 `research/`，不修改生产
代码、测试、runtime 模板或用户已有未提交文件。

## 2. 架构观察模型

按一条端到端数据流审查，而不是按文件逐个点评：

```text
command / target / scope / auth
  -> runtime bootstrap + coordinator
  -> recon / surface / context / knowledge recall
  -> hypothesis + Action Queue
  -> validation runner + raw evidence
  -> Evidence Ledger -> Finding -> Queue / Checkpoint
  -> report / target memory / next-session projection
```

每个节点只记录七项：入口、职责、owner、schema/identity、writer、consumer、错误/恢复出口。由此判断
依赖方向、第二真相源、跨 owner 收敛和修改局部性。

## 3. 维护成本评级

每个维度使用统一三级定义：

| 评级 | 判定 |
|---|---|
| 低 | 边界清楚，常见修改局部完成，失败可定位，现有测试能证明核心契约 |
| 中 | 需要跨模块理解或人工协调，但已有 owner、恢复路径或门禁控制风险 |
| 高 | 常见修改跨多个隐式边界，失败难恢复/难归因，或缺少能证明关键契约的测试 |

评级必须同时包含代码证据和实际维护后果。文件大、模块多、存在 advisory 本身不构成高成本。

## 4. 基线与归因

- 开始和结束均记录 `HEAD`、tracked dirty、untracked、staged 和 diff stat。
- 当前结论标签使用 `HEAD`、`WORKTREE`、`BOTH`。
- 对上一轮 findings 建立追踪表，优先读取修复提交及当前共享边界，不重新扫描所有旧证据。
- 若工作树在审核期间变化，只重查受影响路径和结论，不回滚用户改动。

## 5. 证据和验证

证据强度从高到低为：目标测试/最小复现、确定性生产调用链、owner/schema 契约冲突、文档漂移、
代码气味。当前行为问题要求前三类证据；后两类只进入 advisory 或技术债。

验证采用最小预算：

1. 静态治理命令确认 runtime 和 knowledge 当前状态；不执行 `runtime_doctor --sync`。
2. 对已解决债务运行一个聚焦回归集合，确认审批、auth 隔离和原子持久化契约仍在。
3. 复用当天最近的完整测试结果，不因只读架构复核重复全套测试。
4. 使用 `git diff --check` 和起止快照证明审核没有污染生产工作树。

## 6. 输出结构

- `baseline.md`：当前 Git/工作树、近期修复和旧审核输入。
- `architecture-map.md`：当前入口、owner、依赖和端到端数据流。
- `maintenance-review.md`：评级矩阵、优势、热点、债务追踪、最小治理顺序和无需治理项。
- `validation-results.md`：命令、结果、覆盖含义、限制和失败归因。

报告先回答总体维护成本和架构结论，再给证据。建议按“现在处理 / 随改随治 / 暂不处理”分类，
避免把整个项目改造成新的架构作为默认答案。

## 7. 风险与停止条件

- 旧报告的行号可能因近期提交变化，最终引用必须以当前文件重新定位。
- 完整测试发生在 request-guard 修复前，因此只能作为广覆盖背景；request-guard 使用其提交后的
  聚焦回归证据。
- `hunt.md` drift 只记录，不治理，也不据此把运行时整体评为高成本。
- 当所有评级有证据、旧 findings 完成追踪、剩余 P2 线索完成取舍且起止基线一致时停止。
