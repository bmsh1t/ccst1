# 全仓审核设计

## 1. 审核边界

本任务只产出审查证据和整改建议，不修改生产代码。当前工作树是主对象，`HEAD` 是归因对照面。
所有结论都以项目真实产品契约为准：Claude slash command/inline runtime 是主入口，根目录
`agent.py`、`brain.py` 和 `tools/hunt.py --agent` 是兼容保留的 legacy local-agent 入口。

不拆子任务，也不使用子代理。各工作流共享状态 owner、runtime 和测试契约，拆成独立任务会增加
重复读取和交叉归因；一个任务内按工作流分段、最后统一交叉验证更可靠。

## 2. 基线与归因

审核启动时记录：

- `HEAD` commit 与分支关系；
- tracked dirty paths、untracked paths、diff stat 和 staged 状态；
- 任务期间工作树是否发生变化。

问题基线标签：

| 标签 | 含义 |
|---|---|
| `HEAD` | 在提交态可复现，当前未提交改动不影响根因 |
| `WORKTREE` | 只存在于当前未提交内容，或未提交内容使问题尚未闭合 |
| `BOTH` | 提交态已有根因，当前改动仍保留或扩大问题 |

不使用 stash、reset、checkout 或临时改写用户文件来切换基线。需要比较时读取 `git show HEAD:path`
或导出只读临时副本；临时测试只写 `/tmp`。

## 3. 审核模型

### 3.1 工作流地图

按真实数据流建立一张统一地图：

```text
command / scope / auth
  -> recon + browser/source evidence
  -> surface + context + knowledge recall
  -> hypotheses + Action Queue
  -> validation runner + raw evidence
  -> Evidence Ledger -> Finding -> Queue/Checkpoint
  -> report + memory + next-session projection
```

每个节点记录入口、owner、schema/identity、writer、consumer、派生缓存、错误出口和主要测试。

### 3.2 审核工作流

1. 产品/runtime/文档契约与真实入口。
2. 状态 owner、持久化、锁、原子写和重放收敛。
3. Recon/Surface/Context/Knowledge 的完整性、预算与派生边界。
4. Validation/Evidence/Finding/Queue/Checkpoint 的证据和生命周期门禁。
5. 外部命令、路径、认证、凭据、日志、超时、并发与失败降级。
6. 依赖、打包、shell/Python 双入口、Legacy 兼容和文档漂移。
7. 测试与生产入口的 wiring、负向路径、故障注入和断言有效性。

### 3.3 证据等级

从强到弱：

1. 隔离环境中的最小复现或失败测试；
2. 生产调用链与确定性输入/输出推导；
3. 多处 owner/schema/runtime 契约冲突；
4. 文档/规范与实现不一致；
5. 启发式风险或代码气味。

只有 1-3 可以直接成为 P0/P1。等级 4 必须证明会误导真实运行才成为行为问题；等级 5 只进入
advisory/技术债，不能伪装成缺陷。

## 4. Finding 契约

每个正式 finding 包含：

- ID、标题、P0-P3 严重度、high/medium 可信度；
- 基线标签 `HEAD` / `WORKTREE` / `BOTH`；
- 用户影响与被破坏的 invariant；
- 根因和真实调用链；
- `file:line` 证据及必要关键原文；
- 最小复现、目标测试或静态验证结果；
- 最小修复方向、兼容风险和建议批次。

严重度以影响为准：P0 为数据丢失、越界执行或核心流程普遍不可用；P1 为可复现的核心 invariant
破坏；P2 为有条件行为缺陷、明显测试盲区或高收益技术债；P3 为低风险一致性/维护问题。

## 5. 输出

审核产物写入任务目录 `research/`：

- `baseline.md`：工作树和 HEAD 基线；
- `architecture-map.md`：入口、owner 和数据流地图；
- `validation-results.md`：门禁/测试及失败归因；
- `audit-report.md`：最终 findings、advisories、测试缺口、治理批次和残余风险。

报告先列问题，按严重度排序；没有证据的问题放入“未证实线索”，不混入整改优先级。

## 6. 安全与运行约束

- 不读取 `.env`、`.private/`、真实凭据内容或目标专属响应正文。
- 不执行真实目标扫描、浏览器访问、外部网络请求或状态改变命令。
- 测试只使用 synthetic fixture、`tmp_path`、localhost 或从 index 导出的 `/tmp` 副本。
- 门禁失败先归因；不得为了全绿扩展成无关修复。
- 发现并发工作树变化时停止引用旧行号，重新读取受影响的小范围证据。

## 7. 停止条件

当入口、状态、知识、验证、外部集成、测试和文档七个工作流均完成证据检查，所有 P0-P2 候选
经过复核，目标门禁结果已记录，且报告满足 PRD 验收项时结束。审核不以“提出更多重构”为目标。
