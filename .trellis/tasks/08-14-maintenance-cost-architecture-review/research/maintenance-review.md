# 项目维护成本复核

日期：2026-08-14

## 总体结论

**总体维护成本：中。**

架构的事实 owner、身份、原子写、错误语义和重放边界已经相当明确，测试也能证明关键契约；主要
成本来自业务投影集中在几个大型协调模块、文件型多 owner 的重放诊断，以及保留 Legacy 精确续跑
所需的兼容面。当前没有 P0/P1 架构或治理错误，也没有理由进行全仓重构。

## 评级矩阵

| 维度 | 评级 | 结论 |
|---|---|---|
| 修改局部性与协调器耦合 | 中 | 普通 owner 修改局部；Checkpoint/Context Pack/Autopilot 投影修改需要跨多个契约理解 |
| 状态持久化、恢复与跨文件收敛 | 中 | 单 owner 写入保护强；跨 owner 无事务但有 operation replay、partial 诊断和故障注入 |
| 依赖方向、重复实现和第二真相源 | 中 | owner 方向清楚，无第二 Finding 生命周期；Checkpoint/Queue 存在受控循环和私有 helper 依赖 |
| 测试定位、故障注入和回归信心 | 低 | 196 个 focused 测试文件；核心原子写、并发、损坏输入和重放均有行为测试 |
| Runtime、知识治理和文档同步 | 中 | 门禁完整；runtime 有一项 advisory drift，知识路由仍横跨 registry/Context Pack/召回案例 |
| Legacy 兼容与发布可复现性 | 中 | 主/Legacy 文档边界清楚，但 Legacy session 仍有局部数据丢失风险；三个顶层依赖未固定版本 |
| 运行诊断、错误可见性和人工介入 | 低 | canonical 损坏普遍 fail-fast，runner 返回逐 owner 状态，治理工具可复现当前 drift/collision |

“低”表示该维度当前维护成本低，不表示功能简单；“中”表示需要跨模块理解但已有明确缓解；本轮
没有证据支持任何维度评为“高”。

## 已解决债务

### 上一轮 finding 追踪

| 旧 finding | 当前状态 | 归因 |
|---|---|---|
| F-01 scanner 默认 executable upload | 已由 `a2cca49` 修复并回归 | `HEAD` |
| F-02 `brain.py` model-text -> shell 路径 | 行为未宣称修复；按用户确认冻结为不接入正式能力的 Legacy 分析入口，本轮排除，不重新激活 | `HEAD` residual |
| F-03 AuthSession 跨目标来源合并 | 已由 `6a59128` 修复并回归 | `HEAD` |
| F-04 显式缺失 auth file 静默匿名 | 已由 `6a59128` 修复并回归 | `HEAD` |
| F-05 target profile 中断/损坏丢历史 | 已由 `6a6e661` 修复并回归 | `HEAD` |

因此当前正式主路径没有遗留的上一轮 P0/P1 finding。冻结 Brain 的旧路径保留为明确 residual，既不
计入 inline 主架构的开放缺陷，也不能被误写成“已经修复”；只有未来重新支持该入口时才需要先
重开边界评审。

### 1. Scanner executable upload approval - 已解决 / `HEAD`

统一 `scanner_probe_guard()` 保留普通 POST，同时让明确可产生持久副作用的动作要求单次
`ALLOW_UNSAFE_HTTP_TESTS=1`（`tools/vuln_scanner.sh:257-310`）。上传回归同时证明默认跳过和显式
批准路径（`tests/test_vuln_scanner_script.py:142-161`）。OTP/MFA 与 SAML POST 保持既定默认能力，
没有退化为按 HTTP method 一刀切。

### 2. AuthSession target isolation / explicit file errors - 已解决 / `HEAD`

显式缺失/不可读/损坏 auth file 在共享 loader 失败（`tools/auth_session.py:205-244`）；多来源合并
在 header merge 前拒绝目标冲突（`:284-318`）；case-state import 绑定 CLI target
（`tools/target_case_state.py:1281-1304`）。这比调用方各自过滤更便宜且更可靠。

### 3. Target profile 与 request guard 持久化 - 已解决 / `HEAD`

两者都已使用同目录临时文件、flush、`fsync`、replace，并将损坏状态与真正缺失分离：
`memory/target_profile.py:97-142`、`tools/request_guard.py:90-157`。本轮聚焦回归继续通过。

### 4. Ledger -> Finding -> Queue 失败重协调 - 已解决行为缺口 / `HEAD`

`sync_runner_artifacts()` 保留 summary witness 并逐 owner 报告状态
（`tools/validation_runner.py:1213-1242`）。参数化测试在 Ledger、Finding、Queue 三个边界分别失败，
重放后断言 Ledger 一行、Finding event 一行、Queue attempt 一次，再重放为 deduplicated
（`tests/test_validation_runner.py:2354-2396`）；另有 canonical Finding 已写但 event append 失败的恢复
（`:2399-2428`）。剩余“无跨文件事务”只是中等结构成本，不是开放正确性问题。

### 5. Knowledge trigger collision - 已治理 advisory / `HEAD`

collision 仍由治理工具明确输出 advisory（`tools/capability_governance.py:116-130,222-229`）。
Context Pack 固定两张 Card 预算、selected/deferred 和 reason（`tools/context_pack.py:631-659,
2111-2154`）；正向、稳定排序、负向和预算回归在 `tests/test_context_pack.py:723-783`。不删除通用
触发词，也不继续增加治理层。

## 当前验证问题

### F-01 - P2 / high / `HEAD`: 显式 Legacy agent session 损坏会静默清空并覆盖历史

**影响。** 用户显式选择 `tools/hunt.py --agent --resume` 时，半截或损坏的
`agent_session.json` 会被当成空 working memory；下一次 `save()` 直接覆盖文件，丢失原 working
memory、findings log、completed steps 和 step count。inline `/autopilot` 不使用该文件，因此主路径
不受影响。

**根因。** `HuntMemory._load()` 捕获所有异常后静默继续，`save()` 使用直接 `write_text()`：
`agent.py:1458-1489`。当前兼容测试覆盖 resume 路由和正常 session，但没有损坏输入、原子替换或旧
字节保留回归。

**验证。** `/tmp` 最小复现先写入 `working_memory=SAMPLE, step_count=7`，再模拟半截 JSON；重新
加载得到空 memory/0 steps，调用 `save()` 后磁盘也变为空 memory/0 steps。

**最小治理。** 只在 `HuntMemory` 内复用同目录临时文件 + `fsync` + replace，并让已存在的损坏
JSON 以带路径错误停止 exact resume；增加损坏输入和 replace 失败两项回归。不要移动 Legacy 入口、
不要接入正式状态 owner，也不要修改冻结的 `brain.py`。

## 结构性债务与取舍

### 随改随治：Checkpoint / Action Queue 兼容循环

Checkpoint 导入 Action Queue 私有 helper，Action Queue 的 convenience path 延迟导入 Checkpoint
（`tools/checkpoint.py:29-41`、`tools/action_queue.py:1404-1410`）。现有 ingest、并发和幂等测试充分，
没有行为缺陷。后续真正修改该边界时，优先把触及的纯 conversion/schema 变成可独立测试的公开
owner helper；不要按文件行数拆分，也不要新增 coordinator。

### 随改随治：大型投影协调器

`checkpoint.py`、`autopilot_state.py`、`context_pack.py` 聚合多个 owner，但写入权仍在 owner，主函数
内部大量逻辑已是可测试纯函数。只有后续需求同时修改复杂分支时才提取相关纯函数或 IO helper；
目前拆文件不会减少契约数量，收益不足。

### 暂不处理：Knowledge 路由双重描述

Registry 拥有 ID/file/layer/load/triggers，Context Pack 拥有运行时正则和稳定优先级。此前将路由别名
推入 Registry 的试验只制造了重复来源并已撤回。现有 collision 回归稳定，继续全量迁移没有实际
收益；仅在新增 Card 真实需要相同路由判断修改三处以上时重新评估。

### 暂不处理：Legacy 双入口和冻结 Brain

主/Legacy session 语义在 README、PRODUCT 和 contract tests 中已清楚分开。`brain.py` 不再接入正式
能力，删除或移动只会制造兼容风险。保留入口；F-01 只修其局部持久化可靠性。等有实际使用统计且
确认无人使用后，再单独规划退役。

### 发布时处理：依赖可复现性

`requirements.txt:1-4` 只有 `badsecrets==1.2.1` 固定版本，`anthropic`、`requests`、`PyYAML` 未固定，
也没有 lock/constraints。当前项目主要复制 Claude runtime 文件，尚无可复现发布 artifact，因此是
P3 成本。只有发布可重复安装包或 CI 基线时再增加 constraints/lock 流程。

### 单独处理：`hunt.md` runtime drift

Runtime doctor 仍报告一项 commands advisory、critical drift 0。用户已明确排除，本轮不同步、不把
它混入状态或架构修改。

## 建议优先级

1. **现在处理：F-01 Legacy session 原子写与损坏 fail-fast。** 局部改动、直接避免 exact resume
   数据丢失，不改变架构。
2. **随改随治：Checkpoint/Queue 循环和大型协调器。** 只提取当前修改所需的纯函数/schema/IO helper。
3. **发布时处理：顶层 Python 依赖约束。** 在真正需要可复现 artifact 时做。
4. **暂不处理：多 owner 事务、trigger collision、Legacy 退役、Brain 重构。** 当前保护已足够，
   进一步治理没有可证明收益。

## 不建议做

- 不引入数据库、事件总线、Mutation Coordinator 或全局 writer。
- 不合并 Ledger、Finding、Queue、Checkpoint、Coverage 或 Target Memory。
- 不按行数拆 `checkpoint.py`、`context_pack.py`、`autopilot_state.py`。
- 不删除通用 trigger，不扩大 Card 默认预算。
- 不删除、移动或重定向 Legacy 入口，不重新激活冻结的 `brain.py`。
