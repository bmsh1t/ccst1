# AI-first 执行面收敛完整方案

状态：Wave 0-9 已执行并验收（2026-09-01）

本方案以现代模型自主推理为默认前提：AI 负责假设、路线、具体测试输入、预算和停止条件；确定性代码只保留 AI 无法可靠替代的能力，包括 Scope/Auth、红线、预算、稳定重放、持续回调、原始证据、canonical 写回、恢复和生命周期所有权。

本方案不创建 Trellis 任务，不修改 durable schema。每个阶段必须形成可独立审查、验证和回滚的提交。

## 1. 优化目标

删除固定输入、固定路线和低复用专项执行器，同时保留现有文件化证据链、状态恢复和可审计性。

目标运行链路：

```text
Rules / Skills / Knowledge
          |
          v
AI 选择假设、具体输入、执行媒介、预算和停止条件
          |
          v
Browser / MCP / curl / raw sender / 通用确定性原语
          |
          v
Raw evidence + canonical owner mutation
          |
          v
Queue / Ledger / Finding / Checkpoint projections
```

`request-diff` 只是可选的精确 HTTP 证据重放器，不是默认测试大脑，也不扩张为万能协议 Runner。

## 2. 最终组件决策

### 2.1 保留为核心能力

| 能力 | 决策 | 保留原因 |
|---|---|---|
| Browser 与 MCP 探索 | 保留 | 保存真实应用状态，让 AI 跟随目标行为动态测试。 |
| `curl`、本地 HTTP helper、raw sender | 保留 | AI 直接执行具体请求的最低成本媒介。 |
| `validation_runner.py` | 保留 | 提供 canonical evidence、operation binding 和 Ledger/Finding/Queue 写回。 |
| `request_diff.py` / `request-diff` | 保留但可选 | 精确的同方法、单变量 HTTP 请求对重放和 diff。 |
| `workflow_sequence.py` | 解耦后保留 | 有序业务流、短期 token 刷新、预算和恢复不能依赖模型自述。 |
| `timing_sql_runner.py` | 解耦后保留 | 交错采样、Median/MAD、请求上限和可恢复证据需要确定性实现。 |
| `oast_listen.py` | 收缩为 Listener-only | 持续回调通道、PID 生命周期和关联状态需要代码。 |
| actor/role replay 与 Case State | 保留 | 多身份连续性和可重复权限证据仍有独特价值。 |
| `sender_semantics.py` 与 byte-exact sender | 保留 | 浏览器和 `urllib` 无法证明线级连接语义。 |
| `graphql_audit.sh` | 保留为可选发现便利工具 | 不成为生命周期 owner，也不进入强制路线。 |
| `zero_day_fuzzer.py` | 暂时保留 | 遵循既有明确决策，只允许 AI 按证据触发，输出保持 advisory。 |

### 2.2 删除或收缩

| 当前组件 | 最终决策 | 替代路径 |
|---|---|---|
| `scripts/dork_runner.py`、`scripts/full_hunt.sh` | 先独立完成当前删除 | 使用现有 `hunt.py`、Recon、Surface 和 AI 选路。 |
| `sneaky_bits.py`、`poc_generator.py` | 删除 | AI 按当前验证点生成精确的本地测试输入或证明材料。 |
| JSON/SQL 固定矩阵 | 解除依赖后删除 | AI 直接请求；适合时用 `request-diff`；只有 timing-shaped 证据进入 Timing Runner。 |
| WAF 编码目录和 WAF plan 栈 | 随 JSON/SQL/403 调用方删除 | AI 选择与目标证据绑定的表达形式，由通用 HTTP 执行记录。 |
| `bypass_403.sh`、`bypass_403_plan.py` | 删除（已完成） | AI 使用 browser/curl/raw request；兼容请求对可选用 `request-diff`。 |
| OAST 固定测试输入目录和 `payloads` 命令 | 删除 | AI 将当前 callback URL 放入自己选择的目标相关测试输入。 |
| `vuln_scanner.sh` 固定主动 lane | 退出默认 breadth | 保留扫描器账目和候选提取，由 AI 根据证据直接测试。 |

历史 CHANGELOG 记录保持历史原样。活动文档、命令、Rules、能力画像、Queue hint 和测试不得继续宣传已删除工具。

## 3. `request-diff` 的明确边界

仅当以下条件全部成立时使用 `request-diff`：

1. AI 已经确定精确的 baseline 和 variant 请求。
2. 两个请求均属于当前 TARGET，并使用相同 HTTP 方法。
3. 只改变一个 query、path、header、cookie 或 text/JSON/form body 维度。
4. 当前验证需要稳定重放、raw evidence、diff、operation hash 或 canonical 写回。

以下场景不要求经过 `request-diff`：

- 前期探索和动态选路；
- multipart、compressed wire body；
- protobuf/gRPC、WebSocket frame；
- byte-exact、连接复用和 desync 语义；
- 多步骤浏览器状态或复杂业务流。

这些场景保留 browser/request raw evidence。没有适配 Runner 时，写入 target-owned `finding_claim`，由 `checkpoint.py` 通过既有 Finding owner 对账。Unsupported 只能保持 unresolved/manual，绝不能变成 `tested_clean`。

不新增 WebSocket、gRPC、GraphQL 或 LLM/RAG 专项自动 Runner。

## 4. 固定执行顺序

### Wave 0：封存当前旧入口清理

范围：

- 将当前 `scripts/dork_runner.py`、`scripts/full_hunt.sh` 删除与后续架构变化隔离。
- 同一提交只包含相关文档和测试清理。
- 确认活动命令、hook、文档和代码均不再调用这两个入口。

验收：

- 已有聚焦回归继续通过。
- `git diff --check` 通过。
- 仓库检索不存在活动引用。
- 完成独立 commit 和 push 后才能进入 Wave 1。

回滚：单独 revert，不影响后续执行策略。

### Wave 1：发布 AI-direct 路由契约

先改活动路由，再删除实现，涉及：

- `docs/architecture-contract.md`
- `docs/evidence-runners.md`
- `docs/tool-index.md`
- `docs/autopilot-lanes.md`
- `rules/tool-ai-boundary.md`
- `rules/hunting.md`
- `rules/playbook-router.md`
- `agents/autopilot.md`
- 相关 command 文档和活动 Trellis contract

必须固化：

- Browser/MCP/curl/raw sender 的 AI 直接测试是默认路径。
- Runner 只是可选的确定性证据原语。
- `request-diff` 不生成测试输入，不判断业务影响和最终状态。
- Unsupported shape 保持未解决，不得写成 clean。
- 已删除工具不得继续作为默认路由或能力前置条件。

验收：

- 聚焦 governance/doc contract 测试。
- 检索强制 `request-diff` 文案和即将删除的 command hint。

回滚：纯契约提交，可独立 revert。

### Wave 2：删除独立叶子工具

删除：

- `tools/sneaky_bits.py`
- `tools/poc_generator.py`
- 活动 tool-index 和 command 引用

不修改历史 CHANGELOG。

验收：import/reference 检索，以及聚焦 tool-index/command contract 测试。

回滚：独立删除提交。

### Wave 3：先解耦必须保留的通用执行器

`workflow_sequence.py` 已改为文件内部最小的 stdlib atomic summary write，不再依赖固定 JSON probe。

`timing_sql_runner.py` 已从 SQL/JSON probe 栈解耦，使用本地请求变异、transport、公开 URL、WAF observation 和 atomic write：

- 使用 `urllib.parse` 的局部 query/form 单参数变异；
- 现有 target/Scope/Auth HTTP 执行边界；
- 现有 public URL projection；
- 仅供 Timing classification 使用的最小局部 transport/WAF observation；
- 局部 stdlib atomic summary write。

禁止引入 generic adapter framework 或新状态 owner。

验收：

- `tests/test_workflow_sequence.py`
- `tests/test_timing_sql_runner.py`
- 固定矩阵模块不在 `sys.modules` 时的直接 import smoke
- operation budget、partial、Queue 写回和恢复断言

回滚：一个执行器解耦提交。

### Wave 4：OAST 收缩为 Listener-only

保留：

- `start`、`poll`、`stop`、`status`、`cleanup`；
- provider 生命周期、PID 检查、target path 和 callback correlation；
- callback evidence 和 Action Queue 同步；
- 外部 provider 同意门和失败语义。

删除：

- `OAST_PAYLOAD_TEMPLATES`；
- `payloads` 子命令和 legacy `--payloads`；
- `payloads_<class>.txt` 生成；
- 指挥 AI 执行固定输入目录的文案。

替代契约：AI 读取当前 callback URL，并将其嵌入自己基于 TARGET 行为选择的测试输入。

验收：

- listener 生命周期和 callback poll 测试保留；
- 删除固定输入生成测试；
- callback/Queue schema 不变；
- 旧 callback 状态可以正常恢复。

回滚：独立 OAST 提交。

### Wave 5：删除 403 专项执行栈（已完成）

删除：

- `tools/bypass_403.sh`
- `tools/bypass_403_plan.py`
- 专项测试和 capability-profile 条目

保留 auth/path-normalization Knowledge cards，并将运行路线统一为：

```text
AI 观察到 access boundary
-> AI 选择一个精确的 path/header/method 表达
-> browser/curl/raw sender 执行
-> exact-pair contract 适配时可选 request-diff
-> 不适配时保存 raw evidence/finding_claim/checkpoint
```

不得为了吸收 method-changing 或 wire-specific 403 测试而扩张 `request-diff`。

验收：

- 活动引用不再输出已删除命令。
- 通过通用 HTTP 测试继续覆盖 AuthSession 和 Scope。
- 本地 access-boundary fixture 证明不依赖专项工具也能进入 checkpoint。

回滚：独立 403 删除提交。

### Wave 6：删除 JSON/SQL/WAF 固定矩阵（已完成）

Wave 3 完成后删除：

- `tools/json_inject_probe.py`
- `tools/sql_parameter_probe.py`
- `tools/sql_payloads.py`
- `tools/waf_encoder.py`
- `tools/waf_pass_plan.py`
- 对应固定矩阵测试

已确认 retained production code 和 403 栈均无引用，`tools/waf_response_analyzer.py` 已一并删除。

移除新运行路由：

- `tools/hunt.py` 中的固定 JSON wrapper
- `tools/capability_profile.py` 中的固定 probe readiness（保留 AI-selected/context-only lane）
- command docs、Rules、tool index、hooks 和活动 Trellis specs

历史恢复兼容：

- `autopilot_state.py` 可继续只读旧 `json_inject`、`sql_matrix` summary。
- `checkpoint.py` 不得生成已删除命令；旧 candidate summary 转成通用 AI evidence-review action。
- 旧 partial/invalid summary 保持 unresolved，并指向原 artifact。
- 不再存在新 writer。
- 不迁移、不重写、不删除历史 TARGET artifact。

验收：

- Workflow 和 Timing 在删除模块不存在时仍可导入和运行。
- 带旧 JSON/SQL summary 的 fixture 恢复时不崩溃、不产生 dead command hint。
- 新 TARGET 不产生 JSON/SQL 固定矩阵状态。
- `request-diff` 聚焦测试继续证明可选 exact-pair 证据链。

回滚：删除与兼容路由必须作为一个原子提交。

### Wave 7：收缩 `vuln_scanner.sh`

保留：

- TARGET、Scope/Auth 过滤和 runtime scan lock；
- Nuclei breadth wrapper 和有界目标选择；
- SSRF、redirect、ID-shaped route、auth、协议等被动候选提取；
- 已经有预算边界的第三方扫描结果收集；
- partial/failure marker；
- `summary.json`、各 lane 的 input/selected/remaining 账目；
- `scanner_pass.json` 和 Finding consolidation。

退出默认执行：

- 硬编码 upload path probe；
- 固定 SQL timing string；
- 固定 XSS/SSTI 主动 sweep；
- 固定 MFA/OTP 请求和虚构 endpoint path；
- SAML signature-stripping 请求和虚构 endpoint path sweep。

SAML/MFA/XSS/upload 信号仍可从 Recon、browser、source、JS 或 scanner artifact 提取为 advisory candidate，但不会触发固定主动请求。

兼容规则：读者仍依赖的 summary lane name 可以保留；未执行工作必须表示为 skipped/remaining，而不是 tested 或 clean。不得为本次清理新增 scanner owner 或 schema。

验收：

- `bash -n tools/vuln_scanner.sh`
- 聚焦 summary、partial、remaining、Scope/Auth 和 scanner-pass 测试
- 断言固定输入和虚构 path list 已消失
- 本地 breadth fixture 仍产生 target-owned candidate 和真实 residual ledger

回滚：Scanner 独立提交；这是最高风险阶段。

### Wave 8：对齐活动文档和残留引用

只更新活动材料：

- README、tool index；
- command、agent route；
- Rules 和相关 Knowledge link；
- capability profile；
- 活动 Trellis contract；
- 当前工具可用性测试。

历史 CHANGELOG 和 archived plan 不改，除非被 runtime reader 执行。禁止为已删除 CLI 增加兼容 wrapper。

验收：

- 删除名称只允许出现在历史/归档上下文；
- Knowledge strict audit 和 recall 测试；
- runtime drift、architecture contract 测试；
- `git diff --check`。

回滚：独立文档/spec 对齐提交。

### Wave 9：本地 Before/After 验收

使用相同模型和配置运行现有本地 fixture，比较真实行为而不是只看行数。

必须覆盖：

1. AI 不依赖专项 Runner，发现并测试一个 browser/API hypothesis。
2. 一个精确 HTTP 请求对可选进入 `request-diff`，产生 raw evidence、artifact hash、operation ID、Ledger record 和 candidate projection。
3. 一个 unsupported request shape 保持 unresolved，通过 raw evidence 或 `finding_claim` 进入 checkpoint，不得标记 clean。
4. timing-shaped hypothesis 使用保留的统计 Runner。
5. 多步骤业务流使用保留的 Workflow Runner。
6. OAST sink 使用保留的 Listener 完成 callback correlation，不调用内置测试输入目录。
7. Broad scanner 输出保留 partial 和 `remaining` 账目。
8. 进程重启后恢复相同 Finding、Queue action、evidence reference 和下一条 unresolved question。

最终质量门：

- 每个变化边界的聚焦测试；
- core contract suite；
- 因为属于跨模块删除，最终运行一次 full suite；
- Knowledge audit、runtime drift、Shell syntax、dead-reference search 和 diff inspection；
- 各 Wave 按顺序独立 commit/push。

实际验收结果：localhost Autopilot/runner/report fixture、两轮恢复 fixture、
文档/路由聚焦回归均通过；Knowledge strict audit 无错误；runtime drift 为 0；
Shell syntax 和 dead-reference 检查通过；最终全量测试 `3546 passed`。

## 5. 完成标准

只有同时满足以下条件才能宣布完成：

- AI 直接测试在文档和实际路由中都是默认路径。
- `request-diff` 保持可选，unsupported 边界没有被扩大或伪装成 clean。
- Core Skill 和被删除工具组中不存在固定输入目录。
- 活动 route、Queue hint、capability profile、spec 不再调用已删除 CLI。
- Timing、Workflow、Browser、Actor pair、OAST Listener、byte-exact 执行边界仍可用。
- 没有新增或合并 durable owner/lifecycle schema。
- 历史 JSON/SQL summary 可读，但不能调度 dead tool。
- 固定 sweep 删除后，Scanner residual 仍可见，不能因此得到 `tested_clean`。
- Restart/recovery 和 canonical evidence binding 一致。
- 本地 fixture 同时证明 AI-direct 和 deterministic evidence 路径。

维护目标：

- 在 OAST/Scanner 收缩之前，先从固定矩阵、403、WAF 和叶子工具中删除约 5,700 行生产代码；行数只是结果，不是验收门。
- 将活动执行入口收敛为少量通用边界。
- 普通判断和覆盖变化默认只修改 Skill/Knowledge/Rules，不触碰 durable owner。
- 继续既有十次真实变更统计，不人为制造提交满足指标。

## 6. 风险与控制

| 风险 | 控制 |
|---|---|
| 无人值守固定 sweep breadth 下降 | 保留 Recon/Nuclei/被动候选提取，并用本地 Before/After 验证。 |
| 删除 helper 破坏保留工具 | 必须先完成 Wave 3，再执行 Wave 6。 |
| 旧会话生成 dead command | 保留只读兼容，将旧 summary 转成通用 evidence review。 |
| `request-diff` 变成新的固定轨道 | Contract test 固化 optional 文案并保留 `manual_required`。 |
| Scanner 在删 lane 后错误完成 | 保留 remaining、partial 和 non-clean 语义。 |
| 清理演变成新框架重写 | 不新增 RuntimeStore、数据库、adapter layer、result schema 或协议 Runner。 |
| 大 diff 难以核验 | 每 Wave 独立提交，Wave 7 单独处理。 |

## 7. 最终方案复核

### 架构合理性：通过

方案保持五层契约：AI 负责判断，既有 owner 保管事实，通用执行边界生成证据，Projection 仍然可重建。

### 现代 AI 能力发挥：通过

固定输入目录和默认专项路线被移除，Browser、MCP、HTTP、Workflow、Timing、Callback、Role 和 raw-wire 选择仍完整开放。

### 证据与恢复：有前置条件地通过

如果先删 JSON/SQL 再解耦 Timing/Workflow，会造成 P0 回归。因此 Wave 3 -> Wave 6 的顺序不可调整。历史 summary 只能作为只读兼容证据。

### 维护成本治理：通过

低收益的大型专项组直接删除，不再套兼容 wrapper 或新框架。剩余专项代码只对应持续进程、统计采样、多身份或线级语义等 AI 无法稳定替代的能力。

### 功能权衡：接受

无人值守的固定盲扫 breadth 会缩小，这是单机、单操作者、现代模型定位下的主动选择。只有 Wave 9 证明 AI-direct 仍能产生 canonical evidence，且 Scanner 保持真实 residual 账目后，才允许接受这一权衡。

### 过度设计复核：通过

方案没有引入万能执行器、插件层、数据库、迁移框架或新 schema；优先使用删除、stdlib 局部 helper 和现有 owner API。

### 最终结论

方案已按 Wave 0 -> Wave 9 分阶段执行并通过最终质量门。Wave 3、Wave 6、Wave 7
仍保持独立提交；本地 Before/After、restart/recovery、canonical evidence 和
残余账目验收均已完成。本次清理没有新增未完成的实现项；后续只按十次真实能力变更
观测指标复盘 Skill/Knowledge/Rules-only 比例，不人为制造提交。
