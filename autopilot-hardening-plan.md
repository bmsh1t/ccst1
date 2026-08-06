# `/autopilot` 架构与能力加固规划

> 状态：规划稿
> 负责人：待分配
> 目标运行环境：Linux / Claude CLI
> 适用入口：`/autopilot`、`/autopilot-round`、`/loop`
> 基线：本规划基于 2026-08-05 的项目摘要、代码审计与既有测试基线生成。

## 0. 已确认执行决策

- `finding_index.py` 继续拥有 Finding 生命周期；`action_queue.py` 继续拥有可执行队列；
  `evidence_ledger.py` 是追加式证据事件流，不迁移为 Finding/Queue 的第二事实源。
- Ledger 的 closure identity 固定为 `endpoint × vuln_class`。actor/object/method/variant
  只属于证据身份：`endpoint × vuln_class × method × actor × object × variant`，不能改变
  endpoint closure 的聚合键。
- 继续使用现有结果词汇：`lead`、`signal`、`candidate`、`tested_clean`、
  `tested_finding`、`dead_end`、`blocked_redline`、`not_applicable`。不新增未被现有
  consumers 理解的 `closed`、`reopened`、`verified` 或 `false_positive` 状态。
- `context-file` 仅是 Checkpoint/batch continuation owner 生成的内部 artifact；它只保存
  canonical target、Scope/Auth ref/hash、actor refs 和 invocation metadata，不接受任意用户
  路径，也不保存 token、cookie 或 header 明文。
- Juice Shop 只是本地压测负载源。漏洞数量是观测指标，不是固定通过数量；压测必须覆盖
  多轮、大量 URL/request、状态增长、并发/故障注入、磁盘增长和恢复时间。
- 当前运行模型是单 controller。并发测试只验证锁、原子写和恢复语义，不宣称多 controller
  事务支持。
- Runtime critical manifest 只覆盖 `/autopilot` 实际需要的 command、agent、skill 和 MCP
  contract；HackerOne MCP 明确排除。其他 MCP 按 lane advisory/degraded 处理。

## 1. 执行摘要

当前项目已经具备完整的专家型渗透测试骨架：Claude CLI 负责判断和编排，工具负责确定性执行，Scope/Auth/evidence/finding/checkpoint 负责约束与留痕，MCP/browser 负责真实业务流观察。Recon、Surface、Source/JS、SQL、WAF、Workflow、Timing、IDOR/Authz replay、Validation、Report 等能力已形成不同程度的闭环。

当前最大的风险集中在控制面连续性，而不是扫描器数量：

1. 目标字符串在兼容执行路径中可能重新进入 shell，信任边界不统一。
2. 批量资产选中后的单域续跑会丢失父 Scope 与 Auth 语义。
3. Evidence Ledger 的旧终态可能遮蔽后续重开候选，导致 closure 误判；当前投影必须只保留
   每个 closure cell 的最新有效状态。
4. Validation Runner 没有沿用统一的 AuthSession 输入契约。
5. Runner 对 Ledger、Finding、Action Queue 分步写入，失败后可能出现跨所有者不一致。
6. `autopilot_state.py`、`checkpoint.py`、`surface.py` 存在重复决策和身份规范化逻辑，演进成本高。
7. Runtime drift gate 将非关键漂移与 `/autopilot` 关键依赖混为一谈，诊断与阻断耦合。
8. Capability profile 只检查少量固定文件，无法准确表达各 lane 的真实就绪度。

推荐先修复 P1 信任边界和状态语义，再处理 P2 的耐久性、共享原语和运行时策略。所有修复都应优先落在共享边界，避免在每个调用方增加局部补丁。

## 2. 目标与非目标

### 2.1 目标

- 保证目标解析、Scope、Auth、执行、证据、Finding、Queue、Checkpoint 在整个 `/autopilot` 生命周期中语义一致。
- 让每个候选的当前状态由最新有效事件决定，支持现有词汇下的
  `candidate -> tested_clean|tested_finding|dead_end -> candidate` 重开流程。
- 让 Validation Runner、SQL、Workflow、Timing、IDOR/Authz 等 lane 使用同一套认证会话边界。
- 在不引入第二状态所有者的前提下，提高多文件写入的一致性、幂等性和恢复能力。
- 提取少量纯函数作为共享身份/决策原语，降低控制面重复实现。
- 将运行时检查拆分为关键依赖门禁与完整诊断两种语义。
- 将 Capability profile 扩展为按 lane 的可解释、可审计就绪度。
- 保留原始攻击面、原始证据、失败语义、认证边界和人工判断空间。

### 2.2 非目标

- 不把 `/autopilot` 改造成固定顺序扫描器。
- 不新增并行的主状态系统、第二浏览器队列或第二 Finding 索引。
- 不把候选、扫描器命中或覆盖率缺口直接提升为已验证漏洞。
- 不将 DNS 扩展、接管、OAST、云、凭证等可选 lane 强行放入 baseline Recon。
- 不做通用 AST/任意混淆还原、低层 HTTP/2 desync 生成、完整 OAuth 登录编排或自动接管声明。
- 不处理 Windows runtime 漂移；本规划只定义 Linux/Claude CLI 的运行语义。
- 不清理本次审计前已经存在的工作区修改。

## 3. 现状架构与验收基线

### 3.1 控制流

```text
Claude command arguments
  -> runtime gate
  -> capability projection
  -> compact autopilot state
  -> Action Queue / selected lane
  -> deterministic tool execution
  -> raw evidence + Evidence Ledger
  -> candidate / finding lifecycle
  -> Validation Runner
  -> Finding + Queue + Checkpoint write-back
  -> closure projection
  -> report / next round
```

### 3.2 主要模块

| 层 | 关键文件 | 责任 |
| --- | --- | --- |
| 入口与契约 | `commands/autopilot.md`、`docs/autopilot-lanes.md` | round、lane、Scope/Auth、停止和报告契约 |
| 目标与范围 | `tools/target_paths.py`、`tools/scope_context.py` | 目标规范化、资产批次、端口、排除项 |
| 控制状态 | `tools/autopilot_state.py`、`tools/checkpoint.py`、`tools/autopilot_bootstrap.py` | 续跑投影、决策、handoff、闭环 |
| 执行 | `tools/recon_engine.sh`、各 specialist、`tools/runtime_exec.py` | argv/请求/超时/原始工件 |
| 认证 | `tools/auth_session.py`、`tools/_auth_helper.sh` | session、header/cookie、owner/peer |
| 证据与状态 | `tools/evidence_ledger.py`、`tools/closure_resolver.py`、`tools/finding_index.py` | 证据事件、矩阵、终态和索引 |
| 验证与写回 | `tools/validation_runner.py`、`tools/action_queue.py` | replay、diff、Finding/Queue 同步 |
| 诊断能力 | `tools/runtime_doctor.py`、`tools/capability_profile.py` | runtime 漂移和 lane readiness |

### 3.3 质量基线

- Python AST 检查：353 个文件，0 个语法错误。
- Knowledge strict audit：63 个 capability、61 个文档，0 error、0 warning。
- 测试清单：188 个测试文件，约 2840 个测试函数。
- 最近记录的完整基线：`2999 passed`。
- `git diff --check`：退出码 0。
- 实施阶段每个任务必须补充 focused test，并在阶段门禁执行回归集合。

## 4. 优先级与依赖图

```text
P1-A 目标语法 + argv 边界
  |
  +--> P1-B 父 Scope/Auth 连续性
  |       |
  |       +--> P2-A Validation Runner AuthSession
  |
  +--> P1-C Ledger 最新状态 / 重开语义
          |
          +--> P2-B 生命周期幂等重conciliation与耐久写入

P2-C 共享身份/决策原语  <---- P1-A / P1-C 的测试结论
P2-D 关键 runtime gate  <---- P2-C 后统一依赖清单
P2-E lane capability profile <---- P2-A 与现有 specialist 契约

最终：集成回归 -> Linux CLI 压力验证 -> 发布门禁
```

推荐顺序：P1-A、P1-B、P1-C 并行设计，按 P1-A -> P1-B -> P1-C 落地；随后 P2-A、P2-B，再做 P2-C、P2-D、P2-E。任何阶段都先写失败测试，再改共享实现。

## 5. 阶段一：P1 目标解析与 argv 执行边界

### P1-A.1 建立严格的共享目标语法

**问题**

`tools/target_paths.py:26-81` 对任意非 IP 字符串都可能按域名接受。Recon 主路径使用 argv，但兼容路径在 `tools/hunt.py:1917-1931`、`tools/cve_hunter.py:51-53,68-70,121-123,148-153` 和 `tools/runtime_exec.py:77-92` 中重新拼接 shell 字符串。

**实现任务**

1. 在 `tools/target_paths.py` 定义一个共享的解析结果结构，至少包含 `scheme`、`host`、`port`、`path`、`kind` 和 canonical value。
2. 严格区分 URL、裸域名、IPv4、IPv6、CIDR、通配符和批次文件；对空白、控制字符、shell 元字符、非法端口、嵌套 scheme、用户信息段和未闭合 IPv6 统一报错。
3. 保持现有 `canonical_target_value`、`classify_target`、`target_storage_key` 和 `url_belongs_to_target` 的外部返回兼容；内部全部改用共享解析结果。
4. 为历史 state/recon 目录保留只读迁移映射，不把旧 key 当作新输入重新解析。
5. 将错误分类为可向用户显示的稳定错误码，避免调用方根据异常文本猜测分支。

**验收**

- 同一输入在 Recon、CVE、Hunt、Autopilot、Storage key 中得到一致 canonical identity。
- 非法输入在入口处失败，错误不会进入网络请求或 shell。
- 合法 IPv6、端口 URL、列表文件和 wildcard 的现有行为保持不变。

### P1-A.2 统一 argv subprocess API

**实现任务**

1. 在 `tools/runtime_exec.py` 增加面向 argv 的最小执行入口，复用现有超时、进程组终止、stdout/stderr 合并和退出码语义。
2. 将 `tools/hunt.py`、`tools/cve_hunter.py` 兼容路径改为传递 `list[str]`；参数值不再经过 shell 字符串拼接。
3. 保留 `run_shell_command` 仅用于明确声明的脚本兼容场景；所有目标、header、路径、查询参数都走 argv。
4. 对 shell-only 工具建立窄适配器：脚本路径固定、参数白名单固定、目标作为单独 argv 元素传入。
5. 将命令审计日志记录为 argv 数组和脱敏后的环境元数据，避免日志还原出敏感 header。

**测试**

- 目标中包含空格、引号、分号、换行、反斜杠、Unicode 和 shell 元字符时，执行器只产生一个目标参数。
- 超时、信号终止、部分 stdout/stderr、非零退出码的行为与旧 runner 对齐。
- Hunt/CVE 的 dry-run 能精确断言最终 argv，不触发网络。
- Linux 下用临时可执行脚本验证参数边界和进程组回收。

### P1-A.3 发布门禁

- `python -m compileall` 和目标模块 AST 检查通过。
- 目标解析、runtime_exec、Hunt、CVE focused tests 全部通过。
- 记录迁移前后同一目标的 state key、artifact path 和 replay command，确认无路径漂移。

## 6. 阶段二：P1 父 Scope/Auth 连续性

### P1-B.1 扩展批次选择的上下文契约

**问题**

`commands/autopilot.md:72-76` 要求批量目标继承父 Scope/Auth；`tools/autopilot_state.py:1949-2035` 保留批次身份，但单域继续路径在 `:2300` 只按 domain 重建，CLI (`:3729-3758`) 也只有 `--target`。结果会丢失 `out_of_scope`、`excluded_classes`、parent hash 和 batch authentication。

**实现任务**

1. 为 Autopilot continuation 定义 `InvocationContext` 最小序列化结构：父目标、批次 manifest/key、Scope 版本/hash、Auth session ref、owner/peer actor refs、lane policy 和 invocation id。
2. 在 batch state 中写入 context ref；在单域 state 中保留 `parent_scope`、`parent_auth` 和 `selection_provenance`，而不是只写选中 domain。
3. 增加由 Checkpoint/batch continuation owner 写入的固定目录内部 artifact；CLI 只接受该
   owner 生成、target/hash 校验通过的 continuation ref，不开放任意 `--context-file` 路径。
   `--target` 继续支持人工直接调用；两者同时存在时必须校验 canonical target 一致。
4. 兼容旧 state：缺失 context 时显式标记 `legacy_context=true`，继续使用现有目标推断，但把 Scope/Auth 缺失列为阻断原因并要求重新绑定。
5. 在 `tools/auth_session.py:328-352` 的环境投影中增加非敏感 Scope ref、parent hash、session provenance；敏感 header 仍只存 private session 文件。
6. 在 `tools/auth_session.py:425-463` 及 `tools/_auth_helper.sh:60-85` 中禁止把跨目标误判为清空认证；只有 canonical scope 变化且未提供继承证明时才清理 header。

**数据兼容**

- 新增字段均可选，`schema_version` 递增到下一个兼容版本。
- 旧 state 读取不改写原文件，首次成功 continuation 时写出升级副本和迁移记录。
- `parent_scope_hash`、`auth_session_ref` 不包含 token/header 明文。

### P1-B.2 测试矩阵

| 场景 | 预期 |
| --- | --- |
| batch -> domain continuation | 父 Scope、排除类、batch hash 全部保留 |
| batch -> domain + owner/peer | 显式 actor override 生效，其余 auth provenance 保留 |
| context target 与 CLI target 不一致 | 入口拒绝并返回稳定错误码 |
| 旧 state 无 context | 进入 legacy 状态，缺失 Scope/Auth 被明确记录 |
| scope 相同、host 表面不同 | 保留 session，不触发清空 |
| scope hash 变化 | 清理旧认证并要求新绑定 |
| batch auth private ref 缺失 | lane 不执行，checkpoint 写入阻断原因 |

### P1-B.3 验收门禁

- `/autopilot` 新启动、batch 选择、单域续跑、`/autopilot-round` 和 `/loop` 的 context 投影一致。
- Scope 过滤与 Auth actor matrix 在跨轮次后结果相同。
- 日志、checkpoint、报告中只出现 ref/hash，不出现 token/cookie/header 值。

## 7. 阶段三：P1 Evidence Ledger 最新状态与闭合语义

### P1-C.1 修复候选重开

> 执行状态：当前投影、ClosureResolver、Surface 和 Autopilot consumers 已完成；event ID、
> malformed-row diagnostics 和 fsync 仍按后续耐久性阶段处理。

**问题**

`tools/evidence_ledger.py:527-550` 记录新候选时保留旧 `closed_by_key`，summary 可能同时包含同一 cell 的 `closed_cells` 与 `open_candidates`；`tools/closure_resolver.py:129-154` 和 `tools/autopilot_state.py:2697-2755` 会继续消费旧终态。

**实现任务**

1. 将 Ledger 解释为 append-only event stream；closure cell 固定为
   `(endpoint_identity, vuln_class)`，由最新有效事件投影当前状态；actor/object/method/variant
   只用于更细的 evidence matrix。
2. 在 `build_summary` 中按 event sequence/time + stable event id 排序，生成唯一的 `current_status`；旧状态移到 `history`，不再同时进入 closed/open 当前集合。
3. 仅使用现有 Ledger result vocabulary 建立状态转换表；非法/未知结果进入诊断并保留原始
   行，不把新状态写入现有事件流。
4. `closed_by_key` 只在当前状态为终态且对应最新事件仍是终态时生成；`lead`、`signal`、
   `candidate` 立即移除当前 closed projection。
5. `closure_resolver.py` 只消费 `closed_cells` 当前投影，不再从 `recent_entries` 兜底猜测
   旧终态；`autopilot_state.py` 同样不能直接把原始历史终态当作当前闭合。
6. 为 malformed JSONL 行提供可观察计数和 artifact ref；单行损坏不丢弃整条 ledger，但 closure gate 根据损坏程度决定是否降级为 partial。

### P1-C.2 测试

- `candidate -> tested_clean`：cell closed。
- `candidate -> tested_clean -> candidate`：cell open，旧终态只保留在历史事件中。
- `tested_clean -> signal -> tested_finding`：先重开，再由最新终态重新闭合。
- 同 timestamp 事件：按稳定 event id 决定顺序，结果可重放。
- 重复写入同一 event id：summary 幂等，不增加计数。
- malformed row 位于头、中、尾：可报告损坏位置，其他行仍可投影。
- 同 endpoint 不同 vuln class、actor、object scope：互不覆盖。
- closure projection 与 checkpoint/action queue 对当前状态达成一致。

### P1-C.3 验收

- 任一 cell 在 summary 的当前集合中最多出现一次。
- 重新生成 summary 得到字节级稳定结果（时间字段除外）。
- 回放历史事件可得到与当前 summary 相同的状态指纹。
- 既有 `candidate -> terminal` 测试保持通过，并补齐反向序列和损坏输入测试。

## 8. 阶段四：P2 Validation Runner 认证继承

### P2-A.1 统一 AuthSession 输入

**问题**

控制器和 lane 文档要求每个 lane 继承 Scope/Auth；`tools/validation_runner.py:2866-2966` 目前只有 raw header flags，没有 `--auth-file` / `AuthSession`。SQL、Workflow、Timing 等工具已经使用 `session_from_args`，造成同一轮中认证语义不一致。

**实现任务**

1. 在 `validation_runner.py` parser 复用 `auth_session.add_cli_args`，支持 `--auth-file`、session ref、owner/peer 显式覆盖。
2. 在 `main` 和各 runner 入口调用 `session_from_args`；将生成的 headers/cookies 传入请求层，不复制认证解析逻辑。
3. 继承 `ScopeContext` 的 target validation 和 `out_of_scope` 检查；owner/peer override 只改变 actor，不改变父 Scope。
4. raw header 作为兼容输入保留，但与 AuthSession 同时出现时执行确定性优先级，并在结果中记录 provenance。
5. 将 auth 缺失、session 过期、owner/peer 不完整分别编码为可判断的 runner result，而非普通网络失败。

### P2-A.2 测试与验收

- auth-file、bearer、cookie、owner/peer 双 session 的请求快照均正确。
- AuthSession 与显式 header 冲突时，结果和 provenance 符合文档优先级。
- scope 外 URL 在请求前失败；没有网络副作用。
- IDOR/Authz replay 与 SQL/timing workflow 在同一 context 下使用同一认证投影。
- 旧命令行调用不加新参数时行为兼容，输出增加的字段只允许向后兼容扩展。

## 9. 阶段五：P2 跨所有者生命周期一致性与耐久性

### P2-B.1 以 reconciliation 保持单一状态所有者

**问题**

Runner 当前分别写 Ledger、Finding、Action Queue；`tools/validation_runner.py:887-905` 对各同步失败逐项捕获并仍返回 `updated`。Ledger append (`tools/evidence_ledger.py:285-289`) 缺少锁/fsync；JSONL malformed 行被静默跳过。`finding_index` 已有较强的锁、atomic replace、fsync 和 owner provenance，应复用其模式。

**实现任务**

1. 保留现有 Owner：Ledger 只拥有证据事件；Finding 和 Action Queue 各自拥有其 canonical
   lifecycle。reconciliation 通过稳定 operation id 补齐跨 Owner 写入，不改变事实归属。
2. 给每次 runner 写回生成稳定 `operation_id`、`event_id`、`finding_id` 和 `backlog_id`，重复执行安全幂等。
3. 增加一个窄的 `reconcile_runner_artifacts` 流程：按 operation id 对照 Ledger、Finding、
   Queue owner API 幂等补齐缺失写入；任何 owner 写入失败返回 partial/blocked，并写入
   checkpoint。不得从 Ledger 覆盖 Finding/Queue 已有 canonical 决策。
4. Ledger 写入使用同目标锁、临时文件或 append + flush/fsync 的最小耐久策略；锁粒度与 `finding_index` 对齐。
5. 读 Ledger 时返回 `valid_entries`、`invalid_rows`、`last_valid_offset`，让 closure gate 根据损坏情况做明确决策。
6. 将 `_runner_sync_gate_updates`、`_sync_finding_status`、`_sync_action_queue` 的异常语义改为结构化结果，禁止“同步失败但总体成功”。
7. 提供 `repair`/`rebuild` CLI，仅从 Ledger 和原始 finding artifact 重建 projection，默认 dry-run 并输出 diff。

### P2-B.2 验收

- 任一步骤在进程终止后，重跑 reconciliation 可恢复到同一最终 projection。
- 重复 runner invocation 不新增重复 Finding、Queue item 或 Ledger event。
- 断电模拟后，损坏只影响未完成 event；已有有效事件可恢复。
- 报告明确区分 `updated`、`partial`、`blocked`，不把 projection 失败吞成成功。
- repair dry-run 与实际 repair 的结果可审计、可回滚。

## 10. 阶段六：P2 控制面共享原语与复杂度治理

### P2-C.1 抽取最小纯函数边界

> 执行状态：已于 2026-08-06 完成。共享实现为
> `closure_resolver.extract_endpoint_parts/extract_endpoint_path/canonical_endpoint_path`；
> Checkpoint 以 `ACTION_DECISIONS` 对已选 Action Queue 候选做纯投影，已删除 `_decide`；
> closure projection 已提供公共 API，私有名称仅保留兼容别名。

**问题**

`tools/autopilot_state.py` 约 3797 行，`tools/checkpoint.py` 约 3865 行，`tools/surface.py` 约 3128 行；`autopilot_state._pick_next_action:811` 与 `checkpoint._decide:1218` 存在重复决策，Checkpoint 还依赖 Autopilot 的私有 closure helper。endpoint canonicalization 在 state/checkpoint/coverage/ledger 多处重复。

**实现任务**

1. 先用 characterization tests 固化现有 decision、endpoint identity、closure 输出。
2. 只抽取无 IO、无全局状态的纯原语：`canonical_endpoint_identity`、`canonical_vuln_class`、`latest_cell_status`、`decision_reason`。
3. 让 Autopilot 和 Checkpoint 调用同一原语；保留各自的 orchestration 和格式化层。
4. 删除对私有函数的跨模块导入，改为显式公共函数或本地薄适配器。
5. 不建立通用“控制面框架”；每次抽取必须能减少重复调用或消除语义分叉。

### P2-C.2 验收

- 共享原语有输入/输出契约和异常分类。
- 无路由冲突的旧 state/checkpoint fixture 保持 decision、closure、identity 指纹一致；历史冲突
  统一服从有效 Action Queue 候选，未选中的 report 等资产仍保留在队列。
- 普通 URL/path 的提取规则由共享原语提供；Evidence Ledger 对 SPA `/#/route` 保留专用身份，
  不再与普通 fragment 清理混为同一规则。
- 模块依赖图不出现 state <-> checkpoint 循环。
- 复杂度下降以重复代码量、私有导入数和失败分支数记录，而非只看行数。

## 11. 阶段七：P2 Runtime drift gate 分层

### P2-D.1 关键依赖与完整诊断分离

**问题**

`tools/runtime_doctor.py:9-13,177-196` 比较全部 commands、agents、skills；`tools/autopilot_bootstrap.py:560-576` 对任意 drift 都阻断。这会让与当前 `/autopilot` 无关的 runtime 变化阻塞主流程。

**实现任务**

1. 在 `commands/autopilot.md` 声明 `/autopilot` critical runtime manifest：入口 command、依赖
   agent、必需 skill、关键 MCP contract。HackerOne MCP 不在 manifest 或本规划范围内。
2. `runtime_doctor.compare_runtime` 保留全量报告，同时输出 `critical_drift`、`advisory_drift`、`missing_runtime` 三类。
3. Bootstrap 只对 critical drift 和 missing critical dependency 执行阻断；advisory drift 进入报告、checkpoint 和下一轮提示。
4. 支持 `--fail-on-critical-drift` 与现有 `--fail-on-drift` 并存，旧参数保持严格全量语义。
5. critical manifest 版本化并记录 hash，避免命令/skill 变更后静默失去门禁。

### P2-D.2 验收

- 非 autopilot 命令变更只产生 advisory，不阻断 `/autopilot`。
- critical command/agent/skill/MCP contract 漂移在启动前阻断。
- 完整 doctor 报告仍能发现所有漂移。
- CLI 退出码、JSON 字段和文档示例完成兼容更新。

## 12. 阶段八：P2 Capability profile 按 lane 建模

### P2-E.1 扩展可解释 readiness

**问题**

`tools/capability_profile.py:20-29` 只检查小型固定 registry；`ready` 无法表达 SQL、workflow、browser、OAST、credentials、cloud、Web3 等 lane 的真实条件，导致路由过度乐观或过度保守。

**实现任务**

1. 维持 advisory 语义，新增 lane-scoped profile：`recon`、`surface`、`browser`、`source_js`、`sql`、`workflow`、`timing`、`idor_authz`、`waf`、`cloud`、`oast`、`web3`。
2. 每个 lane 输出 `ready`、`missing`、`degraded`、`evidence_required`、`tool_refs`、
   `profile_version` 和输入 fingerprint；稳定 profile 不写入每次变化的 `checked_at`。
3. 检查项只包括可本地验证的依赖、配置和 runner contract；网络可达性、登录成功和漏洞存在性仍由实际 lane 结果决定。
4. 将 capability profile 注入 bootstrap compact projection，并在 Action Queue 选择中只作为约束/提示，不取代 AI 决策。
5. 为半闭环能力标注人工收束点：takeover provider claim、OAuth login、OAST callback、cloud credential validation 等。

### P2-E.2 验收

- 缺少 SQL helper 时只影响 SQL lane，不影响 Recon/Surface。
- browser MCP 不可用时，browser lane 显示 degraded，队列给出可执行替代路径。
- profile 输出稳定、可 JSON 解析、无敏感凭据。
- 能力报告与实际 runner 的失败原因可关联到同一 tool ref。

## 13. 测试矩阵与验证命令

### 13.1 单元与契约测试

- `tests/test_scope_context.py`、`tests/test_hunt_target_types.py`：目标语法、canonical identity、
  列表/wildcard/CIDR。
- `tests/test_runtime_exec*.py`：argv、超时、进程组、退出码和输出合并。
- `tests/test_autopilot_startup_contract.py`：batch context、Scope/Auth 继承、runtime gate。
- `tests/test_auth_session*.py`、`tests/test_validation_runner*.py`：session provenance、owner/peer、scope gate。
- `tests/test_evidence_ledger.py`、`tests/test_closure_resolver.py`：事件回放、重开、坏行、幂等。
- `tests/test_checkpoint.py`、`tests/test_autopilot_state_tool.py`：characterization、决策一致性、
  closure 指纹。
- `tests/test_runtime_doctor*.py`、`tests/test_capability_profile*.py`：critical/advisory 分层和 lane readiness。

### 13.2 集成测试

1. Fresh target：Recon -> Surface -> Queue -> candidate -> validation -> report。
2. Existing target：加载 state、继承父 Scope/Auth、续跑同一 lane。
3. Batch target：完成一个资产后切换下一个资产，验证 context ref 和 private auth ref。
4. Reopen：candidate -> tested_clean -> candidate -> tested_finding，确认 closure 只读取当前状态。
5. Projection 故障：Ledger 成功、Finding 失败、Queue 失败，重跑 reconcile 恢复一致性。
6. Runtime drift：仅 advisory 漂移、critical 漂移、manifest 缺失。
7. Linux CLI：POSIX shell、SIGTERM、超时、只读 artifact、并发同 target。

### 13.3 建议命令

```bash
python3 -m compileall tools tests
pytest -q tests/test_scope_context.py tests/test_hunt_target_types.py tests/test_runtime_exec.py
pytest -q tests/test_autopilot_startup_contract.py tests/test_auth_session.py
pytest -q tests/test_evidence_ledger.py tests/test_closure_resolver.py
pytest -q tests/test_validation_runner.py tests/test_checkpoint.py tests/test_autopilot_state_tool.py
pytest -q tests/test_runtime_doctor.py tests/test_capability_profile.py
python3 tools/knowledge_audit.py --strict
python3 tools/runtime_doctor.py --fail-on-critical-drift --json
git diff --check
```

完整回归仍以项目现有测试入口为准；上面的 focused 集合必须在每个阶段门禁执行。

## 14. 数据、CLI 与迁移兼容策略

- 所有新增 JSON 字段采用可选字段和显式 `schema_version`；读取器先兼容旧版本，再按需写出升级副本。
- `state/`、`memory/`、`findings/`、`recon/` 中已有原始 artifact 保持不变；迁移只添加 projection、manifest 或 backup。
- token、cookie、Authorization、私有 body 只允许出现在现有 private storage；summary、checkpoint、queue、doctor 和报告写 ref/hash。
- 旧 CLI 参数继续工作；新参数只扩展，不改变未提供新参数时的默认语义。
- canonical identity 变化前先生成旧 key -> 新 key 映射，提供 dry-run、迁移日志和反向映射。
- 读取损坏状态时优先保留可恢复事实并标记 partial；不静默删除、覆盖或“修正”原始输入。

## 15. 运行时压力与故障注入

在功能测试通过后，以本地 Juice Shop 作为负载源增加 Linux 故障注入和容量压测：

- runner 在 Ledger append 后、Finding replace 前退出。
- Finding replace 后、Queue patch 前退出。
- 两个进程同时写同一 target 的 Ledger、Finding、Checkpoint。
- JSONL 中插入头部/中部/尾部坏行。
- runtime manifest 在 round 开始前后发生变化。
- auth private ref、batch manifest、checkpoint witness 被截断或权限变化。
- URL inventory 超过 bounded ranking 上限，确认 raw artifact 未被裁剪。
- 运行至少 8 个 round；`max-lanes=8` 只限制每轮 substantive lane 数，不限制 lane 内请求量
  或后续 round。记录 URL/request 总量、每轮 lane 数和未覆盖 surface。
- 记录 Ledger/Queue/Finding/Checkpoint 的增长率、峰值磁盘占用、每轮耗时、恢复耗时和
  失败后可继续比例；漏洞数量只作观测，不设固定通过阈值。

每个场景记录：输入、命令、退出码、请求数、并发度、有效 artifact、磁盘增量、projection
hash、恢复命令和恢复后 hash。压测同时检查吞吐、并发、磁盘增长、恢复时间以及状态可解释、
可重放、可恢复；不得用“发现几个漏洞”代替系统能力验收。

## 16. 发布门禁与完成定义

### P0/P1 完成门

- 目标解析和执行边界已统一，危险字符串不会穿过 shell 拼接路径。
- batch -> domain continuation 保留父 Scope/Auth，旧 state 有明确 legacy 标记。
- Ledger 当前投影支持重开，closure 不再消费过时 closed cell。
- 以上三项均有失败测试、回归测试和迁移 dry-run 记录。

### P2 完成门

- Validation Runner 使用统一 AuthSession。
- Runner 写回具备 operation/event idempotency，projection 可 reconcile/rebuild。
- shared identity/decision primitives 消除重复语义，模块无私有跨层导入。
- runtime gate 具备 critical/advisory 分层，full doctor 仍可用。
- capability profile 能按 lane 表达 ready/degraded/missing 和人工收束点。

### 最终发布门

1. focused tests 全绿。
2. 完整回归不低于既有 `2999 passed` 基线，新增失败必须有明确归因和记录。
3. knowledge audit strict、critical runtime doctor、`git diff --check` 全部通过。
4. 端到端 fresh、existing、batch、reopen、projection failure、runtime drift 场景通过。
5. 报告、checkpoint、queue、summary 不泄漏敏感认证数据。
6. 生成迁移备份、patch/diff、验证记录和可运行回滚脚本。

## 17. 回滚方案

每个阶段独立提交并保存以下四类产物：

1. 修改后的代码/配置和 schema 迁移文件。
2. `git diff` 或 patch 文件，包含基线、输入和变更范围。
3. 验证记录：命令、字面输出摘要、退出码、artifact/hash。
4. 回滚脚本：恢复代码、恢复 manifest、恢复 projection backup，不删除原始 Ledger/evidence。

回滚顺序遵循“停止新写入 -> 备份当前 projection -> 回退代码 -> 用旧读取器读取原始事实 -> 重建旧 projection”。任何回滚都保留 append-only Ledger 和 raw evidence，避免把故障恢复变成数据丢失。

## 18. 里程碑建议

| 里程碑 | 范围 | 退出条件 |
| --- | --- | --- |
| M1 | P1-A 目标/argv | focused tests、dry-run argv、Linux 进程回收通过 |
| M2 | P1-B Scope/Auth | batch/continuation/auth provenance 集成通过 |
| M3 | P1-C Ledger/closure | reopen、坏行、幂等回放通过 |
| M4 | P2-A/P2-B | AuthSession 统一、reconcile 故障注入通过 |
| M5 | P2-C/P2-D | shared primitive 和 critical drift gate 通过 |
| M6 | P2-E/最终回归 | lane profile、端到端、全量门禁通过 |

## 19. Trellis 拆任务建议

建议每个任务保持单一根因和单一验收面：

- `autopilot-p1-target-argv-boundary`
- `autopilot-p1-context-scope-auth`
- `autopilot-p1-ledger-reopen-closure`
- `autopilot-p2-validation-auth-session`
- `autopilot-p2-runner-reconciliation`
- `autopilot-p2-control-plane-primitives`
- `autopilot-p2-runtime-critical-drift`
- `autopilot-p2-lane-capability-profile`
- `autopilot-final-linux-regression-gates`

每个 Trellis task 应包含：问题复现、涉及文件/函数、数据兼容说明、focused tests、集成 tests、验收命令、回滚产物和完成证据。未满足完成门时，任务保持进行中，不以“代码已改”作为完成标准。

## 20. 审计结论

项目的能力广度已经足够支撑专家型自动化工作流，下一阶段的主要收益来自可靠性和可解释性：统一信任边界、保持上下文、消费最新状态、保证投影可恢复，再用少量共享原语和分层门禁降低控制面复杂度。按照 M1 -> M6 顺序推进，可以在保留现有 specialist 能力和 AI 决策自由度的同时，显著降低 `/autopilot` 长流程中的隐性状态漂移。
