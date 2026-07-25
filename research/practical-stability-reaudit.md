# `/autopilot` 实战稳定性复审

审核日期：2026-07-13
基线：`main` / `3215c83`，包含当前未提交的知识候选闭环与专项知识卡改动
范围：Claude CLI `/autopilot` 的功能、能力、架构、状态闭环、失败恢复和 2–8GB
个人顺序使用模型；不评价项目自身安全加固。

## 最终结论

当前仓库实现已达到**个人顺序使用下的首个实战稳定版**：本轮没有发现未解决的 P0/P1，
inline controller、runtime gate、fresh/existing/batch、evidence -> finding -> report 和中断恢复
均有实现与行为证据。分批全量测试为 **2255 passed**，真实 Claude CLI staged runtime 为
**11 passed**，隔离 localhost 顺序压测为 **1 passed**。

结论必须分三层理解：

| 层 | 结论 | 条件 |
|---|---|---|
| 仓库实现 | 稳定 | 当前工作树、个人单 controller、单目标顺序执行 |
| 真实 `~/.claude` runtime | 暂未 ready | `distill.md`、`kb.md` 有 2 项 drift，bootstrap 正确返回 `stop_runtime_drift` |
| 2–8GB 使用模型 | 架构适配 | 不并发多套 browser/scanner/agent；2GB/4GB 未做真实 OOM 硬件认证 |

因此，当前不是“任何环境直接开跑”的无条件 green：仓库本身可用，但真实 Claude runtime
需要在代码最终确认后显式同步，才能按最新契约运行 `/autopilot`。

## 审核快照

- 39 个 slash commands、11 个 agents、145 个 `tools/` 顶层文件、154 个 `tests/`
  顶层文件、48 张 knowledge cards。
- 当前机器：7.8 GiB RAM、4.0 GiB swap、2 CPU；能力快照为 `ready`。
- 能力快照可见 `playwright-cli`、`subfinder`、`httpx`、`katana`、`gau`、
  `waybackurls`、`ffuf`、`nuclei`，核心缺失项为 0。
- 工作树包含前序知识治理任务的未提交改动；未跟踪 `.claude/` 未读取为仓库契约、未修改。

## Runtime 与真实 wiring

真实启动顺序已固定为：

```text
slash arguments
  -> autopilot_args
  -> runtime_doctor compare
  -> advisory capability_profile
  -> compact autopilot_state
  -> current Claude session inline controller
```

参数错误先于 runtime/state 停止；runtime drift 先于 capability/state 停止；能力探测失败只会
降级建议，不会阻断目标流程。`commands/autopilot.md` 只允许 `continue` 进入动作阶段，并明确：

- `/autopilot` 在当前 Claude 会话 inline 运行；
- 不创建或恢复 legacy `agent_session.json`；
- specialist 默认 0，单次最多一个不嵌套、不能接管 finish 的有界证据任务；
- inline 不接受 legacy parallel/fleet 参数；
- list target 只做 recon/handoff，选择一个 completed domain 后重新读取单目标状态。

staged runtime 测试通过真实 `install.sh`、临时 HOME、真实 `claude` 二进制和 localhost fake
Anthropic endpoint，验证了 command 安装、dynamic argument expansion、URL/auth/list 参数、drift
短路、repo root/nested cwd 一致性及可选 legacy agent 发现，共 11 项通过。该测试不依赖个人
`~/.claude/settings.json`。

真实 runtime compare 结果：

```text
commands: ok=37 diff=2 missing=0 extra=0
agents:   ok=11 diff=0 missing=0 extra=0
skills:   ok=20 diff=0 missing=0 extra=0
drift:    commands/distill.md, commands/kb.md
```

对 `example.com --normal` 的真实 bootstrap 返回 `stop_runtime_drift`，没有读取 capability 或
target state。这是预期保护，不是仓库主链失败。

## 状态与数据闭环

### Fresh / Existing / Batch

- Fresh 在没有 recon/cache 时返回 `run_recon`；不会被普通 advisory queue 抢占。
- Existing 从 artifact、runtime v2、surface、runner、action queue 和 target memory 派生下一步；
  closed checkpoint 会压低历史 focus，避免重复旧路线。
- `recon_no_live_hosts` 是明确终态，不自动无限重跑。
- `wait_recon` / `wait_scan` 必须同时满足 started marker 与活跃 flock；进程终止后内核释放
  flock，孤儿 marker 不再阻塞。
- batch identity 使用 `list stem + canonical path digest`；同名不同目录的 list 不共享 state
  或 recon。batch index 不能进入 surface/scan/hunt。

### Evidence / Finding / Report

```text
recon/browser/source/JS observation
  -> AI hypothesis or durable action
  -> bounded replay + raw evidence
  -> evidence ledger / runner candidate
  -> evidence rubric + /validate
  -> finding_index canonical mutation
  -> exclusive report allocation
  -> finding/report/action closure
  -> checkpoint witness / target-memory proposal
```

target-level `findings.json` 写入者均通过 `finding_index` 的 build/upsert/status API；worker
自己的 `scratch/findings.json` 在 join 时才进入 canonical mutation boundary。scanner index
重建保留 runner-backed、validated 和 reported 行，默认 scanner orphan 才允许被清除。

structured report 路径会综合 finding、`INDEX.json` 和磁盘文件分配未占用 ID，并以排他创建
防止覆盖；crash artifact 只有 Finding ID 一致时才能复用。checkpoint 使用独立
`checkpoint_latest.json` witness，未把 runtime-v1 派生字段写回 `session.json`。

### Knowledge 生命周期

target memory 的 useful pattern/dead end 与 knowledge candidate 是不同生命周期。候选必须带
证据引用，经 pending/reviewed/promoted/rejected/superseded 状态审计后才能晋升；不会修改
finding 状态。四张新增专项卡通过同一 capability registry 和 1–2 card budget 路由，没有
建立第二套 finding 状态。

## 问题分级

### P0

未发现。

### P1

仓库主流程未发现未解决 P1。真实 runtime 的 2 项 drift 是当前环境阻断项，但 preflight
行为正确，不能归类为仓库实现缺陷。

### P2-1：legacy/manual report 路径仍未统一使用新 ID owner

structured finding 报告的覆盖问题已经修复，但 `report_generator.py` 的兼容 fallback 仍按
每个文本文件的行号生成 `type_001`，并用 `w` 打开；同类型多个旧文本文件可能互相覆盖。
manual 模式只用 `HHMMSS` 作为 ID，并把域名点号替换为下划线，也没有复用 canonical
`target_storage_key()`。入口是显式 `report_generator.py --manual` 或无 `findings.json` 的
legacy `hunt.py --report-only`，不在当前 `/autopilot` structured finding 主路径上，因此定为
P2，而不是稳定版阻断项。后续应让两条兼容路径先迁移/upsert canonical finding，再复用同一
排他 report allocator。

### P2-2：部分状态文件仍是顺序写模型

`action_queue`、target memory 等少数 owner 仍直接覆盖 JSON；部分 loader 遇到损坏 JSON
会回落为空状态。单 controller 顺序使用可控，但不具备多 controller 事务语义。若以后开放
并发 controller，应统一原子写、损坏状态和恢复规则，而不是只增加 worker 数量。

### P2-3：跨文件闭环是最终一致

runner -> ledger -> finding -> queue 及 report -> finding -> queue 涉及多个文件。当前依靠
稳定 ID、幂等更新、排他 report create 和重复执行修复局部失败，没有通用 transaction/
reconcile journal。个人顺序模型可用；daemon 化或并发化前需要独立设计。

### P2-4：legacy list 首次读取带一次受控迁移副作用

`autopilot_state` 对 list 会尝试把 stem-only 旧目录迁移到 digest key，只有旧 session 能证明
相同 canonical list owner 时才移动。该路径不会误领同名目录，但严格说 bootstrap target
state read 不是百分之百无写入副作用。后续可把迁移变成显式 maintenance 命令；当前 owner
校验和回归足以使其不成为 P1。

### P2-5：协调器和 Shell/Python artifact 契约仍较重

`hunt.py`、`checkpoint.py`、`context_pack.py`、`autopilot_state.py` 修改面较大；recon Shell
产物由 Python adapter/state 消费。现有 owner API 和跨层测试能控制回归，不能只因行数判为
架构失败；后续应按 projection/normalizer 边界渐进拆分。

## 2–8GB 运行边界

- **2GB**：单 target、优先 `--quick`、单 browser session，browser/recon/scanner 严格顺序；
  不使用 specialist、legacy agent 或 parallel workers，阶段结束后释放重型进程。
- **4GB**：可用默认 cadence 或 `--normal`；browser 与一个 scanner 顺序执行，source/JS
  按需加载，避免同时保留多个 Chromium context。
- **8GB**：可用 `--deep` 和最多一个 bounded specialist；仍不建议并发多域 scanner、多个
  browser 和 legacy local-agent fleet。

本机 localhost 压测覆盖 fresh -> existing -> batch handoff -> runner candidate -> durable queue
-> checkpoint -> phase lock，并连续读取 state 12 次：**0.041 秒，测试进程 max RSS 增量
0 KiB**。这证明 compact state/checkpoint 主链轻量且重复读取稳定，不代表真实 Chromium、
Nuclei、recon 工具组合在 2GB 上已经通过 OOM 认证。

## 验证结果

| 验证 | 结果 |
|---|---|
| autopilot/bootstrap/runtime/finding/knowledge focused suites | 274 passed |
| 真实 Claude CLI staged runtime | 11 passed |
| localhost 顺序压力测试 | 1 passed，12 次 state poll 0.041s，RSS 增量 0 KiB |
| phase terminate/orphan/runtime-v2 witness focused | 4 passed |
| 分批全量 pytest | 1063 + 410 + 538 + 81 + 163 = 2255 passed |
| `knowledge_audit.py --strict` | capabilities=54, documents=52, errors=0, warnings=0 |
| `knowledge_candidates.py audit --strict` | ok=true，0 errors |
| Python compileall | 通过 |
| `git diff --check` | 通过 |
| 遗留 localhost pytest 服务 | 未发现 |

## 使用前动作

1. 先完成当前工作树的代码审核/提交，保证可复现基线。
2. 经显式确认后运行 `python3 tools/runtime_doctor.py --sync --prune`。
3. 再运行 `python3 tools/runtime_doctor.py --fail-on-drift`，必须为 clean。
4. 用真实 Claude 会话做一次 `/autopilot <localhost-target> --quick --normal` smoke；只有
   bootstrap 为 `continue` 才进入目标动作。

在上述 runtime 同步完成后，推荐继续以 `/autopilot target --deep --normal` 作为较充足资源下
的深度入口；资源紧张时用 `--quick --normal`，不要把 legacy parallel 参数带入 inline
`/autopilot`。
