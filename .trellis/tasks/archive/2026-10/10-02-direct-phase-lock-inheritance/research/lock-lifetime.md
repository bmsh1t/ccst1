# F02 证据与调用边界

来源：既有审核 `/tmp/ccst-audit-2026-10-02/AUDIT.md:34-40`、只读探子 `/root/direct_phase_lock_plan`；主代理已点验 exact owner、Hunt 接线、完整 phase 测试及归档设计。规划未重跑故障复现或实现测试。

## 根因和已有能力

- `tools/runtime_phase_exec.py:29-42` 未启用 `include_fd`、未提供 `pass_fds`；`:61-69` 是公开 CLI。
- `tools/runtime_exec.py:208-217` 使用 `start_new_session=True`、默认 `pass_fds=()`；`:433-456` 的 live API 已透传参数。
- `tools/runtime_state.py:248-256` 的 `include_fd=True` 只关闭父句柄，避免 `LOCK_UN` 解掉共享 open-file-description 的锁；`:365-373` 正确按锁事实判断活跃。
- `tools/hunt.py:80-90,821-826,886-891` 已有可复用 FD 接线；不需要抽象新执行层。
- direct Recon 从 `tools/recon_engine.sh:1062-1065` 包装；列表逐目标仍重入该路径（`:1268,1586-1588`）。direct Scan 从 `tools/vuln_scanner.sh:228-243` 包装；环境 marker 仅防重复包装，不是资源锁。

## 测试与历史决策

- `tests/test_runtime_state.py:376-392` 固定 `pass_fds == ()`；`tests/test_runtime_phase_execution.py:164-187` 固定 direct `locks == []`。本次需要改变这两项旧预期，而不是削弱正确断言。
- `.trellis/tasks/archive/2026-09/09-28-shared-phase-execution/design.md` 明确旧重构保留 Hunt/direct FD 差异，不重定义 SIGKILL 所有权；F02 是后续缺陷修复，不否认旧重构验收范围。
- `tests/test_runtime_state.py:338-359` 已验证 inheriting child 在上下文退出后持锁；`:442-486` 只终止锁 owner，没有 surviving child，不能代替本次回归。
- phase 测试文件提供 readiness、临时 child、进程组清理与真实双入口矩阵；`_run_interrupted` 的 PIPE/`communicate` 和 `_assert_finished` 的终态 marker 不适用于 wrapper SIGKILL。`_alive` 排除 zombie，仍需真实 wait/reap。
- 现有 `CHILD` 的非 exit 模式会创建孙进程；新用例只需单个 surviving child，不应为复用字符串引入无关进程树。隔离 subreaper 仅属于测试收尾，不进入产品。

## 排除项

旧 `.trellis/tasks/09-27-fix-scanner-lock-identity` 是另一审计的 F06 target identity 问题；本轮 F02 单独建任务。`tools/dns_expand.py:478` 的独立锁调用、主动关闭 FD 或脱离正常执行边界的后代不在本次保证内。F03 与后续 Store/证据/报告问题分别处理。

## 规范

`runtime-autopilot.md` 超过 32 KiB 自动注入上限，目标段落位于文件后部，因此不把整文件放入 JSONL 后接受静默截断。实施/检查开始时必须直接读取 canonical 文件中 `Scenario: Active target and child-process argv boundary` 的完整段落，直到下一节 `Scenario: Canonical Checkpoint Decision Projection`。以标题定位而非固定行号为准，不复制规范作为第二权威，也不扩大注入配置。

`.trellis/spec/backend/contracts/runtime-autopilot.md:874-880` 保留了旧 direct 不继承 FD 的说明，本次修改其执行边界段落；适用质量、错误与日志约束见同层规范。Agent 负责判断，工具仅补确定性资源所有权，不增加推荐/调度能力。
