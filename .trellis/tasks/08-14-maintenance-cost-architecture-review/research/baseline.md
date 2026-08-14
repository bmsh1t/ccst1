# 审核基线

日期：2026-08-14

## Git 身份

- 分支：`main`
- 起始 HEAD：`17e58b228a17b1a5598ff27aa6c8f2c607a630ab`
- HEAD subject：`fix: harden request guard state persistence`
- 与 `ccst1/main`：ahead 11，behind 0
- staged：无
- 主审核对象：当前工作树
- 归因对照：以上 HEAD 提交态

## 起始工作树

审核开始时，除被 Git 忽略的当前 Trellis 任务目录外，工作树只有以下用户已有内容：

- tracked delete：`shenhe.md`（486 行删除）；
- untracked：`DEEP_MODE_AUTOPILOT_SUMMARY.md`；
- untracked：`guihua.md`；
- untracked：`jyou.md`；
- untracked：`zyou.md`；
- untracked：`wordlists/onelistforallmicro.txt`。

审核不读取这些未跟踪文档的正文，不修改、回退、暂存或提交这些路径。

## 增量依据

上一轮完整审核基线为 `c2aca248d121fb63fceb94cac1e004877447145c`，报告位于
`.trellis/tasks/archive/2026-08/08-14-full-project-architecture-quality-audit/`。本轮只追踪之后的
已提交变化及剩余维护成本。

| 提交 | 已处理边界 | 本轮归类 |
|---|---|---|
| `a2cca49` | executable upload canary 复用 scanner 审批门禁 | 已解决债务 |
| `6a59128` | AuthSession 跨目标来源隔离、显式 auth file 失败 | 已解决债务 |
| `6a6e661` | target profile 原子替换、损坏输入 fail-fast | 已解决债务 |
| `882b4ea` | validation/ViewState 工作流及文档、知识增量 | 已提交能力变化 |
| `d3e2526` | 时间与 auth 边界回归 | 测试强化 |
| `17e58b2` | request guard 原子替换、损坏输入 fail-fast | 已解决债务 |

旧审核发现不因历史报告继续保持开放；只有当前代码、当前回归或确定性复现仍能证明的问题进入
本轮正式结论。

## 规模快照

- `tools/` 顶层 Python 模块：156；
- `tests/` 顶层测试文件：196；
- `commands/` Markdown 命令：40；
- active knowledge cards：57；
- 主要投影/协调模块：`checkpoint.py` 4395 行、`autopilot_state.py` 3995 行、
  `context_pack.py` 3552 行、`hunt.py` 2606 行；行数仅用于导航成本，不直接判定缺陷。

## 归因规则

- `HEAD`：提交态可复现；
- `WORKTREE`：只由当前未提交变化引入；
- `BOTH`：提交态根因仍被工作树保留或扩大。

任务结束前重新采集 HEAD、staged、tracked dirty 和 untracked 路径；任何变化都必须重新核验受影响
证据。

## 结束快照

报告和验证完成后、提交审核产物前重新采集：

- HEAD 仍为 `17e58b228a17b1a5598ff27aa6c8f2c607a630ab`；
- staged 仍为空；
- tracked dirty 仍只有 `shenhe.md` 删除（486 行）；
- untracked 仍为起始记录的 5 个文件；
- 未发生生产代码、测试、runtime 模板或用户文件漂移；
- 本任务只写被 Git 忽略的当前 Trellis 任务目录。
