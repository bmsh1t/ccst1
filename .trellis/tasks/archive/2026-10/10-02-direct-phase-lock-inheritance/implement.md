# F02 执行计划

## 门禁

- [x] R17 已独立提交 `18322c4`；创建本任务时 Git 工作区干净。
- [x] 既有入口、锁 owner、Hunt 复用模式、真实测试和旧设计边界已核对；PRD 已收敛。
- [x] PRD/design/implement 与 spec/research JSONL 已准备。
- [x] `task.py validate` 通过；超长 runtime 规范改由 research 明确引导按目标段落直接读取，避免注入截断。
- [x] 用户在最终方案之后回复 `go`，已运行 `task.py start`，状态为 `in_progress`。

## 实施顺序

1. 确认基线与 before-dev 规范；按 research 指引直接读取 runtime 的完整子进程边界段落，主代理亲自阅读待改函数和测试。
2. 只在 `run_phase_command()` 启用 `include_fd=True` 并透传 `pass_fds`；不改其他执行 owner。
3. 更新两处旧 FD 预期；在现有 phase 测试文件补 recon/scan 的 wrapper SIGKILL 回归，使用隔离测试 reaper，确保错误路径也清理进程。
4. 原位同步 runtime 子进程契约及错误矩阵/测试说明；不改 R17 段落或新增规范文件。
5. 运行下列单批定向检查，完成本任务全差异复核。若使用只读代理独立核验，由主代理处理修改与最终验证。

```bash
python3 -m pytest -q tests/test_runtime_phase_execution.py \
  tests/test_runtime_state.py::test_runtime_phase_lock_remains_held_by_inheriting_child \
  tests/test_runtime_state.py::test_direct_phase_runner_marks_child_lock_ownership \
  tests/test_runtime_state.py::test_direct_phase_runner_finalizes_interrupted_runner
```

已有真实进程矩阵包含清理 grace；预计单批约 60 秒内。只使用临时数据、自建进程与合成环境；无目标网络、真实 scanner、模型调用、依赖安装或全局 runtime 校验。无充分新证据不重复失败命令，环境失败和产品失败分开报告。不默认全量测试或 build。

## 完成与停止点

最后核对 `git diff --check` 及整个任务 diff，确认无 PID/时间猜测、重复控制器、异常吞噬、弱化断言或范围外编辑。单独列出代码/测试/规范提交批次，请用户确认后提交，不推送。若必须修改 runner/锁 owner/其他入口，先回到规划，不借故障扩大范围。

## 实施与核验结果（2026-10-02）

- 产品仅修改 `tools/runtime_phase_exec.py` 两处接线：`include_fd=True` 和 `pass_fds=(lock_fd,)`；锁 owner、runner、wait gate、Store 与其他入口未改。
- 两个既有测试文件同步 FD 预期，并新增 recon/scan 两个真实 CLI SIGKILL 用例。隔离 subreaper 回收测试 orphan；20 秒可捕获软时限先进入 finally 清理，35 秒外层时限仅为硬兜底。
- 只读代理 `/root/f02_lock_lifetime_review` 核验完整四文件差异，无产品或正常回归阻断；其低概率超时清理建议已由主代理处理，再运行验证。
- 上述单批 pytest 命令结果 **34 passed**（包括两个新 SIGKILL 用例），无 skip；未运行全量、真实 scanner、目标/模型实验或全局 runtime 校验。
- 主代理已检查最终完整差异，`git diff --check` 无错误；runtime 契约仅修改执行边界段落，已提交的 R17 段落保持不变。无新依赖、控制器或无关变更。
- 用户确认后已提交 `14f0261`（`fix: inherit direct phase locks in child processes`）：仅包含 `tools/runtime_phase_exec.py`、`tests/test_runtime_state.py`、`tests/test_runtime_phase_execution.py`、`.trellis/spec/backend/contracts/runtime-autopilot.md`。提交前内容哈希与已验证版本一致；提交后 Git 工作区干净，未推送，任务尚未归档。

原审核复现保存在 `/tmp/ccst-audit-2026-10-02/results.json`；修复后的主要证据为本次仓库内定向回归。

## 集中验收与归档（2026-10-08）

基线 `a31535d` 的 `B-locks` 组一次通过 **34 项**，无失败/错误/跳过；主线程逐项核对原始 AC。
本任务已归档，保留上述原工作提交；完整证据见 `../10-04-stabilization-acceptance/acceptance.md`。
