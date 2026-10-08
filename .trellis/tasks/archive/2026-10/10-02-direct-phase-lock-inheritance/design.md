# F02 设计：复用既有锁句柄传递

## Owner 与最小修改

`runtime_state.runtime_phase_lock()` 已拥有锁；`runtime_exec.run_live_argv_command()` 已拥有进程启动、信号与清理。`runtime_phase_exec.run_phase_command()` 仅负责接线，仿照现有 Hunt 路径：

1. `runtime_phase_lock(..., include_fd=True) as (_path, lock_fd)`。
2. 原 `run_live_argv_command(...)` 增加 `pass_fds=(lock_fd,)`。

两处必须一起改：继承 FD 却保留旧上下文的显式 `LOCK_UN` 会解除共享锁；只启用 `include_fd` 却不传 FD 仍无法跨 wrapper 死亡持锁。不复制实现、不新增 helper 或全局 FD registry。

## 生命周期契约

| 事件 | 锁与状态 |
|---|---|
| 成功获取锁 | 先锁后 running 标记，child 继承同一 open-file-description |
| 竞争锁 | busy=75；不启动 child、不修改标记 |
| 正常/非零/可捕获信号/启动失败 | 沿原 runner 与 finally 收尾；最后的 FD 关闭后释放锁 |
| 仅 wrapper 被 SIGKILL | child 继续持锁；running 标记不被虚构改写，wait 仍有效 |
| surviving child 退出且无其他持有者 | 内核释放锁；旧 running 标记不再形成 wait，后续启动可获取锁 |

不增加 direct timeout。原 int/75/124、cwd/env、信号安装策略、认证和 target identity 不变。FD 的生命周期是资源事实，不是新的 AI 路由规则。

## 回归设计

沿用 `tests/test_runtime_phase_execution.py` 的临时文件与 readiness 模式，不运行真实 Recon/scanner。更新既有真实 FD 检查和 `tests/test_runtime_state.py` 的调用契约断言；后者在 mocked runner 执行期间用 `os.fstat` 检查传入 FD 有效，不能在上下文关闭后只检查数字。

新 SIGKILL 用例按 recon/scan 参数化，运行真实 wrapper CLI。只杀 wrapper，随后核验存活 child、wait、busy、sentinel 与 running 标记；最后清理 child 并检查锁释放。输出用 DEVNULL/临时文件，避免 child 继承 PIPE 导致 `communicate()` 等不到 EOF；不调用要求终态 marker 的 `_assert_finished()`。

为可靠回收 orphan，用一个测试专属子进程作为 Linux subreaper（标准库 `ctypes` 调用 `prctl`），不修改 pytest 主进程的全局回收语义。保持 supervisor/helper 在现有测试文件内；复用 readiness、有界等待与进程组清理，finally 回收 wrapper 及被收养的测试 child。新增用例不需要孙进程。失败同样清理；不把“zombie 已不活跃”当作已回收，也不引入产品进程管理机制。

## 文件与兼容

- `tools/runtime_phase_exec.py`：两处 FD 接线。
- `tests/test_runtime_state.py`：替换原“不传 FD”预期，保留其他调用与收尾断言。
- `tests/test_runtime_phase_execution.py`：真实 FD 预期与 SIGKILL 生存/竞争/回收回归。
- `.trellis/spec/backend/contracts/runtime-autopilot.md`：在既有子进程契约中移除 direct 不继承 FD 的旧限制，补充新保证及范围。不修改已提交的 R17 部分。

无需状态迁移或全局安装；只影响后续启动。若回退，仅撤销本任务差异，旧缺陷会恢复；不能通过修改 wait gate 掩盖回退后的失锁。
