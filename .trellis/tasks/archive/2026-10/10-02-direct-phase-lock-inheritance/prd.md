# F02：direct phase 锁继承

## 目标

direct recon/scan 的实际任务进程仍运行时，即使 wrapper 被 SIGKILL，目标 phase 也应保持被占用，不能错误允许同阶段重复启动。智能判断仍归 Agent，本任务只修已有执行边界。

## 背景与范围

- 审核 F02/P1 已在临时进程复现：wrapper 死亡后 child 仍活，但 `runtime_wait_action()` 取消等待且第二次加锁成功。
- 根因位于 `tools/runtime_phase_exec.py:29-42`：未把已有 phase-lock FD 传给 runner。`tools/runtime_exec.py:208-217` 的 child 独立建 session；锁 owner 的继承能力已经存在于 `tools/runtime_state.py:204-256`。
- F01 已单独提交 `4646762`，R17 已单独提交 `18322c4`；用户批准 R17 提交后进入本项独立规划。当前不承接 F03 或整体长期记忆验收。

## 需求

- R1：direct recon/scan 的实际任务进程继承并持有当前目标、当前 phase 的既有锁；wrapper 的异常死亡不能提前释放任务仍持有的锁。
- R2：工作进程持锁时仍返回 `wait_recon`/`wait_scan`；第二个同目标同 phase 请求返回 busy=75，且不启动工作、不重写运行标记。
- R3：最后一个锁持有者退出后自动释放锁，允许下一次执行；保留正常退出、非零退出、SIGINT/SIGTERM、启动失败和 Hunt 已有超时清理语义。
- R4：不改变 cwd/env、认证来源、target identity、原始 int 返回值、direct 无外层 timeout 与严格信号安装的契约。SIGKILL 不伪造 finally 或完成标记；遗留 running 标记仍由真实锁状态解释。
- R5：不新增执行器、进程控制器、PID/时间猜测、状态 owner、配置或依赖。回归只使用自建短生命周期进程和临时文件，清理并回收测试创建的进程，不访问目标网络或全局 runtime。

## 验收标准

- AC1 / R1：通过真实 direct 执行链确认 child 持有当前 phase 锁 FD；recon/scan 均覆盖。
- AC2 / R1-R2：只 SIGKILL wrapper 后，已就绪 child 仍存活且 wait 保持；同 phase 第二次启动返回 75，无 sentinel 或运行标记变更。
- AC3 / R3-R4：退出或清理 surviving child 后 wait 清空、同锁可重新取得；SIGKILL 路径保留历史 running 标记而不伪造完成。测试进程被回收。
- AC4 / R3-R4：现有成功/非零/124/busy、信号、Hunt 超时、启动失败、argv/env/cwd 和输出回归通过；未继承 FD 的两处旧预期按新契约更新，其余断言不削弱。
- AC5 / R5：产品修改只落在现有 direct 入口的 FD 接线；更新相关测试和现有规范，不修改真实目标状态或混入其他审核修复。

## 范围外

不修改 `runtime_exec` 清理算法、锁 owner、wait gate、Shell 内部 timeout/trap、Store 或 F03 partial 登记；不扩展到 `dns_expand.py` 独立调用链。不能声称约束主动关闭 FD 或独立脱离执行边界的任意后代。真实自主调查、长期记忆与全量工程验收均另行处理。
