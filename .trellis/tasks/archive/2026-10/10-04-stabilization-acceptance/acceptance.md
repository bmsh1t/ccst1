# F01–F11 集中工程验收记录

## 本轮结论

2026-10-08，六组获批检查首次执行全部通过：**421 个唯一 testcase，0 failures/errors/skipped，整体退出码 0**。
执行窗口 **02:45:49–02:46:25 UTC**；各组 JUnit 时间合计 **33.876 秒**。没有重跑、未执行组或本批未解释的验收阻塞。
F01/F02 原始需求已核对、满足归档条件；F03–F11 已归档，不重复处理。其他 32 项历史任务保留。
用户在获知 421 项通过及仅剩记录/提交/四项归档/journal 后回复“继续”，确认执行该收尾批次，不推送。

## 基线、命令与隔离

- 基线：`a31535d5dbbdb80b4194a36932b36679b71af511`。
- 源码 archive SHA-256：`a11376faf115a4b4f7d9aeb71a22e3837b5b4368ac143e3a9363b6da175a35b3`。
- 实际脚本：`/tmp/ccst-acceptance-command.RhPZai.sh`，逐字等于 `implement.md` 的唯一 Bash 块；SHA-256 为 `b9ba29d941dbec8336871987b0bb88543418acf79f0084eda81e4fb790666f4a`。
- RUN：`/tmp/ccst-acceptance.TxXDML`；测试从 git archive 的 `repo/` 副本导入。每组独立 HOME/TMPDIR/HUNT_MEMORY_DIR/basetemp；`env -i` 白名单，禁用用户 site/第三方 pytest 插件，未继承认证或代理。
- Store/raw/receipt/cache/report 和被终止进程均为测试自建；仅自建 loopback 服务接收合成凭据，无真实目标、scanner、模型、安装或 runtime 同步。
- 执行代理在 02:46:47 UTC 检查 `/proc` argv/cwd，RUN 关联残留为空，没有 kill；记录为 `RUN/process-check.json`。这不是系统级网络/进程监控证明。
- 主线程逐字核对脚本、复算 archive hash、解析全部 JUnit 并对照日志/result/exit-code；421 个 `(classname,name)` 互不重复。产品/测试无改动，未重复运行 pytest。

复跑固定于该提交，执行脚本拒绝 HEAD/工作区漂移；更新基线须重新核对，不将结果外推到不同源码。
原始材料保留在 `/tmp` 供审阅，本文件持久保存摘要；临时路径不是永久归档服务。

## 环境

| 项目 | 本轮 | CI 锁/配置 |
|---|---|---|
| Python | `/usr/bin/python3` 3.13.5 / GCC 14.2.0 | 3.13 |
| pytest | 9.0.2 | 9.1.1 |
| requests | 2.32.5 | 2.34.2 |
| PyYAML | 6.0.2 | 6.0.3 |
| certifi | 2025.11.12 | 2026.7.22 |

实测来源 `RUN/environment.txt`；锁值 `requirements-ci.lock:69,733,737,812`。未安装/升级依赖，不能声称 CI 精确锁环境全量通过。
使用系统 timeout：A/C/D/E/F 上限 60 秒，B 上限 120 秒；均未触及上限。

## 实际结果

| 组目录 | 覆盖 | passed | deselected | JUnit 秒 | 退出码 |
|---|---|---:|---:|---:|---:|
| A-auth | F01 | 37 | 0 | 1.430 | 0 |
| B-locks | F02 | 34 | 0 | 12.732 | 0 |
| C-store-evidence | F03–F05 | 77 | 0 | 3.991 | 0 |
| D-reports | F06–F08 | 150 | 222 | 7.064 | 0 |
| E-runtime | F09 | 22 | 67 | 0.627 | 0 |
| F-cache-guidance | F10/F11 | 101 | 0 | 8.032 | 0 |

每组 failures/errors/skipped 均为 0。deselected 是批准的选择器排除，不算已验证，也不是 skip。
stdout D/E 时间 7.07/0.62 秒与 JUnit 口径略有差别；上表统一 JUnit 原值。
每组 `RUN/<组目录>/` 有完整 argv `command.txt`、UTC 起止时间、`pytest.log`、`junit.xml`、`result.json`、`exit-code.txt`。
整体输出/退出码为实际脚本同名 `.log` / `.exit-code.txt`；汇总 `RUN/execution-summary.json`，以原始材料为准。

## 审核项与验收映射

| 项 | 原工作提交 | 本轮关键证据 |
|---|---|---|
| F01 | `4646762` | A：八键替换、来源/Origin、匿名往返、真实 Shell、loopback 重定向隔离 |
| F02 | `14f0261` | B：FD 继承、仅 wrapper SIGKILL 后占锁、busy 不改状态、child 回收后重取、信号/超时兼容 |
| F03 | `b460f05` | C：partial/unknown、saved-summary 幂等、显式 claim 恢复、请求/raw 不重执行、partial 不完成 |
| F04 | `704009c` | C：subject/control 授权竞争、拒绝无 completion/receipt、恢复重试、无关事件、writer 前 hash |
| F05 | `70871aa` | C：损坏/撤销与 succession 约束 actor coverage、不复活旧结果；Pack/Checkpoint 同 seam 且只读 |
| F06 | `b63ad6a` | D：reporter 错误传播、合法零报告、batch 保留成功并继续、非报告分发兼容 |
| F07/F08 | `fd02dc8` | D：当前正文附件闭包、文件/登记/发布失败及重试、delivery currentness、validate→report 接线 |
| F09 | `538975e` | E：receipt root/record 校验、合法兼容、bootstrap stop_runtime_error、零 target-write/同步 |
| F10 | `6245fb0` | F 中 83 项：最终 cache-status 修复后完整文件，失败保全、真实 provider parser、原子发布 |
| F11 | `3c83280` | F 中 18 项：三文档真实 CLI、11 条读取示例非空、条件/observation 引用及无副作用 |

精确节点/owner 锚点见两份 `research/f01-f05-acceptance.md`、`research/f06-f11-acceptance.md`；命令只维护于 `implement.md`。

### F01/F02 原始 AC

- F01 AC1–AC3：A 的 18 个往返组合验证污染/坏旧值、显式 Origin/scheme/port/session ID、匿名/未绑定/空 mapping；全部通过。
- F01 AC4：幂等、无关 env/原对象不变、12 个真实 Bash helper 组合；AC5：来源与目标冲突、auth-file/raw-header、越界及 loopback redirect；无 skip，全部通过。
- F02 AC1：真实 direct/hunt recon/scan 的有效 lock FD；AC2：两种 phase wrapper SIGKILL 后 wait/busy=75、无 sentinel/marker 变更；全部通过。
- F02 AC3：独立 subreaper 回收 child、锁重取、running marker 不伪造完成；AC4：整个 phase 文件及三个 runtime_state 节点覆盖退出/信号/超时/失败/argv/env/cwd；全部通过。
- F02 AC5：原四文件提交范围与原 PRD 一致，本轮不修订产品/测试且仅自建状态/进程；符合。普通信号测试不证明所有孙进程 waitpid，严格回收证据是 SIGKILL reaper。

主线程完整阅读两任务 PRD/design/implement。归档分别绑定原工作提交 `4646762` / `14f0261`，不是本轮记录提交；旧记录保留，本轮作为追加证据。

## 未测边界与收尾

- 仅证明本批工程契约，未跑全仓测试、真实部署、外部提交、线上自主调查、付费模型或长期能力实验。
- 文件/环境隔离不是 OS 网络沙箱；F04 不保证任意外部文件写入原子性；F02 不约束主动关闭 FD/脱离边界的任意后代。
- 本轮无产品/API/schema 变更或新依赖；仅补现有质量规范的三行隔离说明，避免将 HOME/basetemp 当成 BASE_DIR 读路径隔离。
- F04/F06 旧 archive commit 空值保留为已解释的记录差异，不重写旧归档。
- 已批准顺序：验收记录提交 → 精确归档 F01/F02/验收任务/父任务 → journal；其他 32 项不动，不推送。
- 独立最终质量复核 `/root/stabilization_final_check` 已通过：原始证据、F01/F02 AC、隔离表述和四任务边界无阻塞。验收记录提交 `fde6342`、四任务归档提交 `eb6218e`、Codex journal Session 31 均已完成登记。本批无剩余工作，未推送。
