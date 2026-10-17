# B7：自包含 Git 交付验收

## 当前结果

用户同意的必要前置审核与 portable reader 已完成。A10 勾选；C 的兼容 reader 已发布、
只读回读成功。用户确认分批清单后，两批代码已提交，原任务已归档；收尾日志单独提交。
没有个人 runtime 部署、模型下载、真实目标操作或在线能力验证。

```text
C = /root/tool/ccst(rename-_Ya66f2)/ccst3/ccst
B = /tmp/ccst-6k-accept-XQES5z/b7
F7 = B/repo
独立 Git = B/git-preview/.git（验收时C index/refs未动）
验收前 HEAD = 99a653b14ece0f925a625c8645a690aaa8a7a218
cleanup 前置树 = a216a4bf15a03d8956e8a446e4bfcb0299dadb86
integration 树 = d59dfb26e48f8942d65e08d25410bb4f56dd5ba0
D7 = /root/.local/state/ccst-recovery/6k-full-integration/20261017T040325Z-b7-C
```

F7 从拟提交 index 导出 674 个白名单源文件，逐项与 Git blob 比对，不复制 C 未纳入的
advisory/metrics 代码；完整方法树为 56 活动文件和 99 历史文件。旧的 S/F 不变。
独立 Git 的 alternates 只读引用 C 对象；不将它叫可移植 Git 仓库。持久包另保存确切
源码、两批 patch 和边界清单，不依赖复制 alternates 路径来恢复候选。

## 修复边界

根因：旧终态读取与恢复共同绑定历史目录/见证 inode；Git checkout 不保留这些身份。
仅 `tools/hot_method.py` 的 catalog/read 显式选 `local_identity=False`，返回
`revision_validation=published_content`。仍核对完整匹配的 applied 日志链、原件及
独立 witness/blob 字节和路径安全；新读操作仍捕获并核对当次文件身份。

apply 的当前版本前置、历史重试、recover 默认保持严格本地身份。新 checkout 可读不等于
可继续旧事务，不增加 adopt/rebind、Git 特判、重建见证或失败 fallback。不修改活动方法、
manifest、transaction、decision 或 receipt。既有 A6 来源不可独立核实的状态保持可见。

## 新增行为验证

全部测试用 F7 自己的代码和现有测试，白名单环境、临时 HOME/数据根；bubblewrap 独立
网络/文件系统边界与 Python socket/I/O guard 叠加，不读取 C/S/个人 runtime/真实目标。

| 验证 | 结果与证据 |
|---|---|
| 拟提交新 checkout 本身 | 全 56 正文逐字节/hash 回读、62 origins 健康；根和见证确为新 inode；review/private-source 限制不变 |
| 新 checkout 维护边界 | 旧 A6 recover、形状合法的 synthetic 普通 apply 都因旧目录身份拒绝；知识树前后不变 |
| portable 小 fixture | 本地 bootstrap→apply→copytree 新 inode 可读；14 类 pending/日志/原件/正文/witness/shape/symlink 损坏拒绝，旧 read CAS 拒绝 |
| 本地恢复回归 | 11 类第三态/同字节换 inode/metadata/父目录/slot/alias 等冲突；complete/restore 方向、两种历史重试、cleanup 目录同步故障及 v1 兼容 |
| 方法矩阵合计 | `B/results/delivery.json` 37 条通过；`delivery.log` 末尾完整 `passed, cases=37`，独立审核逐条核对 |
| cleanup 专项 | 8 条通过、退出 0：缺失拒绝→真实只读关联允许→原件改变使报告 stale 而技术判断不变；错误 refs/时序/partial/副作用拒绝，真实 runner→Store control 登记，无新 Finding |
| 既有相关回归 | 6 passed in 5.31s、退出 0；Finding 原件登记、claim CLI、报告绑定/过期、只读 preflight、延期报告 |

方法拒绝反例比较知识树 bytes、类型、dev/ino、mode、uid/gid、mtime/ctime、nlink，证明
调用前后持久状态不变；不称作写系统调用的形式化证明或断电恢复测试。本次不重跑原 71 项
全矩阵/59 项回归，也不扩修已确认与本任务无关的两项旧测试失败。

### 验收脚本/包装问题（已留证）

- 首次 witness/blob alias 反例已正确拒绝，临时脚本期待的错误短语写反；只修 assertion。
- cleanup runner 返回尚未登记的 summary；临时脚本漏掉现有 `sync_runner_artifacts`。
  补上真实登记调用后，8 项专项全部通过；没有为测试修改产品或原有项目测试。
- 方法脚本完成 37 条后，外层 zsh 的 `status` 为只读变量，退出码采集失败。因此该批只声明
  全部断言及完成标记通过，**不声称捕获了 Python exit=0**。后续命令改用 bash/rc；没有为
  修正采集重复跑整个方法矩阵。原始错误与已通过记录均保留。
- C 只读包装初次硬编码不存在的 `/usr/local/bin/python3`，bwrap 在启动产品前失败。
  改为实际 `sys.executable=/usr/bin/python3` 后 catalog/read 均退出 0；未改 C 权限或产品。

## C 发布与保护

04:03:25 UTC 在 678 项明确源码/方法清单及 C index 字节守卫通过后，仅原子替换
`tools/hot_method.py`，保留 owner/mode；D7 已先保存该文件 before/after、prepared 与发布脚本。

```text
reader before = f69fc8d9b7bd988a7fd7c8d519a59acc54f239eff618af36b3207f927e37fe80
reader after  = 8240360cd86d236152f9c647abf6abc6df0df6bb583e1fe904302ce0107b2c4e
manifest      = 2cdd38b1b507c2fbf4aefb06b9d71c514cd417172cb3ff556287cb16b6415b06
```

其余 677 项 bytes、身份、mode、owner 及 C index 未变，包含真实本地方法日志/见证和无关
产品 WIP。随后 C 自身代码在 C 全根只读挂载、既有 source-only guard 下执行 catalog 与
全 56 正文读取均成功；`c-readback.json` 保存真实回执。C 原 CLAUDE/context_pack/tool-index
完整工作树字节保留，提交时另取已审的 partial blob，不能 whole-file 暂存。

## 审核、提交及归档

两项独立只读复核无阻断 finding：新增 reader/测试证明力度，以及前置闭包/partial 接线。
具体一次性提交顺序及白名单见 [分批计划](final-commit-plan-2026-10-17.md)。
新 spec 的三条任务 research 链接须在归档提交改为 archive 路径；归档后的 task 内越级
spec 链接及 JSONL 路径也要同步。B6 执行 payload 仅随本地目录归档保留，不作为 Git 源码。

renderer 复测须含 6 个 JSONL 文件（4 spec + 2 research）及 3 件规划正文，无截断且总量
不超过 131072 bytes；实际最终数值、包 hash 与恢复回读见 [持久回执](b7-durable-package.json)。
这些结果证明本批工程交付，不代表个人 runtime 已同步或公开案例已独立复现。

## 已确认提交与归档

用户回复“确认”，随后“继续”；按原四批清单执行，不 push、不 amend。
- `a4a22e2d0b81d2c232be3518bdba89e652b19635`：cleanup前置，6路径；树与验收候选一致。
- `ba183ca88e1bf311e59f3b41348c318f96047e3f`：6k集成，178路径；树与验收候选一致。
- 原任务以 `--no-commit --skip-branch-validation` 归档；只暂存29项任务工件与spec链接修正。
- b6-inputs全部74文件仅在本地随目录移动保留，内容/身份不变，不纳入Git；其他WIP保持原样。
- 日志仅追加本次记录及对应索引，使用 `add_session.py --no-commit`；四批最终hash另保存在D7收尾回执。
