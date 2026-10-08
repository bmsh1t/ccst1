# 集中工程验收设计

## 边界与唯一事实来源

本任务不改变任何产品 owner、schema、公共接口或运行时行为。沿现有测试验证
AuthSession → 子进程，Runner → Store，当前证据 → Ledger/Context/Checkpoint，
Finding → Report，以及 runtime receipt、披露 cache 和文档 CLI 的实际接线。
`acceptance.md` 只记录本轮执行事实，不成为新的产品状态或测试注册表。

## 固定源码与临时状态

- 固定 `a31535d`，执行前确认 HEAD 相同且没有产品/测试改动。变化则重新核对计划，不偷偷验证旧基线后声称覆盖新代码。
- 用 `git archive` 将该提交导出到新 `/tmp/ccst-acceptance.XXXXXX/repo`；测试只从副本导入。当前树无 tracked symlink，`.gitattributes` 无 export-ignore；目标 state/findings/recon/auth/hunt-memory 和 active-target 文件均未跟踪。
- 副本解决 F01 loopback 测试默认 `BASE_DIR` 读取 Scope 时接触原工作区状态的问题。不能仅更改 pytest basetemp 或 HOME 后声称隔离。
- 每组独立 HOME、TMPDIR、HUNT_MEMORY_DIR、basetemp；使用 `env -i` 白名单环境、系统 PATH，禁止用户 site/第三方 pytest 插件，清除旧 auth、proxy、PYTHONPATH/PYTEST_ADDOPTS 注入；只为 loopback 设置 NO_PROXY。
- 合成凭据仅进入测试自建进程/loopback；不运行真实 scanner、模型或安装器。这是源码路径和环境隔离，不是 OS 网络沙箱；所选 fixture 的具体行为必须保持已核对状态。

## 六组覆盖与去重

| 组 | 范围 | 选择依据 |
|---|---|---|
| A | F01 | 原批准 auth 文件 + 三个来源/重定向兼容节点 |
| B | F02 | 原批准 phase 文件 + 三个锁/异常接线节点 |
| C | F03–F05 | 明确的 Store、Runner、Ledger、truth、Pack、Checkpoint 节点并集 |
| D | F06–F08 | 现有四文件报告/附件/交付选择器，包含 validate→report bridge |
| E | F09 | receipt reader→bootstrap 的既有选择器 |
| F | F10/F11 | 两个现有测试文件，补足 F10 最后修复后的整文件证据 |

C 与 D 共享 `test_target_store.py`，但 C 的显式函数不命中 D 的选择器；不重复同一节点。
A/C 在 Runner 文件也是不同节点。不可把 D/E 的 `-k` 追加到 C，否则会把显式节点过滤为空。
完整 argv 只维护于 `implement.md`；研究文件的历史命令候选不是另一个必跑列表。

## 超时、失败与证据

普通组上限 60 秒；B 上限 120 秒，为真实进程矩阵和内部 20 秒软期限/35 秒硬期限保留清理余量。
每组使用标准 `timeout`、pytest 自带 faulthandler、stdout/stderr 和 JUnit；不引入 pytest-timeout。
外层超时、异常或 skip 不算通过；B 异常退出时检查并只清理本次 RUN 关联的测试进程，不对系统进程批量 kill。
首个失败停止后续组，先归因；已成功且源码/环境未变的组不重跑。修复或环境变化后的最小重验范围必须说明。

`acceptance.md` 记录基线、源码 archive SHA-256、解释器/依赖版本、每组完整命令引用、退出码、
计数、耗时、日志/JUnit 路径和摘要、未覆盖/阻塞；`/tmp` 原始日志是诊断材料，不替代持久化结论。
当前 pytest 与 CI lock 存在版本差异，按实记录；不联网安装以制造 CI 等价结论。

## 收尾与回滚

本轮仅编辑任务/验收记录、必要的原位规范说明及批准后的归档/journal。默认无规范行为变更；
旧 F04/F06 的 archive commit 字段缺失保留为历史记录差异，不借机修历史文件。
F01/F02 逐项对照已完整阅读的原始 PRD/design/implement；通过后提出归档，未通过则保留任务。
验收和父任务只有所有必要验收、子任务与历史核对完成才可归档；其余 32 项不动。
工作记录提交 → 精确归档提交 → journal 提交，提交前一次性确认批次；不 amend、不 push。
失败不需要回滚产品或真实状态；保留临时诊断与未完成任务，调整计划须再次批准。
