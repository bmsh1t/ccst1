# 6k 规划续接与收尾记录（2026-10-15）

## 恢复点与范围

从 Codex session `01a13d50-dbf2-7d32-8fa7-56c2ca5538de` 恢复可读历史，实际仓库仍为
`/root/tool/ccst(rename-_Ya66f2)/ccst3/ccst`。本轮继续已有规划，不新建任务、不激活任务。
`task.json` 仍为 `planning`；用户已选择 D1=A，但尚未批准最终完整规划的实施。

完整 PRD、设计、实施计划、来源/差分/能力矩阵及两个上下文清单均已存在。早期
`final-plan-review-2026-10-15.md` 中“缺设计/实施计划”的陈述属于当时状态，不再作为
当前缺文件的证据。R1–R6、A1–A9、D1=A 及既有产品工作树继续保留。

本轮只调整任务内两个 JSONL、PRD 的状态链接、实施前读取/隔离门槛，增加原文加载图与
本记录；不改产品代码、方法内容、全局规范、Trellis loader、用户 runtime 或目标资料。

## 两项规划核验问题

### 上下文注入

旧 implement/check 清单分别引用 436,087 / 387,171 bytes；其中有 5 / 4 项超过
单文件 32,768-byte 上限。loader 先读取 manifest，再读取 PRD/design/implement，
所以仅缩短单文件仍可能挤出关键规划正文。原 `task.py validate` 的成功状态不能证明
自动上下文完整。

本次采用现有小规范加 [原文加载图](context-reading-map.md)，按批次显式读取完整
canonical 规范和来源台账。没有复制“压缩版规范”，没有删除来源内容，也没有改变全局
注入上限。最终以真实 renderer 的正文包含关系与截断标记检查为准。

### 差分矩阵相对链接

旧 session 的链接检查将 research 文档中的相对路径拼在任务根目录，而非链接所在
Markdown 的目录，因此误报 `v23-delta-matrix.md` 到 `capability-disposition-matrix.md`
的 sibling 链接。当前按文档所在目录解析，文件存在；无需修改正确链接。

## 历史 runtime 安装事件：未恢复

原 session rollout 的 1064、1073 行记录：`bash install.sh --help` 没有产生帮助输出，
而是实际同步了 30 个文件、移除了 1 个过期托管文件，并更新 `/root/.claude` 中的
`.ccst-installed.json`。原命令未隔离 HOME，虽然 exit 1，副作用已发生。

原记录未给出被移除文件的身份，也没有可证明运行前 runtime 全部字节的快照。本轮不
推测还原方案，不执行同步/回滚，不把 checkout 的范围核验说成个人 runtime 已恢复。
恢复/部署该目录仍是独立待用户决定的操作；不会因批准本项目实现而顺带执行。

后续规划核验只读产品脚本及 parser 源码，不用运行 `--help` 猜测脚本是否无副作用。
实施阶段的 installer 验收仅使用临时 HOME，并让 doctor 显式指向同一临时 runtime-root；
任一隔离值缺失立即停止。绝不复跑上述历史命令作为验证。

## 核验范围与记录

本轮原文/状态检查已确认任务身份、D1=A、全部规划工件存在、相对链接可解析以及
既有 19 个 tracked 修改和 60 个 untracked 文件。规划编辑前的逐文件字节快照与
NUL 分隔 Git 状态存于 `/tmp/ccst3-plan-restored-20261015-o5mafb8_/baseline.json` 及
同目录 `before/`；79 个任务外文件已记录 SHA256，避免非 ASCII 文件名的引号误解析。

本记录区分规划结构/注入验证与产品行为验收。V1–V7 尚未执行，A1–A9 不因规划收尾而
勾选；没有产品测试、构建、安装、网络目标操作或提交。

## 最终规划窄检查：已执行并通过

在 C 执行以下临时检查脚本，exit 0，耗时 0.236 秒；脚本与详细输出保留在同一临时
目录，不新增项目测试文件：

```bash
python3 -B /tmp/ccst3-plan-restored-20261015-o5mafb8_/validate_planning.py
```

| 检查 | 实际结果 |
|---|---|
| `python3 -B .trellis/scripts/task.py validate .trellis/tasks/10-14-6k-full-integration` | exit 0，无超大文件警告 |
| 实际 Codex implement renderer + wrapper | 6 个 manifest 正文及 PRD/design/implement 全部完整包含；114,237 bytes；无截断或仅路径退化 |
| 实际 Codex check renderer + wrapper | 相同的完整正文包含检查通过；114,229 bytes；无截断或仅路径退化 |
| 任务 Markdown 相对文件链接 | 27 条按所在文档目录解析，全部存在 |
| 6k 来源台账 | 62 项原字节 hash、54 份当前副本 hash、62 个规划归档绑定及 MD/JSON ID 一致；来源文件集合无遗漏 |
| 2.3 对照台账 | 123 个不同源文件的登记 hash 匹配；不代表方法效果或宿主消费者已验证 |
| 需求与改动范围 | R1–R6/A1–A9/D1=A 原文未变；task.json、design、既有台账未变；79 个任务外文件和产品 tracked diff 与本轮基线一致 |
| 实施计划 Bash 代码块 | `bash -n` 语法通过，未执行代码块命令 |

机读结果为临时目录下 `validation-result.json`；两份实际上下文为
`implement-context.txt` / `check-context.txt`，validator 原输出为 `task-validator.txt`。
这些是本机核验附件，持久结论记录在本节；临时附件不是新规范或产品真源。

独立只读审阅对本轮六个规划文件未提出可操作问题。主会话复核差异并运行上述检查；
任务目录受 Git ignore，范围结论使用逐文件快照比对，不只依赖 `git diff`。

规划现可提交最终审阅；仍待用户随后明确批准，才启动同一任务实施。方法、Store、
浏览器登记等产品接线未在本轮实现，个人 runtime 历史事件仍未恢复。
