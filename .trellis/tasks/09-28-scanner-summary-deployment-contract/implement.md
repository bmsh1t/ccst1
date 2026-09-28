# 执行计划

状态：Scanner 已提交并归档；安装筛选实现、31 项定向验收与规范更新完成，等待独立提交确认。

1. [完成] 读取现有 owner、规范与相关测试；仅创建 task/research 文件。
2. [完成] 本地临时复现 F1/F2，命令与结果见 research/findings.md。
3. [完成] 拆为两个可独立验收/回滚的子任务；父任务不直接改产品。
4. [完成] 用户已批准原规划及 Scanner 两次范围补充，两个子任务均按顺序激活。
5. [完成] Scanner 实现、验收与规范更新，提交 e755065，归档 45fdf1e。
6. [完成] 安装筛选实现与验收；既有测试隔离 HOME/PATH，rsync/cp 均通过，不触碰个人 runtime。
7. [待提交] 安装器提交计划独立确认；父任务 R1/R2/R3 与旧暂存日志已核对，再收尾归档。

## 验证预算

每个子任务运行一条对应 focused pytest，目标约 60 秒；成功提供足够证据后停止。
父任务不再叠加全仓测试或构建。若环境缺少 rsync，明确报告相关测试 skip，不假装覆盖该分支。

## 基线保护

- 保留 `.trellis/workspace/Codex/index.md` 和 `journal-1.md` 的现有暂存/工作区字节。
- 参考 `/tmp/fact-contract-baseline.vmDsm7/` 做保护比对；任务提交只能使用精确路径。
- 仅使用普通 tools/ 源码与临时 fixture，不扫描或修改真实 target/个人 runtime。
- Scanner 起点为 `7c3556d`；安装器起点为 Scanner 归档后的 `45fdf1e`，base_branch 为
  `fix/scanner-summary-input-contract`。两个实现使用独立分支，没有合并旧基线分支。

Scanner 的同源 Coverage/Surface 编码边界已获批补入范围，详情见子任务 verification.md；安装器仍独立实施和验收。
第二次验收为 64 passed/1 failed；Finding 的 `summary.json` 排除项已获批，不修改通用 JSON reader。
最终修复后同一 focused 命令为 67 passed；没有追加全仓检查。安装器在 Scanner 提交与归档后启动。
安装器现已完成 31 项独立验收；两项测试结果分别记录，不宣称跑过一次合并全仓测试。
