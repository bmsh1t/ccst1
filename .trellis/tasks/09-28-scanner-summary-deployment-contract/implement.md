# 执行计划

状态：已实施获批的 Scanner 五文件边界，67 项定向验收通过，规范已同步；等待 Scanner 独立提交确认。

1. [完成] 读取现有 owner、规范与相关测试；仅创建 task/research 文件。
2. [完成] 本地临时复现 F1/F2，命令与结果见 research/findings.md。
3. [完成] 拆为两个可独立验收/回滚的子任务；父任务不直接改产品。
4. [完成] 用户已批准原规划，已创建并启动 Scanner 分支/子任务；安装子任务尚未开始。
5. [完成] Scanner 子任务实现、最终 diff、定向验收与规范更新；工作提交仍待确认。
6. 再执行安装筛选子任务；沿既有测试隔离 HOME/PATH，不触碰个人 runtime。
7. 每个子任务的提交计划独立确认；父任务最终核对 R1/R2/R3 和旧暂存日志，再收尾归档。

## 验证预算

每个子任务运行一条对应 focused pytest，目标约 60 秒；成功提供足够证据后停止。
父任务不再叠加全仓测试或构建。若环境缺少 rsync，明确报告相关测试 skip，不假装覆盖该分支。

## 基线保护

- 保留 `.trellis/workspace/Codex/index.md` 和 `journal-1.md` 的现有暂存/工作区字节。
- 参考 `/tmp/fact-contract-baseline.vmDsm7/` 做保护比对；任务提交只能使用精确路径。
- 仅使用普通 tools/ 源码与临时 fixture，不扫描或修改真实 target/个人 runtime。
- 两个子任务起点均暂记当前 `fix/closure-evidence-snapshot-consistency`；实际激活前核对，
  不让流程元数据代替真实 Git 分支关系。

Scanner 的同源 Coverage/Surface 编码边界已获批补入范围，详情见子任务 verification.md；安装器仍独立实施和验收。
第二次验收为 64 passed/1 failed；Finding 的 `summary.json` 排除项已获批，不修改通用 JSON reader。
最终修复后同一 focused 命令为 67 passed；不再追加全仓检查。Scanner 提交与收尾后再启动安装器子任务。
