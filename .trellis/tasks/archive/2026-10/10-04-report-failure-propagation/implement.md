# F06 实施计划

1. 在 `tools/hunt.py` 增加最小 `ReportGenerationError`，让 `generate_reports` 对 child execution
   failure 与成功但无法解析计数分别构造带目标/诊断的错误；保留成功整数和缺目录返回 `0`。
2. 将 `main()` 的裸成功返回改为整数；report-only 单目标捕获报告错误返回 `2`，批量按稳定顺序
   继续每个目标、记录错误并在循环结束返回 `2`；模块入口改用 `raise SystemExit(main())`。
3. 更新 `tests/test_finding_index.py` 的失败/不可解析断言，并补充超时、空输出、缺目录不启动
   child 的 helper 回归。
4. 在 `tests/test_hunt_initialization.py` 增加隔离的 report-only CLI 进程回归：单目标失败、批量
   失败后成功、全成功零计数、无 findings 根目录，并保护 status/setup/普通 hunt 分支。
5. 运行最小验证：

   ```bash
   python3 -m pytest -q tests/test_finding_index.py tests/test_hunt_initialization.py \
     -k 'hunt_report or report_only or non_report'
   git diff --check
   ```

6. 复核 diff：确认没有修改 `runtime_exec` 协议、没有历史 Markdown 兜底、没有真实网络/目标
   操作或新增依赖；随后交给质量检查。

## 风险停止点

- 若现有测试发现其他 `main()` 调用依赖 `None`，先扩大调用者检索并回到设计，不在本任务中
  添加兼容包装层。
- 若临时 CLI 测试触发真实工具、网络或用户目录，立即停止并修正隔离；不通过放宽断言掩盖。

## 执行记录（2026-10-05）

- 已恢复会话 `01a10696-9186-7ae1-baa2-19e12cf6aab0`：最终规划已获用户批准，任务启动后因
  OpenAI resource mismatch 中断，原会话没有实现改动。本会话重新关联现有任务并完成三文件实现。
- 已运行步骤 5 的定向 pytest 命令：**27 passed，exit 0**。真实入口回归使用临时副本和 mock
  执行器，未访问真实目标或网络；未运行全量测试、构建、lint 或 typecheck。
- 独立只读复核完整三文件 diff，未发现阻塞问题或范围内证明缺口；未重复运行测试。
- 根因是执行结果到报告计数的契约丢失，旧测试还固化了静默零值。已在共享 helper 区分领域
  错误，并用真实 `__main__` 进程测试防止仅修 `main()` 返回值却遗漏入口传播。
- 报告规范同步到 `.trellis/spec/backend/contracts/validation-evidence.md` 的现有七节契约；
  当前停在提交批准门，未提交、归档或推送。F07/F08 及后续子任务尚未开始。

## 收尾记录（2026-10-06）

- 恢复会话 `01a10be2-70a1-7752-8f9d-8b6df708301f`，核对四文件完整 diff；独立只读复核无阻塞问题。
- 重新运行步骤 5 的定向 pytest：**27 passed，exit 0**；`git diff --check` 通过。
  未运行全量测试、构建、lint 或 typecheck，未访问真实目标或网络。
- 工作提交：`b63ad6a98c17c14305612ed387028d91a0de5fd9`，`fix: propagate report generation failures`。
- 本任务直接在 `main` 完成、没有 PR；使用 `archive --skip-branch-validation --no-commit`
  归档到 `.trellis/tasks/archive/2026-10/10-04-report-failure-propagation`，保留真实分支元数据。
  归档与 journal 单独提交，不修改 `.trellis/` 忽略规则，不推送；F07/F08 未开始。
