# F06：报告失败传播与 CLI 退出状态

## 目标与用户价值

报告生成器已经启动但执行失败、超时或没有遵守计数输出契约时，`hunt.py --report-only`
必须明确失败。合法的当前零报告仍然成功，操作者可以据退出码和目标诊断判断是否需要重试，
而不是把故障误认为没有报告。

## 已确认事实

- `tools/hunt.py:273-281` 的 `_extract_generated_report_count` 已兼容 `Indexed N current reports`
  和旧的 `Generated N reports`，无法解析时返回 `None`。
- `tools/hunt.py:1061-1082` 的 `generate_reports` 目前把子进程 `success=False`、超时和不可解析
  输出都折叠为 `0`；找不到 findings 目录则在启动子进程前返回 `0`，这是现有无工作语义。
- 生产调用者只有 `tools/hunt.py:1492-1500` 的单目标和无目标批量 report-only 分支；普通 hunt
  不自动生成报告（`tools/hunt.py:1359-1363` 保留 `reports=0`）。
- `tools/runtime_exec.py:365-374,525-544` 已将非零退出、超时和启动失败统一为 `(False, 输出诊断)`，
  不保留具体子进程码；共享 helper 不应为 F06 改协议。
- 现有回归 `tests/test_finding_index.py:1143-1160` 已覆盖成功零、正数和旧格式，但错误地把失败
  与不可解析输出期待为 `0`；`tests/test_hunt_initialization.py` 尚无 main/report-only 进程出口覆盖。

## 要求

- R1：成功计数是非负整数（包括 `0`）；失败用明确的领域错误表示，保留目标、失败类别和子进程
  输出诊断，不能读取历史 Markdown 数量兜底。
- R2：单目标 report-only 遇失败返回稳定非零码；无目标批量继续处理所有 findings 子目录，任一
  目标失败最终返回非零，并保留其他目标已成功生成的结果。
- R3：findings 目录不存在、批量根目录不存在或没有子目录继续表示无工作成功 `0`；这与已启动
  子进程但执行/协议失败不同。
- R4：普通 hunt、报告生成器、Store、发布和 `run_argv` 共享协议保持不变；报告仍是显式步骤。

## 验收条件

- [x] `Indexed 0 current reports`、正数和 `Generated N reports` 返回成功整数。
- [x] 子进程非零、超时、空输出和不可解析输出均返回明确失败，诊断包含目标/原因，不能伪装成 `0`。
- [x] 单目标实际 CLI 进程返回非零；批量失败后仍执行后续目标，全部成功且计数为零时返回零。
- [x] 无 findings 根目录维持无工作成功；`--status`、`--setup-wordlists` 和普通 `--target`
  分支不因入口改造改变既有调用行为。
- [x] 定向 helper 与 CLI 回归在隔离临时目录、mock 子进程、无网络条件下通过。

## 决策与边界

- 采用 `ReportGenerationError` 作为 `generate_reports` 的失败表示；保留成功整数 API，避免让
  调用方通过真假值混淆 `0` 与失败。
- `main()` 改为返回 CLI 状态码，模块入口使用 `raise SystemExit(main())`；报告失败使用错误码
  `2`，符合后端 CLI 约定。批量循环按确定顺序继续执行，不以 `all()` 短路。
- 只在当前 owner `tools/hunt.py` 和其已有 focused tests 中改动；不修改 runtime subprocess
  helper、报告索引协议、历史报告文件或其他审计项。

## 顺序与批准边界

第一个修复子任务；本文件、`design.md`、`implement.md` 和上下文清单完成后，等待用户对最终
规划摘要的新批准，再执行 `task.py start` 和实现。

## 范围外

其他审计项、新功能、架构重构、真实目标操作、全局安装/同步和未经确认的数据迁移。
