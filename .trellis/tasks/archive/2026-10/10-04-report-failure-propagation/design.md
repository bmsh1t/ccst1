# F06 技术设计：报告失败传播与 CLI 退出状态

## 边界

```text
report_generator.py subprocess
        -> runtime_exec.run_argv_command (现有 bool + bounded diagnostic)
        -> hunt.generate_reports (成功 count 或 ReportGenerationError)
        -> hunt.main report-only branch (single/batch aggregation)
        -> process exit code
```

`run_argv` 仍是共享执行 owner；F06 只在 Hunt 把它的布尔结果和计数协议转换为领域结果。
普通 hunt 的扫描/登记/仪表盘路径不进入该链路。

## 数据与错误契约

`generate_reports(domain)` 保持成功返回 `int`，包括当前索引为零的合法结果。findings 目录不
存在时继续返回 `0` 且不启动子进程。子进程失败（包括超时、启动失败）抛出
`ReportGenerationError`，错误文本包含目标、`execution` 类别和 bounded child output；子进程
成功但 `_extract_generated_report_count` 为 `None` 时抛出同一异常，类别为 `protocol`，并保留
输出。不会扫描旧 Markdown 作为替代计数。

`main()` 返回整数：status/setup-wordlists/成功 report-only/成功 hunt 返回 `0`；单目标报告失败
和批量任一报告失败返回 `2`。批量逐个调用并记录失败，继续后续目标；失败日志包含目标和异常
诊断，成功目标的副作用保留。`__main__` 通过 `raise SystemExit(main())` 传播返回值。

## 兼容性

- 保留 `_extract_generated_report_count` 的两种输出格式和 `run_argv` 的 `(bool, str)` 语义。
- 保留 600 秒超时、stdout/stderr 合并诊断、显式报告步骤和无 findings 的无工作成功。
- 不改变 `report_generator.py` 的索引、Store 绑定、发布或历史 Markdown 行为。

## 测试隔离

函数级测试 monkeypatch findings/reports 路径与 `run_argv`，覆盖成功计数、失败、超时诊断、空/坏
输出和缺目录不启动 child。CLI 测试在临时复制的 `hunt.py` 上通过 `runpy(..., run_name="__main__")`
启动真实入口，mock auth/config/tool checks 与 child runner，断言 `CompletedProcess.returncode`。
批量测试固定 findings 子目录顺序并用标记文件证明失败后仍处理后续成功目标；另保留非报告分支
的轻量保护。

## 取舍与回滚

一个异常类型比返回 `(ok, count)` 少改成功调用方，也不会让 `0` 产生真假值歧义。若实现后发现
现有调用者需要非抛出式报告状态，可在同一 owner 内把异常转换为等价的返回码，但不得恢复静默
零值。回滚仅需恢复 `tools/hunt.py` 与两份 focused test 的本批变更，不触碰目标状态或报告文件。
