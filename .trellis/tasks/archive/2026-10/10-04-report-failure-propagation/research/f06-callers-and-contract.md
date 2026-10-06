# F06 研究记录：调用链与错误契约

## 来源与范围

本记录基于当前 HEAD `554eea5` 的源码静态核对和 `/tmp/ccst-audit-2026-10-02/AUDIT.md`；
本规划阶段未重新运行审计复现，也未修改产品文件。

## 关键锚点

- `tools/hunt.py:273-281`：计数解析支持 `Indexed`/`Generated`，不匹配返回 `None`。
- `tools/hunt.py:1061-1082`：`generate_reports` 缺目录返回 `0`；child 失败或 count 为 `None`
  当前均返回 `0`。
- `tools/hunt.py:1492-1500`：report-only 是唯一两个生产调用位置；单目标与批量均忽略返回值。
- `tools/hunt.py:1517-1519,1526-1527`：普通 hunt 预期异常为 exit 2；模块入口当前没有传播
  `main()` 返回值。
- `tools/runtime_exec.py:365-374,525-544`：非零/超时/启动失败转为 `(False, stdout+stderr)`；
  共享 helper 不保留 child exit code。
- `tools/report_generator.py:486`：成功输出 `[+] Indexed {total} current reports`；成功零是合法
  的当前索引结果。
- `tests/test_finding_index.py:1143-1160`：已有计数回归，失败和未知输出的预期编码了待修缺陷。
- `.trellis/spec/backend/error-handling.md`：核心逻辑不吞错误；CLI 入口返回稳定非零码，模块
  入口使用 `raise SystemExit(main())`；错误需含失败对象和可执行诊断。
- `.trellis/spec/backend/contracts/validation-evidence.md:640-645`：Hunt 只计算 successful
  indexed reports，不回退 stale files。

## 结论

失败表示应在 `hunt.generate_reports` 这一共享 owner 处一次转换，不能在两个 main 分支分别猜测
`0` 的含义。批量应收集失败而非短路；无工作目录保持既有成功语义，以免把“没有需要索引的目标”
误判为损坏。
