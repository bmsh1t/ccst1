# Scanner 摘要损坏输入与计数契约

## Goal

让 Scanner 的损坏摘要和未完成输入继续可诊断、可复核；不以异常或假空结果丢失恢复线索。

## Confirmed Facts

- 父任务 F1 已复现：`autopilot_state_read.py:204-265` 将 lane_coverage=[] 映射为 missing；
  1.9/1.1/0.8 截为 1/1/0，reader 标 valid 且 gate 不再输出 residual。
- 非有限数触发 OverflowError；坏 UTF-8 触发 UnicodeDecodeError，未走其他损坏摘要的 partial 分支。
- `autopilot_gate.py:161-222` 重复相同计数转换；直接调用 build_closure_projection 的
  state 也必须验证，不能仅信任已投影的 accounting_valid。
- `vuln_scanner.sh:539-729` 正常写整数计数和 continuation；坏输入不是新的合法生产格式。
- 基线复现/边界记录位于父任务 research/，未证明真实目标误耗尽。
- 首次真实 Store 验收揭示 `coverage_matrix.py:1513-1520` 先于 Scanner reader 解码同一摘要；
  `surface_projection.py:45-54` 也有同源编码缺口。用户已批准两处现有损坏边界补充。
- 第二次验收揭示 `finding_index.py:149-168,744,803` 的机器文件排除集缺少 Scanner 专属
  `summary.json`，root JSON 枚举因此读取它。用户最新 `go` 已批准只补既有排除集，不扩大通用 reader。

## Requirements

- R1：已存在但损坏的摘要（编码/JSON/根对象/显式 lane 容器）保持 partial、原始 path 可读；
  不抛未预期转换异常，也不伪装成 missing/成功零条。
- R2：Scanner reader 和 gate 共用一个计数校验；拒绝布尔、小数、非有限数和矛盾计数，
  保留合法非负整数及整数文本的现有支持。损坏计数不得隐藏待复核工作。
- R3：合法摘要、旧版缺少 lane_coverage、空 lane 字典、candidate_only/skipped/partial 的
  既有语义不变；保留 continuation、summary path、review token、闭合抑制与完整原文。
  Scanner summary 不属于独立 Finding claim；独立 claim 的完整材料和候选语义继续可恢复。
- R4：不新增状态源、依赖、schema/hash 或额外文件读取；不调整 Scanner 执行和 Recon 规则。

## Acceptance Criteria

- [x] AC1（R1）：坏 UTF-8/JSON、错误根/容器、NaN/Infinity、None/布尔/非整数等边界均有
  focused 回归；读前后原始文件和 Store binding 不变。
- [x] AC2（R2）：reader 后接 gate 与直接 state -> gate 均保留损坏 residual，不靠 mock 绕过
  校验；合法 selected+remaining=input_total 保持原结果。
- [x] AC3（R3）：missing 文件/缺少旧可选字段/空字典有明确兼容断言；合法剩余输入的
  continuation、路径和 token 不变；partial=0 与 candidate-only 不被误闭合；summary 不进入 claim，独立 claim 原文保留。
- [x] AC4（R4）：仅改已批准的现有产品模块和相关测试/规范，单条定向验收通过，无多余采集。

## Approved Scope

产品共五文件：`tools/autopilot_state_read.py`、`tools/autopilot_gate.py`、
`tools/coverage_matrix.py`、`tools/surface_projection.py`、`tools/finding_index.py`；
相关回归集中在 `tests/test_autopilot_state_tool.py`，规范更新现有 Recon/Surface 契约。
最终 focused 验收为 **67 passed, 225 deselected in 1.67s**；三轮证据见 verification.md。
实现获批不等于提交获批，提交仍需另行确认。

## Out of Scope

- `vuln_scanner.sh` 的执行/发布、Recon phase gate、其他 JSON reader、Runtime 安装筛选。
- 自动重试、自动修复/覆盖源 summary、裁剪原文、扫描、部署、数据库或 hash 变更。
- 子代理、旧暂存日志、未获批的额外实施/提交。
