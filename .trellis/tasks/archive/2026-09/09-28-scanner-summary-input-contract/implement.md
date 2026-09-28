# 实施与验收计划

状态：用户已批准全部五文件边界；实现、定向验收和规范同步完成；已提交 e755065，用户已确认归档。

## 执行清单

1. [完成] 从 `7c3556d` 创建并激活 `fix/scanner-summary-input-contract`；不重建分支，保留两份旧暂存日志。
2. [完成] reader/gate 共用 `_scanner_lane_accounting`，区分坏输入与合法空/缺失，保留无效标志。
3. [完成] 增加文件 reader→Closure、直接 gate 和真实 Store 的 bounded state→Closure 回归。
4. [完成] 按追加批准修复 Coverage/Surface 同源 UnicodeError 边界，保留现有坏 JSON 语义。
5. [完成] 按追加批准把 Scanner `summary.json` 加入 Finding 既有非 claim 排除集；真实 claim 保留。
6. [完成] 运行下面一条定向验收：67 passed, 225 deselected in 1.67s；原失败整链测试保持原样。
7. [完成] 更新 recon-surface 现有七段契约；完整差异与基线保护审查记录见 verification.md。
8. [完成] 用户已确认 scoped 计划并提交 e755065；后续 go 已确认归档，再处理安装筛选子任务。不 push/merge/deploy。

## 验收命令

```bash
python3 -m pytest -q tests/test_autopilot_state_tool.py tests/test_scanner_pass.py tests/test_coverage_matrix.py::test_default_xss_skip_is_visible_without_closing_coverage -k 'scanner or residual_global_review or default_xss_skip'
```

约 60 秒预算；足够通过后不运行全仓、构建或重复测试。首轮旧命令及两次范围修订的完整证据
保留在 verification.md 和 research/first-check.log、second-check.log；最终输出为 final-check.log。
父任务的基线复现脚本断言旧缺陷，不作为修复后成功验收。

## 审查与回滚边界

- Scanner 两份计数规则收敛在已有 reader 纯函数；不抽取 Recon 规则，不新增第三个解释器。
- Coverage/Surface 只扩已有编码异常边界；Finding 只补文件归属，不更改通用 JSON reader。
- 没有 broad exception 吞错、状态写入、自动 broad scan、hash/schema 修改或新增依赖。
- 直接 API 校验、原始材料、pending action、continuation/path/review token 均保留。
- 提交必须精确指定本任务路径；两份旧暂存日志不纳入、不改写。产品可按独立提交回滚，无数据迁移。
