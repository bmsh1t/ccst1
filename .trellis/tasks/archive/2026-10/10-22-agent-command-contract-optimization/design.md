# Design

基线 `2ce0171`。按用户审阅的
`.trellis/workspace/Codex/research/10-22-agent-command-optimization/PLAN.md` 实施。

## Boundaries and data flow

- 验证/报告、记忆、coverage 和 metadata owner 不迁移。Markdown 修正调用合同，
  不修改发布 ID、Store schema、claim、Scope/Auth 或已登记 bytes。
- Chain connector 方法在 `triage-validation.md` 增补完整章节；Web3/Token 在已有
  Decision Tree 补全原 command/agent 方法。六个入口引用模块，保留独有接口。
- `surface._surface_options` 只删候选数量触发的 chain 推荐，不新增策略或阈值。
- Disclosure：显式 `--vertical` -> keyword-only API -> 有界 similar 查询 -> 完整
  cache -> Markdown。行业优先占一个既有五次配额，默认技术标签顺序不变。

## Disclosure persistence

仍使用每目标一个 cache。完整成功 payload 增 `vertical` 字符串；legacy 缺失视为
没有行业提示。TTL 与行业都匹配才命中，行业不同的完整缓存仍可作为失败回退。
Markdown 分别披露 requested/material vertical，不把旧行业材料当本次查询结果。
不按行业新增文件表，也不自动从 business_model 解析行业；由 agent 显式传入。

实际 output 在查询前确定并严格读取。局部章节提取保留精确 `## Read in full`
到下一同级/更高标题的原文，忽略 fenced code 内标题；仅缺文件表示无旧内容，
解码/读取失败向上传播，避免无声覆盖。新全文阅读使用摘要旁
`disclosed_patterns.readings.md`（自定义 output 用同样 suffix），工具只链接不改正文。
由 agent 首次创建新阅读文件后补一次链接；后续摘要重建自动引用它。
文件分别复用 `write_text_atomic`，不宣称跨文件事务或并发编辑锁。

## Compatibility and rollback

保留默认调用、provider 接口、无行业 legacy cache、状态/时间/partial/no-mcp 语义。
新增 API 参数均可选且 keyword-only。独立阅读文件不参与目标 lifecycle。
已有引用不自动搬走；旧章节继续保留，避免迁移风险。
代码可由 Git revert 回退；既有缓存新增字段可由旧 reader 忽略，阅读 artifact 不丢失。
单目标 cache 只留最后完整查询，切回更早行业需重新查询。

## Scope map

必改：`tools/disclosure_search.py`、`tools/surface.py`；三专项 module 与六个入口；
triage/validate/validator/report-writer/hunt 的发布说明；surface/check-coverage/kb/
context-pack 的读取责任；remember/recon、README/tool-index 和相应 backend specs。
用户要求由主代理修改；default 探子只做定点检索和独立核验。
