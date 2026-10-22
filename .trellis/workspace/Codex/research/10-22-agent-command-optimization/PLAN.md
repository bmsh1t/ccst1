# Agent / command 优化边界

基线：`2ce0171`，分支 `refactor/10-11-capability-architecture`，工作树干净。
用户已审阅本计划并回复“开始”。实施任务：
`.trellis/tasks/10-22-agent-command-contract-optimization/`；本文件保留为批准范围。

## 目标与验收

1. **验证与发布入口对齐。** `/triage` 保留一句描述即可快判的 advisory 能力；
   single-step `/validate` 成功后消费收据，deferred 或新的交付需求才 `/report`。
   修改 `commands/triage.md`、`commands/validate.md`、`agents/report-writer.md`、
   `README.md`，保留既有 publisher、ID 与 owner 接口。
2. **查看不强制刷新或记账。** `surface`、`check-coverage`、`kb`、`context-pack`
   复用当前有效事实，缺口时才查询相关 owner；真正结束仍满足 Coverage/Closure。
   修正 `find-gaps --all` 的无效说明，认知写回引用现有共享协议。
3. **专项方法只有一份完整正文。** Chain connector 方法归
   `skills/src-hunter/modules/triage-validation.md`；Web3 与 Token 方法分别归现有
   `web3-audit.md`、`meme-coin-audit.md`。迁移 command/agent 的独有细节后再删除副本；
   保留 description、输入、权限、范围、结果与父会话回交。非 HTTP 合约保留分析材料，
   不编造 Store Finding URL。`tools/surface.py` 移除仅凭候选数推荐 chain-builder 的接线。
4. **披露查询保留人工阅读成果。** `tools/disclosure_search.py` 与
   `agents/disclosed-researcher.md` 增加显式行业提示接线；缓存命中区分查询行业，失败
   仍保留最后完整缓存并说明旧材料的查询条件。新全文阅读保存独立 artifact，生成摘要
   指向它；已有 `## Read in full` 引文在后续重建中保留，不静默擦除。
5. **记忆与导航示例可执行。** `commands/remember.md` 使用原验证收据的
   `summary_path`，不声称 Finding 有 summary locator；`commands/recon.md` 的负经验
   示例给出条件、重开条件与真实 operation/step。无登记证据用 advisory note。
   README 和 `docs/tool-index.md` 同步当前 source acquisition、专项与 target 参数。

## 兼容与边界

- 保留全部 10 agents / 37 commands；`/triage` 此次薄化，不整项删除。
- 原 `src-hunter` description、完整 6k rules / 知识库、调查与结束合同保留。
- 不新增 controller、路由注册表、评分器、生命周期、通用缓存框架或依赖。
- 不更改 Store schema、Scope/Auth、claim、证据登记、报告 hash 或真实目标数据。
- 不读取、修改或运行项目 `tests/`；不接触个人/全局 runtime、正式知识审核、
  上游服务或付费模型。不 push，不归档旧任务。

## 验证计划

在一次约 60 秒内的 focused check 中使用隔离的生产源码副本和合成材料：

- 披露查询真实 owner + stub provider：行业进入查询；同条件复用缓存；条件变化不错误
  命中；查询失败不覆盖旧缓存；默认/no-mcp 语义与旧引文、独立全文文件保持。
- Surface 的真实纯函数：普通 Review Pool 不推荐 chain-builder，其他证据选项保持。
- 命令参数、模块引用、Markdown anchors、description / 工具权限、完整迁移方法与
  原 6k 文件保持检查；安装资产清单仅在临时目录核验。
- 最后审阅完整 diff，更新必要的 backend spec；不把文档字节缩减解释为实际模型收益。

当前计划无需要用户决定的产品分歧。沿此已审范围执行；如果实际范围
超出以上边界，先说明证据及新的范围。
