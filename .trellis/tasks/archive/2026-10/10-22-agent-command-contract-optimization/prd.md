# 收敛 agent 与 command 合同及重复流程

## Goal

让 agent、command 和现有工程 owner 使用一致合同，减少重复发布、刷新和方法副本，
同时保留完整 6k 调查能力和原生 description 发现。用户已在审阅 PLAN 后回复“开始”。

## Requirements

- R1：`/triage` 保留 protocol-neutral advisory 快判。single-step `/validate` 成功后
  消费已登记报告收据；deferred 尚缺正文或明确的新目的地才走 `/report`。
  依据：`commands/triage.md:12,41`、`commands/validate.md:69,103`、`README.md:296`。
- R2：查看 Surface/Coverage/KB/Context 不强制重建全链或记录无增量认知。实际结束
  保留 Coverage/Closure 与执行收据责任。`find-gaps` 没有 `--all`，缺口由 AI 判价值。
  依据：`commands/surface.md:108`、`commands/check-coverage.md:30,39`、
  `commands/kb.md:175`、`commands/context-pack.md:104`、`tools/coverage_matrix.py:1674`。
- R3：专项方法归现有完整模块，先保全独有方法再薄化六个入口；保留 description、
  工具权限、输入、输出和父会话边界。纯合约不编造 HTTP Finding。Surface 不按
  Review Pool 数量推荐 chain-builder。
  依据：`agents/web3-auditor.md:31,82`、`commands/token-scan.md:30`、
  `commands/chain.md:29`、`tools/surface.py:2083`。
- R4：行业提示参与有界披露查询和缓存匹配；失败保留完整旧缓存并披露材料的旧条件。
  重建摘要保留既有全文引文，新全文阅读放独立 artifact 并被摘要引用。
  依据：`tools/disclosure_search.py:208,375,384,408`、`agents/disclosed-researcher.md:58`。
- R5：记忆示例使用原验证收据的 `summary_path`，负经验有条件、重开条件和真实
  operation/step；无登记证据保存 advisory note。导航宣传与当前采集行为和参数一致。
  依据：`commands/remember.md:69`、`commands/recon.md:213`、`README.md:314,340`。

## Acceptance Criteria

- [x] A1/R1：活动调用者不再要求成功 single-step 后必调 `/report`；deferred 与
  新交付入口保留，既有 publisher ID/owner/immutable bytes 合同不改。
- [x] A2/R2：纯查看/读卡不强制写目标或重建全链，真正收尾仍满足 Coverage/Closure；
  展示 `find-gaps` 全部未处置格与按需分页的当前含义。
- [x] A3/R3：三专项的全部独有方法、停止条件、输入输出与原 description/权限保全；
  仅完整模块含方法副本，普通 URL Pool 不触发 chain-builder。
- [x] A4/R4：合成 provider 接线证明行业不被五次配额挤掉，缓存不跨行业命中；失败
  不改变旧 cache bytes/mtime；cached/live/unavailable/no-mcp 与自定义输出保留旧引文
  和独立阅读文件，读失败不覆盖摘要。
- [x] A5/R5：记忆示例及导航与真实参数匹配，Finding 无 summary locator 的边界清楚。
- [x] A6：一次 focused 隔离检查与完整 diff 审阅通过；原 6k rules/知识库、主 Skill
  description、Store schema、报告原件、真实目标和个人 runtime 均不改。

## Constraints

不读取、修改或运行项目 `tests/`；不访问真实目标、正式知识审核、个人/全局 runtime，
不联网、不安装、不调用付费模型、不 push、不归档旧任务。保留全部 10 agents / 37
commands；本轮不整项退役，不新增 controller、schema、依赖或通用缓存框架。

验收证据见 `research/README.md`、`research/result.json` 与可复跑的
`research/check_entry_contracts.py`。宿主触发、模型效果和费用未纳入结论。
