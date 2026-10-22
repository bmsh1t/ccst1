# 6k 的 CCST 宿主与底座接线

CLAUDE.md、十一份 rules、src-hunter 和知识库保留完整方法与能力；活动正文已采用
CCST 路径与操作。本文件导航现有合同并记录来源；根 AGENTS.md 不再是项目入口。

## 读取与维护

- 从选定 checkout 完整加载 CLAUDE.md 及十一规则。rules/docs/tools 相对 checkout，
  Skill 内的 `知识库/`、`modules/` 相对该包，安装器递归同步。
- 方法读取、短表展开与维护遵守
  [Shared Knowledge Recall](../skills/runtime-protocol.md#shared-knowledge-recall)：原生 Read/Grep，
  按问题读完整方法；缺失明示，不用历史正文补位。
- 方法维护只写 checkout 的 `skills/src-hunter/知识库/` 及必要索引；安装副本只读。
  按 hunt-iter 准入、三问和来源核对，由主会话修改并保留 Git 差异；子代理只提候选。
  已审共享卡仍走 knowledge 审核/晋升。

## 目标、材料与清理

材料目录、owner 与清理步骤见 [目标材料规则](../rules/desktop-task-folder.md)，
KEY 取 target_storage_key/工具回执。开始/续接遵守所用命令入口和
[Shared Memory Continuity](../skills/runtime-protocol.md#shared-memory-continuity)，
自动模式沿用 Bootstrap/round。各类状态仍由现有 owner 保存，工作笔记按需引用；
无 target 的集团 seeds 按 [campaign](../rules/ccst/campaign.md) 续接，不借旧目标 Store。
已登记证据、报告与恢复材料保持原位；桌面目录只作用户要求的导出副本。

## 工具与宿主

- 浏览器按 [浏览器规则](../rules/playwright-browser-mcp.md) 使用会话可见 Playwright/Chrome
  DevTools MCP；FOFA 用可用的 FOFA/FofaMap MCP。工具名/参数以当前 schema 为准。
  三账号支持在 `mcp-servers/fofa_MCP/`，双槽启动器在 `bin/`，配置见
  [native-tools](native-tools.md)；资产存在不证明 MCP 已启用，也不授权修改个人配置。
- 代理按 [resin-proxy](resin-proxy.md) 当前配置，Git remote 取当前仓库。
  push、安装和个人配置变更均非规则隐含动作。
- 执行前查 [tool-index](tool-index.md#execution-contract-lookup) 的匹配合同。
  Scope/Auth、claim/CAS、operation、cleanup、裁决与资格仍归各自 owner。

## 报告与连续性

发布前遵守 [vuln-report-format](../rules/vuln-report-format.md)，参数查
[report](../commands/report.md)。保留当前 Finding/assessment/delivery 绑定、不可变文件；
外发/共享副本脱敏，私有原件完整。技术成立、目的地资格、发布与外部提交各有真实状态。
持续推进/迭代遵守 CLAUDE.md 与当前入口的范围、停止、预算和资源边界。证据即时写 owner，
稳定结论及暂停/切换/compaction 的认知交接按
[Cognitive Write Timing](../skills/runtime-protocol.md#cognitive-write-timing)。
未知效果、cleanup 和终态记录仍须完成；有界停止保留残余，不记为已覆盖。

## 来源与历史

原始 6k 快照及 `knowledge/methods/clown/`、旧 manifest/.history 保留来源和旧版本回执。
`tools/hot_method.py` 仅供显式旧版本读取、维护或恢复，不更新当前原生目录。
历史已审卡中的 `rules/{campaign,context-loading,coverage-gate,hunting,red-lines,reporting,
retrospective,tool-ai-boundary,web-intel}.md` 对应当前 `rules/ccst/<同名>.md`；不改旧审核字节。

原 S52 的混入浏览器正文、残缺表格和缺失 Phase 0 保留为来源事实；活动浏览器规则已单源，
现存白盒方法配合 `skills/src-hunter/modules/whitebox-audit.md` 使用，不声称补出了缺失原稿。
`docs/user-guide/` 的 Grok 原指南作为来源资料留存，不是 CCST 当前配置教程。
