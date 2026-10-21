# 6k 的 CCST 宿主与底座接线

CLAUDE.md 内嵌主契约，十一份 rules、src-hunter 和知识库保留完整方法与能力。
当前路径、工具调用和文件操作直接写在对应活动正文中；本文件汇总边界与来源，
不要求执行时逐条翻译另一套宿主指令。根 AGENTS.md 不再是本项目入口。

## 读取与维护

- 从选定 CCST checkout 开始，完整加载 CLAUDE.md 及其十一规则导入。SRC 先读
  `skills/src-hunter/知识库/打穿短表.md`，再按现场展开相关完整方法；不每站通读整库。
- 规则、docs、tools 路径以 checkout 为根。Skill 内的 `知识库/`、`modules/` 相对该包，
  安装器会递归同步；安装副本可以读取，方法维护只写 checkout 的
  `skills/src-hunter/知识库/` 及必要索引，避免两个可写来源。
- 方法维护按 `rules/hunt-iter.md` 的准入、三问和来源核对，由主会话直接改 Markdown，
  Git 保留差异；子代理只提候选。已审共享卡继续使用 knowledge 的审核/晋升流程。
- 原生读取不经过 catalog、manifest 或 hot_method；缺失就报告缺失，不用历史正文悄悄补位。

## 目标、材料与清理

材料归属和清理见 [目标材料规则](../rules/desktop-task-folder.md)；
KEY 来自 target_storage_key/工具返回值。开始/续接按所用命令入口和
[Shared Memory Continuity](../skills/runtime-protocol.md#shared-memory-continuity)，
自动模式沿用 Autopilot 的 Bootstrap/round 流程，不追加一套目录初始化或恢复步骤。

资产与提取源码归 recon，原始证据归 evidence 或既有注册根，浏览器原件归目标 private
目录，报告经 publisher 发布。目标事实、Action、Finding 与认知交接使用现有 TargetStore/API；
运行状态、checkpoint 与批次续接使用各自 owner，工作笔记按需并引用真实状态。
无具体 target 的集团 seeds 按
[campaign](../rules/ccst/campaign.md) 保存与续接，不借用旧目标的 Store。

清理临时工作文件不清除目标历史；既有证据 ref、已发布报告与恢复材料保持原位。
桌面目录仅在用户要求导出时作为交付副本，不能变成第二套运行状态。

## 工具与宿主

- 浏览器完整调用步骤见 [浏览器规则](../rules/playwright-browser-mcp.md)，使用当前会话
  实际暴露的 Playwright/Chrome DevTools MCP 和参数。导入/登记走已有证据接口。
- FOFA 使用当前可用的 FOFA/FofaMap MCP。原版三账号支持位于 `mcp-servers/fofa_MCP/`，
  双槽浏览器启动器位于 `bin/`；配置方式见 [native-tools](native-tools.md)。资产存在不代表
  MCP 已启用，也不授权修改个人宿主配置。实际工具名以会话 schema 为准，避免重复查询。
- 代理按 [resin-proxy](resin-proxy.md) 当前配置使用；Git remote 取当前仓库。
  Git push、安装和更改个人配置不是规则隐含动作。
- 执行接口查 [tool-index](tool-index.md)，事实恢复查
  [runtime-protocol](../skills/runtime-protocol.md)。Scope/Auth、claim/CAS、operation、
  cleanup、技术裁决和目的地资格继续由各自 owner 负责。

## 报告与连续性

正文、等级、发布/更新与私有实值边界见 [vuln-report-format](../rules/vuln-report-format.md)，
具体 publisher 参数见 [report](../commands/report.md)。先完成正文格式再发布，保留当前
Finding/assessment/delivery 绑定与不可变文件；外发/共享副本脱敏，受控私有原件保持完整。
技术成立、目的地资格、报告发布和外部提交各有真实状态，不能凭文件存在互相替代。

持续推进和方法迭代保留；当前用户范围、停止指令、明确预算及真实执行资源仍生效。
动作结果即时交原 owner 保存，稳定结论及暂停/切换/compaction 的认知交接走 memory API。
未知效果、cleanup 和终态记录必须处理；有界停止保留残余，不宣称未测项已覆盖。

## 来源与历史

原始 6k 快照及 `knowledge/methods/clown/`、旧 manifest/.history 保留来源和旧版本回执。
`tools/hot_method.py` 仅供显式旧版本读取、维护或恢复，不更新当前原生目录。
历史已审卡中的 `rules/{campaign,context-loading,coverage-gate,hunting,red-lines,reporting,
retrospective,tool-ai-boundary,web-intel}.md` 对应当前 `rules/ccst/<同名>.md`；不改旧审核字节。

原 S52 的混入浏览器正文、残缺表格和缺失 Phase 0 保留为来源事实；活动浏览器规则已单源，
现存白盒方法配合 `skills/src-hunter/modules/whitebox-audit.md` 使用，不声称补出了缺失原稿。
`docs/user-guide/` 的 Grok 原指南作为来源资料留存，不是 CCST 当前配置教程。
