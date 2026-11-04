# 6k 的 CCST 宿主与底座接线

CLAUDE.md、十一份 rules、src-hunter 和知识库保留完整方法与能力；活动正文已采用
CCST 路径与操作。本文件导航现有合同并记录来源；根 AGENTS.md 不再是项目入口。

## 读取与维护

- 从选定 checkout 完整加载 CLAUDE.md 及十一规则。rules/docs/tools 相对 checkout，
  Skill 内的 `知识库/`、`modules/` 相对该包，安装器递归同步。
- 方法读取、短表展开与维护遵守
  [Shared Knowledge Recall](../skills/runtime-protocol.md#shared-knowledge-recall)：原生 Read/Grep，
  按问题读完整方法；缺失明示，不用历史正文补位。

## 目标、材料与清理

显式 `/autopilot` 调用中，6k 提供范围语义、调查方法与证据判断；
启动、后台等待、继续和退出按
[Shared Automation](../commands/autopilot.md#shared-automation) 执行。

Claude 宿主入口并行送达完整 `src-hunter` 正文和共享运行协议，Bootstrap 单独完成
Scope/Auth、安装一致性和目标状态准入。正文分块带来源指纹、原包路径和结束标记，
避免宿主预览截断与末尾空白丢失；收到正文不等于获准执行。
`body` 直接读取当前项目完整正文，不访问 Hook、会话或 runtime。宿主只保留
本次会话/调用/目标绑定，不保存正文快照；历史源码由 Git 保存。超限 Bootstrap
通过私有文件完整交付，该副本不作为目标事实或恢复缓存。目标列表先走已有批次选择，再绑定具体目标。

同会话复用上下文；`host.state_command` 合并 Scope/Auth、循环刷新与同任务确认，不重跑
Bootstrap/初始化。压缩或重启后 SessionStart 恢复正文，同一次刷新附带 owner 记忆与交接。
普通正文更新重新送达当前全文；执行 Refresh 的 `recovery.source_context.commands` 并完整
读取所有同 hash 分块后替换旧指令，同时更新
停止审查绑定，原目标、记忆、待办和时间/Round 额度保留。旧 `context*.json` 不读取、
不迁移、不删除。当前正文或绑定损坏仍报错；普通问答、取消和换任务不激活 Stop。
通用状态/记忆查询不接触 host 绑定。
Claude 原生后台结果的完整 `task-notification` 封套不算新用户任务，只保留当前启停状态，
不激活已暂停的调用。该封套识别不是发送者认证，不读取模型历史。
Stop 读取当前 owner 与同一 Checkpoint Global Review 的停止依据；未完执行不能正常收尾，
重复无进展退出标为未完成。Closure 仍单独判定是否有证据声明耗尽。
可选 `--max-seconds=SECONDS` 在入口绑定时限，恢复保留起点和额度；
lane 限制绑定入口额度/继承的活动 Round。结束复核不能新增或缩短额度，
也不能借旧已完成 Round 停止新调用。费用上限由原生宿主执行。
Recon/Scan 运行中可并行独立且有依据的调查；锁只防同阶段重复启动，
结束前仍须回收结果。有效范围/限制/整体阻塞退出不要求补齐耗尽表单。

安装与恢复钩子通过 [sync-check](../commands/sync-check.md) 的既有 ownership/journal
写入选定 runtime 的 `settings.json`，只管理 CCST 组；首次安装或 hook 版本变化要求
全量 kinds 加 `--prune`。未授权时不安装个人 runtime。原生 description 发现保持不变。
宿主、安装器、runtime doctor 和能力标记共用 runtime 选择顺序：显式参数 >
`CCST_RUNTIME_ROOT` > `CLAUDE_CONFIG_DIR` > `~/.claude`。
旧源码摘要本身不阻断入口；执行入口仍检查 Hook 配置/回执、实际到达和项目/会话绑定。
缺少实际到达记录时，入口错误指出 binding、checkout 和 runtime 路径，正文读取不受影响。
由宿主完整交付的正文变更可直接刷新；入口配置和其他关键安装资源变化仍需同步。
宿主机制已在 Claude Code 2.1.304 的隔离假 API 上验证；正文送达与停止校验不证明
模型正确使用方法，也不能发现所有绕过登记合同的原生请求。

目录、owner 和清理见 [目标材料规则](../rules/desktop-task-folder.md)；
恢复和认知写回见 [Shared Memory Continuity](../skills/runtime-protocol.md#shared-memory-continuity)。
无 target 的集团 seeds 按 [campaign](../rules/ccst/campaign.md) 续接。

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

发布格式见 [vuln-report-format](../rules/vuln-report-format.md)，执行参数及 owner 绑定见
[report](../commands/report.md)；连续性与交接按
[Cognitive Write Timing](../skills/runtime-protocol.md#cognitive-write-timing)。

## 来源与历史

原始 6k 快照及 `knowledge/methods/clown/`、旧 manifest/.history 保留来源和旧版本回执。
`tools/hot_method.py` 仅供显式旧版本读取、维护或恢复，不更新当前原生目录。
历史已审卡中的 `rules/{campaign,context-loading,coverage-gate,hunting,red-lines,reporting,
retrospective,tool-ai-boundary,web-intel}.md` 对应当前 `rules/ccst/<同名>.md`；不改旧审核字节。

原 S52 的混入浏览器正文、残缺表格和缺失 Phase 0 保留为来源事实；活动浏览器规则已单源，
现存白盒方法配合 `skills/src-hunter/modules/whitebox-audit.md` 使用，不声称补出了缺失原稿。
`docs/user-guide/` 的 Grok 原指南作为来源资料留存，不是 CCST 当前配置教程。
