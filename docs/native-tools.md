# 6k 支持工具的 CCST 接线

浏览器使用宿主配置的官方 MCP；项目保留 FOFA 支持源码。仓库变更不启动服务、
安装依赖或修改个人配置，工具可用性以当前会话实际调用为准。

## FOFA

当前有可用 FOFA/FofaMap MCP 时直接使用。需要原版三账号服务时，按
[FOFA MCP](../mcp-servers/fofa_MCP/README.md) 配置环境并启动 stdio 服务。
已有 `mcp/fofamap-client` 继续指向其外部实现；不用同时启用两个入口重复查询。
查询结果仍需按 CCST 的目标与证据接口保存。

## 浏览器 MCP

宿主直接配置官方 Playwright MCP / Chrome DevTools MCP；agent 按
[浏览器规则](../rules/playwright-browser-mcp.md)调用。隔离上下文、独立 Profile 或已有
浏览器连接使用官方 MCP 的配置能力，按需选择；项目不再分配固定端口或管理浏览器进程锁。

Linux root 启动 Chromium 报 `Running as root without --no-sandbox` 时，优先使用支持沙箱的
非 root 宿主；必须保留 root 的隔离环境可为 Playwright MCP 启动参数增加 `--no-sandbox`
（等价 `browser.launchOptions.chromiumSandbox=false`）。这会关闭 Chromium 自身沙箱，
不作为所有环境的默认值。参数变更后重新加载对应 MCP 服务；仅改配置文件不改变已运行连接。
以真实导航成功验证启动，不以进程存在或工具已列出作为可用证明。

旧配置迁移：若宿主启动命令仍指向已退役的 `bin/playwright-dual-slot.mjs`，需改为官方 MCP
入口后再启动该服务。删除仓库脚本不会修改宿主配置，也不会关闭原浏览器。原会话的
`mcp-shared-browsers` Profile 与锁不自动清理；仅确认所属会话停止后处理遗留锁，保留用户数据。

浏览器导出通过现有 `browser_mcp_import.py` 与 `record-observation` 登记，
详见 [证据接口](evidence-runners.md#native-observation-registration)。

## 原指南

[原版用户指南](user-guide/README.md) 的 27 篇正文保持原文，适用于 Grok；
当前 CCST 路径、工具和持久化差异以 [runtime adapter](ccst-runtime-adapter.md) 为准。
