# 6k 支持工具的 CCST 接线

原包功能源码保留在项目内，启用使用当前宿主的 MCP 配置。迁入没有启动服务、
安装依赖或改个人配置；已有会话里的工具以实际可调用结果为准。

## FOFA

当前有可用 FOFA/FofaMap MCP 时直接使用。需要原版三账号服务时，按
[FOFA MCP](../mcp-servers/fofa_MCP/README.md) 配置环境并启动 stdio 服务。
已有 `mcp/fofamap-client` 继续指向其外部实现；不用同时启用两个入口重复查询。
查询结果仍需按 CCST 的目标与证据接口保存。

## Playwright 双槽

需要两个独立会话时可将 MCP 宿主的 stdio 命令设为：

```text
node /absolute/path/to/ccst/bin/playwright-dual-slot.mjs
```

启动器沿用 9222/9223 两个 CDP 端口、每槽独立 profile 与进程锁，stderr 输出诊断，
stdio 交给 Playwright MCP。Chrome/Edge 不在常见路径时设置 `CHROME_PATH`。
异常退出留下的锁需确认对应会话已停止后手动清理；启动器会提示锁目录，避免并发时误删另一会话正在创建的锁。
这两个端口应交由此启动器管理；它会复用端口上已有的 CDP 浏览器，不会退出时关闭浏览器。

可用 `PLAYWRIGHT_MCP_CLI` 指向已经安装的 Playwright MCP JavaScript CLI。
未设置时沿用原包的 `npx -y @playwright/mcp@latest`；首次启动可能下载依赖，
需要固定版本的环境可显式指定已安装 CLI。启动器不修改 npm 缓存，也不依赖某台机器的缓存路径。

Linux 需要可运行的图形浏览器环境。普通单会话继续使用当前宿主已有浏览器 MCP。
浏览器导出通过现有 `browser_mcp_import.py` 与 `record-observation` 登记，
详见 [证据接口](evidence-runners.md#native-observation-registration)。

## 原指南

[原版用户指南](user-guide/README.md) 的 27 篇正文保持原文，适用于 Grok；
当前 CCST 路径、工具和持久化差异以 [runtime adapter](ccst-runtime-adapter.md) 为准。
