# Tools 目录说明

`tools/` 存放当前命令和 agents 调用的 Python / shell 工具实现。不要从
这个文件判断工具路由；它只保留最小导航，避免和主索引重复。

当前权威索引：

- `docs/tool-index.md`：每个 `tools/*` 的用途、触发条件和 quick-pick 表
- `commands/autopilot.md`：Claude CLI 自动化主流程
- `commands/hunt.md`：主动测试主入口
- `CLAUDE.md`：运行时角色、主入口和边界

维护规则：

1. 新增 `tools/*` 后，先更新 `docs/tool-index.md`。
2. 如果工具对应 slash command，再更新 `commands/*.md`。
3. 历史 batch / campaign 脚本不要放回 `tools/`；归档到 `archive/`。
4. 已废弃工具不要静默删除，先在 `docs/tool-index.md` 标为 deprecated。

