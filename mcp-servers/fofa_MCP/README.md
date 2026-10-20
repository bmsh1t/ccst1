# FOFA MCP

从用户提供的 6k 快照迁入的三账号 FOFA 服务。使用 FastMCP、stdio、httpx，
提供 `get_alerts` 查询工具和 `search_prompt` 提示词；主号遇限流时依次尝试备用账号。
源码存在不代表宿主已经启用。CCST 既有 FofaMap 也可使用，按现场需求选一个入口。

需要 Python >=3.10 和 uv；依赖见 pyproject.toml 与 uv.lock。配置本目录
私有 `.env`（参照 `.env.example`）或宿主进程环境，环境变量优先。
可选备用账号及重启说明见 [账号配置](fofa_accounts.md)。

在本目录启动：

```bash
uv run --locked python fofa.py
```

或给 MCP 宿主配置 stdio 命令 `uv`，参数使用实际绝对路径：

```json
{
  "command": "uv",
  "args": ["run", "--directory", "/absolute/path/to/ccst/mcp-servers/fofa_MCP", "--locked", "python", "fofa.py"]
}
```

这是命令参数示例，外层 MCP 配置格式由当前宿主决定。首次运行 uv 会准备依赖。
`get_alerts(domain="example.com")` 默认带 `status_code=200`；传空字符串取消该过滤。
域名/IP/端口/host/body/icon_hash/icp 条件会组合成 FOFA 查询。
返回资产是调查材料，不自动变成目标授权、验证结论或 Store 记录。

`fofa_dual.ps1` 是可选的 PowerShell 直接查询辅助函数；先配置同名环境变量，
再 dot-source 该文件并调用 `Invoke-FofaSearch -Query 'domain="example.com"'`。
它只读进程环境，不自动加载 `.env`。共享材料不写凭据。

原 README 提及 MIT，但提供的快照没有 LICENSE 文件；这里不补造许可文件。
