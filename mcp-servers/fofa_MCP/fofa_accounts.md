# FOFA 账号配置

| 账号 | Email 环境变量 | Key 环境变量 |
|---|---|---|
| 主号 | FOFA_EMAIL | FOFA_KEY |
| 备用 1 | FOFA_EMAIL_BACKUP | FOFA_KEY_BACKUP |
| 备用 2 | FOFA_EMAIL_BACKUP2 | FOFA_KEY_BACKUP2 |

主号优先，遇限流/配额不足时尝试备用 1、备用 2；未配置 Key 的账号跳过。
Python 服务优先读取 MCP 宿主传入的环境，随后补读本目录私有 `.env`。
PowerShell 辅助函数只读环境。更改后重启对应服务/重新加载函数。
Key 不写入对话、Skill、知识库或报告。三个都失败时保留错误，继续使用已有资产材料。

轮换实现沿用 `fofa.py` 的 `_account_list`、`_exhausted`、`_is_rate_limited`。
仓库没有复制原包的个人 `.env` 或任何真实账号配置。
