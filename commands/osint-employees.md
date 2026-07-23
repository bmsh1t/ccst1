---
description: 收集公开邮箱/姓名并生成用户名候选；已知用户名时可跳过。Usage /osint-employees <target> [--with-linkedin] [--with-pydictor-social]
---

# /osint-employees

未知用户名时运行：

```bash
tools/osint_employees.sh target.com
```

流程：theHarvester → 邮箱 local-part 姓名 → username-anarchy；可选 CrossLinked 和姓名 pydictor。工具发现顺序为显式环境变量、`$PATH`、`$HOME/Tools`，不会自动安装。

输出位于 canonical `recon/<target-key>/osint/`：`emails.txt`、`employee-names.txt`、
`usernames.txt` 及可选 `personal-passwords.txt`；URL、域名和 host:port 与其他 target 工具共用 key。

如果已提供经过审阅的 users file，Credential Lane 直接使用它，跳过本步骤；已确认用户名和推断用户名必须在 decision package 中分开计数。该命令只准备候选，不触发 live 认证。
