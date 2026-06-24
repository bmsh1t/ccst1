# 知识库索引

默认只加载本索引。根据当前目标、skill、证据形态和假设，再选择具体知识卡或现有参考资料。

## 核心路由

| 文件 | 作用 | 何时读取 |
|---|---|---|
| `rules/playbook-router.md` | 证据形态到本地深度参考和项目工具的路由 | 已有 JWT、SSRF、OAuth、GraphQL、AI/RAG、上传解析等明确 Web 证据时 |
| `skills/security-arsenal/REFERENCES.md` | 外部参考库索引 | 当前项目内置方法论不够，需要外部 playbook、writeup、工具目录时 |
| `skills/security-arsenal/METHODOLOGY_CHEATSHEET.md` | 压缩方法论速查 | 需要快速补充某类漏洞的测试步骤时 |

## 本地知识卡

| 知识卡 | 作用 | 推荐关联 Skill |
|---|---|---|
| `knowledge/cards/auth-access.md` | 认证、会话、角色、组织边界的发散问题 | `bb-methodology`, `web2-vuln-classes`, `triage-validation` |
| `knowledge/cards/auth-hidden-switches.md` | 登录隐藏参数、认证分支开关和低风险 ATO 验证思路 | `web2-vuln-classes`, `bb-methodology`, `triage-validation` |
| `knowledge/cards/api-idor.md` | API 对象级越权和多租户访问控制 | `web2-vuln-classes`, `bb-methodology`, `triage-validation` |
| `knowledge/cards/ssrf-url-fetch.md` | URL fetch、webhook、导入转换类 SSRF 思路 | `web2-vuln-classes`, `security-arsenal`, `triage-validation` |
| `knowledge/cards/graphql.md` | GraphQL、subscription、global ID 的权限边界 | `web2-recon`, `web2-vuln-classes`, `triage-validation` |
| `knowledge/cards/sqli-hidden-surfaces.md` | Header、路径段、跨接口隐藏参数等 SQLi 非显式输入面 | `web2-recon`, `web2-vuln-classes`, `triage-validation` |
| `knowledge/cards/upload-parser.md` | 上传、导入、转换、解析器链路 | `web2-recon`, `web2-vuln-classes`, `triage-validation` |
| `knowledge/cards/race-conditions.md` | 并发状态差异和 race 风险的低风险建模 | `bb-methodology`, `web2-vuln-classes`, `triage-validation` |
| `knowledge/cards/coverage-prompts.md` | 覆盖基线漏测提醒 | `bb-methodology`, `web2-recon`, `web2-vuln-classes` |
| `knowledge/cards/dead-ends.md` | 常见低价值方向和停止条件 | `bb-methodology`, `triage-validation` |

## 加载策略

1. 先读取 `memory/goals/active.json`，确认当前目标、阶段和假设。
2. 根据阶段选择 Skill。
3. 根据证据从本索引选 1-2 张知识卡。
4. 如果证据命中 `rules/playbook-router.md`，优先按 router 读取更深参考。
5. 产出的新思路必须回到目标层记录为 lead / next action / dead end。

## 输出要求

使用知识库生成新思路时，必须同时给出：

```text
Evidence: 当前依据
Hypothesis: 安全假设
Next action: 最小可验证动作
Stop condition: 放弃条件
Related card: 使用的知识卡或参考文件
```
