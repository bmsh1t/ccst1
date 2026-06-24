# 覆盖基线 Gate

覆盖基线用于防止过早收工。它不是要求每个方向都实测，而是要求 Claude 对覆盖状态负责。

## 核心原则

Claude 不能直接说“测试完成”或“没有发现问题”，除非已经交代：

- 已覆盖哪些核心 surface / lane
- 哪些产生了 Lead / Signal / Candidate
- 哪些被判定为 `n/a`
- 哪些被阻塞为 `blocked`
- 哪些因为红线不能继续
- 哪些仍是 `unknown`
- 下一步是什么

## 状态枚举

覆盖状态只能使用以下值：

| 状态 | 含义 |
|---|---|
| `unknown` | 尚未判断或尚未测试 |
| `queued` | 已计划测试，但本轮未完成 |
| `tested` | 已完成低风险验证，未发现有效线索 |
| `lead` | 有线索，但还缺少复现、影响或权限差异 |
| `signal` | 有行为差异或证据，但还不能进入验证 |
| `candidate` | 证据足够，应该进入 `/validate` |
| `blocked` | 被权限、环境、账号、红线或信息不足阻塞 |
| `n/a` | 明确不适用 |
| `dead-end` | 已证伪或低价值，继续投入不划算 |

## 必填理由

以下状态必须写理由：

- `tested`：写明证据或测试方式
- `blocked`：写明阻塞原因和需要什么输入
- `n/a`：写明为什么不适用
- `dead-end`：写明证伪原因
- `unknown`：写明下一步或为什么本轮未覆盖

## 交付前检查

最终回复前必须回答：

```text
COVERAGE SUMMARY
- Covered:
- Leads / Signals:
- Candidates:
- Blocked:
- Not applicable:
- Dead ends:
- Still unknown:
- Next actions:
```

## 矩阵检查

如果当前目标有 recon、findings、scanner_pass 或手工测试结果，先使用结构化覆盖矩阵：

```bash
python3 tools/coverage_matrix.py rebuild --target <target>
python3 tools/coverage_matrix.py find-gaps --target <target>
```

矩阵不是唯一真相，但它是防偷懒的硬证据：

- `find-gaps` 非空：只能 checkpoint 或继续，不能声称全面完成。
- `find-gaps` 为空：还要检查 `/surface` Workflow Leads、target memory dead ends、unsafe-skipped、blocked/n/a。
- rebuild 后 endpoint 为空：说明输入不足，应标记为 `unknown` 或 `blocked`，而不是 `tested`。
- 被红线阻止的 gap 应记录为 `blocked: red-line`，不能用危险动作补覆盖。

如果存在高价值 `unknown`，不能说“完成全面测试”，只能说：

```text
本轮覆盖了 X；仍未覆盖 Y；下一步建议 Z。
```

## 高价值 surface

通常应优先交代这些 surface：

- 登录、注册、找回密码、邀请、SSO/OAuth/SAML
- 用户、组织、团队、角色、权限
- 导出、下载、分享、批量操作
- 上传、导入、转换、解析、预览
- webhook、callback、URL fetch、集成
- admin、internal、debug、settings、billing
- GraphQL、WebSocket、API mutation
- CI/CD、公开仓库、配置和 secret 暴露面

## 和红线的关系

覆盖基线不能覆盖红线。

如果某个 lane 需要高压流量或破坏性状态改变，只能标记为：

```text
blocked: red-line
```

并写出低风险替代验证方式。

## 和目标层的关系

覆盖结论应写回目标层：

- 新线索：`python3 tools/target_memory.py lead "..."`
- 下一步：`python3 tools/target_memory.py next "..."`
- 无效方向：`python3 tools/target_memory.py dead-end "..."`

结构化 coverage JSON 由 `tools/coverage_matrix.py` 维护；目标层负责记录矩阵之外的上下文，例如红线阻塞、账号缺失、业务流程未知、死路和下一步。
