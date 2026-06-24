---
description: 管理 Claude CLI 漏洞挖掘中的活跃目标记忆。用法：/target show | /target set <target> --mode hunt --phase recon | /target lead "..." | /target next "..." | /target handoff "..."
---

# /target

管理活跃目标记忆层。

`/target` 只负责目标聚焦和上下文续接。它不替代 `/scope`、`/pickup`、
`/remember`、`hunt-memory` 或 `findings`。

## 适用场景

- 开始或切换活跃目标
- 记录线索、下一步、无效方向或目标特定模式
- 在上下文变长前写一份简短 handoff
- 恢复工作时快速获取目标摘要

## 不适用场景

- 通用 payload 库；这属于知识库层 / security arsenal
- 报告前验证；使用 `/validate`
- 验证后的发现持久化；使用 `/remember`
- 范围解释和资产说明；使用 `/scope`

## 命令

```bash
python3 tools/target_memory.py show
python3 tools/target_memory.py show target.com

python3 tools/target_memory.py set target.com \
  --mode hunt \
  --phase recon \
  --goal "Find high-value Web/API leads" \
  --hypothesis "Multi-tenant API may have object-level authorization gaps" \
  --skill bb-methodology \
  --skill web2-recon \
  --knowledge attack-surface \
  --knowledge vuln-patterns

python3 tools/target_memory.py note "Login is account-gated; API paths expose org_id"
python3 tools/target_memory.py lead "Possible IDOR on /api/org/{id}/users"
python3 tools/target_memory.py next "Run role_diff with two accounts against org user list"
python3 tools/target_memory.py dead-end "GraphQL introspection disabled; no operation names in JS"
python3 tools/target_memory.py pattern "Export endpoints are high-signal on this target"
python3 tools/target_memory.py handoff "Recon complete; next step is role-diff on org APIs"
```

## 写入位置

```text
memory/goals/active.json
memory/goals/targets/<target>.json
memory/goals/sessions/<timestamp>-<target>.md
```

## 层级边界

目标记忆只保存目标相关状态：

- 活跃目标
- 当前阶段
- 当前假设
- 线索
- 下一步
- 已证伪或低价值方向
- 目标特定的有效模式
- 会话交接摘要

目标记忆不保存：

- payload 集合
- 全局方法论
- 红线规则
- 完整扫描日志
- 最终报告证据

## 建议 Claude 流程

1. 如果存在，先读取 `memory/goals/active.json`。
2. 运行 `python3 tools/target_memory.py show`。
3. 根据 mode、phase 和 active hypothesis 选择相关 skill。
4. 只加载当前线索需要的知识库文件。
5. 长会话结束前运行 `python3 tools/target_memory.py handoff "...summary..."`。

## 记录纪律

写目标记忆时，每条记录都要具体：

```text
Evidence: URL、参数、token、响应差异、源码路径或浏览器状态
Why it matters: 对应的安全假设
Next action: 一个可 replay 的测试，或一个源码/浏览器检查
Stop condition: 什么条件下放弃该方向
```
