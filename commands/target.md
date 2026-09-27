---
description: 管理 Claude CLI 漏洞挖掘中的活跃目标记忆。用法：/target show | /target set <target> --goal "..." | /target lead "..." | /target next "..." | /target handoff "..."
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

首次使用先显式初始化 Store；已有活动 Store 时该命令幂等返回。
历史待导入、preview 或损坏状态会报错，不会隐式迁移。

```bash
python3 tools/target_store.py init --store --target TARGET
python3 tools/target_memory.py set TARGET --goal "Find high-value Web/API leads"
python3 tools/target_memory.py show
python3 tools/target_memory.py show TARGET

python3 tools/target_memory.py note "Login is account-gated; API paths expose org_id"
python3 tools/target_memory.py lead "Possible IDOR on /api/org/{id}/users"
python3 tools/target_memory.py next "Compare org user list access across both accounts"
python3 tools/target_memory.py handoff "Recon complete; next step is role-diff on org APIs"
```

`set TARGET` 只选择已初始化目标，省略 `--goal` 会保留原目标意图。
`--mode`、`--phase`、`--hypothesis`、`--skill`、`--knowledge` 已退役；运行阶段由
Runtime 管理，结构化假设由 Case 管理，Skill/知识选择由 AI 按当前证据决定。
其他写入命令可以加 `--target TARGET`，避免依赖活跃目标指针。

`dead-end` 和 `pattern` 必须关联已登记执行。将下例的 `OPERATION_ID:0` 替换为真实
执行收据 ID 与从零开始的 observation 序号；无执行证据时使用 `note` 保存未验证观察。

```bash
python3 tools/target_memory.py dead-end "Peer account cannot read this object" \
  --target TARGET --conditions "same tenant, peer role, tested object" \
  --reopen-when "role or ownership changes" --operation-ref OPERATION_ID:0
python3 tools/target_memory.py pattern "Object-owner comparison isolates access behavior" \
  --target TARGET --operation-ref OPERATION_ID:0
```

## 写入位置

```text
memory/goals/active.json                 活跃目标选择指针
state/<target_key>/metadata.sqlite3       目标意图与经验
```

`show` 从同一 Store 读取；旧 `memory/goals/targets/` 和 `sessions/` 文件只供历史检查
与显式导入，不再作为正常写入位置。

## 层级边界

目标记忆只保存目标相关状态：

- 活跃目标
- 目标意图
- 假设线索及适用条件
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
3. 从 Store、Runtime、Case 与当前证据恢复意图和假设，选择相关 Skill。
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
