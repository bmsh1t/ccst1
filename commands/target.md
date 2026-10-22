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

仅未初始化的新目标先显式初始化 Store；已有目标直接 `show TARGET` 恢复。
`set` 用于主动选择目标或设置意图，不是恢复前提；下列命令按需使用。
已有活动 Store 时 `init` 幂等返回。
历史待导入、preview 或损坏状态会报错，不会隐式迁移。

```bash
python3 tools/target_store.py init --store --target TARGET
python3 tools/target_memory.py set TARGET --goal "Find high-value Web/API leads"
python3 tools/target_memory.py show TARGET

python3 tools/target_memory.py note "Login is account-gated; API paths expose org_id" --target TARGET
python3 tools/target_memory.py lead "Possible IDOR on /api/org/{id}/users" --target TARGET
python3 tools/target_memory.py next "Compare org user list access across both accounts" --target TARGET
python3 tools/target_memory.py handoff "Recon complete; next step is role-diff on org APIs" --target TARGET
```

`set TARGET` 只选择已初始化目标，省略 `--goal` 会保留原目标意图。
`--mode`、`--phase`、`--hypothesis`、`--skill`、`--knowledge` 已退役；运行阶段由
Runtime 管理，结构化假设由 Case 管理，Skill/知识选择由 AI 按当前证据决定。
已知目标时用 `show TARGET` 读取，写入命令显式加 `--target TARGET`；并发和子代理同样如此，
避免读写落到共享活跃指针指向的其他目标。无参 `show` 仍可查看主动选择的活跃目标。

`dead-end` 和 `pattern` 必须关联已登记执行。将下例的 `OPERATION_ID:0` 替换为真实
执行收据 ID 与从零开始的 observation 序号；无执行证据时使用 `note` 保存未验证观察。

```bash
python3 tools/target_memory.py dead-end "Peer account cannot read this object" \
  --target TARGET --conditions "same tenant, peer role, tested object" \
  --reopen-when "role or ownership changes" --operation-ref OPERATION_ID:0
python3 tools/target_memory.py pattern "Object-owner comparison isolates access behavior" \
  --target TARGET --operation-ref OPERATION_ID:0
```

## 版本、来源与纠错

检索候选用 `python3 tools/experience_recall.py query --target TARGET --query "..."`；
历史翻页用 `history --target TARGET --limit 20`，反证与依赖展开用
`context --target TARGET --id EXPERIENCE_ID --version N`。各命令接受各自返回的
`--cursor`；`python3 tools/experience_recall.py --help` 列出现行入口。

完整原文和精确来源由 TargetStore 提供，以下均为只读：

```bash
python3 tools/target_memory.py version --target TARGET --id EXPERIENCE_ID --version N
python3 tools/target_memory.py sources --target TARGET --id EXPERIENCE_ID --id ANOTHER_ID
python3 tools/target_memory.py entity --target TARGET --owner experience --id EXPERIENCE_ID
python3 tools/target_memory.py knowledge-source --target TARGET --id KNOWLEDGE_ID
python3 tools/target_memory.py history-source --target TARGET --id IMPORTED_EXPERIENCE_ID --full
```

`version` 省略 `--version` 时读当前版本；`entity` 返回写关系所需的 owner 绑定，
可用 owner 见 `entity --help`。`history-source --full` 展开已导入记录的原文与历史元数据。

纠错通过追加关系保存。先读取 `show TARGET --json` 的当前 revision，再显式写入：

```bash
python3 tools/target_memory.py link --target TARGET --id NEW_EXPERIENCE_ID --to OLD_EXPERIENCE_ID \
  --relation supersedes --conditions "same declared scope" --reason "corrected observation" \
  --command-id UNIQUE_COMMAND_ID --expected-revision REVISION
python3 tools/target_memory.py retract-link --target TARGET --id LINK_ID \
  --reason "correction withdrawn" --command-id ANOTHER_COMMAND_ID --expected-revision NEW_REVISION
```

`--relation` 支持 `supersedes`、`refutes`、`depends_on`；不同适用条件保留为条件性关系。
`retract-link --id` 指关系 ID；撤回仍保留历史。两种写入都支持 `--actor`（默认 operator），
revision 冲突时先重新读取，不重写旧经验或伪造版本。

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

1. 确定本次实际目标；共享 active pointer 仅表示主动选择，不能覆盖已知目标。
2. 运行 `python3 tools/target_memory.py show TARGET`，无需先 `set`。
3. 从 Store、Runtime、Case 与当前证据恢复意图和假设，选择相关 Skill。
4. 只加载当前线索需要的知识库文件。
5. 按 [Shared Memory Continuity](../skills/runtime-protocol.md#shared-memory-continuity)
   保存必要交接，使用 `python3 tools/target_memory.py handoff "...summary..." --target TARGET`，
   按该合同附条件、下一意图和已登记执行引用。

## 记录纪律

写目标记忆时，每条记录都要具体：

```text
Evidence: URL、参数、token、响应差异、源码路径或浏览器状态
Why it matters: 对应的安全假设
Next action: 一个可 replay 的测试，或一个源码/浏览器检查
Stop condition: 什么条件下放弃该方向
```
