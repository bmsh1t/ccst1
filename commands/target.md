---
description: 管理 Claude CLI 漏洞挖掘中的活跃目标记忆。用法：/target show | /target set <target> --goal "..." | /target lead "..." | /target next "..." | /target handoff "..."
---

# /target

恢复、召回和保存当前目标经验；调用时机统一按
`skills/runtime-protocol.md#shared-memory-continuity`。

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
```

`set TARGET` 只选择已初始化目标，省略 `--goal` 会保留原目标意图。
`--mode`、`--phase`、`--hypothesis`、`--skill`、`--knowledge` 已退役；运行阶段由
Runtime 管理，结构化假设由 Case 管理，Skill/知识选择由 AI 按当前证据决定。
已知目标时用 `show TARGET` 读取，写入命令显式加 `--target TARGET`；并发和子代理同样如此，
避免读写落到共享活跃指针指向的其他目标。无参 `show` 仍可查看主动选择的活跃目标。

## 交接与证据

交接正文说明已证明的结论、仍未知的假设和当前阻塞；conditions 保留实际 origin、
身份、对象及适用条件，next-intent 写具体下一问题。保存后消费真实回执：

```bash
python3 tools/target_memory.py handoff '已证明的结论；未验证范围与阻塞' \
  --target TARGET --conditions '实际 origin、身份、对象与当前条件' \
  --next-intent '下一步具体检查及需要重开的条件' \
  --operation-ref OPERATION_ID:STEP --command-id UNIQUE_COMMAND_ID --json
```

省略 `--next-intent` 合法且表示没有下一意图，不继承以前的 `next` 或旧交接。
`next`/`handoff` 是建议，不创建或完成 Queue Action，也不构成 Autopilot 停止理由。
每个 `--operation-ref` 引用支持该结论的真实 observation 步骤，可重复传入；不把整批
默认绑定到 `:0`。原件路径和 Finding ID 不能代替执行引用；无证据时保留为未验证建议。

`dead-end` 和 `pattern` 必须关联已登记执行。`OPERATION_ID:STEP` 替换为回执 ID
与实际从零开始的步骤。阴性需要明确条件和重开条件；不能因不可报告就认定为阴性。

```bash
python3 tools/target_memory.py dead-end "Peer account cannot read this object" \
  --target TARGET --conditions "same tenant, peer role, tested object" \
  --reopen-when "role or ownership changes" --operation-ref OPERATION_ID:STEP
python3 tools/target_memory.py pattern "Object-owner comparison isolates access behavior" \
  --target TARGET --operation-ref OPERATION_ID:STEP
```

所有经验文本（含 conditions、next-intent）只保存角色与目标私有凭据引用，不写 Cookie、
token、密码实值、个人身份信息或客户数据。未验证内容用明确的 `note`；拒绝的阴性不能静默改成 note。
登记和原件恢复按 `docs/evidence-runners.md`；不为保存记忆重做实验。
同一记忆写入重试保留输入和 `--command-id`；修订结论用新 ID 和显式纠错关系。

## 恢复与问题召回

有效 Bootstrap 的 `state.target_memory` 可直接复用；否则用 `show TARGET`，需要整体
领域视图时用 `resume.py --target TARGET`。恢复条目含 version、条件与来源/纠错健康。
`experience_window` 给出查询、历史和反证入口；五条预览不是完整记忆。

```bash
python3 tools/experience_recall.py query --target TARGET --query '当前问题与适用条件' --json
python3 tools/experience_recall.py history --target TARGET --limit 20 --json
python3 tools/experience_recall.py context --target TARGET --id EXPERIENCE_ID --version VERSION --json
```

`current` 与 `recalled` 分开消费；query 的 `counterevidence` 页独立于排名 top-k。
query 精确来源展开可用 `--source-ref experience:ID`；保留历史版本则用下节的 version。
按它的 `next_command` 展开相关纠错/依赖，按条目的 `expand_command` 读精确版本；
不得把它的游标传给 query/history。三种游标分别归各自命令；反证预算用
`--context-limit`/`--context-max-bytes`，不与 query 的 `--limit` 混用。
恢复窗口的 `context_command` 中 ID/version 使用已返回条目的值。
缺信息/失效材料保持未知；最新、命中或无反证都不是适用证明。

查询不写记忆、不构建索引或下载模型。保存可显式指定 `--update-index text|relations|all`；
`--index-encoder PATH` 要求 text/all 和已有本地模型。索引失败 exit 2 会携带已提交回执
及独立恢复命令：只重建派生索引，不重复保存事实。损坏代次用
`experience_recall.py index-build --target TARGET --full-rebuild` 或 `relation-build` 修复。
query/status 的健康和 acquisition 描述实际来源读取，不把缓存命中当来源已验证。
未指定时不更新索引；知识晋升的相同选项更新共享索引。目标更新只重新采集受影响的
来源组，缺旧捕获时全量采集；当前事实和引用字节重新核对，共享知识仍核验完整审核来源。

## 版本、来源与纠错

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

`--relation` 支持 `supersedes`、`refutes`、`depends_on`，也可在保存时传 `--links-json`。
仅与两端声明条件完全相同的纠错影响整条记录；其他保留为条件性关系，unknown 不是通配。
`retract-link --id` 指关系 ID；撤回保留原质疑条件及历史，不复活旧结论。
两种写入都支持 `--actor`（默认 operator），
revision 冲突时先重新读取，不重写旧经验或伪造版本。

结构化建议用 `note --claims-json`：subject/predicate/object/conditions/timing/source_refs。
可选 condition_bindings 绑定 `entity` 返回的精确实体；validity 同时包含带时区的 from/until，
且 from < until。未声明保持未知，文本条件不证明兼容，关系主张不确认 Finding 或授权执行。

`knowledge-source` 返回已审资料的精确绑定；加 purpose=basis 或 origin 后传入
`--sources-json`。版本为发布回执 SHA256，不替换成 Store revision；只有 basis 能支持主张。
资料变更或审核撤回保留可见的来源失效。`history-source` 的四字段绑定只允许 origin，
不能作为主张依据；`--full` 读原文、元数据和可用性，可用字节仍是 unverified。
原件损坏/缺失只报告诊断，不回退到旧现场或导入摘要。旧 PatternDB 回执缺归档时，
使用显式 `target_migration.py --backfill-pattern-source SOURCE --repo-root ROOT --target TARGET`
核对同一固定来源补归档，不重跑执行或创建替代笔记。

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
