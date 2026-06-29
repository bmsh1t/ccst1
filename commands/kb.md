---
description: 使用知识库层为当前 Skill 补充思路、案例和停止条件。用法：/kb index | /kb suggest | /kb card <name> | /kb promote
---

# /kb

使用知识库层。

`/kb` 负责让 Claude 在当前目标和当前 Skill 的基础上，按需读取知识库卡片，
生成更好的假设、思路分支、技巧家族、payload/bypass 方向、补充 checklist、
下一步和停止条件。

## 用法

```text
/kb index
/kb suggest
/kb card api-idor
/kb card auth-access
/kb card ssrf-url-fetch
/kb card dead-ends
/kb promote
```

## 子命令语义

### `/kb index`

读取 `knowledge/index.md`，只输出可用知识卡、外部参考和加载建议。

### `/kb suggest`

基于当前目标记忆和当前任务，选择 1-2 张最相关知识卡。

建议读取顺序：

1. `memory/goals/active.json`
2. `knowledge/index.md`
3. 当前 Skill
4. 命中的知识卡
5. 必要时读取 `rules/playbook-router.md`

### `/kb card <name>`

读取指定知识卡，例如：

```text
knowledge/cards/api-idor.md
knowledge/cards/auth-access.md
knowledge/cards/ssrf-url-fetch.md
knowledge/cards/dead-ends.md
```

输出时必须包含：

```text
Evidence: 当前依据
Hypothesis: 安全假设
Technique family: 相关技巧 / payload / bypass 家族
Checklist gap: 需要补漏的点
Next action: 最小验证动作
Stop condition: 放弃条件
Related card: 使用的知识卡
```

### `/kb promote`

把目标记忆或复盘中的可复用经验晋升到知识库。

晋升前必须读取：

```text
knowledge/promotion-rules.md
knowledge/card-template.md
```

新增或更新知识卡时，默认按 `knowledge/card-template.md` 的经验压缩库结构：

```text
能力定位
触发信号
思路分支
技巧家族 / Payload 家族
补充 Checklist
最小验证
常见误判 / 死路
关联 Skills
晋升到 Skill / Queue 的条件
可晋升经验
```

不要晋升：

- 目标专属临时线索
- 未验证漏洞结论
- 敏感凭证或真实用户数据
- 大段扫描日志
- 红线规则

## 和其他命令的分工

| 命令 | 职责 |
|---|---|
| `/target` | 管当前目标、线索、下一步、handoff |
| `/kb` | 提供知识库思路、技巧、payload/bypass 家族、补漏 checklist 和可复用经验 |
| `/hunt` | 执行漏洞挖掘流程 |
| `/validate` | 验证 Candidate |
| `/remember` | 保存验证后的发现或成功模式 |

## 纪律

- 默认不要全量读取知识库。
- 知识库提供思路和战术知识，但不替代 Skill 的路线选择和验证。
- 具体 payload、WAF 绕过、SQLi 绕过、parser 差异等可以写入知识卡，但必须保留前置条件、误判边界和最小验证方式。
- 任何知识卡输出都必须回到目标层形成 lead、next action 或 dead end。
- 和 `rules/` 冲突时，以 `rules/` 为准。
