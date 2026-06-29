# 知识晋升规则

本文件定义哪些内容可以从目标记忆、hunt journal 或人工复盘中晋升到知识库层。

## 可以晋升

满足任一条件，可以考虑晋升：

- 同一模式在两个以上目标中重复出现
- 某个检查思路明显提高了有效 lead 命中率
- 某个方向被多次证明低价值，适合写入 dead end
- 某类技术栈、框架、产品形态有稳定攻击面特征
- 某个可复用经验或反例能帮助 Skills 层更好选择分支

## 不应晋升

以下内容不要进入知识库：

- 只属于单个目标的临时线索
- 未经验证的漏洞结论
- 真实 token、cookie、密钥、个人数据或客户数据
- 大段扫描输出、HTML、响应包
- 明确属于检查层的红线规则
- 会诱导无差别 payload spray 的内容

## 晋升格式

晋升时优先写成知识卡，而不是长文。

每条经验至少包含：

```text
Evidence pattern: 触发它的证据形态
Why it matters: 为什么值得测
Thought branches: 可以如何扩展思路
Technique / payload / bypass family: 可复用技巧或 payload/bypass 家族
Checklist gap: 容易漏掉的检查点
Next action: 最小验证动作
Stop condition: 何时停止
Validation requirement: 进入 Candidate 前需要什么证据
False positives / dead ends: 常见误判或死路
Promote to Skill / Queue when: 什么时候交给 Skill 或 action queue
```

## 从目标层晋升

目标层字段的处理建议：

| 目标层字段 | 晋升目标 |
|---|---|
| `active_leads` | 只有多个目标复现时才晋升为知识卡 |
| `dead_ends` | 可晋升到 `knowledge/cards/dead-ends.md` |
| `useful_patterns` | 可晋升到对应漏洞/攻击面知识卡 |
| `session_handoffs` | 不直接晋升，只作为复盘素材 |

## 复核要求

晋升前检查：

- 是否去除了目标专属敏感信息
- 是否能被其他目标复用
- 是否有明确停止条件
- 是否和 `rules/` 冲突
- 是否能帮助 Skills 层做更好的分支选择
