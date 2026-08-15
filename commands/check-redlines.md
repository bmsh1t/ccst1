---
description: 检查当前计划、请求或候选动作是否命中 DDoS / 破坏性行为 / 主动 stored XSS 红线。用法：/check-redlines
---

# /check-redlines

检查当前动作是否违反红线规则。

这个命令只回答：**这个动作会不会伤害目标系统、真实数据或真实用户？**
红线检查是窄边界安全检查，不是泛化权限闸门，也不重复裁决授权或漏洞价值。

## 必读文件

运行本命令时必须先读取：

```text
rules/red-lines.md
```

必要时再读取：

```text
memory/goals/active.json
knowledge/index.md
rules/hunting.md
```

## 适用场景

当 action 标记 `redline_required`，或动作可能造成高压流量、真实状态改变、实际上传、
持久化可执行内容等副作用时运行；具体边界和四级决策只读取 `rules/red-lines.md`。

## 输出格式

```text
RED-LINE CHECK
- Action: 准备执行的动作
- DDoS risk: yes/no/unclear
- Destructive risk: yes/no/unclear
- State-changing: yes/no/unclear
- Stored-XSS persistence risk: yes/no/unclear
- Test-owned resource: yes/no/unclear
- Low-risk alternative: yes/no
- Decision: allow / allow-with-controls / downgrade / pause
- Controls: 频率、测试资源、停止条件、回滚或清理方式
- Safe alternative: 低风险替代验证方式
```
