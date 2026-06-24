---
description: 检查当前计划、请求或候选动作是否命中 DDoS / 破坏性行为红线。用法：/check-redlines
---

# /check-redlines

检查当前动作是否违反红线规则。

这个命令用于执行前检查，不是报告验证，也不是漏洞 triage。它只回答一个问题：**这个动作会不会造成 DDoS、高压流量或破坏性状态改变？**

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

- 准备执行批量请求、并发测试、race 测试或扫描扩展
- 准备发送 `POST`、`PUT`、`PATCH`、`DELETE`、GraphQL mutation
- 准备测试订单、支付、退款、钱包、短信、邮件、Webhook、CI/CD
- 准备使用可能影响真实账号、真实数据或真实业务状态的 PoC
- 不确定某个动作是否会造成破坏性副作用

## 判断流程

1. 判断是否存在 DDoS / 高压流量风险。
2. 判断是否存在数据修改、删除、污染或不可逆状态改变。
3. 判断操作对象是否为测试账号、测试组织或自己创建的可清理资源。
4. 判断用户当前回合是否明确授权执行该类动作。
5. 如果任一条件不清楚，默认暂停，不执行。

## 输出格式

```text
RED-LINE CHECK
- Action: 准备执行的动作
- DDoS risk: yes/no/unclear
- Destructive risk: yes/no/unclear
- State-changing: yes/no/unclear
- Test-owned resource: yes/no/unclear
- Current-turn authorization: yes/no
- Decision: allow / downgrade / pause
- Safe alternative: 低风险替代验证方式
```

## 决策规则

### allow

只有低频、低副作用、只读或测试资源内的最小验证可以继续。

### downgrade

如果风险可疑但有替代方案，将动作降级为：

- 只读请求
- dry-run
- 本地 PoC
- 代码审计
- 记录为 Lead
- 请求测试资源

### pause

出现以下情况必须暂停：

- 可能造成 DDoS 或资源耗尽
- 可能修改、删除、破坏真实数据
- 可能触发真实支付、转账、退款、发货、短信、邮件、CI/CD
- 操作对象不是测试资源
- 用户当前回合没有明确授权

暂停时不要继续执行该动作，只报告阻塞原因和安全替代方案。
