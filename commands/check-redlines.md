---
description: 检查当前计划、请求或候选动作是否命中 DDoS / 破坏性行为 / 主动 stored XSS 红线。用法：/check-redlines
---

# /check-redlines

检查当前动作是否违反红线规则。

这个命令用于执行前检查，不是报告验证，也不是漏洞 triage。它只回答一个问题：**这个动作会不会伤害目标系统、真实数据或真实用户？**

红线检查是窄边界安全检查，不是泛化权限闸门。低频只读验证、浏览器观察、
JS/source 分析、CVE 情报、OAST、受控口令测试、反射/DOM XSS 低风险验证、
参数/路径/角色差异分析默认不应被红线阻断。

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
- 准备发送可能改写真实数据的 `PUT`、`PATCH`、`DELETE`、GraphQL mutation
- 准备执行可能改变真实订单、支付、退款、钱包、短信、邮件、Webhook 或 CI/CD 状态的动作
- 准备使用可能改变、破坏、污染真实账号、真实数据或真实业务状态的 PoC
- 准备向目标系统持久化位置提交可执行 stored XSS payload
- 不确定某个动作是否会造成破坏性副作用

## 判断流程

1. 判断是否存在 DDoS / 高压流量风险。
2. 判断是否存在数据修改、删除、污染，或改变真实账号/权限/CI/CD 状态的副作用。
3. 判断是否会写入可执行、持久化、影响真实用户的 payload。
4. 判断操作对象是否为测试账号、测试组织或自己创建的可清理资源。
5. 判断是否存在 dry-run / preview / validate-only / inert marker / 本地复现等低风险替代。
6. 如果伤害风险不清楚，默认降级到安全替代；如果确认会伤害目标，暂停。

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
- Decision: allow / downgrade / pause
- Safe alternative: 低风险替代验证方式
```

## 决策规则

### allow

低频、低副作用、只读、不会持久化可执行 payload、或测试资源内的最小验证可以继续。

### downgrade

如果风险可疑但有替代方案，将动作降级为：

- 只读请求
- dry-run
- preview / validate-only
- inert marker
- 本地 PoC
- 代码审计
- 记录为 Lead
- 请求测试资源

### pause

出现以下情况必须暂停：

- 可能造成 DDoS 或资源耗尽
- 可能修改、删除、破坏真实数据
- 可能提交 stored XSS 可执行持久 payload
- 可能触发真实支付、转账、退款、发货、短信、邮件、CI/CD，或改变真实账号/权限
- 操作对象不是测试资源
- 没有安全替代方案且缺少当前回合明确 opt-in

暂停时不要继续执行该动作，只报告阻塞原因和安全替代方案。
