---
id: race-conditions
type: technique-card
related_skills:
  - bb-methodology
  - web2-vuln-classes
  - triage-validation
trigger_tags:
  - race
  - concurrency
  - state-diff
  - low-frequency
risk: high
maturity: draft
load_priority: medium
deep_refs: []
---

# Race Condition / 并发状态差异

## Quick Recall

- 触发：同一资源有次数/额度/状态转换，且存在检查后修改或重复提交窗口。
- 最小验证：先建状态模型；只有测试资源和明确授权时，才用最少并发请求验证窗口。
- 证据门：说明竞争窗口、攻击者权限、状态/影响差异；请求数量本身不是证据。
- 停止：没有测试资源、只能高压或破坏性验证，或单次 replay 已证明幂等/事务保护。

## 适用场景

- 业务状态依赖顺序、次数、额度、邀请、优惠、使用量、审批或验证流程
- 同一动作可能被重复提交
- 前端或后端存在“检查后再修改”的流程
- 目标暴露支付、订单、库存、优惠券、邀请、OTP、配额、审批等状态机

## 触发信号

- 响应中出现 quota、limit、remaining、status、state、pending、used、redeemed
- 同一资源存在 confirm、apply、redeem、claim、accept、approve、cancel 等动作
- 前端禁用按钮，但请求接口仍可直接 replay
- 日志、JS 或错误信息显示异步任务、队列或延迟一致性

## 发散问题

- 检查和写入是否在同一个事务里完成？
- 同一资源能否被重复兑换、重复接受、重复提交？
- 状态从 pending 到 confirmed 期间是否存在短窗口？
- API 是否依赖前端防重复提交？
- 不同端点是否能改变同一状态，但校验不一致？

## 推荐动作

- 先做流程建模，画出状态转换，不直接并发打请求。
- 优先用源码、日志、响应差异、单次 replay 证明存在状态边界。
- 如果必须验证并发，必须先过 `rules/red-lines.md`，并仅使用测试资源、最小请求数和当前回合明确授权。
- 对真实支付、订单、钱包、短信、邮件、库存、CI/CD 等状态，不执行破坏性验证，只记录为 Lead 和安全验证条件。

## 关联 Skills

- `bb-methodology`
- `web2-vuln-classes`
- `triage-validation`

## 停止条件

- 无可控状态转换
- 只能通过高压流量或破坏性动作继续
- 操作对象不是测试资源
- 单次 replay 已显示服务端有稳定幂等或事务保护

## 检查要求

- Race 方向默认高风险，先过红线。
- 不得把并发请求数量当成“测试质量”。
- Candidate 前必须能说明状态机、竞争窗口、攻击者权限、影响和低风险复现路径。

## 可晋升经验

- 某类状态字段反复提示 race 风险
- 某类业务流程中前端防重复提交反复弱于后端幂等保护
- 某些 race 方向多次因红线不可验证，应沉淀为 blocked 模式
