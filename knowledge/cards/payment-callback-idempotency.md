---
id: payment-callback-idempotency
type: technique-card
related_skills:
  - web2-vuln-classes
  - triage-validation
trigger_tags:
  - payment-callback
  - webhook
  - callback-signature
  - idempotency
  - replay-window
  - async-settlement
risk: medium
maturity: draft
load_priority: medium
deep_refs: []
---

# 支付回调、签名绑定与幂等边界

## Quick Recall

- 触发：存在 `notify`/`webhook`/callback、异步结算、订单状态或权益发放链路。
- 先画出 `pending -> paid/failed/refunded` 状态和“谁可以推进状态”，再比较签名覆盖、订单金额、受益人和幂等键。
- 最小验证只使用自有测试订单或 dry-run：合法 baseline、单变量签名/字段/重试差异和状态 read-back。
- 重放成功不等于影响；必须证明重复或错绑回调改变了订单、余额、权益或通知状态。
- 真实扣款、发货、退款和第三方通知默认停止，转为 Lead 并记录所需授权和可回滚条件。

## 能力定位

本卡补充 `business-logic-state-machines` 对异步支付边界的覆盖。它提供状态、身份、签名和幂等的组合检查，不替代 `triage-validation` 的证据门，也不要求固定 payload 顺序。

## 触发信号

- URL、JS 或 API 文档出现 `notify_url`、`webhook`、`callback`、`transaction_id`、`notify_id`、`idempotency_key`、`paid_at`。
- 同一订单同时有浏览器 return、服务端 notify、轮询、队列消费或定时补偿。
- 回调 body 含金额、币种、订单号、收款方、状态、时间戳和签名，但服务端响应没有明确绑定关系。
- 重试、乱序、超时补偿或“已处理”响应可能让同一事件再次进入业务状态机。

## 思路分支

- 状态分支：回调前后订单/支付/权益的状态、金额和受益人是否一致，失败/退款是否能逆向或重复推进。
- 签名分支：签名覆盖的是原始 bytes、规范化字段还是部分字段；订单、金额、状态、受益人和时间戳是否都绑定到同一消费对象。
- 身份分支：`transaction_id`/`notify_id`/订单号/租户/用户是否互相绑定，换订单或跨账号时是否仍被接受。
- 幂等分支：同一事件重试、不同事件复用同一键、空键/大小写变体、并发到达和乱序到达分别如何处理。
- 连接器：回调更新后是否触发发货、积分、订阅、退款、邮件、webhook 或后台任务；只沿已有证据链向下一层。

## 技巧家族 / Payload 家族

- 事件形状：只改变一个字段或一个事件标识，比较验签结果、状态、响应和 read-back；不使用固定字典批量尝试。
- 重试形状：相同事件重复、同订单不同事件、同幂等键不同 body、同 body 不同幂等键；每次只选一个变量。
- 时间形状：合法时间窗口、过期、未来、时区/精度差异，只在测试订单上记录服务端判断。
- 解析形状：重复字段、空值、数字/字符串金额、大小写和 JSON shape 只作为 parser differential 候选，不能直接定性。

## 补充 Checklist

- 是否保存合法支付流程的请求、响应、订单状态、金额、币种、用户和受益人 baseline？
- 签名验证视图和业务消费视图是否读取同一对象、同一规范化结果？
- 幂等键到底绑定事件、订单、用户、租户还是 body hash，失败重试是否清理或锁定状态？
- 是否检查异步回调与浏览器 return 的优先级、乱序和最终一致性？
- 是否记录最小 read-back 和停止条件，避免真实扣款、发货或外部通知？

## 最小验证

- 在自有/训练订单上保存 `before` 状态和合法 callback baseline。
- 单变量修改签名覆盖字段、订单/金额/状态绑定或幂等键，比较状态码、响应体、账本和最终状态。
- 对重复/乱序只做少量、可回滚的同步触发；结果必须能对应到唯一事件和订单。
- 若只能证明回调被接收、DNS/HTTP 被请求或响应变了，保持 Lead/Signal，不升级 Candidate。

## 常见误判 / 死路

- 返回 `200` 或“success”不代表订单已支付；必须 read-back 服务端状态和权益。
- 签名缺失/错误被拒绝只是预期行为；必须证明合法签名消费了错误对象或状态。
- 幂等键重复返回相同响应不一定是漏洞，只有重复副作用或跨对象错绑才有影响。
- 没有测试订单、dry-run 或回滚路径时，不继续真实支付/退款/发货验证。

## 关联 Skills

- `web2-vuln-classes`
- `triage-validation`

## 晋升到 Skill / Queue 的条件

- 具体 callback、状态和最小 replay 已明确时，交给 `triage-validation` 的验证队列。
- 若问题只在签名覆盖/消费对象不一致，转 `signature-scope-mismatch`。
- 若问题只在并发窗口，转 `race-conditions`；若是通用状态推进，转 `business-logic-state-machines`。

## 可晋升经验

- 某种回调事件/订单/幂等键绑定模式在多个目标重复出现，并有可定位状态证据。
- 某种失败/重试/乱序处理反复造成错误权益或错绑受益人。
