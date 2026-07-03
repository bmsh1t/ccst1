---
id: business-logic-state-machines
type: technique-card
related_skills:
  - web2-vuln-classes
  - bb-methodology
  - triage-validation
trigger_tags:
  - business-logic
  - logic-flaw
  - state-machine
  - workflow-validation
  - client-side-controls
  - payment
  - rounding
  - gateway-state
risk: medium
maturity: draft
load_priority: high
deep_refs: []
---

# 业务逻辑 / 状态机 / 客户端信任边界

## Quick Recall

- 业务逻辑漏洞不是 payload 优先；先还原正常业务状态机，再找服务端没有重新校验的前置条件、顺序、金额、身份、数量和一次性约束。
- 高价值入口包括 cart/checkout/price/coupon/order、注册/登录/找回、邀请/审批/成员、订阅/配额、邮箱/组织归属和双用途 endpoint。
- 客户端字段不可信：隐藏字段、价格、数量、折扣、角色、邮箱、流程 step、redirect、feature flag、plan、scope 都要看服务端是否重算。
- 支付/计费链优先盯三点：取整方向与精度、收款方/受益人是否服务端锁定、网关状态未确认时是否提前发放权益。
- 示例字段如 `price=1`、`quantity=-1`、`coupon=ONCE`、`role=admin`、`email=...@trusted.tld` 是候选形态，不是固定字典。
- Candidate 需要证明业务状态被错误推进、限制被绕过、服务端接受不该接受的状态，或低权限用户获得高价值能力。
- 真实高影响状态默认先用 dry-run、预览、自有测试资源、可回滚对象或训练资源；不为了验证而直接造成真实扣款、发货、删除或外部副作用。

## 能力定位

本卡给 `web2-vuln-classes` 补充业务流程建模和状态机验证思路。它是供料层：帮助 AI 想到非注入、非传统 CVE 的高价值测试路径，不替代当前 Skill 的 red-line、coverage 和验证门。

## 触发信号

- 浏览器 XHR、JS/source、表单或隐藏字段里出现价格、折扣、积分、库存、状态、角色、邮箱、组织、审批、邀请、step、token、nonce。
- 同一业务有多步流程：加入购物车、结账、确认、付款、发货；注册、验证邮箱、登录；申请、审批、加入组织。
- 前端禁用按钮、隐藏字段、readonly 字段、客户端计算总价或 UI 控制流程顺序。
- 异常输入或边界值可能改变状态：负数、零、超大数、小数、重复提交、空数组、旧 token、过期 coupon、重复订单。
- 一个 endpoint 同时服务普通用户和管理员、创建和更新、验证和执行、预览和提交。

## 思路分支

- 客户端信任：服务端是否重新计算价格/数量/折扣/权限/角色，还是直接接受前端提交值。
- 流程重排：跳过 step、重复 step、提前调用确认/执行接口、复用旧 token 或把预览请求升级为提交。
- 状态边界：已取消、已退款、已过期、已使用、已审批、已邀请、未验证邮箱等状态是否仍可被后续接口接受。
- 异常输入：负数、超大数、小数、字符串、数组/对象包裹、重复参数、编码差异是否触发服务端分支。
- 双用途 endpoint：普通用户字段和管理员字段是否共用同一 handler，导致 role/plan/scope/status 被 mass assignment 或弱隔离。
- 解析差异：邮箱地址、域名、组织名、货币、时间、地区、大小写、Unicode/IDN、注释或分隔符在不同组件中解析不一致。

## 技巧家族 / Payload 家族

- Price/cart 形态：`price=1`、`quantity=-1`、`discount=100`、重复 coupon、旧 cart item、客户端总价与服务端总价不一致。
- Workflow 形态：直接访问 `/checkout/confirm`、重放确认请求、跳过验证 step、使用预览 token 调执行接口。
- Exceptional input：负数、零、最大整数、小数精度、科学计数法、空值、重复字段、数组/对象包裹。
- Identity parsing：`user@trusted.tld.evil.tld`、带注释/大小写/Unicode/加号/多收件人格式的邮箱或组织标识，只作为解析差异候选。
- Dual-use endpoint：同一 PATCH/POST 是否接受 `role`、`isAdmin`、`plan`、`status`、`verified`、`approved`、`limit` 等高价值字段。
- Token/state reuse：一次性 token、优惠码、邀请链接、重置链接、审批 token、购物车/订单 ID 是否可跨账号、跨状态或跨时间复用。

## 补充 Checklist

- 是否记录正常流程的每一步请求、服务端状态、前置条件和结束状态？
- 是否确认关键字段由服务端重算，而不是由浏览器或移动端提交？
- 是否测试了跳步、重放、重复提交、旧 token、过期状态和跨账号复用？
- 是否把 write 类测试限制在训练资源、自有对象、dry-run、预览或可回滚状态？
- 是否寻找能放大影响的 connector：Authz、IDOR、Race、mass assignment、payment/order/coupon、account linking。
- 是否记录 stop condition，避免在真实目标上继续推进到不可逆外部副作用？

## 最小验证

- 先保存合法 baseline：账号、对象、余额/配额/状态、流程步骤、关键请求和预期结果。
- 每次只改一个业务变量：价格、数量、coupon、step、状态、角色、邮箱、token 或 endpoint。
- 优先证明服务端接受了不该接受的状态，例如购物车总价被客户端字段影响、流程可跳步、旧 token 可复用、低权限字段被持久化。
- 真实目标上停在最小证据：自有对象状态差异、预览/dry-run 响应、可回滚测试记录或训练资源，不默认触发真实扣款、发货、删除、群发或第三方动作。

## 常见误判 / 死路

- 前端按钮禁用或隐藏不是漏洞，必须证明后端接受直接请求。
- 价格/角色字段回显不等于持久化，必须证明服务端状态或后续权限/金额改变。
- 业务规则看起来奇怪不等于安全问题，必须说明攻击者如何获益或越过限制。
- 真实支付/订单/发货/外部通知链路如果没有 dry-run 或测试资源，先记录 Lead 和最小证据，不直接推进。

## 关联 Skills

- `web2-vuln-classes`
- `bb-methodology`
- `triage-validation`

## 晋升到 Skill / Queue 的条件

- 出现具体 endpoint、状态变量和可复现差异时，写入 action queue，类型 `business-logic-state-machines`。
- 发现跨账号、跨组织、角色或对象边界时，转 `auth-access` / `api-idor`。
- 发现重复提交或竞态窗口时，转 `race-conditions`，但先保持低频状态建模。
- 发现 hidden/mass assignment 字段时，转 `api-testing-workflow` 或 `missing-parameter-discovery`。

## 可晋升经验

- 某类业务流程反复信任客户端价格、数量、状态或流程 step。
- 某类邮箱/域名/组织解析差异能稳定绕过权限或注册控制。
- 某类 token、coupon、邀请或订单状态可跨账号、跨时间或跨流程复用。

## 源报告（on-demand）

- source_report_ids: `1446090`, `219215`, `592803`, `486629`, `808975`
- 用途：这些 ID 只作为本地案例库查询指针。只有当前证据已命中本卡触发信号，且需要真实攻击链形状、报告写作先例或相似案例时，才按需查询 gitignored 的 `distill/` 本地缓存；不要默认拉取全文，不把报告正文、目标域名、payload 或 PII 写入知识卡。
