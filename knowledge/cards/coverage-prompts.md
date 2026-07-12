---
id: coverage-prompts
type: checklist-card
related_skills:
  - bb-methodology
  - web2-recon
  - web2-vuln-classes
trigger_tags:
  - coverage
  - missed-lane
  - checklist-gap
risk: low
maturity: draft
load_priority: medium
deep_refs: []
---

# 覆盖提醒

## Quick Recall

- 触发：当前 surface、证据或 checkpoint 显示某个相邻测试面尚未覆盖。
- 最小验证：只选择与现有证据相邻的一条 lane，先记录 baseline、验证路径和停止条件。
- 证据门：每项覆盖必须能回到可 replay 请求、证据记录和明确的状态出口。
- 停止：没有语义相关性、只剩泛化清单，或继续动作会触碰红线/真实业务状态。

## 触发信号

- API、认证、上传、URL Fetch、GraphQL/WebSocket 或业务状态机出现未闭合的 surface。
- 当前 action queue、evidence ledger 或 checkpoint 明确显示某类 lane 缺少验证或收敛记录。

## 推荐动作

- 从当前证据选择一条最小遗漏 lane，补齐 replay、evidence、stop condition 和最终状态。
- 不把本卡的覆盖提醒直接变成固定扫描顺序；无法证明相关性时降级为记录项。

## 检查要求

- 每个提醒都必须有对应的 baseline、最小验证路径和 `next action`/`blocked`/`n/a`/`dead-end` 出口。
- 覆盖统计可以保留未测数量，但不得把数量本身升级为漏洞或强制执行理由。

这张知识卡用于提醒 Claude 不要漏掉常见高价值测试面。它不是强制全测清单，而是覆盖基线的发散辅助。

## API / Web 覆盖提醒

看到 API surface 时，不要只测详情接口。考虑：

- list
- detail
- search
- export
- download
- share
- invite
- bulk
- mutation / action
- history / audit

## 认证与权限覆盖提醒

看到登录、组织、团队、角色时，考虑：

- 未登录
- 普通用户
- 组织成员
- 管理员
- 跨组织 / 跨租户
- 过期 token
- 权限变更后的旧 session
- 邀请 / 转移 / 账号绑定流程

## 上传 / 导入 / 转换覆盖提醒

看到上传或导入时，考虑：

- 文件名
- MIME
- 文件内容
- metadata / EXIF
- 异步处理
- 预览 / 转换
- 下载权限
- 清理机制

## URL Fetch / Webhook 覆盖提醒

看到 URL、callback、webhook、preview、import 时，考虑：

- 服务端是否真的访问外部 URL
- 重定向
- DNS / IPv6 / 编码 / 解析差异
- OAST 低频验证
- 是否有响应内容回显
- 是否只能证明 DNS-only

## GraphQL / WebSocket 覆盖提醒

看到 GraphQL 或 WS 时，考虑：

- schema / operation 名称
- node/global id
- mutation
- subscription / channel
- role diff
- tenant / org id
- 批量或 alias 风险只能低风险验证，不能做压力测试

## 业务逻辑覆盖提醒

看到订单、支付、钱包、积分、优惠券、库存、通知时，默认先过红线：

- 是否会产生真实扣费、转账、退款、发货
- 是否会修改真实数据
- 是否能 dry-run
- 是否能使用测试资源
- 是否只能记录为 blocked / red-line

## 收敛提醒

每条未完成方向都必须落到一个状态：

- `next action`
- `blocked`
- `n/a`
- `dead-end`
- `candidate -> /validate`

不能只写“后续继续关注”。
