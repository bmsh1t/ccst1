# 覆盖提醒

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
