# postMessage 的 origin 校验与内容信任缺陷

## 适用场景

- 页面用 window.postMessage 跨窗口/iframe 通信
- 监听器处理消息并写 DOM/发请求/改状态
- 存在嵌入第三方 iframe 或被嵌入

## 触发信号

- 监听器 origin 校验缺失或弱匹配
- 消息数据直接进 innerHTML/eval/导航
- 消息控制敏感动作而不校验来源

## 发散问题

- 监听器校验 origin 了吗？校验够严吗？
- 消息内容流向哪个 sink？
- 谁能向这个窗口发消息？

## 推荐动作

- 枚举 message 监听器，检查 origin 校验强度。
- 追踪消息数据到 sink。
- 从可控源发消息验证注入。

## 关联 Skills

- web2-vuln-classes
- security-arsenal
- triage-validation

## 停止条件

- 监听器精确校验 origin 且对内容做上下文编码
- 消息不流入敏感 sink

## 检查要求

- 必须证明跨源消息可达成 XSS 或敏感动作，且可复现。

## 可晋升经验

- 见 postMessage 监听器必查两点：origin 精确性、内容到 sink 的路径。

## 源报告（on-demand）

- source_report_ids: `129873`, `398054`, `499030`, `603764`, `389108`, `423218`, `662083`, `868615`
- 用途：这些 ID 只作为本地案例库查询指针。只有当前证据已命中本卡触发信号，且需要真实攻击链形状、报告写作先例或相似案例时，才按需查询 gitignored 的 `distill/` 本地缓存；不要默认拉取全文，不把报告正文、目标域名、payload 或 PII 写入知识卡。
