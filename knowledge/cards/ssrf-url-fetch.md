---
id: ssrf-url-fetch
type: technique-card
related_skills:
  - web2-vuln-classes
  - security-arsenal
  - triage-validation
trigger_tags:
  - url-fetch
  - webhook
  - import-url
  - server-side-fetch
  - nextjs-image-optimizer
risk: medium-to-high
maturity: draft
load_priority: high
deep_refs: []
source_refs:
  - type: corpus-report
    corpus: hackerone-disclosed-reports
    id: "541169"
  - type: corpus-report
    corpus: hackerone-disclosed-reports
    id: "1685822"
  - type: corpus-report
    corpus: hackerone-disclosed-reports
    id: "1092230"
  - type: corpus-report
    corpus: hackerone-disclosed-reports
    id: "1153862"
  - type: corpus-report
    corpus: hackerone-disclosed-reports
    id: "727330"
  - type: corpus-report
    corpus: hackerone-disclosed-reports
    id: "859962"
  - type: corpus-report
    corpus: hackerone-disclosed-reports
    id: "287835"
  - type: corpus-report
    corpus: hackerone-disclosed-reports
    id: "704621"
---

# SSRF / URL Fetch 面

## Quick Recall

- 触发：用户可控 URL、webhook/import/preview 等功能，并有后端主动请求线索。
- 最小验证：先用单一可控 callback 建立服务端访问 baseline，再一次只改变一个解析变量。
- 证据门：记录来源、时间、请求特征、状态/回显和实际影响；访问自有 URL 不等于高危 SSRF。
- Next.js `/_next/image` 返回 200 只说明优化器产生了响应；必须用唯一 OAST callback、可解释的
  upstream 内容差异或单个内部资源证据证明真实 server-side fetch。
- 停止：无法证明服务端请求、只有 DNS-only 信号，或需要访问未授权内部系统。

## 适用场景

- 目标提供 webhook、callback、URL import、图片抓取、PDF/HTML 转换、头像抓取、链接预览等功能
- 后端会主动访问用户提供的 URL
- 上传或导入流程中存在外部资源引用
- AI/RAG、文档处理、截图服务、爬虫服务可读取外部 URL

## 触发信号

- 参数名包含 url、uri、callback、webhook、image、avatar、fetch、import、preview、pdf、html
- 响应时间、错误信息或回调记录显示服务端进行了外部请求
- 转换器、截图服务或文档解析器暴露网络访问行为
- URL 校验和实际请求行为存在重定向、解析或协议差异
- 过滤器是 filter-then-fetch：校验与真正请求之间存在 TOCTOU；0-TTL 或 DNS 重绑定可让校验态与连接态解析到不同 IP
- Next.js/React SSR 目标出现 `/_next/image?url=...&w=...&q=...`、image optimizer 错误或 remote pattern 拒绝信息

## 发散问题

- 服务端是否真的发起请求，还是只做前端预览？
- URL 校验发生在请求前还是请求后？
- 重定向链是否改变了最终访问目标？
- DNS、IPv6、短写、编码、大小写、尾随点等解析差异是否影响校验？
- 请求结果是否可回显，还是只能通过状态差异或 OAST 观察？

## 推荐动作

- 先证明服务端会访问外部 URL，再考虑内部资源方向。
- 使用单一、可控、低频的回调观察，不做批量探测。
- 一次只改变一个解析变量：协议、host、端口、重定向或路径。
- 记录请求来源、时间、header、状态差异和是否有响应内容回显。
- 对 `/_next/image` 先用允许的正常图片建立 optimizer baseline，再使用唯一自有 callback；400 常是
  `images.remotePatterns`/domain allowlist 的正常拒绝，200 也不能替代 callback 或 upstream 差异证据。

## 关联 Skills

- `web2-vuln-classes`
- `security-arsenal`
- `triage-validation`

## 停止条件

- 无法证明服务端访问了用户控制 URL
- 只有 DNS-only 信号，无法说明内部访问、数据返回或状态影响
- 所有重定向和解析差异都被服务端稳定拦截
- `/_next/image` 只有 200/400、图片占位符或统一优化错误，没有唯一回调、内容差异或内部目标证据
- 继续测试会触发高频扫描或访问未授权内部系统

## 检查要求

- Candidate 前必须证明服务端请求行为和安全影响。
- 不能把“服务端访问了我的 URL”直接等同于高危 SSRF。
- 不能把 Next.js image optimizer 的 HTTP 200、转换后的图片体或错误文案单独升级为 SSRF Candidate。
- 涉及云元数据、内网服务或敏感资源时必须遵守授权和红线规则。

## 可晋升经验

- 某类 URL fetch 功能常见的解析差异
- 某个产品形态中高信号的 URL 参数命名
- 多次证明低价值的 DNS-only SSRF 模式
