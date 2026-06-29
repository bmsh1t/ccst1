---
id: ssrf-internal-impact
type: technique-card
related_skills:
  - web2-vuln-classes
  - triage-validation
trigger_tags:
  - ssrf
  - internal-service
  - metadata
  - url-parser
  - impact-proof
risk: high
maturity: draft
load_priority: medium
deep_refs:
  - knowledge/cards/ssrf-url-fetch.md
  - knowledge/playbooks/controlled-rce-validation.md
  - /root/tool/ccst/ctf-skills/ctf-web/server-side.md
  - /root/tool/ccst/ctf-skills/ctf-web/server-side-advanced-2.md
  - /root/tool/ccst/ctf-skills/ctf-web/server-side-advanced-3.md
  - /root/tool/ccst/ctf-skills/ctf-web/server-side-advanced-4.md
---

# SSRF 内部影响证明

## Quick Recall

- SSRF callback 只是入口信号；高价值在服务端网络身份、内部服务可达性、metadata/控制面风险和链式影响。
- 默认不做大范围端口扫描，不批量读取内部数据，不抓取云凭证。
- 最小影响证明优先：单个明确内部目标、状态级响应、banner/health 级证据、可复现请求。
- SSRF-to-RCE 或 SSRF-to-internal-read 要转受控影响证明 playbook。
- 深挖时读取 `deep_refs` 中的 `ctf-web` SSRF/parser 深度参考，提取 parser
  mismatch、redirect、内部服务链路和协议差异思路，不照搬内网扫描或凭证抓取流程。

## 能力定位

本卡用于在 `ssrf-url-fetch` 已证明服务端请求行为后，补充内部影响证明思路。
它不替代 SSRF 入口验证，只处理“如何安全证明影响”。

## 触发信号

- 已证明服务端会请求攻击者控制 URL。
- URL 校验和实际请求存在重定向、DNS、IPv6、编码、协议、host 解析差异。
- 错误信息、响应时间、状态码或回显显示服务端可触达内部地址、metadata、管理面或服务发现系统。
- 目标技术栈存在 Docker API、Redis、Elasticsearch、Kubernetes、云 metadata、admin health、debug endpoint 等内部服务信号。

## 思路分支

- External callback proof：证明请求由目标服务端发起。
- Internal reachability proof：证明单个明确内部 host/port/path 可达。
- Parser discrepancy proof：证明 allowlist/filter 与实际 fetcher 解析不一致。
- Metadata risk proof：证明 metadata 服务或云控制面可触达，但默认不读取凭证。
- Chain proof：SSRF -> internal admin/API/read primitive -> controlled RCE/secret risk/业务影响。

## 技巧家族 / Payload 家族

- 重定向链、DNS 重绑定、IPv6/IPv4 映射、整数/八进制/短写 IP、尾随点、大小写和编码差异。
- URL parser 差异：校验器与 fetcher 对 scheme、userinfo、fragment、反斜杠、双 `@`、换行等解析不同。
- 协议和端口差异：HTTP/HTTPS、gopher-like、file-like、custom fetcher 行为，只在证据命中时考虑。
- 状态级内部证明：health/status/version/banner 级证据，不默认读取敏感内容。

## 补充 Checklist

- 是否已经证明是服务端请求，而不是浏览器请求？
- 是否记录了来源 IP、时间、User-Agent、Host、请求路径和 token？
- 是否只验证一个明确内部目标，而不是扫描内网？
- 是否避免读取 metadata credentials、数据库内容、队列消息、真实配置或用户数据？
- 是否能把 SSRF 影响链到业务风险，而不是只报告 DNS callback？

## 最小验证

- 使用一次性 OAST token 证明服务端请求来源。
- 对内部路径只测试单个高信号、低副作用 endpoint，例如 health/version/status。
- 对 metadata 风险只证明可达性或安全控制缺失，不默认拉取凭证材料。
- 如果响应有回显，只截取最小非敏感证据。
- 如果只能 blind，记录时间差、错误差、回调差，不扩大枚举。

## 常见误判 / 死路

- DNS-only callback 不等于高危 SSRF。
- 浏览器发起的请求不是 SSRF。
- 代理/WAF 健康检查、预取、链接扫描可能伪造 callback。
- 内部 403/401 也可能是有价值信号，但不能直接当作数据访问。

## 关联 Skills

- `web2-vuln-classes`
- `triage-validation`
- `bb-methodology`

## 晋升到 Skill / Queue 的条件

- 只有外部 callback 时，保持 Signal，继续找回显、内部可达性或链式影响。
- 有明确 internal target/path/next question 时，写入 action queue，类型 `ssrf-internal-impact`。
- SSRF 能触发内部执行、管理 API 或敏感配置访问时，转 `controlled-rce-impact` 或对应验证 Skill。

## 可晋升经验

- 某类 URL fetch 功能在特定框架/云环境中反复能触达内部控制面。
- 某类 parser discrepancy 稳定绕过 allowlist。
- 某类 DNS-only SSRF 多次低价值，应沉淀为 dead-end 条件。
