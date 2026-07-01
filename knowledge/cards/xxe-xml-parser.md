---
id: xxe-xml-parser
type: technique-card
related_skills:
  - web2-vuln-classes
  - triage-validation
trigger_tags:
  - xxe
  - xml-parser
  - xinclude
  - soap
  - saml
risk: medium
maturity: draft
load_priority: medium
deep_refs:
  - /root/tool/ccst/ctf-skills/ctf-web/server-side.md
---

# XXE / XML Parser 面

## Quick Recall

- XXE 的关键不是“有 XML 字符串”，而是后端 parser 会处理 DTD、外部实体、XInclude 或外部资源引用。
- 入口不只 SOAP/XML API，也包括 SAML、SVG、DOCX/XLSX/PPTX、RSS/Atom、PDF/Office 转换、移动端 XML 和导入/预览 worker。
- 先建立合法 XML baseline，再单变量验证 entity、DOCTYPE、XInclude、content-type 和 parser 差异。
- 有回显时比较 entity 展开结果；无回显时用一次性 OAST callback 证明服务端解析器行为。
- 400/错误响应不是失败或成功的直接结论；只有错误消息或业务字段反射 entity 展开结果时，才能作为 parser 行为证据。
- file-read、SSRF、metadata、SAML auth impact 是影响方向，不是默认读取/扫描动作。
- 示例 payload 只作为候选形态，不是固定字典；具体语法取决于 XML 上下文、命名空间和 parser。

## 能力定位

本卡给 `web2-vuln-classes` 提供 XML parser 攻击面的联想、技巧家族和补漏项。
它不替代 Skill 的流程判断，也不自动进入敏感文件读取或内网探测。

## 触发信号

- 请求或响应出现 XML、SOAPAction、SAMLResponse、NameID、SVG、Office 文档、RSS/Atom、import/preview/convert。
- JSON API 对 `Content-Type: application/xml` 或 XML body 有不同错误、状态码、长度或 parser 报错。
- 上传/导入/转换器会解析 SVG、DOCX、XLSX、PPTX、PDF 内嵌 XML 或外部引用。
- 错误里出现 SAX、DocumentBuilder、libxml、lxml、dom4j、xerces、XMLReader、XInclude 等线索。

## 思路分支

- Classic XXE：外部实体被展开并回显或进入错误。
- Error-reflected XXE：数值、ID、库存、搜索等业务字段被 parser 消费，entity 展开后进入校验错误或异常消息。
- Blind XXE：无回显但解析器对 OAST 域名发起 DNS/HTTP 请求。
- XInclude：DTD 被禁用但 `xi:include` 仍被处理。
- Parser confusion：JSON/XML/form 的 content-type、SOAPAction、namespace 或编码差异触发不同 parser。
- File-read chain：证明单个文件可达后，链到源码、配置、路由或 token/signing secret 假设。
- SSRF chain：证明 XML parser 可请求外部 URL 后，再判断是否能访问单个明确内部 health/status 目标。

## 技巧家族 / Payload 家族

- DTD/entity 形态：内联实体、外部 SYSTEM 实体、参数实体、错误回显实体。
- XInclude 形态：在支持 namespace 的字段中尝试包含本地或远程资源。
- Archive/XML 形态：在 SVG、DOCX、XLSX、PPTX、RSS/Atom 内嵌外部引用或实体。
- Content-type 差异：同一 endpoint 对 JSON、XML、form-urlencoded 的解析和鉴权顺序差异。
- OAST 形态：一次性 token 域名，记录来源 IP、时间、路径和 User-Agent。

## 补充 Checklist

- 是否测过同业务的 SOAP/SAML/SVG/Office 导入 sibling parser？
- 是否区分了前端 XML 处理、WAF 报错和真实后端 parser？
- 是否验证了 XML 被业务字段消费，而不只是被网关拒绝？
- Blind 信号是否有唯一 token、时间窗口和请求参数对应关系？
- file-read 或 SSRF 方向是否有最小影响证明，而不是直接扩大读取或扫描？

## 最小验证

- 记录合法 XML 请求/响应 baseline。
- 单次替换为无害 entity 或 OAST entity，比较状态码、长度、错误、回显或 callback；若错误消息反射 marker，保存原始请求/响应作为 parser 行为证据。
- 对 XInclude、SVG、Office 文档等二阶 parser，记录 store step 和 trigger step。
- Candidate 前至少需要：可 replay 请求、解析器行为证据、影响路径和红线说明。

## 常见误判 / 死路

- XML parse error 不等于 XXE；可能只是格式错误。
- 含业务字段值的错误消息可以是证据，但必须和无害 entity baseline 对照，证明是服务端展开而不是客户端替换或普通格式错误。
- OAST callback 不等于可读文件；可能只能证明外连或预取。
- WAF/代理返回的 XML 错误不代表应用 parser 可控。
- 只在本地客户端展开实体不算服务端漏洞。

## 关联 Skills

- `web2-vuln-classes`
- `triage-validation`
- `bb-methodology`

## 晋升到 Skill / Queue 的条件

- 只有 XML/parser 信号时，作为 Lead 交给当前 Skill 做 baseline。
- 有 endpoint、XML 输入、单变量 probe 和差异时，可写入 action queue，类型 `xxe-xml-parser`。
- 已证明 file-read、SSRF 或 SAML/auth 影响时，转 `triage-validation` 或对应影响卡。

## 可晋升经验

- 某类产品/框架的 XML parser 默认行为。
- 某类上传/导入格式稳定触发 XML 二阶解析。
- 某类 content-type 差异可复用为 XML parser 发现入口。
