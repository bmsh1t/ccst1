---
id: xss-client-injection
type: technique-card
related_skills:
  - web2-vuln-classes
  - triage-validation
trigger_tags:
  - xss
  - reflected-xss
  - stored-xss
  - client-xss
  - csp
  - sanitizer
  - mxss
risk: medium
maturity: draft
load_priority: medium
deep_refs: []
---

# XSS / 客户端注入上下文

## Quick Recall

- XSS 不是固定打 `<script>`；先识别输入来源、输出位置、编码层和真实执行上下文。
- Reflected XSS 重点看 search/error/redirect/preview/filter 等即时反射；Stored XSS 重点看 comment/profile/message/Markdown/rich-text/admin review 等二次触发页。
- DOM XSS 需要证明 source-to-sink：hash/search/referrer/window.name/postMessage/localStorage 到 `innerHTML`、`document.write`、script URL、template 或 eval-like sink。
- Payload 示例是候选形态，不是固定字典；上下文不同，闭合方式不同。
- Candidate 必须有真实浏览器执行证据、可复现 URL/请求和影响解释。
- CSP 不是简单“有就挡住”；要读完整 header，寻找 directive 注入、`script-src-elem` 覆盖、nonce/hash、允许脚本源、JSONP/CDN gadget、`base-uri` 和 `object-src` 缺口。
- CSP 绕过不一定靠直接脚本执行；要额外看 nonce 复用、响应类型覆盖和无脚本外带通道（CSS/表单/资源加载）。
- 真实目标上不默认主动测试会污染他人可见内容的 stored XSS；训练/测试资源、自己可控内容或当前轮明确授权时可以验证。

## 能力定位

本卡给 `web2-vuln-classes` 补充 XSS 输入面发现、上下文识别、payload 家族和最小验证思路。它只提供知识和联想，不决定测试顺序，也不替代浏览器边界类检查。

## 触发信号

- 参数、路径、表单字段、搜索词、错误信息、重定向提示、模板预览或富文本内容被反射到页面。
- 评论、昵称、简介、消息、工单、文件名、Markdown、HTML sanitizer 输出或后台审核页存在二次渲染。
- JS/source 显示 `innerHTML`、`outerHTML`、`insertAdjacentHTML`、`document.write`、`dangerouslySetInnerHTML`、template render、URL 拼接或 postMessage sink。
- CSP、HTML sanitizer、WAF、模板引擎、Markdown 解析器或前端框架转义策略存在差异。

## 思路分支

- Reflected：固定 baseline 页面，确认反射点在 HTML text、attribute、script string、URL、CSS、template 中哪个上下文。
- Stored：只在训练/测试资源、自有对象或明确授权内容上验证；记录 store step、trigger step 和触发身份。
- DOM：先用浏览器 DevTools/Playwright 证明 source 到 sink，再调整 payload，不把普通 DOM 反射当执行。
- CSP/sanitizer：先看哪些标签、属性、协议、事件、模板语法被保留，再选择最小可执行形态。
- CSP bypass：检查 header 中是否有用户可控片段；例如 `report-uri /csp-report?token=<user>` 允许注入 `;script-src-elem 'unsafe-inline'`，在 Chrome 中放行 inline `<script>`。
- Sanitizer/parser differential：净化发生在解码前、渲染时再解码，或旁路预览/二级渲染未复用主净化器时，要把“净化视图”和“浏览器最终解析视图”拆开验证。
- Chain：低价值 self-XSS 或后台-only XSS 只有能链到 CSRF、OAuth、admin review、cache poisoning、account linking 或敏感 token 才值得升级。

## 技巧家族 / Payload 家族

- HTML text context：代表形态如 `<script>alert(1)</script>`、`<svg onload=alert(1)>`，只用于确认执行，不代表最终 payload。
- Attribute context：先闭合属性再构造新节点或事件，例如 `"><svg onload=alert(1)>`；如果属性值被强编码，转向协议/模板/DOM sink。
- JS string context：先确认单双引号、转义和 script 边界，再考虑字符串闭合、注释截断或模板字面量变体。
- URL/protocol context：`javascript:`、data URL、开放重定向和链接点击需要结合可触发路径评估。
- Markdown/rich-text：看 sanitizer 是否允许 HTML、SVG、MathML、链接协议、图片事件或二次渲染。
- DOM source/sink：hash/search/window.name/postMessage/localStorage 到 `document.write`、`innerHTML`、template 或 navigation sink；每次只换一个 source 或 sink。
- CSP directive 形态：`script-src-elem 'unsafe-inline'`、nonce/hash 复用、允许域 JSONP、AngularJS gadget、`base-uri` 改写、dangling markup；示例是候选，不是固定绕过字典。

## 补充 Checklist

- 是否记录了原始输入、输出上下文、编码层和触发页面？
- 是否区分 reflected、stored、DOM、self-XSS、admin-only XSS 和 sanitizer bypass？
- 是否用真实浏览器确认执行，而不是只看响应反射？
- Stored 场景是否记录 store step、trigger step、受影响身份和清理方式？
- CSP 是否阻止 inline script？是否存在 nonce、hash、strict-dynamic、允许脚本源或 JSONP/上传/CDN gadget？
- CSP 是否有用户可控 report-uri/token/path 片段，能否注入新 directive？新 directive 在目标浏览器中是否覆盖旧策略？
- 是否存在能放大影响的 connector：CSRF、点击劫持、OAuth redirect、cache poisoning、admin review、账户绑定或敏感 API token？

## 最小验证

- Reflected：构造最短 payload，保存 URL/请求、浏览器执行证据和响应上下文。
- Stored：仅在允许环境中写入自有测试内容，触发一次目标页面，记录触发身份和清理动作。
- DOM：用 Playwright/DevTools 记录 source 值、sink 调用和浏览器执行结果。
- 对真实目标，默认停止在可证明执行的最小证据，不做用户批量投递、蠕虫式传播、持久污染或窃取真实数据。

## 常见误判 / 死路

- URL 中出现 payload 不等于 XSS；必须证明进入可执行 sink。
- HTML 实体编码、React/Vue 默认转义、CSP 阻断或 sanitizer 删除标签时，单次反射只算 Lead。
- CSP header 注入只算 Lead，必须证明目标浏览器实际执行脚本；不同浏览器对 `script-src-elem`、sandbox 和 legacy directive 的处理可能不同。
- Self-XSS、低权限自见内容或不可触发后台页面通常低价值，除非有明确 connector。
- 单次 alert 不说明业务影响；需要说明可执行脚本能影响哪个身份、页面、权限或数据面。

## 关联 Skills

- `web2-vuln-classes`
- `triage-validation`

## 晋升到 Skill / Queue 的条件

- 有明确输入面、输出上下文和浏览器执行证据时，交给当前 Skill 判定 Candidate 或继续寻找 connector。
- 有 stored 或 DOM 触发路径但缺少影响时，写入 action queue，类型 `xss-client-injection`。
- 需要跨源、frame、CSRF、postMessage 或 CORS 影响验证时，同时加载 `knowledge/cards/browser-client-boundaries.md`。

## 可晋升经验

- 某类框架、sanitizer、Markdown 或 template 组合反复出现可迁移 bypass。
- 某类低价值 XSS 能稳定链到高价值 connector。
- 某类 context break 或 CSP 绕过在多个目标中可复用。

## 源报告（on-demand）

- source_report_ids: `893305`, `2279346`, `1436142`, `386334`, `199779`, `1115139`, `777241`, `1087122`, `633231`, `1125425`, `662287`, `1731349`, `1212067`, `1198517`, `824689`, `1665658`
- 用途：这些 ID 只作为本地案例库查询指针。只有当前证据已命中本卡触发信号，且需要真实攻击链形状、报告写作先例或相似案例时，才按需查询 gitignored 的 `distill/` 本地缓存；不要默认拉取全文，不把报告正文、目标域名、payload 或 PII 写入知识卡。
