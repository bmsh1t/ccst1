---
id: browser-client-boundaries
type: technique-card
related_skills:
  - web2-vuln-classes
  - triage-validation
trigger_tags:
  - cors
  - csrf
  - clickjacking
  - dom-xss
  - postmessage
  - open-redirect
  - cookie-manipulation
  - dom-clobbering
risk: medium
maturity: draft
load_priority: medium
deep_refs:
  - /root/tool/ccst/ctf-skills/ctf-web/client-side.md
---

# 浏览器端边界 / CORS / CSRF / Clickjacking / DOM

## Quick Recall

- 浏览器类问题必须用真实浏览器模型验证：Origin、Referer、SameSite、iframe、CORS credential、DOM source-to-sink。
- Header 缺失、可 iframe、Origin 反射或 DOM 反射本身只是 Lead；Candidate 需要证明跨源读、敏感状态改变、可点击高影响动作或可控 sink。
- CORS Candidate 的核心证据是攻击者 Origin 下浏览器能带凭据读取敏感响应，例如 accountDetails/API key；只看到 ACAO 反射还不够。
- `Origin: null` 是高信号 CORS 变体：sandboxed iframe、data/file URL、opaque origin 等能制造 null origin；只有服务端同时允许 credentials 并返回敏感响应才升级。
- Trusted insecure protocol 变体要看受信任 http 子域、mixed content、子域 takeover、redirect 或 downgrade 是否能作为可投递 origin；还必须证明攻击者能在该 trusted origin 上执行 JS 或控制页面。
- CSRF 不等于“没有 token”；要看 Cookie 是否发送、SameSite、方法/content-type、token 绑定和业务动作影响。
- CSRF token 不是二元防护；要按 method、token presence、session binding、non-session cookie binding、duplicate-cookie binding 分开验证。
- 无防护表单的最小验证可以是训练/测试资源上的 auto-submit form，证明浏览器会自动带凭据完成状态改变。
- DOM/XSS 要证明 source 到 sink，而不是只看 URL 里有字符串。
- DOM payload 必须匹配 sink 上下文；例如 `document.write` 写入属性时，需要先闭合属性再构造可执行节点。
- DOM open redirect/cookie/clobbering 也要证明 source-to-sink；例如 URL 中未编码 `url=https://...` 被脚本正则取出后写入 `location.href`。
- `postMessage` 不只是普通 DOM source：必须同时证明 sender origin 可控、listener 校验过弱，以及 message 数据真的流进敏感 sink 或高价值动作。

## 能力定位

本卡给 `web2-vuln-classes` 补充浏览器执行模型和客户端边界验证，不替代具体漏洞 Skill。

## 触发信号

- 表单、状态改变 API、CORS header、Origin/Referer 校验、iframe/XFO/CSP、postMessage、hash/search 路由、DOM sink。
- 浏览器 Network/Console 中出现跨源、preflight、SameSite、frame blocked 或脚本错误。

## 思路分支

- CORS：Origin allowlist、null origin、credentials、preflight 与实际响应不一致、受信任不安全协议或子域。
- CSRF：token 缺失/未绑定、SameSite 绕过、简单请求、方法覆盖、JSON/form parser 差异。
- CSRF token matrix：POST 正常 token、GET/POST method swap、删除 token、错误 token、跨 session token、token+cookie pair、form token 等于 cookie token。
- SameSite bypass matrix：区分 site 和 origin；按 Lax 顶层 GET / method override、Strict 站内 gadget / client-side redirect、sibling-domain XSS/CSWSH、新签发 Lax cookie 窗口逐项验证。
- Referer validation matrix：有 Referer、无 Referer、origin-only Referer、full-url Referer、路径/query 中包含目标域名、子域/后缀混淆分别验证。
- Clickjacking：敏感页面可被 frame，且能诱导点击高影响按钮。
- CSRF token 不等于 clickjacking 防护；如果敏感页面可被 iframe，用户点击仍可带 token 触发按钮。
- Clickjacking 证据必须来自真实第三方 top origin（exploit server、data/file opaque origin 或不同站点测试页），不能用目标页面上的 `setContent` 冒充跨站；否则会漏掉 SameSite / third-party cookie 差异。
- Clickjacking 如果目标表单字段可由 URL 参数预填，风险会从“点击已有按钮”升级为“提交攻击者控制的数据”；要同时记录预填 source、字段名、最终提交结果。
- Frame-buster JS 不是可靠防护；如果缺少 `X-Frame-Options` / `frame-ancestors`，`iframe sandbox="allow-forms"` 可能禁用目标页脚本但保留表单提交能力。
- Clickjacking 可以作为 connector 触发 DOM XSS、表单提交、状态改变或多步 workflow；不要只看单独 clickjacking 价值，要看被点击动作后面的 sink / workflow。
- Multistep clickjacking 要把每一步当成状态机：第一击改变 iframe 内页面/状态，第二击命中更新后的确认按钮或下一步动作。
- DOM：URL/hash/referrer/postMessage/localStorage source 流向 innerHTML、eval、location、script URL。
- DOM navigation/cookie：URL/search/hash/postMessage source 流向 `location.href`、`location.assign`、`window.open`、`document.cookie`、history/router。
- DOM clobbering：HTML id/name/anchor 属性污染全局对象或配置对象，再被后续脚本当作 trusted value 读取。
- Cookie manipulation 要追踪 source page、cookie value、cookie 属性和 consumer page；写入页和触发页可能不是同一个页面。

## 技巧家族 / Payload 家族

- Origin 形态：合法子域、尾随点、大小写、null、同站不同源、受信任子域 takeover。
- CORS 读取形态：`fetch(..., {credentials: "include"})` 读取敏感 JSON，再用测试域日志证明跨源可读。
- Null origin 形态：`<iframe sandbox="allow-scripts ...">` 内发 credentialed XHR/fetch，让浏览器发送 `Origin: null`；如果响应包含 API key/session-adjacent 数据，再回传到测试服务器。
- Insecure trusted origin 形态：服务端信任 `http://trusted-subdomain`，攻击者通过明文子域、可控子域或协议降级页面发起 credentialed read。
- Trusted-origin gadget 形态：stock/status/help 等受信任子域存在反射 XSS 或可控页面时，先跳转到该 origin，再由该 origin 对主站敏感读接口发起 `withCredentials` 请求并把最小证据回传到测试日志。
- 嵌套跳转 payload 形态：当 exploit 页面把 URL-encoded payload 放入 JS navigation 字符串时，用 `JSON.stringify(targetUrl)` 或等价安全构造，避免未编码引号打断外层脚本；HTML 执行点仍需要真实闭合标签。
- CSRF 形态：form POST、GET 状态改变、text/plain、method override、token replay。
- Token method/presence 形态：表单是 `POST + csrf` 不代表 GET 也校验；`csrf` 参数存在时校验不代表缺失时拒绝。分别测试 GET no-token、POST no-token、POST bad-token。
- Token binding 形态：拿攻击者 session 的合法 token 去 victim session 提交，验证 token 是否绑定当前 session/user。
- Token-cookie pair 形态：如果 token 绑定 `csrfKey` 这类非 session cookie，要检查是否存在 cookie injection / response splitting / sibling endpoint 可以给 victim 种同一对 token+cookie。
- Duplicate-cookie token 形态：如果 form `csrf` 只和 cookie `csrf` 比较，而 cookie 可被种植，则任意自选 token 也可能成立；重点证明“form token == cookie token”而不是 token 本身可信。
- Lax method-override 形态：`SameSite=Lax` 仍会在跨站顶层 GET/navigation 中发送 cookie；如果服务端支持 `_method=POST`、`X-HTTP-Method-Override` 或路由层 method override，GET form 可能触发 POST 等价状态改变。
- Strict on-site gadget 形态：`SameSite=Strict` 阻止跨站入口请求带 cookie，但目标站自己的客户端跳转、meta refresh、open redirect、hash/router 或表单自动提交可以把第二跳变成 same-site 发起。
- Sibling-domain 形态：SameSite 判断的是 site 不是 origin；`cms.`、`static.`、`chat.`、`help.` 等同站不同源上的 XSS、可控 JS、CSWSH 或表单 gadget，可能带主站 Strict/Lax cookie 访问敏感接口。
- Cookie-refresh 形态：OAuth/social-login/SSO 重新签发 session 后，Chrome 对未显式 SameSite 的新 Lax cookie 有短时间跨站 POST 窗口；若需要 popup，确认是否必须由用户点击触发。
- Referer missing 形态：如果服务端只在 Referer 存在时校验，`Referrer-Policy: no-referrer` 或 `<meta name="referrer" content="no-referrer">` 可能让跨站状态改变 fail-open。
- Referer substring 形态：如果服务端只检查 Referer 字符串中是否包含目标域名，可用 full-url Referer 把目标域名放进 exploit URL 的 path/query；需要 `Referrer-Policy: unsafe-url` 或等价策略让浏览器发送完整 URL。
- Auto-submit 形态：隐藏字段 + `document.forms[0].submit()` 只作为训练/测试资源的状态改变证明，不对真实敏感动作默认执行。
- Clickjacking 形态：先确认无 `X-Frame-Options` / `frame-ancestors`，再在真实第三方页面中 iframe 目标，验证登录态 cookie 会发送，最后用透明 iframe 与诱饵元素对齐敏感按钮坐标。
- Prefilled-form clickjacking 形态：`/my-account?email=attacker@example.com` 这类 URL 参数先填入表单，再用透明 iframe 诱导点击 submit；验证时要证明 iframe 中字段值确实被预填。
- Frame-buster bypass 形态：目标页存在 `if (top != self)` 这类脚本时，测试 sandbox iframe 是否能让页面可见且表单可提交；常见最小能力是 `sandbox="allow-forms"`，不要随手加 `allow-scripts`。
- DOM-XSS connector 形态：URL 参数预填 `<img ... onerror=print()>` 这类 DOM sink 输入，clickjacking 只负责触发 submit / click，让页面后续 `innerHTML`、navigation 或 handler 执行。
- Iframe offset 形态：目标按钮不在首屏时，不必要求用户滚动；可以通过 iframe `top` 负偏移把目标按钮坐标映射到可见诱饵位置，但必须重新计算有效坐标。
- Multistep 形态：在同一个 iframe 上准备多个诱饵按钮，例如 first click 命中 `Delete account`，页面切到确认态后 second click 命中 `Yes`；每一步都要记录目标坐标、等待时间和状态变化。
- DOM 形态：hash/search/window.name/postMessage 到 sink 的最短路径。
- Context break 形态：属性上下文、文本上下文、脚本字符串上下文分别需要不同闭合方式；先识别上下文再选 payload。
- Open redirect 形态：`url=https://attacker.example` 这类原始 URL 是否被 DOM 代码取出并赋给 navigation sink；编码后不一定命中脚本正则。
- Cookie manipulation 形态：source 是否写入 `document.cookie` 并影响后续页面、跳转、偏好、session-adjacent 状态或业务分支。
- Cookie-to-XSS 形态：商品/详情页把 `window.location` 写入 `lastViewedProduct` 之类 cookie，首页/导航再把该 cookie 作为 link/html 输出；需要两步验证：先污染 cookie，再跳到 consumer page。
- Cookie parser 差异形态：命名参数、无名 query 尾巴、hash、单双引号、URL 编码在 `window.location -> document.cookie -> HTML/DOM sink` 链上可能表现不同；例如 `&'><script>print()</script>` 是候选形态，不是固定字典。
- DOM clobbering 形态：`<a id=defaultAvatar name=avatar href=...>` 这类元素是否覆盖脚本读取的全局属性；示例是候选，不是固定字典。
- DOM clobbering property-chain 形态：重复 `id` 可能让 `window.someName` 变成 HTMLCollection，`name=child` 再暴露 `window.someName.child`；如果脚本读取 `.href`、`.src`、`.url`、`.avatar` 等属性，要看属性归一化后是否进入未转义 sink。
- DOM clobbering sanitizer-bypass 形态：清洗器如果遍历 `node.attributes`、`node.children`、`node.id`、`node.name` 等 DOM 属性，允许的子元素也可能 clobber 这些属性；例如允许 `<form id>` 和 `<input name>` 时，`<input name=attributes>` 可能让清洗器漏删 `tabindex/onfocus`。
- DOM clobbering 顺序形态：如果脚本先读取配置再 append 当前评论 body，当前 payload 可能只能影响后续评论、后续记录或二次加载；需要用 tail item / clean page 验证。
- DOM clobbering auto-trigger 形态：如果可保留 `id`、`tabindex` 和 focus handler，可用 exploit iframe 先加载含 payload 页面，等异步评论/记录插入后再导航到 `#id` 触发 focus；示例是执行模型，不是固定 payload。

## 补充 Checklist

- 是否用浏览器确认 Cookie/凭据真实发送？
- 是否区分跨源“可发请求”和“可读响应”？
- 是否验证了 ACAO 与 ACAC 同时满足，且响应体确实可被攻击者脚本读取？
- `Origin: null` 是否来自真实浏览器 opaque origin，而不是手工 curl header？
- trusted origin 是否有可投递的 JS/control gadget，而不只是手工伪造 `Origin` header？
- 是否确认 frame 内动作需要用户点击还是可自动触发？
- CSRF token 是否完成矩阵验证：method swap、缺失 token、错误 token、跨 session token、token-cookie 绑定和 cookie 种植？
- SameSite 是否完成绕过矩阵验证：Lax 顶层 GET、method override、站内 redirect/router gadget、sibling-domain gadget、OAuth/SSO cookie refresh 和新 cookie 时间窗口？
- 是否区分 same-site 与 same-origin，并检查 sibling 子域上的 reflected/stored/DOM XSS、CSWSH、open redirect 或可控静态页面？
- Referer 防御是否完成矩阵验证：缺失 Referer、origin-only、full-url、path/query 注入目标域名、子域/后缀混淆和浏览器 referrer policy？
- Clickjacking 是否在第三方 top origin 下验证了 iframe 内仍是登录态，而不是在同源调试页面里点击？
- Clickjacking 表单动作是否存在 URL 参数预填、hash/localStorage 预填或 DOM 自动填充，能让攻击者控制提交值？
- Clickjacking 是否只依赖 frame-buster JS；如果是，是否验证过 sandbox iframe 禁脚本但保留必要用户动作？
- Clickjacking 触发的动作后面是否连接 DOM XSS、URL sink、表单回显、状态机或多步 workflow？
- 是否测量了敏感按钮坐标，并确认诱饵元素与 iframe 中按钮对齐？
- 目标按钮不在首屏时，是否记录了 iframe offset 后的可见坐标和实际点击结果？
- 多步 workflow 是否记录了 step1/step2 的页面状态、坐标和点击顺序，而不是只验证第一个按钮？
- 是否记录 source、sink、触发页面和浏览器证据？
- DOM redirect 是否证明了实际跨站 navigation，而不是只看到参数出现在 URL？
- Cookie manipulation 是否证明后续页面读取了被写入的 cookie？
- Cookie manipulation 是否区分了写入页面和消费页面，并复现了完整二跳链？
- DOM clobbering 是否证明污染的元素/属性被脚本读取并改变行为？
- DOM clobbering 是否确认了 duplicate id/name 的解析结果、HTMLCollection 属性、以及 payload 在列表/评论迭代中的生效顺序？
- DOM clobbering 是否检查了 sanitizer / HTML filter 本身读取的 DOM 属性是否可被 clobber，而不只检查业务脚本 sink？

## 最小验证

- 用 Playwright 建立真实页面 baseline。
- 单变量修改 Origin/Referer/frame/source，比较 header、console、Network 和页面状态。
- CSRF token 链按 `valid baseline -> missing/bad token -> method swap -> cross-session token -> token-cookie pair / duplicate-cookie` 验证。
- SameSite 链按 `cookie attribute baseline -> cross-site simple/top-level request -> method override -> on-site gadget -> sibling-domain gadget -> cookie refresh window` 验证。
- Referer 链按 `正常跨站 Referer -> no-referrer -> origin-only/full-url -> path/query domain injection -> 状态改变证据` 验证。
- CORS trusted-origin 链按 `Origin header baseline -> trusted origin JS/control -> credentialed read -> 测试日志证据` 验证。
- Clickjacking 链按 `frame policy baseline -> third-party iframe login-state -> button coordinate alignment -> controlled click outcome` 验证。
- Prefilled-form 链按 `prefill source -> iframe field value -> coordinate click -> submitted state` 验证。
- DOM-XSS connector 链按 `prefill source -> DOM sink after click -> iframe offset/coordinate -> browser execution` 验证。
- Multistep 链按 `step1 coordinate -> iframe state transition -> step2 coordinate -> final outcome` 验证。
- 状态改变只在训练/测试资源或明确授权动作上验证。

## 常见误判 / 死路

- `Access-Control-Allow-Origin: *` 无 credentials 通常不是高危。
- 手工 curl 改 `Origin` 只能证明服务端信任关系；如果没有可信 origin 上的 JS/control gadget，不能直接升级为可利用跨源读。
- 只看到隐藏 `csrf` 字段不能判定 CSRF 已防护；如果 token 只在某个 method、存在时、或与非 session cookie 比较，仍可能被跨站 form 利用。
- Cookie injection / response splitting 是 CSRF token 绕过的 connector；必须证明 victim 侧 cookie 被种植并和 form token 一起提交。
- `SameSite=Strict` 不等于 CSRF/CSWSH 结束；同站不同源 sibling gadget 仍可能带 cookie，站内跳转 gadget 也可能把第二跳变成 same-site。
- `SameSite=Lax` 不等于跨站 POST 永远失败；顶层 GET、method override 和新签发 cookie 的浏览器窗口都要单独验证。
- Referer 防御如果缺失时放行、或只做 substring/startsWith 这类弱匹配，仍可被浏览器 referrer policy、URL path/query 或子域混淆绕过。
- XFO 缺失但无敏感可点击动作通常低价值。
- `page.setContent()` 在目标 URL 上构造 overlay 只能验证坐标，不能证明跨站 clickjacking；需要切到 exploit origin 后再确认 iframe 登录态和点击结果。
- DOM 反射不等于可执行 sink。
- DOM open redirect 单独通常是中低价值；优先寻找 OAuth、SSO、account-linking、token leakage、phishing 或 CSP bypass connector。
- Cookie manipulation 如果只能改无害偏好通常低价值；需要证明会影响安全状态或链到其他漏洞。
- DOM clobbering payload 没触发时，不要只换标签；先检查污染元素是否出现在 sink 读取之前，以及旧 clobber 是否抢占了同名属性解析。

## 关联 Skills

- `web2-vuln-classes`
- `triage-validation`

## 晋升到 Skill / Queue 的条件

- 有真实浏览器证据、跨边界影响和最小 replay 时写入 action queue，类型 `browser-client-boundaries`。

## 源报告（on-demand）

- source_report_ids: `129873`, `398054`, `499030`, `603764`, `389108`, `423218`, `662083`, `868615`
- 用途：这些 ID 只作为本地案例库查询指针。只有当前证据已命中本卡触发信号，且需要真实攻击链形状、报告写作先例或相似案例时，才按需查询 gitignored 的 `distill/` 本地缓存；不要默认拉取全文，不把报告正文、目标域名、payload 或 PII 写入知识卡。
