---
id: proxy-cache-boundaries
type: technique-card
related_skills:
  - web2-vuln-classes
  - triage-validation
trigger_tags:
  - host-header
  - request-smuggling
  - cache-poisoning
  - cache-deception
risk: high
maturity: draft
load_priority: medium
deep_refs:
  - /root/tool/ccst/ctf-skills/ctf-web/server-side-advanced.md
---

# Proxy / Host Header / Request Smuggling / Cache

## Quick Recall

- 这类问题先建模链路：客户端 -> CDN/cache -> 前端代理 -> 后端应用；不要直接上大 payload。
- Host header 和 XFH 重点看绝对链接、重置密码、OAuth callback、tenant routing、cache key 和后端路由。
- Host 也可能直接参与本地/管理面授权判断；`Host: localhost` 一类变体只作为单变量验证，不做通用喷洒。
- Cache poisoning/deception 要证明“未入 key 的输入影响可缓存响应”或“私有响应被静态扩展路径缓存”。
- Poisoning 必须命中 victim 实际访问的 cache key；带随机 query 的验证只证明影响，不等于可投递给 victim。
- Victim cache key 不只看 URL 和 `Vary`；真实浏览器导航、raw API request、资源加载、Accept/Accept-Encoding、User-Agent 和 Host 分桶可能不同，最终投递要用 victim 实际请求形态验证。
- 复杂链路可能需要同时维持多个缓存条目，例如“状态切换/重定向条目 + 资源导入条目”；验证时要证明每个条目都在 victim 路径上被命中。
- 多层 cache 要区分外层 key 和内层 fragment key；外层 query-keyed 不代表内层也 keyed，随机 query 可能只是绕过外层 cache 的探针。
- Cache deception 要验证动态私有路由在静态后缀路径下是否被缓存，例如 `/my-account/anything.js` 返回账号页并出现 `x-cache: hit`。
- Web cache deception 不等于 poisoning：目标是诱导 victim 把自己的私有动态响应存进共享 cache，再由攻击者无凭据读取同一 cache key。
- Smuggling-to-cache poisoning 要把“队列污染”转成“cache key 下的错误响应”：内层请求触发 host-controlled redirect，下一条未被正常响应预热的 cacheable JS 请求收到 302 并被缓存。
- Smuggling-to-cache deception 可以让 victim 的认证私有页响应错配到静态资源 key；核心是 incomplete-header absorber 继承 victim Cookie，而不是普通路径后缀诱导。
- Request smuggling 要有稳定 timing/desync/queue 证据；只在训练或明确授权环境做低频探测。
- CL.TE/TE.CL 命中时常见证据是 timeout 后的队列污染，例如后续请求变成 `GPOST` / malformed method。
- 前端响应 `Connection: close` 不等于 smuggling 失败；如果后端连接池被污染，下一条新客户端连接仍可能触发 `GPOST` / `GGET` 等 malformed method。
- Smuggling 的影响不止确认 desync：如果存在 reflected XSS、请求捕获、内部管理动作或浏览器专属 sink，要继续评估能否把 smuggled request 投递给 victim 请求形态。
- H2.TE / H2 downgrade 测试要确认客户端真的发出了 forbidden header；许多高级 H2 client 会静默剔除 `transfer-encoding`，导致假阴性。
- H2.CL 依赖 HTTP/2 `content-length: 0` 与实际 DATA 不一致；很多普通客户端会修正或拒绝不一致长度，需要能保留 mismatch 的低层发送方式。
- H2 request splitting 与 H2 CRLF-to-TE 不同：前者用 CRLF 直接在 downgraded HTTP/1.1 里拆出第二条请求，后者是注入 TE 后让 body 被 chunked 解析。

## 能力定位

本卡给 `web2-vuln-classes` 补充代理、缓存和传输边界的思路，不替代专门工具和红线检查。

## 触发信号

- Header：Host、X-Forwarded-Host、Forwarded、X-Original-URL、X-Rewrite-URL、X-Forwarded-Proto。
- Cache：Age、X-Cache、CF-Cache-Status、Vary、Surrogate、CDN、静态扩展、utm 参数。
- Smuggling：CL/TE、HTTP/2 downgrade、连接复用、异常 timing、队列污染、不同前后端错误。

## 思路分支

- Host/proxy trust：链接生成、路由、租户、密码重置、SSO callback。
- Admin/local bypass：普通 Host 为 401/403，localhost/internal Host 进入管理面，说明授权依赖 Host 而非身份。
- Cache poisoning：unkeyed header/query/cookie 影响响应。
- Resource-import poisoning：unkeyed host/proxy header 改写 HTML/JS 里的资源 URL，或把 JS/CSS 资源请求缓存成跳转到攻击者控制资源。
- Targeted poisoning：缓存按 `Vary: User-Agent`、语言、设备、实验桶、地区或其他隐式维度分桶时，先确认 victim 所在分桶再投递。
- Cache key implementation flaws：query、单个参数、重复参数、分隔符、GET body、URL normalization 和资源类型都可能让 cache 与后端看到不同输入。
- Coordinated poisoning：一个缓存条目改变 victim 状态或导航，另一个缓存条目承载最终资源/DOM sink；例如缓存化语言切换 302 后再命中本地化页面或资源导入。
- Cache key injection：cache key 拼接符、`Vary` 分量、header 分量或 excluded 参数处理不严时，URL 中的分隔符/片段可把攻击者响应撞到 victim key。
- Internal cache poisoning：外层 cache 与内层 fragment cache 的 key 规则不同；外层 query buster 能绕开共享页面 cache，同时观察内层片段是否仍 hit。
- Cache deception：动态私有页面在静态路径/扩展下被缓存。
- Smuggling-to-cache poisoning：先找可控 Host/redirect/Location 连接器，再把该响应错配到 cacheable resource key；最终证明 `X-Cache: miss` 的 302 变成后续 `hit`。
- Smuggling-to-cache deception：内层请求指向 `/my-account`、profile、API key 页等私有路由，并故意停在未结束的 header，让 victim 的下一条静态资源请求把 Cookie 拼进内层请求；响应被 cache 存到资源 key 下。
- Path mapping deception：后端把 `/private/anything.js` 映射回 `/private`，cache 按 `.js` 静态规则存储响应。
- Delimiter deception：origin 把 `;`、encoded delimiter 或其他字符当路径截断点，cache 却继续把后缀当静态资源或缓存规则的一部分。
- Normalization deception：origin 与 cache 对 `%2f`、`%2e%2e`、encoded `#/?`、dot-segment 的解码/归一化顺序不同，导致一个看到私有路由，另一个看到静态目录/文件。
- Exact-match deception：cache 不按扩展或目录缓存，而只按精确文件名规则（如 robots/sitemap/favicon 一类）缓存；需要把私有路由和精确文件名规则拼到同一请求里。
- Smuggling：CL.TE、TE.CL、TE.TE/TE header 混淆、H2 downgrade、前后端解析差异。
- Smuggling front-end bypass：前端按路径/Host/方法拦截，但 smuggled request 由后端直接处理；需要继续验证后端自己的 Host、认证和 body 长度要求。
- Smuggling victim delivery：把已确认的队列污染转成 victim-facing 请求，例如让后端下一条 victim 请求命中反射页、请求捕获端点、可缓存响应或内部动作；最终看 victim 侧执行/泄露/状态结果，而不是攻击者单次响应。
- H2 response queue poisoning：HTTP/2 前端 downgrade 时保留 `transfer-encoding: chunked`，后端按 chunked 提前结束；内层完整请求的响应会留在队列里，可用 `/x` 404 sentinel 识别是否抓到其他用户响应。
- H2.CL resource delivery：前端按 H2 DATA 接收，后端按 downgraded `Content-Length: 0` 提前结束，DATA 里的 smuggled prefix 可改写下一条资源请求；要卡在 victim 浏览器导入 JS 前。
- H2 CRLF header injection：前端 downgrade 时没有清洗 header value 中的 CRLF，可把 `foo: bar\r\nTransfer-Encoding: chunked` 注入成后端可见的 TE header。
- H2 request splitting：前端 downgrade 时把 CRLF header value 原样拼进 HTTP/1.1 headers，可用 `\r\n\r\nGET /x HTTP/1.1\r\nHost: ...` 直接拆出第二条请求并污染响应队列。

## 技巧家族 / Payload 家族

- 单 header 变体：Host、XFH、Forwarded、scheme/port、path rewrite。
- Cache key 变体：ignored query、unkeyed header、extension suffix、Vary 差异。
- 投递形态：先在带 cache buster 的 URL 上确认 unkeyed input，再回到 victim 会访问的精确路径污染并观察 miss/hit。
- Unkeyed header resource 形态：`X-Forwarded-Host`、`X-Host` 或类似未知 header 进入 `<script src=//host/...>`；要设置同路径 exploit 资源，并证明无 header 请求命中 cached poisoned resource import。
- Unkeyed cookie 形态：服务端把 cookie 值写入可执行上下文，但 cookie 不在 cache key；例如 cookie 进入 JS object/string 时，用最小断句 payload 证明执行。
- Multiple-header redirect 形态：一个 header 触发行为分支（如 `X-Forwarded-Scheme: nothttps` 触发 302），另一个 header 控制 sink（如 `X-Forwarded-Host` 控制 `Location`）；常见目标是把 `/resources/js/tracking.js` 这类资源缓存成 302 到 exploit server 同路径。
- Targeted UA 形态：如果响应 `Vary: User-Agent`，先用评论、日志、图片 beacon 或安全可控资源拿到 victim UA，再用同 UA 和同请求形态污染对应分桶；不要用自己的 UA 证明可投递。
- Request-shape 形态：`page.request`/curl 命中的 cache key 可能不同于浏览器导航；对最终投递路径要用 Playwright 浏览器导航或完整复刻 `Accept`/fetch metadata 头验证。
- Unkeyed query 形态：整条 query 不进 cache key 时，不能再用 query 当 cache buster；改用 keyed header（如 `Origin`）建立 oracle，再回到无 buster 的 victim path 投递。
- Unkeyed parameter 形态：普通参数进 key，但 `utm_*` 等 analytics 参数被排除；用 keyed 参数做 oracle，确认去掉 excluded 参数后仍命中含 payload 的响应。
- Parameter cloaking 形态：cache 和后端对分隔符/重复参数解析不同；例如 cache 把 `utm_content=foo;callback=alert(1)` 当成一个 excluded 参数，后端却把 `callback` 覆盖到 JSONP sink。
- Fat GET 形态：GET body 被后端解析但不进 cache key；可用 request line 中的正常参数建立 key，再用 body 中的重复参数覆盖后端行为。
- URL normalization 形态：raw 请求可把未编码 payload 写入 404/错误页缓存，浏览器访问编码后的 URL 因 cache normalization 命中未编码响应；需要 raw request poison + browser encoded navigation 双证据。
- Multi-entry 形态：先识别 victim 的状态/语言/地区/认证分桶，再分别污染“状态连接器”和“最终 sink 条目”；如果直接状态修改响应带 `Set-Cookie` 不可缓存，回看是否存在可缓存 redirect、rewrite 或 normalized path 作为连接器。
- Cache-key injection 形态：用 `Pragma: x-get-cache-key` 或等价 oracle 观察 key 结构；重点看 `Vary: Origin`、分隔符、大小写敏感 header、被排除参数和 fragment/hash 截断如何影响 key，不把 `$$`、`utm_content`、`origin` 当成固定字典。
- Header injection to body 形态：如果某资源在特定参数下把 `Origin` 等 header 写入响应头，检查后端是否会解码 `%0d%0a` 并造成 response splitting；HTTP/2 场景注意 header name 小写和客户端是否真的发出该形态。
- Internal fragment 形态：用随机 query 绕过外层 cache，同时带 XFH/Host 观察 canonical、analytics、geolocate 等片段是否局部更新；去掉 header 后若片段仍指向攻击者 host，说明内层 fragment 被污染。
- WCD path-mapping 形态：`/account/random.js` 返回账号页且 `X-Cache: miss -> hit`，说明 origin 映射回动态路由而 cache 按静态扩展缓存；真实利用要换唯一随机路径避免命中自己的缓存。
- WCD delimiter 形态：先用 `/accountX` 和 `/account<delim>X` 找 origin delimiter，再加静态后缀验证 cache 是否仍按完整路径缓存；`;`、encoded `#`、encoded `?` 只是候选，不是固定清单。
- WCD normalization 形态：`/resources/..%2faccount` 与 `/account%23%2f%2e%2e%2fresources` 代表两类方向：origin 归一化 vs cache 归一化；必须分别证明谁把路径看成私有路由、谁把路径看成静态规则。
- WCD exact-match 形态：如果目录/扩展规则无效，回看精确文件名缓存规则；把私有路由通过 delimiter/normalization 拼到 `robots.txt`/同类文件名规则上，再验证私有响应被缓存。
- WCD-to-CSRF 形态：如果泄露的是 victim 私有页中的 CSRF token，不止报告 token 泄露；可以在授权训练环境链到一次自动提交表单，证明实际状态改变。
- Smuggling 变体：只记录低频 timing/desync，不做高压连接扰动。
- CL.TE 形态：前端按 `Content-Length` 转发，后端按 `Transfer-Encoding` 提前结束；chunked 结束符后残留 1 个字节/方法前缀，下一条 POST 可能变成 `GPOST`。
- TE.CL 形态：前端按 chunked 解包，后端按较短 `Content-Length` 截断；chunk 数据里完整伪造的请求行会残留到后端队列，后续请求触发 malformed method。
- TE.TE / TE obfuscation 形态：重复、大小写、空白或无效值的 `Transfer-Encoding` 可能让前后端选择不同解析分支；示例只是形态，不能当固定字典喷洒。
- Backend-pool probe 形态：客户端连接被前端关闭时，改用“攻击请求一条连接 + probe 请求另一条连接”观察后端连接池污染；probe 的方法会影响证据，GET 可能显示 `GGET`，POST 才对应 `GPOST`。
- Differential response 形态：把残留请求行导向 harmless 不存在路径（如 `/404` 类），随后用干净 GET `/` probe；如果 probe 稳定收到 404/Not Found，说明响应队列被前一条 smuggled request 改写。
- Front-end control bypass 形态：先确认直接访问被前端挡住，再把目标路径放进 smuggled request；如果后端要求 `Host: localhost` 或内部 Host，要把它放入 smuggled request，而不是外层请求。
- Header-conflict absorber 形态：当前端/下一条请求的 headers 会和 smuggled request 冲突时，用 `Content-Type` + `Content-Length` + body 前缀（如 `x=`）吸收后续请求开头，避免污染 smuggled request 的 header 区。
- Chunk-size accounting 形态：TE.CL payload 的 chunk size 只计算 chunk data，不包含 chunk terminator 的 CRLF；手动长度错误常表现为前端 400，而不是漏洞不存在。
- Smuggled reflected-XSS delivery 形态：内层请求指向可反射页面，把 payload 放在目标实际会输出的 header、参数或路径段中；示例是 `User-Agent` attribute break、搜索参数或错误页参数，不是固定字典。需要保留 absorber/body 长度，让后续 victim 请求不会破坏内层请求结构。
- Smuggled redirect cache-poisoning 形态：内层请求触发按 `Host` 生成 `Location` 的跳转，攻击者 Host 指向可返回 JavaScript 的 exploit server；内层请求仍需要 `Content-Type`、`Content-Length` 和短 body absorber，例如 `x=1`，让下一条 JS 请求映射到 302 响应并写入 cache。
- Smuggled private-page cache-deception 形态：内层只发送 `GET /my-account HTTP/1.1` 和一个未完成 header（如 `X-Ignore: X`），不要加空行结束 headers；等待 victim 请求静态资源后，从 JS/CSS/image cache key 中搜索私有页标记和 API key。
- Raw H2.TE 形态：用能保留 forbidden header 的工具发送 HTTP/2 `transfer-encoding: chunked`，DATA 为 `0\r\n\r\nGET /x HTTP/1.1\r\nHost: ...\r\n\r\n`；如果库会过滤该 header，要改用 Burp、raw `hyperframe/hpack` 或等价低层客户端。
- Response-queue hunting 形态：外层和内层都指向不存在的 `/x`，自己的响应稳定是 404；等待目标用户动作后再次取队列，出现非 404，尤其是带 `Set-Cookie` 的 302，就可能是可接管会话。
- Raw H2.CL 形态：HTTP/2 headers 带 `content-length: 0`，DATA 直接放 `GET /resources HTTP/1.1\r\nHost: exploit\r\nContent-Length: 5\r\n\r\nx=1`；`Content-Length: 5` 是 absorber，避免后续资源请求破坏内层请求。
- H2.CL JS delivery 形态：先确认 `/resources` 这类路径会 302 到 `/resources/` 且 Host 可控，再让 exploit server 在 `/resources` 和 `/resources/` 返回 JavaScript；日志出现 Victim `GET /resources/` 只是命中信号，最终要看浏览器执行。
- H2 CRLF-to-TE 形态：HTTP/2 header value 内嵌 `\r\nTransfer-Encoding: chunked`，body 使用 `0\r\n\r\n` 结束 chunked，再放入 smuggled request；需要低层客户端允许 CRLF header value。
- H2 request-splitting 形态：HTTP/2 header value 内嵌 `\r\n\r\nGET /x HTTP/1.1\r\nHost: target`，外层 path 也用 `/x` 作为 404 sentinel；不需要 body，也不依赖 `Transfer-Encoding`。
- Search-history / comment capture 形态：内层 POST 写入自有 session 可读的历史、评论、日志或同类存储面；若表单需要会话/CSRF，内层请求要带攻击者自己的 Cookie、CSRF、Content-Type 和足够覆盖 victim 请求头的 `Content-Length`；提取时先 HTML unescape 再 URL decode，最后优先复用完整 Cookie line。

## 补充 Checklist

- 是否记录 baseline cache header、Age 变化和 replay 次序？
- 是否确认影响的是共享 cache，而不是浏览器本地缓存？
- 是否确认最终命中的路径、query、method、Host、User-Agent、Accept 和资源类型与 victim 实际请求一致？
- Host 影响是否能链到 password reset、SSO、cache 或 internal routing？
- Host 影响是否改变了认证/授权结果，而不只是页面里的绝对 URL？
- `Vary` 或隐式分桶是否已对齐目标用户，而不是只在攻击者自己的分桶里中毒？
- unknown header 是否经过目标自身响应差异验证，避免把通用 header 字典当成结论？
- query/param 类是否区分了“用于 cache buster 的 keyed 输入”和“被排除但影响响应的 unkeyed 输入”？
- 是否测试了分号、重复参数、GET body 和 URL 编码/解码导致的 cache/back-end parser discrepancy？
- 是否考虑多条缓存记录需要同时有效，而不是只污染了其中一个中间页面或资源？
- 是否检查 `Set-Cookie`、private/no-store、redirect 和状态切换响应的 cacheability，必要时寻找可缓存连接器？
- 是否用 cache key oracle 观察 header/key 分量拼接，而不是只凭 URL 猜测 key collision？
- 多层 cache 场景是否分别验证了外层页面 cache 和内层 fragment cache 的 key 规则？
- WCD 是否用自有账号先证明动态私有响应可被静态规则缓存，再换未使用过的 victim 路径投递？
- 是否区分 path mapping、delimiter、origin normalization、cache normalization、exact-match file rule，而不是只试 `.js` 后缀？
- 如果 WCD 泄露 CSRF token，是否评估能否链到实际业务动作；真实目标上仍要遵守非破坏性和最小影响原则。
- Smuggling 是否有稳定对照，而不是网络抖动？
- 是否同时有 timing 信号和应用层异常（如 malformed method），而不是只凭一次超时？
- 如果前端关闭连接，是否尝试过新客户端连接上的低频 GET/POST probe 来验证后端连接池污染？
- CL.TE/TE.CL/TE.TE 是否分别记录了前端视角、后端视角、残留字节、probe 方法和响应队列证据？
- 是否用 differential response（例如后续 `/` 变 404）确认过队列污染，而不是只记录一次 malformed method？
- 绕过前端控制时，是否分别确认了前端阻断点、后端内部 Host/认证要求、headers conflict、body absorber 和最终影响？
- 已确认 smuggling 后，是否评估过 victim-facing 影响：reflected XSS 投递、请求捕获、cache/redirect 连接器或内部动作，而不是停在 desync 证据？
- Smuggling cache poisoning 是否确认了 cacheable key 上的 `miss -> 302 Location -> hit`，以及 exploit server 在跳转后的 path/query 上返回正确 JS？
- Smuggling cache deception 是否确认私有页响应真的落在静态资源 key 下，并从所有 JS/CSS/image 资源中搜索账号页、API key 或身份标记？
- H2.TE 是否验证了客户端发送帧里确实包含 `transfer-encoding`，而不是被 HTTP/2 库或 curl 行为过滤？
- Response queue poisoning 是否使用 404 sentinel、目标用户节奏、`Set-Cookie`/`Location` 线索和后端连接 reset 规则来区分自己的响应与捕获响应？
- H2.CL 是否验证了 `content-length: 0` 与 DATA mismatch 被保留，并先用 `SMUGGLED`/404 或 host-controlled redirect 确认队列影响？
- 资源投递类是否确认 exploit server path/query 与 redirect 后路径一致，并且 victim 请求发生在 JS import 时序上？
- H2 CRLF 注入是否确认 downgraded 后端能看到新 header，而不是只在 H2 层发送了包含换行的普通字符串？
- H2 request splitting 是否区分了“注入新 header”和“拆出新请求”：需要两个 CRLF 边界，并用 `/x` 404 sentinel 证明第二条请求进入后端队列。
- 捕获请求类是否处理了内层存储请求的攻击者会话/CSRF、HTML/URL 编码、截断的 Cookie、完整 Cookie line 复用，以及只带单个 cookie 不足以复现的情况？
- 手写 CL/chunk 长度时，是否按原始字节复算；TE.CL 是否排除了 chunk terminator 的 CRLF？

## 最小验证

- 一次只改一个 header/path/cache-key 变量。
- Cache 类至少两次 replay 证明 miss/hit 和污染可见性。
- Poisoning 链按 `cache-buster oracle -> harmful response -> no-header hit -> victim request shape hit -> victim path delivery` 验证。
- Targeted 链按 `分桶信号 -> victim bucket discovery -> 同请求形态 poison -> victim bucket no-header hit -> 执行/影响证据` 验证。
- Implementation-flaw 链按 `cache key oracle -> parser discrepancy -> harmful sink -> clean-key hit -> browser/victim execution` 验证。
- Multi-entry 链按 `每个缓存条目 oracle -> 协同顺序 replay -> clean hit 分别确认 -> victim navigation/resource chain -> browser execution` 验证。
- Internal-cache 链按 `outer cache-buster -> inner fragment signal -> remove header clean fragment hit -> victim path poison -> browser resource request` 验证。
- Deception 类用 victim 会访问的伪静态路径触发缓存，再用无凭据请求读取同一路径证明私有响应被共享缓存。
- WCD 链按 `自有账号动态页 baseline -> cache rule probe -> unique victim URL -> victim delivery -> no-cookie/raw read cached private response -> impact action/secret` 验证。
- WCD normalization 链按 `origin view 与 cache view 分别建模 -> encoded delimiter/dot-segment probe -> miss/hit -> victim delivery -> no-cookie read` 验证。
- Smuggling 类按 `baseline -> 单变量 CL/TE 差异 -> 攻击连接 -> 新连接 probe -> malformed method 或 differential 404/queue 证据 -> 前端控制绕过/影响验证 -> 停止条件` 验证，只做低频安全探测。
- Smuggling-to-XSS 链按 `desync 证据 -> 反射 sink baseline -> 内层请求构造 -> absorber/长度复算 -> 低频重复投递 -> victim 浏览器执行证据` 验证；训练环境可用 lab solved/alert 作为结果信号。
- Smuggling-to-cache 链按 `desync 证据 -> host-controlled redirect connector -> exploit server JS -> 未预热 cacheable JS key miss -> inner absorber/长度复算 -> cached 302 hit -> victim 浏览器执行` 验证；若最终 key 已是正常 `X-Cache: hit/Age`，换未使用资源路径或等待 TTL。
- Smuggling-to-WCD 链按 `私有页无 anti-cache baseline -> incomplete-header inner request -> victim static resource request -> resource key hit 私有页 -> no-cookie read secret -> 提交/最小影响证明` 验证。
- H2 response-queue 链按 `raw H2 forbidden header 保真 -> 404 sentinel -> 队列错位 -> 捕获目标 302 session -> 带 Cookie 访问管理面 -> 最小影响动作` 验证。
- H2.CL resource-delivery 链按 `raw H2 CL/DATA mismatch -> SMUGGLED/404 证据 -> Host-controlled /resources redirect -> exploit server JS -> victim resource log -> browser execution/lab solved` 验证。
- H1/H2 capture 链按 `desync/CRLF 保真 -> smuggled POST 写入自有可读存储面（带攻击者会话/CSRF）-> victim request capture -> decode 完整 Cookie line -> 复用 Cookie 访问账号或最小影响页面` 验证。
- H2 request-splitting queue 链按 `CRLF request split 保真 -> /x 404 sentinel -> 捕获 admin 302 session -> 带 Cookie 访问 /admin -> 最小影响动作` 验证。

## 常见误判 / 死路

- Host 反射在错误页或非安全链接里通常只是 Lead。
- Cache HIT 但不含攻击者输入不构成 poisoning。
- 带 cache buster 的 poisoned hit 只证明 oracle，不证明 victim 可投递；必须回到 victim 实际路径。
- raw request poisoned hit 不等于浏览器 poisoned hit；如果真实导航的 `Accept` 或其他请求形态不同，可能是另一个 cache key。
- JSONP/geolocate 这类资源开头有 helper 函数时，不要只看响应前几行；要确认最终 callback sink 或浏览器执行结果。
- URL normalization 类如果只用浏览器直接请求，payload 会被编码而不执行；如果只用 raw 请求，不证明 victim 可触发。
- Cache key injection 中看到可控 key 字符串不等于可利用；必须找到可缓存的 harmful response 和 victim key collision。
- 内层 fragment 被污染但外层 victim 页面没有命中时，只是中间状态；必须回到无 buster victim path 验证真实资源请求。
- 只污染状态连接器或只污染资源导入都不够；组合链需要同时有效。
- 自己先访问过的 WCD URL 可能已经缓存了自己的私有响应；投递 victim 必须换新的 cache buster/path。
- 浏览器可能把部分 delimiter（如 raw `#`）当 fragment 不发给服务器；利用时要确认 victim 浏览器实际发送的编码形态。
- 单次超时不等于 request smuggling。
- 客户端连接被关闭不代表后端队列没有被污染；反过来，单次 `GGET`/`GPOST` 也要用对照确认不是普通方法过滤。
- 只在同一客户端 socket 连续发送可能漏报；很多前端会关闭客户端连接，但复用后端连接池。
- Smuggled request 里加了内部 Host 仍失败时，常见原因是下一条请求的 Host/header 被拼进同一 header 区；需要用 body absorber 隔离。
- TE.CL payload 返回 400 时先复算 chunk size 与 CRLF 边界，不要立刻判定无漏洞。
- 攻击者自己的响应包含 XSS payload 不等于投递成功；request smuggling 的 victim delivery 可能是异步和间歇的，需要有界低频重试和 victim 侧证据。
- Smuggling cache poisoning 如果省略内层 `Content-Length`/body absorber，后续资源请求可能无法正确映射成可缓存的 302；提前用浏览器或 baseline 请求刷新最终 JS key，可能把正常响应预热成 `hit` 并掩盖 302 错配证据。
- Smuggling cache deception 如果把内层 headers 完整结束，通常只能得到无 Cookie 的 `/my-account` 跳转；如果在队列未被 victim 消费前自己抓静态资源，可能把匿名登录跳转或自己的内容写进 cache。
- H2.TE 如果一直只有正常 200，先本地解码 HEADERS 帧确认 `transfer-encoding` 是否真的发送；不要把客户端过滤误判为目标不可利用。
- Response queue 已污染时，后续 admin 请求也可能先吃到自己的 404；带有效 session 访问管理面需要重复几次或先用普通请求重置后端连接。
- H2.CL 中看到 victim 访问 exploit server 不等于一定执行；如果不是在浏览器导入脚本资源前污染连接，浏览器可能只是加载了 payload 但不作为 JS 执行。
- 捕获到单个 cookie 片段不等于可用会话；如果被 `Content-Length` 截断、大小写不一致或只复制一个 cookie，访问可能不生效，需要调长度、HTML/URL decode，并保留同一 Cookie 行里的配套字段。
- H2 request splitting 如果只注入了单个 CRLF，通常只是 header injection，不会拆出第二条请求；如果拿到 admin session 后 `/admin` 先返回自己的 404，继续重试或按目标连接 reset 规则刷新队列。

## 关联 Skills

- `web2-vuln-classes`
- `triage-validation`

## 晋升到 Skill / Queue 的条件

- 有链路层 baseline、单变量差异和可复现影响时写入 action queue，类型 `proxy-cache-boundaries`。
