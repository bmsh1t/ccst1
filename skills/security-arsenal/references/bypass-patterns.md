# Bypass Pattern References

These are conditional probe shapes, not a default firing dictionary. Load this file only after the active evidence indicates parser mismatch, allowlist logic, upload validation, redirect validation, or WAF/router normalization issues. Every probe needs a baseline request, expected observation, and stop condition.

## SSRF IP / URL Parser Bypass Shapes

Use only after a server-side fetch primitive is evidenced. Prefer read-only callbacks or controlled internal test services before cloud metadata or protocol pivots.

| Shape | Example | Use when | Stop condition |
|---|---|---|---|
| Decimal loopback | `http://2130706433/` | Filter blocks dotted IPv4 but parser accepts integer host | No differential DNS/connect behavior |
| Hex loopback | `http://0x7f000001/` | Parser normalizes numeric host forms | Same response as blocked baseline |
| Octal loopback | `http://0177.0.0.1/` | Legacy parser accepts octal segments | No parser-specific delta |
| Short IPv4 | `http://127.1/` | Host parser expands abbreviated IPv4 | Same block page as baseline |
| IPv6 loopback | `http://[::1]/` | IPv4-only denylist suspected | No network or status delta |
| IPv4-mapped IPv6 | `http://[::ffff:127.0.0.1]/` | Dual-stack normalization differs | No resolver/connect delta |
| Redirect chain | `https://allowed.example/redirect?to=http://127.0.0.1/` | Filter validates first hop but fetcher follows redirects | Redirect not followed or every hop validated |
| DNS rebinding | controlled host resolves external then private | Resolver result differs between validation and fetch | No explicit authorization for rebinding test |
| Encoding confusion | encoded `#`, `@`, slash, or host separators | URL validator and fetcher parse different components | No component-boundary delta |
| Unicode/numeric normalization | enclosed or full-width numeric host glyphs | Host normalization differs across layers | Same normalized host as baseline |
| Protocol pivot | `gopher://`, `dict://`, `file://` | Scheme allowlist or adapter mismatch is evidenced | Scheme rejected consistently |

Evidence gate: show raw request/response for baseline, blocked internal form, and one normalized variant that changes resolver/connect/read-back behavior.

## Open Redirect Bypass Shapes

Use when redirect validation is evidenced and the next hop matters, such as OAuth code theft, token leakage, or trusted-domain navigation. Open redirect alone remains a chain seed.

| Shape | Example | Observation to seek |
|---|---|---|
| Double URL encoding | `%252F%252Fexample.org` | Validator decodes once, redirector decodes twice |
| Backslash normalization | `https://target.example\@example.org` | Browser/server disagree on host boundary |
| Protocol-relative | `//example.org` or `///example.org` | Redirector allows network-path references |
| Userinfo separator | `https://target.example@example.org` | Validator checks substring before `@` |
| Whitespace/control char | `//example%09.org` | Normalizer strips or splits host differently |
| Fragment confusion | `https://example.org#target.example` | Validator checks fragment or display text |
| Null truncation | `https://example.org%00target.example` | Legacy parser truncates while validator does not |
| Parameter pollution | `?next=target.example&next=example.org` | Different layer chooses first vs last value |
| Path confusion | `/redirect/..%2F..%2Fexample.org` | Router normalizes path into redirect target |
| Unicode normalization | visually similar host/path | Human/UI allowlist differs from parser result |

Evidence gate: capture 302 Location and final browser destination. For OAuth, prove code/token delivery to attacker-controlled redirect before report.

## File Upload Bypass Shapes

Use after an upload parser, storage path, converter, or execution/read-back boundary is identified. Do not execute uploaded content on real infrastructure unless the current turn authorizes that state-changing test.

| Shape | Example | Signal |
|---|---|---|
| Extension layering | `file.php.jpg`, `file.phtml`, case variants | Storage/runtime chooses a different extension than validator |
| Content-Type mismatch | image header + active body | Validator trusts MIME header, backend uses content |
| Magic bytes polyglot | `GIF89a` + secondary syntax | Parser accepts file as image while another layer interprets payload |
| Server config file | `.htaccess` or equivalent | Upload path can alter interpreter behavior |
| SVG active content | SVG with script or external entity shape | Image pipeline preserves active XML/browser behavior |
| Race window | upload then fetch before cleanup | Temporary file is reachable before validation removes it |
| Archive traversal | zip entry with `../` path | Extractor writes outside intended directory |

### Magic Bytes Reference

| Type | Hex |
|---|---|
| JPEG | `FF D8 FF` |
| PNG | `89 50 4E 47 0D 0A 1A 0A` |
| GIF | `47 49 46 38` |
| PDF | `25 50 44 46` |
| ZIP / DOCX / XLSX | `50 4B 03 04` |

Evidence gate: preserve raw upload request, stored file URL or conversion output, and response proving parser/read-back/execution boundary. Prefer harmless marker read-back before active payloads.

## SQLi WAF / Router Normalization Shapes

Use only after stable SQLi-like baseline-vs-perturbation evidence exists. These shapes are for parser-differential confirmation, not blind spraying.

| Shape | Example | Use when |
|---|---|---|
| Inline comments | `SE/**/LECT` | Keyword filter is suspected |
| Version comments | `/*!50000 SELECT*/` | MySQL-compatible parser suspected |
| Case variation | `SeLeCt` | Case-sensitive filter suspected |
| URL encoding | encoded quote/operator | Decode order differs across proxy/app/database |
| Unicode apostrophe | typographic quote variants | Unicode normalization differs |
| Whitespace variants | comments, tabs, newlines | Parser and WAF split differently |

Evidence gate: one stable baseline, one benign syntax perturbation, one normalizer-differential response, and a clear stop condition for noisy timing or WAF-only deltas.

## Path Traversal / File Selector Normalization Shapes

Use after a normal file selector, download, include, template, theme, locale, archive, or document preview path is identified.

| Shape | Use when | Stop condition |
|---|---|---|
| Dot segment | Parser may normalize `../` after validation | Same error as baseline and no path delta |
| Encoded segment | Decode order differs across proxy/router/app | Decoder rejects consistently |
| Double encoding | Frontend decodes once, backend decodes twice | No backend-specific delta |
| Mixed slash | Windows/Unix separator handling differs | Same normalized path |
| Suffix bypass | Backend appends fixed extension | No read-back or file selection delta |
| Archive traversal | Extractor writes or reads nested path | Would overwrite or access real sensitive files |

Evidence gate: normal file baseline, one traversal variant, raw response difference, and bounded read target. Do not bulk-read secrets.

## Host Header / Proxy Trust Shapes

Use after Host/X-Forwarded/Forwarded headers influence routing, redirects, links, reset URLs, cache keys, or upstream selection.

| Shape | Observation to seek |
|---|---|
| `Host` swap | Absolute URL, redirect, password reset, or backend route changes |
| `X-Forwarded-Host` | App trusts forwarded host over canonical host |
| `Forwarded` header | Proxy/app parses standardized host/proto/user boundary |
| `X-Original-URL` / `X-Rewrite-URL` | Frontend and backend route disagree |
| Scheme confusion | `X-Forwarded-Proto` changes secure-cookie or redirect behavior |
| Port confusion | Host allowlist treats host:port differently than backend |

Evidence gate: raw replay showing downstream consumer impact. Reflection alone is not enough.
