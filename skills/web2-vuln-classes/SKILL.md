---
name: web2-vuln-classes
description: Web/API vulnerability-class routing guide for autonomous assessment. Use when the focus or target memory names a concrete class such as IDOR, access control, JWT/OAuth/SAML, GraphQL, SQLi/NoSQL, SSRF, upload, SSTI, deserialization, XXE, path traversal, request smuggling, cache poisoning/deception, race, browser boundary, WebSocket, LLM tool flow, or controlled RCE. Provides lane triggers, first safe action, evidence gate, stop condition, chain path, and on-demand reference routing.
---

# WEB2 VULN CLASSES — Compact Routing Layer

> **Live-action boundary for Claude CLI**: do not skip a lane just because it
> mentions OTP/SMS, payment, order, wallet, cart, or checkout. Those are valid
> high-value surfaces. The boundary is the *effect*: real state-changing or
> external-side-effect actions such as modifying/deleting resources, real
> charge/refund/transfer, order cancel/fulfill/repush, or bulk message sending
> require explicit current-turn intent. Prefer source, JS, captured traffic,
> GET/HEAD, role diff, dry-run reasoning, and low-volume controlled probes first.

This Skill is the **default-loaded decision layer** for Web/API bug classes. Keep
it small. Put payload bodies, bypass tables, grep lists, and tool syntax in the
on-demand references below.

## Runtime Contract

1. Read target memory first: current surface, hypothesis, active leads, dead ends.
2. Pick one lane from evidence, not from a generic checklist.
3. Build a baseline request/response before perturbing input.
4. Change one boundary at a time: identity, object, parser, content type, method,
   origin, cache key, state transition, or transport framing.
5. Save raw request/response evidence for every Candidate.
6. Queue executable actions through project scripts or explicit commands; browser
   observation alone can create a Lead, not a Validated Finding.
7. Use `triage-validation` before reporting. Bare primitives stay Lead/Candidate
   until impact, identity boundary, chain, and stop condition are proven.

## Four-Layer Memory Hooks

Load these cards through `context_pack.py`; do not read all of them manually.

| Lane | Knowledge card |
|---|---|
| API testing / docs / parser/auth matrix | `knowledge/cards/api-testing-workflow.md` |
| IDOR / BOLA / object authorization | `knowledge/cards/api-idor.md` |
| Business logic / state machine | `knowledge/cards/business-logic-state-machines.md` |
| Auth / roles / org boundary | `knowledge/cards/auth-access.md` |
| JWT / OAuth / SAML / SSO | `knowledge/cards/auth-sso-token-edge-cases.md` |
| Password reset / MFA / OTP / credential flow | `knowledge/cards/auth-credential-recovery-flows.md` |
| Missing parameter discovery | `knowledge/cards/missing-parameter-discovery.md` |
| Management exposure / path pattern | `knowledge/cards/path-pattern-management-exposure.md` |
| GraphQL | `knowledge/cards/graphql.md` |
| SQLi hidden surfaces | `knowledge/cards/sqli-hidden-surfaces.md` |
| NoSQL query injection | `knowledge/cards/nosql-query-injection.md` |
| SSRF URL fetch / internal impact | `knowledge/cards/ssrf-url-fetch.md`, `knowledge/cards/ssrf-internal-impact.md` |
| Upload parser / upload execution | `knowledge/cards/upload-parser.md`, `knowledge/cards/upload-to-execution.md` |
| Controlled RCE / SSTI / command injection | `knowledge/cards/controlled-rce-impact.md`, `knowledge/cards/server-side-template-injection.md` |
| XXE / XML parser | `knowledge/cards/xxe-xml-parser.md` |
| Path traversal / file read | `knowledge/cards/path-traversal-file-read.md` |
| Deserialization / signed objects | `knowledge/cards/insecure-deserialization.md` |
| XSS / browser boundaries | `knowledge/cards/xss-client-injection.md`, `knowledge/cards/browser-client-boundaries.md` |
| Proxy/cache/smuggling | `knowledge/cards/proxy-cache-boundaries.md` |
| WebSocket / realtime API | `knowledge/cards/websocket-realtime-api.md` |
| Info disclosure / source/config | `knowledge/cards/information-disclosure-source-config.md` |
| Web LLM / tool chains | `knowledge/cards/web-llm-tool-chains.md` |
| Node / prototype pollution | `knowledge/cards/node-prototype-pollution.md` |
| Race conditions | `knowledge/cards/race-conditions.md` |

## On-Demand References

Read only when the active evidence asks for concrete detail:

| Need | Reference |
|---|---|
| URL/parser bypass, SSRF IP forms, redirect validation, upload validation, path traversal normalization, WAF/router normalization | `skills/security-arsenal/references/bypass-patterns.md` |
| SSTI, command injection, SQLi confirmation, GraphQL batching, XXE, SAML/XML, deserialization, smuggling payload families | `skills/security-arsenal/references/payload-families.md` |
| DOM/source sinks, language grep, server-side RCE/deserialization sink search | `skills/security-arsenal/references/sink-and-grep-patterns.md` |
| Recon, ffuf, Semgrep, subdomain takeover checks, cloud/storage enum, SAML tooling | `skills/security-arsenal/references/recon-tool-usage.md` |

## Boundary-First Pattern Router

Use the distilled project decision shape, not raw external notes or fixed
payload routes: `boundary -> baseline -> hidden surface -> bug family ->
primitive -> connector -> impact`. Keep this as an AI reasoning aid; do not
import flag hunting, admin-bot assumptions, DoS/ReDoS, persistent shell, or
broad payload spraying into real targets.

### Boundary-First Pass

```text
1. Boundary: browser-only, backend-only, mixed app, auth flow, proxy/parser, worker/job?
2. Baseline: what does one normal request/response look like for this feature?
3. Hidden surface: what do JS/source/routes/headers/methods/content-types reveal?
4. Bug family: injection, authz, parser mismatch, upload, token/SSO, state machine, cache/client?
5. Primitive: can I prove one leak, one bypass, one callback, one marker, or one role diff?
6. Connector: what adjacent gadget turns that primitive into account, data, authz, or controlled RCE impact?
```

### Pattern Map

| Signal | Route |
|---|---|
| Object ID, tenant/org/user/account/invoice/order IDs | IDOR / object auth matrix |
| Token, callback, redirect, JWK/JKU/KID, SAMLResponse | JWT/OAuth/SAML/SSO lane |
| Query, sort, filter, report, export, header/cookie/path segment input | SQLi/NoSQL hidden surface |
| URL fetch, webhook, import, preview, callback | SSRF URL fetch; add internal impact only after server-side fetch proof |
| Upload, import, convert, preview, SVG/Office/XML | Upload parser; upgrade to upload execution only with storage+access+execution proof |
| Template syntax, command output, shell primitive | SSTI/command/controlled RCE |
| CL/TE, host header, proxy trust, cache key, unkeyed header | Proxy/cache/smuggling |
| Origin, postMessage, DOM, CORS, clickjacking | Browser boundary |
| WS handshake/frame/subscription | WebSocket / realtime API |
| Source/config/secret/file read signal | Info disclosure / path traversal / management exposure |

## API Hunting Playbook

1. Classify API: public read, authenticated self-service, admin, internal, partner,
   mobile, websocket, GraphQL, SOAP/XML, background job.
2. Map endpoint × method × identity × object × parser before fuzzing.
3. Split trust boundaries: client, gateway, backend, worker, datastore, cache.
4. Test object-level auth with same path and different verb before broad enum.
5. Test parser/content-type/method override only with raw replay and one changed axis.
6. Escalate only after evidence crosses a boundary: own object -> other owned
   account -> other role/tenant -> data write/read/RCE impact.

### Object-Level Auth Matrix

| Dimension | Minimal check | Stop condition |
|---|---|---|
| User / tenant / org | Same request with two owned identities | Same 403/404 and no data delta |
| Method | `GET` vs `PATCH/DELETE/POST` on same object | State-changing proof would touch real data |
| Path / rewrite header | method diff -> path/header rewrite -> raw replay | No server-side path delta |
| Field / GraphQL selection | Same object with sibling fields/mutations | Introspection only, no protected data/action |
| Workflow state | Before/after step request replay | Would charge/refund/cancel/notify without opt-in |

### Access-Control Boundary Matrix

| Pattern | First safe action | Evidence gate |
|---|---|---|
| URL-based access | Replay exact URL as lower role | Raw 200/field delta for protected data/action |
| Method-based access | Compare same path across verbs | Method changes authz decision, not only routing |
| Header rewrite | Test `X-Original-URL` / `X-Rewrite-URL` with raw replay | Backend honors rewritten path after frontend block |
| Referer-based access | Replay with and without `Referer` | Server authorizes from header, not browser UI |
| Admin role switch | Compare own admin/non-admin or two owned accounts | Privilege boundary changes server-side effect |

Use Playwright request/raw replay for restricted headers; browser fetch cannot set
some headers and must not become a false negative.

### Missing Parameter Signal Lane

`parameter is null`, `missing parameter`, schema errors, validator errors, Swagger,
OpenAPI, JS models, mobile traces, and old versions are parameter sources. Build a
target-specific wordlist from target material, then test one low-impact parameter
at a time. Do not bulk-enumerate real users, PII, passwords, addresses, or tokens.

### Management Exposure Lane

Pattern-based management exposure uses target naming: `admin`, `manage`,
`metrics`, `health`, `config`, `stats`, logs, source maps, backups, manifests,
and sibling paths. First action is read-only fingerprint plus auth boundary check.
Do not import keys into cloud panels or take resource control; record minimal
secret/config evidence and a validation plan.

### SQLi Lane Flow

示例输入面按证据选择，不是固定顺序; not a fixed checklist.

1. Start with explicit query semantics: search/filter/category/sort/pagination/report/export.
2. Add hidden surfaces only from evidence: headers, cookies, path segments,
   request metadata, log-backed fields, second-order stores.
3. Run baseline confirmation before type classification: normal value vs one benign
   perturbation, then boolean/error/sort/length delta.
4. Prefer boolean or structural confirmation before time/OOB. Stop on WAF-only,
   unstable timing, or no reproducible raw diff.
5. Read `payload-families.md` only for SQLi type classification or DBMS fingerprint detail.

### Hidden Auth Switch Lane

Hidden auth switches include disabled providers, SOAP/LDAP/SAML fallbacks, legacy
login routes, `isAdmin=true`-style selectors, and source/channel/provider fields.
First action: owned/test account baseline across visible flow and hidden selector.
Do not silently fall into password brute force. If credential testing is selected,
route to `skills/credential-attack/` or a controlled `/spray` run with lockout,
rate limits and stop conditions.

## Chain Shapes

| Primitive | Connector | Validated impact |
|---|---|---|
| Open redirect | OAuth callback / token leakage | Account takeover or code theft proof |
| SSRF callback | Internal admin / metadata credential | Data/control-plane impact with raw evidence |
| Upload parser | Stored file access / converter | Parser bug or upload-to-execution chain |
| GraphQL introspection | Node/global ID / mutation auth | Object or field-level auth bypass |
| XSS | Session action, CSRF gap, token read, admin path | Account/data action impact |
| Request smuggling | Cache poisoning, request capture, auth bypass | Victim request or response boundary proof |
| Info disclosure | Source/config/route/secret | Follow-on auth, storage, or code path impact |
| Race primitive | Quota/payment/OTP/state transition | Double spend/bypass in controlled target/test resource |

## Lane Cards

Each lane keeps only trigger, first safe action, evidence gate, stop condition,
chain path, and reference routing.

### 1. IDOR / BOLA
- Trigger: object IDs, tenant/org/user/account/order/invoice IDs, GraphQL node IDs.
- First safe action: compare same request with two owned identities; change one ID.
- Evidence gate: other owned account data/action is returned or accepted server-side.
- Stop condition: stable 403/404/no field delta; no second identity.
- Chain path: IDOR -> privilege, export, GraphQL, account takeover, or mass assignment.
- Read if needed: `knowledge/cards/api-idor.md`.

### 2. Broken Access Control
- Trigger: role, admin, method, Referer, `X-Original-URL`, path rewrite, hidden route.
- First safe action: raw replay across role/method/path/header boundary.
- Evidence gate: protected server-side action/data differs by boundary bypass.
- Stop condition: UI-only difference or same backend authz result.
- Chain path: access bypass -> admin function -> data/action impact.
- Read if needed: `knowledge/cards/auth-access.md`.

### 3. XSS / Browser Injection
- Trigger: reflected/stored/DOM XSS, postMessage, CSP, client redirects.
- First safe action: source -> sanitizer/transform -> sink path with harmless proof.
- Evidence gate: browser-context execution or sensitive action/data connector.
- Stop condition: reflection only, CSP blocks execution, no controllable sink.
- Chain path: XSS -> CSRF/action, token exposure, admin browser, ATO.
- Read if needed: `sink-and-grep-patterns.md`.

### 4. SSRF
- Trigger: URL fetch, webhook, import, preview, oEmbed, callback, server-side request.
- First safe action: prove server-side fetch with allowlisted baseline or controlled callback.
- Evidence gate: server-side fetch plus second signal; DNS-only is insufficient.
- Stop condition: browser-only redirect or no resolver/connect/read-back delta.
- Chain path: SSRF -> internal admin/metadata credential/control-plane.
- Read if needed: `bypass-patterns.md` for URL parser or IP normalization.

### 5. Business Logic
- Trigger: price, coupon, checkout, quantity, workflow skip, client-side controls.
- First safe action: model state machine and replay current user/test resource only.
- Evidence gate: server accepts invalid state/value/order that changes outcome.
- Stop condition: client-only display bug or real charge/refund/cancel needed without opt-in.
- Chain path: logic flaw -> money/state/authz/data impact.
- Read if needed: `knowledge/cards/business-logic-state-machines.md`.

### 6. Race Conditions
- Trigger: concurrent, parallel, TOCTOU, payment, OTP, coupon, quota, cart, checkout.
- First safe action: identify one idempotent or test-scope state transition and run low-count parallel replay.
- Evidence gate: reproducible duplicate transition or limit bypass; rate limit and lockout observed.
- Stop condition: noisy timing, real irreversible state, or no stable transition delta.
- Chain path: race -> double spend, OTP/MFA bypass, quota/limit overrun.
- Read if needed: `knowledge/cards/race-conditions.md`.

### 7. SQLi / NoSQL
- Trigger: SQLi, NoSQL, operator injection, query/filter/sort/pagination/header/cookie input.
- First safe action: baseline confirmation with one low-impact perturbation.
- Evidence gate: type classification plus reproducible boolean/error/length/sort delta.
- Stop condition: WAF-only signal, unstable timing, no raw diff.
- Chain path: injection -> read/write/auth bypass; NoSQL -> auth/filter bypass.
- Read if needed: `payload-families.md` for SQLi families, `knowledge/cards/nosql-query-injection.md` for operator/type behavior.

### 8. JWT / OAuth / OIDC / SAML / SSO
- Trigger: JWT, JWK/JKU/KID, alg confusion, redirect_uri, state, PKCE, RelayState, SAMLResponse.
- First safe action: map issuer/key source, callback, state binding, account linking, and token/session boundary.
- Evidence gate: server accepts changed identity/account/session or leaks code/token to controlled endpoint.
- Stop condition: decode-only, metadata-only, or redirect alone without chain.
- Chain path: redirect/PKCE/state/key-source flaw -> account linking or ATO.
- Read if needed: `payload-families.md` for SAML/XML examples; `bypass-patterns.md` for redirect bypass.

### 9. File Upload
- Trigger: upload, import, avatar, attachment, SVG/Office/XML, converter, storage path.
- First safe action: save raw upload request and verify storage/read-back/parser behavior.
- Evidence gate: safe verification of parser/component boundary or storage access execution proof.
- Stop condition: filename-only rejection or no read-back/processing delta.
- Chain path: upload parser -> XXE/XSS/deserialization; upload execution -> controlled RCE.
- Read if needed: `bypass-patterns.md` for validation bypass; `payload-families.md` for XXE/SSTI/RCE families.

### 10. GraphQL
- Trigger: GraphQL, introspection, node/global ID, mutation, subscription, field-level auth matrix.
- First safe action: schema/map; test sibling field or mutation with two owned identities.
- Evidence gate: field-level auth matrix shows protected data/action; introspection alone is informational.
- Stop condition: schema only, no object/field/mutation boundary.
- Chain path: node global ID -> object auth bypass; subscription -> realtime leak.
- Read if needed: `payload-families.md` for batching/query body shapes.

### 11. LLM / AI Features
- Trigger: chatbot, prompt injection, indirect prompt, RAG, agent tool, markdown exfil, tool call.
- First safe action: map tool permissions, data boundary, and user/session separation.
- Evidence gate: prompt path causes unauthorized tool/data/action in controlled target/test resource.
- Stop condition: model says forbidden or outputs text only without data/action boundary.
- Chain path: indirect prompt -> data exfil/tool misuse/account action.
- Read if needed: `knowledge/cards/web-llm-tool-chains.md`.

### 12. API Misconfiguration
- Trigger: mass assignment, over-posting, CORS, prototype pollution, JWT none/alg, method override.
- First safe action: derive candidate fields from schema/JS/XHR; replay one safe extra field.
- Evidence gate: server persists or authorizes unexpected field/action.
- Stop condition: ignored field, client-only reflection, no server state diff.
- Chain path: mass assignment -> role/plan/status; prototype pollution -> auth/RCE sink.
- Read if needed: `knowledge/cards/api-testing-workflow.md` and relevant class card.

### 13. Account Takeover / Recovery
- Trigger: reset token, email change, username enumeration, MFA, remember device, account linking.
- First safe action: map token -> account -> session binding using owned accounts.
- Evidence gate: account/session/email/MFA boundary changes server-side.
- Stop condition: enumeration only, no auth boundary, or lockout/rate limit threshold reached.
- Chain path: reset/SSO/email/MFA flaw -> ATO.
- Read if needed: `knowledge/cards/auth-credential-recovery-flows.md`.

### 14. SSTI / Command Injection / Controlled RCE
- Trigger: template injection, command injection, output channel, blind timing, shell primitive.
- First safe action: engine/context classification with harmless output or timing baseline.
- Evidence gate: controlled RCE proof shows output/timing channel and bounded execution identity.
- Stop condition: 500/timeout only, destructive command needed, no cleanup path.
- Chain path: primitive -> controlled RCE -> bounded impact statement.
- Read if needed: `payload-families.md` and `sink-and-grep-patterns.md`.

### 15. Subdomain Takeover / Cloud / Infra
- Trigger: dangling CNAME, storage bucket, Firebase/open rules, exposed admin/metrics/config.
- First safe action: read-only fingerprint and provider-specific proof without takeover.
- Evidence gate: provider confirms claimable resource or readable storage/config boundary.
- Stop condition: ambiguous fingerprint, no target ownership/claimability evidence, takeover/write needed.
- Chain path: takeover/config -> app data/source/secret/auth boundary.
- Read if needed: `recon-tool-usage.md`.

### 16. HTTP Request Smuggling / Cache
- Trigger: Content-Length, Transfer-Encoding, H2 downgrade, host header, proxy trust, cache poisoning/deception.
- First safe action: scripted baseline for frontend/backend framing or cache key workflow.
- Evidence gate: raw desync/request-capture/cache-key/private response evidence.
- Stop condition: timing-only, prod-wide poison, or victim impact without controlled target/test resource.
- Chain path: smuggling -> request capture/cache poison/auth bypass; deception -> private response leak.
- Read if needed: `payload-families.md` for smuggling families; `bypass-patterns.md` for proxy/cache normalization.

### 17. MFA / 2FA
- Trigger: OTP, TOTP, backup code, remember device, MFA skip, lockout, rate limit.
- First safe action: own account baseline, lockout/rate observation, one low-volume replay.
- Evidence gate: MFA state or token binding bypass with owned/test account.
- Stop condition: lockout threshold, real SMS/email flood, no state delta.
- Chain path: MFA bypass -> session/ATO.
- Read if needed: `knowledge/cards/auth-credential-recovery-flows.md`.

### 18. Path Traversal / LFI / File Read
- Trigger: download/view/include/template/theme/locale/archive/file path parameter.
- First safe action: normal file baseline and one traversal/encoding variant.
- Evidence gate: controlled file read or route/config/source disclosure.
- Stop condition: error-only, no read-back, sensitive bulk read required.
- Chain path: file read -> source/config/secret -> auth/RCE/SSRF connector.
- Read if needed: `bypass-patterns.md`.

### 19. XXE / XML Parser
- Trigger: XML/SOAP/SAML/SVG/Office/RSS/Atom/import/conversion parser.
- First safe action: harmless entity or controlled callback with raw upload/request evidence.
- Evidence gate: external entity, XInclude, file-read, or SSRF behavior observed.
- Stop condition: XML error only or sensitive file/OOB without authorization.
- Chain path: XXE -> file read/SSRF/upload parser chain.
- Read if needed: `payload-families.md`.

### 20. Deserialization / Signed Objects
- Trigger: serialized cookie, ViewState, remember-me, signed object, gadget, pickle, PHP serialize.
- First safe action: decode/encoding map and single-byte tamper to test integrity signature boundary.
- Evidence gate: state tamper accepted or gadget chain reachable in controlled target/test resource.
- Stop condition: signature/encryption rejects tamper, format only, no reachable sink.
- Chain path: state tamper -> privilege; gadget -> controlled RCE.
- Read if needed: `payload-families.md` and `sink-and-grep-patterns.md`.

### 21. Host Header / Proxy Trust / CRLF
- Trigger: Host, XFH, Forwarded, X-Original-URL, CRLF, response splitting.
- First safe action: raw replay one header at a time; compare reset links, redirects, cache keys, routing.
- Evidence gate: server-side trust or response header/body injection changes action/data boundary.
- Stop condition: reflection only, browser-only display, no downstream consumer.
- Chain path: host/proxy trust -> password reset, cache poison, SSRF connector.
- Read if needed: `bypass-patterns.md` and `payload-families.md`.

### 22. WebSocket / Realtime API
- Trigger: websocket, socket.io, STOMP, SignalR, GraphQL subscription, CSWSH, message schema.
- First safe action: capture handshake and first frames; classify cookie/query/subprotocol/first-message auth.
- Evidence gate: foreign/null Origin with credentials, or message schema object auth bypass.
- Stop condition: no authenticated handshake, no controllable channel/object, Origin consistently rejected.
- Chain path: CSWSH/WS BOLA -> private event/data/action leak.
- Read if needed: `knowledge/cards/websocket-realtime-api.md`.

## Global Stop Conditions

Stop or downgrade to Lead when there is no raw baseline, no controllable input, no
owned/test identity, no repeatable response delta, or the next step requires
bulk traffic, destructive state, real-user data, third-party OOB, persistent
shell, prod-wide cache poison, cloud takeover, or sensitive file reads without
current-turn authorization.
