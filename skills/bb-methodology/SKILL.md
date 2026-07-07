---
name: bb-methodology
description: Use at the START of any bug bounty hunting session, when switching targets, or when feeling lost about what to do next. Master orchestrator that combines the 5-phase non-linear hunting workflow with the critical thinking framework (developer psychology, anomaly detection, What-If experiments). Routes to all other skills based on current hunting phase. Also use when asking "what should I do next" or "where am I in the process."
---

# Bug Bounty Methodology: Workflow + Mindset

Master orchestrator for hunting sessions. Combines the 5-phase non-linear workflow with the critical thinking framework that separates top 1% hunters from the rest.

## 四层记忆接入

本 Skill 是会话路线控制器。执行时遵守 `skills/runtime-protocol.md`：

1. 先读取目标层，确认当前 target、phase、hypothesis、active leads 和 next actions。
2. 再选择本轮执行路径；不要跳过目标层直接开始泛扫。
3. 当路线需要更多思路时，读取 `knowledge/index.md`，最多选择 1-2 张相关知识卡；按当前证据和高价值漏洞族覆盖模型路由，不固定偏向某几个漏洞类别。
4. 任何高压流量、并发、状态改变或真实业务影响动作，先按 `rules/red-lines.md` 降级或暂停。
5. 结束前按 `rules/coverage-gate.md` 交代 covered / blocked / unknown / next actions。
6. 高强度 hunt 遵守 `rules/hunting.md#high-intensity-hunting-posture`：
   深度来自证据循环、角色/对象差异、覆盖和复盘，不来自高压流量、凑步骤或破坏性利用。

---

## PART 1: MINDSET (How to Think)

### Core Principle

Hunting is not "find a bug" -- it is "prove an attack scenario." Think like an attacker with a specific goal, not a scanner looking for patterns.

### Daily Discipline: Define, Select, Execute

Before touching any tool:

1. **Define**: "Today I target [feature/domain] to achieve [CIA impact]"
2. **Select**: Choose 1-2 vuln classes (IDOR, Race Condition, etc.)
3. **Execute**: Focus ONLY on selected techniques. No wandering.

Selection is a current-session tactic, not a persistent exclusion. When switching
targets or opening a fresh Claude Code CLI, reset temporary focus/skip choices:
new target default keeps only the scanner's built-in XSS lane skip, and scanner
full is the explicit path when the current run must include XSS. Do not inherit
old “skip/ignore” requests or bug bounty exclusion heuristics.

### 5 Ultimate Goals (Pick One Per Session)

1. **Confidentiality** -- steal data the attacker shouldn't see
2. **Integrity** -- modify data the attacker shouldn't change
3. **Availability** -- 只通过非破坏性证据说明可用性风险，不执行 DDoS、压力测试或真实服务中断
4. **Account Takeover** -- control another user's account
5. **RCE** -- execute commands on the server

### 4 Thinking Domains

#### 1. Critical Thinking (deep analysis)

**Question trust boundaries:**
- Frontend control disabled? Send request directly via proxy
- `user_role=user` cookie? Change to `admin`
- Keep payment/billing/refund/credit/wallet as high-value logic lanes; avoid only real money movement unless explicitly intended
- `<script>` blocked? Try `<img onerror=...>`

**Reverse-engineer developer psychology:**
- Feature A has auth checks -> Similar feature B (newly added) probably doesn't
- Complex business flows -> Edge cases have bugs
- `/api/v2/user` exists -> Does `/api/v1/user` still work with weaker auth?

**What-If experiments:**
- Skip workflow step -> hit the next state directly
- Skip 2FA -> navigate to `/dashboard`
- For quota/checkout/OTP/cart race ideas, first run `rules/red-lines.md`; use test resources, local reasoning, or minimal authorized replay instead of high-pressure traffic
- Replace `guid=f8a2...` with `id=100` on sibling endpoint -> IDOR?

#### 2. Multi-Perspective (multiple angles)

| Perspective | What to check |
|------------|---------------|
| Horizontal (same role) | User A's token + User B's ID -> IDOR |
| Vertical (different role) | Regular user -> `/admin/deleteUser` |
| Data flow (proxy view) | Hidden params in JSON: `debug=false`, `discount_rate` |
| Time/State | Race conditions, post-delete session reuse |
| Client environment | Mobile UA -> legacy API with weaker auth |
| Business impact | "What's the $ damage if this breaks?" |

#### 3. Tactical Thinking (pattern detection)

- **Naming anomaly**: `userId` everywhere but suddenly `user_id` -> different dev, weaker security
- **Error diff**: Same 403 but different JSON structure -> different backend systems
- **Environment diff**: Prod vs Dev/Staging -> debug headers, CSP disabled
- **Version diff**: JS file before/after update -> new endpoints, removed params
- **Supply chain**: Check framework/library versions for known CVEs
- **Third-party integration**: Stripe/Auth0/Intercom -> webhook signature missing?

#### 4. Strategic Thinking (big picture)

- **Asymmetry**: Defender must patch ALL holes. You only need ONE.
- **Intuition engineering**: Log why something "feels wrong." Verify later. Update mental DB.
- **Unknown management**: Can't understand something? Add to "investigate later" list. Just-in-Time Learning.

### Amateur vs Pro: 7-Phase Comparison

| Phase | Amateur | Pro |
|-------|---------|-----|
| Recon | Main domain only | Shadow IT, dev environments, all assets |
| Discovery | Look for errors | Look for design contradictions, business logic flaws |
| Exploit | Give up when blocked | Build filter-bypass payloads |
| Escalation | Report the phenomenon only | Chain to real harm (session steal, ATO) |
| Feasibility | Include unrealistic conditions | Minimize attack prerequisites |
| Reporting | State facts only | Prove concrete security impact |
| Retest | Check if old PoC fails | Analyze fix method, find incomplete patches |

### Two Approach Routes

- **Route A (Feature-based)**: "This feature is complex" -> deep-dive its input handling -> find vuln
- **Route B (Vuln-based)**: "I want IDOR" -> find endpoints with sequential IDs -> test access control

### Anti-Patterns (Stop Doing These)

- **Program hopping**: Stick with one target minimum 2 weeks / 30 hours
- **Tool-only hunting**: Automation finds duplicates. Manual testing finds unique bugs.
- **Rabbit hole**: Max 45 min per parameter. Set a timer. If stuck, sleep on it.
- **No goal**: "Just looking around" = wasted time. Always Define first.

---

## PART 2: WORKFLOW (What to Do)

### The 5-Phase Non-Linear Flow

```
+-------------------------------------------------+
|                                                 |
|  +----------+    +----------+    +----------+   |
|  | 1. RECON |---+| 2. MAP   |---+| 3. FIND  |  |
|  +----------+    +-----+----+    +-----+-----+  |
|       ^                |               |         |
|       |                v               v         |
|       |          +----------+    +----------+    |
|       +----------| 4. PROVE |---+| 5. REPORT|   |
|                  +----------+    +----------+    |
|                                                  |
|  Non-linear: stuck at any phase -> go back       |
|  New API found at phase 3 -> return to phase 2   |
|  WAF blocks at phase 4 -> origin IP from phase 1 |
+-------------------------------------------------+
```

**THIS IS NOT LINEAR.** Move freely between phases. When stuck, return to a previous phase.

### Phase 0: SESSION START (Every Time)

**Before touching any tool, answer these:**

1. **Define**: "Today I target [feature/domain] to achieve [C/I/A/ATO/RCE]"
2. **Select**: Choose 1-2 vuln classes (IDOR, XSS, SSRF, etc.)
3. **Execute**: Focus ONLY on selected techniques

**Route selection -- Wide or Deep?**

| Signal | Wide (recon sweep) | Deep (focused testing) |
|--------|-------------------|----------------------|
| New program, first day | X | |
| Wildcard scope `*.target.com` | X | |
| Main webapp, been here >3 days | | X |
| Scope update (new domain added) | X | |
| Found interesting subdomain | | X |

### Phase 1: RECON

**Goal**: Maximize attack surface. Find what others missed.

**Wide approach** (initial sweep):
```
Subdomain enum -> DNS resolution -> HTTP probing -> Port scan -> Tech detect
```

**Deep approach** (targeted):
```
Google Dorks -> JS file download -> Hidden param discovery -> API mapping
```

| What you find | Next action |
|--------------|-------------|
| Live subdomains with tech stack | Phase 2 (Mapping) |
| Known software (WordPress, Jira) | Check CVEs + defaults immediately |
| Cloud resources (S3, Firebase) | Test permissions (read/write/list) |
| Path/API/file/param naming pattern or read-only record surface | Load `knowledge/cards/path-pattern-management-exposure.md`, generate bounded target wordlist, then do structured-record/config/secret triage |
| Nothing after 5 min on a host | Skip, try next host (5-minute rule) |

**Command**: `/recon target.com`

### Phase 2: MAPPING & ANALYSIS

**Goal**: Understand the app like its developer does.

**Checklist:**
- [ ] Map all endpoints (Burp/Caido sitemap + JS analysis)
- [ ] Identify auth model (cookie, JWT, OAuth, SAML?)
- [ ] Find business-critical flows (registration, password reset, data export, payment/cart/order logic)
- [ ] Download and analyze JS files for hidden routes, secrets, logic
- [ ] Identify roles and permissions (user, admin, API keys)
- [ ] Note "weird" behaviors (anomalies in naming, errors, timing)

| What you find | Next action |
|--------------|-------------|
| JS files with interesting code | Taint analysis (Sink -> Source) |
| OAuth/SAML authentication | OAuth/SAML checklist |
| API with ID parameters | Phase 3, target IDOR |
| API returns missing/null/type/schema/validator parameter error | Load `knowledge/cards/missing-parameter-discovery.md`, build target-specific param words, then verify low-risk response shape |
| JWT/JWE/JWKS/OAuth/OIDC/SAML/token/account-linking edge | Load `knowledge/cards/auth-sso-token-edge-cases.md`, capture legal-flow baseline, then test binding differences |
| Node/Express/Next/prototype/VM/template evidence | Load `knowledge/cards/node-prototype-pollution.md`, prove source+sink before exploit claims |
| Parser/proxy mismatch, encoded path, method/content-type diff | Route to `rules/playbook-router.md`; change one boundary at a time |
| Complex business logic workflow | Phase 3, target BizLogic |
| postMessage listeners | DOM analysis, postMessage-tracker |

### Phase 3: VULNERABILITY DISCOVERY

**Goal**: Find the bug. Use Error-based first, then Blind-based.

**Decision flow based on what you're testing:**

```
What input are you testing?
+-- ID parameter (user_id, order_id)
|   -> IDOR checklist
+-- Search/filter/sort field
|   -> SQLi, NoSQLi probing
+-- Missing/Null parameter signal
|   -> Load knowledge/cards/missing-parameter-discovery.md; build target-material wordlist; verify low-risk response-shape diff
+-- Path pattern / management console
|   -> Load knowledge/cards/path-pattern-management-exposure.md; bounded target words; read-only structured-record/config/secret triage
+-- SQLi obvious params quiet but API/header/path/sibling endpoints exist
|   -> Load knowledge/cards/sqli-hidden-surfaces.md, then enumerate target-relevant non-obvious input surfaces
+-- URL input / webhook / PDF gen
|   -> SSRF checklist
+-- JWT / OAuth / SAML / SSO callback / account linking
|   -> Load knowledge/cards/auth-sso-token-edge-cases.md; compare legal-flow baseline, token/callback binding, issuer/key source, identity mapping
+-- Text field reflected in page
|   -> XSS (DOM or reflected)
+-- File upload
|   -> Upload/parser lane; if storage+access+execution primitive appears, load upload-to-execution and controlled-rce-impact
+-- Node / Express / prototype / template / VM sink
|   -> Load knowledge/cards/node-prototype-pollution.md; prove merge/path-set source and observable sink
+-- Quota / checkout / OTP / workflow state
|   -> Business logic, race conditions
+-- Login / 2FA / password reset
|   -> Auth bypass; if hidden auth selector or username-enum signals exist, load knowledge/cards/auth-hidden-switches.md
+-- Profile update API
|   -> Mass Assignment
+-- Template / wiki editor
|   -> SSTI
+-- Nothing obvious
    -> Fuzz with ffuf, try Error-based probing
```

**Error vs Blind decision:**
1. Try Error-based first (send `'`, `"`, `{{7*7}}`, `${7*7}`) -- watch for 500 errors, stack traces
2. No error? Time-based (`SLEEP(10)`, `; sleep 10;`) -- watch response time
3. No time diff? OOB (`curl attacker.com`, interactsh) -- watch for DNS callback
4. Still nothing? Boolean (`AND 1=1` vs `AND 1=0`) -- watch content-length diff

**Blind-class OAST shortcut:** When step 3 (OOB) is the right next action,
do not hand-substitute URLs. Run `python3 tools/oast_listen.py start
--target T` then `python3 tools/oast_listen.py payloads --target T
--vuln-class {SSRF|XXE|RCE|SQLi}` to print pre-substituted payloads, fire
them, then `python3 tools/oast_listen.py poll --target T` to drain
callbacks. Full 4-command workflow lives in `commands/hunt.md` →
"Blind-class confirmation workflow (OAST)".

| What you find | Next action |
|--------------|-------------|
| Low-impact behavior (redirect, self-XSS, cookie injection) | Chain it -- find a connector gadget |
| Confirmed vuln (XSS, IDOR, SQLi) | Phase 4 (Prove and Escalate) |
| Blocked by WAF/CSP/403 | Bypass techniques, then retry |
| Known software vuln (CVE) | 1-day speed workflow |
| Nothing after 20 min on this endpoint | Rotate (20-minute rule) |

### Boundary Pivot Prompts

When testing stalls, use the distilled boundary-first decision shape without
importing external writeup assumptions. Ask:

```text
1. Boundary: browser, backend, auth flow, proxy/parser, worker, cache, or storage?
2. Baseline: what is one normal request/response for the workflow?
3. Hidden surface: what did JS/source/routes/headers/methods/content-types reveal?
4. Primitive: can I prove one role diff, marker, callback, file/config read, or token/session mismatch?
5. Connector: what turns that primitive into data, account, authz, or controlled RCE impact?
6. Stop: what evidence would make this a dead end?
```

Use this to generate new leads, not to force a payload path. Do not copy flag
paths, admin-bot assumptions, DoS/ReDoS, persistent shell, or broad payload
spraying into live targets.

### Phase 4: PROVE & ESCALATE

**Goal**: Prove maximum business impact. Turn Low into Critical.

**Escalation decision:**
```
What did you find?
+-- XSS
|   +-- Can steal cookie/token? -> Session hijack -> ATO
|   +-- Cookie is HttpOnly? -> Force email change via XHR -> ATO
|   +-- Self-XSS only? -> Find CSRF to trigger it
+-- IDOR
|   +-- Can read PII? -> Automate scraping, show scale
|   +-- Can change password/email? -> Direct ATO
|   +-- UUID only? -> Find UUID leak source, then retry
+-- SSRF
|   +-- DNS only? -> DON'T REPORT. Try cloud metadata
|   +-- Can reach 169.254.169.254? -> Extract keys -> RCE
|   +-- Internal port scan? -> Find Redis/K8s -> RCE
+-- SQLi
|   +-- Error-based? -> Extract data (passwords, tokens)
|   +-- Can INTO OUTFILE? -> Web shell -> RCE
|   +-- Blind? -> Boolean/Time extraction
+-- Open Redirect
|   +-- OAuth flow? -> Token theft -> ATO
|   +-- javascript: scheme? -> XSS
+-- Blocked by defense
|   -> Bypass (WAF/CSP/proxy/sanitizer/2FA)
+-- Low-impact, can't escalate alone
    -> Find connector gadget for chain
```

**After proving impact, check:**
- [ ] Can attack work with 0-1 clicks? (minimize prerequisites)
- [ ] Does it affect all users or specific role?
- [ ] What's the business $ impact?

### Phase 5: VALIDATE & REPORT

**Goal**: Get paid. Make triager's job easy.

**Pre-report gate:**
```
Run /validate (7-Question Gate)
+-- All 7 pass? -> Write report
+-- Any fail? -> Do not report; demote to Lead/Signal if a concrete next evidence action remains.
+-- Borderline? -> Run /triage for quick go/no-go
```

Validation is not an exploration kill-switch. During FIND/PROVE, keep useful
leads, anomalies, hypotheses, and chain seeds with their next evidence action.
The strict gate applies when promoting a Candidate into a Validated Finding or
Report.

**Report:**
```
Run /report
+-- Platform-specific format (H1/Bugcrowd/Intigriti/Immunefi)
+-- Title: [Bug Class] in [Endpoint] allows [role] to [impact]
+-- Impact-first summary (sentence 1 = what attacker CAN do)
+-- Exact HTTP requests in Steps to Reproduce
+-- Under 600 words
+-- CVSS 3.1 score that MATCHES actual impact
```

**After submission:**
- [ ] While waiting for triage: try to escalate further (A->B signal method)
- [ ] If fix deployed: re-test for bypass (incomplete patch = new bug)
- [ ] Record finding with `/remember` for hunt memory

---

## PART 3: NAVIGATION & TIMING

### Non-Linear Navigation Quick Reference

| I'm stuck because... | Go to... |
|----------------------|----------|
| Can't find any subdomains | Phase 1: Try different recon sources, Google Dorks |
| Found subdomain but don't know what to test | Phase 2: Map the app, download JS, understand auth |
| Testing but nothing works | Phase 3: Switch vuln class (20-min rotation rule) |
| Found a bug but impact is low | Phase 4: Escalation paths or gadget chaining |
| WAF/CSP/403 blocking my payload | Bypass techniques, then return to current phase |
| Been stuck for 45 min on one param | STOP. Rabbit hole. Move to next endpoint. |
| New API endpoint discovered during testing | Return to Phase 2: map it before attacking |
| Found one bug | A->B signal: same dev made more mistakes. Hunt 20 min for siblings. |

### 20-Minute Rotation Clock

Every 20 minutes ask yourself: **"Am I making progress?"**
- Yes -> Continue
- No -> Rotate to next: endpoint -> subdomain -> vuln class -> target
- Been on same target 2+ weeks with no findings? -> Consider switching program

### Tool Routing by Phase

| Phase | Tools | Why this order |
|-------|-------|----------------|
| Recon: Subdomains | `subfinder` -> `amass` -> `puredns` -> `httpx` | Passive first (no detection) -> resolve DNS -> probe HTTP + tech stack |
| Recon: URLs | `gau` + `waymore` -> `katana` -> `uro` | Archive (forgotten endpoints) -> active crawl (JS-rendered) -> deduplicate |
| Recon: JS | `jsluice` + `mantra` + `trufflehog --only-verified` | Extract URLs/secrets -> find API keys -> verify keys actually work |
| Recon: Ports | `naabu` (wide) -> `rustscan` (deep) | Fast top-1000 sweep -> full 65535 on interesting targets |
| Recon: Scan | `nuclei -tags cve` -> `nuclei -tags takeover` | Known CVEs first -> then takeover (act immediately) |
| Mapping: Params | `arjun` + `paramspider` + ParamMiner | Discover hidden params + mine archives + cache headers |
| Mapping: Missing params | `context-pack missing-param` + target-material words + low-rate diff/grouping | Turn missing/null/schema/validator signals into target-specific hidden parameter candidates |
| Mapping: Hidden auth params | `context-pack auth-hidden` + browser/source review | Find login branch switches without credential brute force |
| Mapping: JS code | Download -> `jsluice` -> VS Code/Cursor grep | Extract -> static analysis -> AI-assisted taint analysis |
| Mapping: Dorks | Manual Google Dorks | Custom per-target queries find what automation misses |
| Discovery: Fuzz | `ffuf -ac` + `cewl` custom wordlist | Auto-calibrate filtering + target-specific words beat generic lists |
| Discovery: Path pattern | `context-pack path-pattern` + bounded target wordlist | Reuse target naming conventions and management-surface records instead of generic spray |
| Discovery: XSS | `kxss` -> `dalfox` | Filter (which params reflect?) -> scan (only reflective params) |
| Discovery: SQLi | `ghauri` | Modern blind SQLi on ID-like parameters |
| Discovery: Hidden SQLi surface | `context-pack sqli` + manual replay | Header/path/sibling hidden params before heavier tools |
| Discovery: SSRF | `interactsh-client` | Self-hosted OOB listener for blind SSRF/XXE/RCE |
| Discovery: WAF | `wafw00f` | Identify WAF vendor and baseline filtering behavior |
| Exploit: 403 | `byp4xx` or `nomore403` | 20+ bypass techniques automated |
| Exploit: Takeover | `subzy` | Checks CNAME against 70+ vulnerable services |
| Exploit: Cloud | `s3scanner` + `aws` CLI | Scan bucket permissions -> extract metadata credentials |
| Exploit: Secrets | `trufflehog --only-verified` | Only verified working keys (no false positives) |

### Session End Checklist

- [ ] Save all Burp/Caido project files
- [ ] Record any "weird but not yet exploitable" behaviors (future gadgets)
- [ ] Update notes with failed attempts (don't re-test with same techniques)
- [ ] Log findings with `/remember`
