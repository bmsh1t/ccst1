---
name: bug-bounty
description: Bug bounty workflow coordinator for recon, pre-hunt learning, target isolation, chain building, validation gates, and report preparation. Use when a task spans multiple hunting phases or needs routing to narrower skills for recon, vuln-class testing, payload/bypass references, triage validation, report writing, CTF/lab isolation, or VAPT-style evidence handling.
---

> **Live-action boundary for Claude CLI**: this broad skill may mention OTP/SMS,
> race, payment, coupon, wallet, cart, checkout, or order flows. Do not suppress
> those lanes by keyword; they are often high-value. Control real side effects:
> persistent mutation, real money movement, irreversible lifecycle changes, or
> bulk external sends require explicit current-turn intent and bounded volume.

# Bug Bounty Master Workflow

Use this as the broad coordinator for `Recon -> Learn -> Hunt -> Validate -> Report`.
Keep this file as the routing and decision layer. Load detailed payloads, bypasses,
tool commands, and grep patterns only when the current evidence needs them.

## 四层记忆接入

执行时遵守 `skills/runtime-protocol.md`：

1. 先读取目标层：`memory/goals/active.json` 或 `python3 tools/target_memory.py show`。
2. 本 Skill 只做跨阶段协调和路由，不默认全量读取知识库。
3. 需要发散思路时，按证据读取 `knowledge/index.md` 和相关知识卡。
4. 涉及高频、并发、状态改变、真实数据、支付、账号或 CI/CD 时，先读取 `rules/red-lines.md`。
5. 结束前按 `rules/coverage-gate.md` 输出覆盖摘要，并把 lead / next / dead-end 写回目标层。

## Skill Routing

Use narrower skills first when the task is clearly scoped:

| Need | Route |
|---|---|
| Session strategy, target selection, hunter mindset, repeatable hunt cadence | `skills/bb-methodology/SKILL.md` |
| Recon, scope expansion, endpoint discovery, source-intel collection | `skills/web2-recon/SKILL.md` |
| Specific Web/API vuln class testing | `skills/web2-vuln-classes/SKILL.md` |
| Payload families, bypass patterns, sink names, grep patterns | `skills/security-arsenal/SKILL.md` |
| Finding validity, report/no-report, chain precedence | `skills/triage-validation/SKILL.md` |
| Report draft and triager-facing wording | `skills/report-writing/SKILL.md` |
| Android/iOS app work | `skills/mobile-pentest/SKILL.md` |
| CI/CD workflow, supply-chain workflow, GitHub Actions | `skills/cicd-security/SKILL.md` |
| Web3, wallet, token, smart-contract scopes | Web3/token skills |

Return here for end-to-end flow, target isolation, bug chaining, and multi-domain decisions.
Do not let this broad skill override fresh target/session defaults, browser-first evidence
collection, CTF/lab sandbox scope, or source-intel guidance from active commands, agents,
and rules.

## Reference Loading Rules

Do not paste payload tables into this coordinator. When the evidence asks for details:

- Parser confusion, SSRF/open-redirect/upload/SQLi bypasses → `skills/security-arsenal/references/bypass-patterns.md`.
- Source review sinks and language grep patterns → `skills/security-arsenal/references/sink-and-grep-patterns.md`.
- Recon, ffuf, Semgrep, endpoint discovery, scope commands → `skills/security-arsenal/references/recon-tool-usage.md`.
- SSTI, command injection, XXE, smuggling payload families → `skills/security-arsenal/references/payload-families.md`.

Payloads are conditional probe shapes. Select by trigger condition, expected observation,
evidence gate, and stop condition; do not run a fixed dictionary by default.

## THE ONLY QUESTION THAT MATTERS

> **Can an attacker do this right now against a real user who has taken no unusual actions, and does it cause real harm such as stolen money, leaked PII, account takeover, or code execution?**

If the answer is no, do not report it yet. Keep it as a Lead/Signal only when there is a
specific next evidence action; otherwise rotate or drop it.

### Theoretical Bug = Not Report-Ready

| Pattern | No-report reason |
|---|---|
| "Could theoretically allow..." | Not exploitable yet |
| Many preconditions | Victim or attacker path is unrealistic |
| Wrong implementation but no practical impact | Harmless defect |
| Dead code | Not reachable |
| Source maps without secrets | No concrete impact |
| DNS-only SSRF | Need read-back, internal access, or exfil proof |
| Open redirect alone | Need ATO/OAuth/sensitive navigation chain |
| "Could be used in a chain" | Build the chain first |

## CRITICAL RULES

1. **Use the provided target set directly**. External scope text is context; the active command target set is the execution surface unless the user changes it.
2. **Separate hunting from validation**. Preserve Leads/Signals during exploration; run validation gates before report writing.
3. **No theoretical reports**. Prove concrete harm or keep a chain candidate with a next evidence action.
4. **One bug class at a time**. Go deep enough to prove or kill a hypothesis; avoid shallow spray.
5. **Impact first**. Ask what valuable asset is exposed if auth, parser, workflow, cache, or state handling breaks.
6. **Keep authenticated coverage**. IDOR/BOLA/priv-esc/mass assignment/JWT/GraphQL/stateful bugs often need one real session; IDOR/BOLA usually need two identities.
7. **Script critical actions**. Replay, state-changing checks, batch validation, and exploit verification must use project scripts or explicit commands and preserve raw request/response evidence.
8. **Respect red lines**. Real charges/refunds/transfers, destructive changes, bulk external sends, and high concurrency need explicit current-turn intent.
9. **Avoid recon spirals**. Repeated 401/403/404 with no route delta is a stop signal; rotate after the time-box.
10. **Business impact beats class name**. Severity depends on context and victim impact, not only the vulnerability label.
11. **Do not promote ordinary knowledge**. Small practical gaps go to context_pack, knowledge cards, seeds, and tests; only rare transferable techniques become Skill candidates.

### Auth-Aware Reminder

When a bug class lives behind login, keep authenticated coverage active. Use `session_id` /
audit artifacts to diff attacker vs victim behavior. Reference `docs/auth-sessions.md` and
`docs/auth.example.json`.

### Finding State Model

Use this model. `rules/hunting.md` is canonical; this skill keeps the execution reminder:

```text
Lead -> Signal -> Candidate -> Validated Finding -> Report
```

- **Lead**: plausible endpoint, source-intel hypothesis, anomaly, or chain seed with a next evidence action.
- **Signal**: observed behavior that might matter but needs replay, victim proof, or impact confirmation.
- **Candidate**: enough concrete evidence exists to run `/triage` or `/validate`.
- **Validated Finding**: passed the 7-Question Gate and pre-submission gates.
- **Report**: human-reviewed report draft or submission package.

The gates are pre-report controls. Do not use them to erase raw hunt leads. Demote,
rotate, or drop items with an explicit reason.

### Target Isolation

Temporary focus/skip instructions are not long-term rules.

- New target default keeps only the built-in XSS lane skip; use scanner full when the current run must include XSS.
- Temporary skips are per-current-target and per-current-invocation only.
- Only the current user turn can set or clear a temporary module skip for the current target.
- A temporary skip does **not** replay onto the previous target or future target.
- If repo `config.json` enables `ctf_mode`, the provided target set and repo config are the authoritative lab scope record.
- Do not require public-program, written-permission, or ownership-confirmation text as an external gate for an explicit lab/CTF target.
- Production-looking brands, public-sector/government-style labels, account/login/register wording, account-gated surfaces, and old target-history caution notes are sandbox context by default; they are not lane kills.

### CTF / Lab Recon

For explicitly authorized labs, CTFs, or local fixtures, explore normally inside the provided target set. Do not copy lab domains, credentials, one-time answers, or target-specific payloads into project memory. Only write back reusable route gaps, evidence gates, seeds, stop conditions, or de-noising regressions.

## Methodology Boundary

This coordinator must not duplicate `skills/bb-methodology/SKILL.md`.

Use `skills/bb-methodology/SKILL.md` for mindset, cadence, session start, Q7 priority routing,
source-intel loops, coverage rhythm, and hunter-specific workflow details. Keep this file focused
on routing, state, validation, chain coordination, and report readiness.

## Phase Flow

### Phase 1: Recon

Goal: build a bounded target map and identify high-value surfaces without drowning in tooling.

- Route command-heavy recon to `skills/web2-recon/SKILL.md` or `skills/security-arsenal/references/recon-tool-usage.md`.
- Prefer target-relevant scope, live hosts, app flows, API shapes, JS/source clues, auth/session behavior, and changelog deltas.
- Treat scanner output as Leads until raw evidence and impact are proven.

### Missing Parameter Signal

When an endpoint returns `missing parameter`, `parameter is null`, `required parameter`, type mismatch, schema mismatch, validator/binder errors, or similar parameter-validation output, load `knowledge/cards/missing-parameter-discovery.md` instead of treating the error as a finding.

```text
baseline error -> target-specific material wordlist -> low-rate param discovery -> response-shape diff -> minimal own/test-object validation
```

Stop if the next step would require bulk enumeration of real users, PII, passwords, addresses, tokens, orders, or destructive/state-changing actions.

### Path Pattern / Management Exposure

When a target has patterned paths, filenames, API prefixes, parameters, subdomains, static assets, or exposed management/log/config/monitor surfaces, load `knowledge/cards/path-pattern-management-exposure.md`.

```text
observed naming pattern -> bounded target wordlist -> read-only surface baseline -> structured record/config extraction -> secondary recon or secret Candidate
```

Do not convert this lane directly into password brute force, cloud-console import, server takeover, or real infrastructure enumeration. Password testing is allowed as a separate controlled `/spray` / `credential-attack` workflow when the operator or `/autopilot` selects that lane under `rules/red-lines.md`.

### Phase 2: Learn

Before deep testing, learn the app like a user:

- What user roles, assets, payments, documents, messages, integrations, and admin flows exist?
- What changed recently in changelog, releases, commits, or public reports?
- Which endpoints hold the worst-case impact if auth or workflow state breaks?
- Which bug classes are less saturated for this target?

### Phase 3: Hunt

Keep notes in this shape:

```text
Lead: endpoint / behavior / source clue
Signal: raw observation and why it may matter
Next evidence action: one bounded replay, diff, or proof step
Stop condition: what result kills this path
State: Lead | Signal | Candidate | Dead End
```

High-value lane reminders:

- IDOR/BOLA: two identities, object ownership proof, read/write impact.
- SSRF: server-side fetch evidence, read-back/internal impact, not DNS-only.
- OAuth/OIDC/JWT: token/source/key confusion, redirect/state/PKCE/account-linking chains.
- SQLi: if explicit params are quiet, route to `knowledge/cards/sqli-hidden-surfaces.md`; 示例输入面按证据选择，不是固定顺序 / not a fixed checklist.
- GraphQL: field-level auth, `node`/global ID, batching/rate-limit, introspection as surface only.
- Race/business logic: model state machine, low-frequency controlled replay, no real charge/refund without intent.
- Cache/smuggling: cache key, victim request shape, queue/capture evidence, script raw replay.
- Browser boundaries: CORS/CSRF/clickjacking/DOM/open redirect need victim and sensitive-action proof.
- WebSocket/realtime: Origin, message schema, authz, replay, and cross-session impact.
- Upload/parser: parser boundary, conversion/read-back, storage/runtime split.
- CI/CD: workflow trigger, expression/dataflow, secret or write impact; route to `skills/cicd-security/SKILL.md`.

### Path 8: Hidden Auth Switches

If auth behavior hints at hidden switches, role flags, legacy parameters, mobile/API variants, or admin-only binders, load `knowledge/cards/auth-hidden-switches.md`. Use owned/test-account baselines and do not silently fall into password brute force.

```text
normal auth boundary -> candidate hidden switch -> owned/test account diff -> privilege or workflow impact proof
```

## A->B BUG SIGNAL METHOD (Cluster Hunting)

A weak primitive becomes valuable when it connects to a concrete next hop. Record the primitive,
connector, victim path, and impact before reporting.

### Known A->B->C Chains

| A: Initial Signal | B: Connector | C: Impact |
|---|---|---|
| Open redirect | OAuth redirect URI or token delivery | Account takeover |
| Host header injection | Password reset poisoning | Account takeover |
| SSRF DNS callback | Internal HTTP read or metadata read-back | Internal access / cloud impact |
| XSS | Sensitive action or token theft | Account action / ATO |
| CORS difference | Credentialed sensitive response | Data theft |
| No rate limit | OTP/account recovery path | ATO candidate |
| Cache poisoning | Victim request shape + cache key control | Stored response impact |
| GraphQL introspection | Field-level auth bypass | PII or privileged mutation |
| Upload parser mismatch | Read-back or execution boundary | File read / XSS / RCE candidate |

### Cluster Hunt Protocol

1. Start from an observed Signal, not a generic checklist.
2. Ask what same trust boundary also touches auth, cache, parser, storage, workflow state, or identity.
3. Build one next evidence action with a stop condition.
4. Preserve raw request/response for baseline and changed request.
5. Promote to Candidate only when impact is concrete.
6. If chain is not proven, keep it as `CHAIN_REQUIRED`, not a report.

## Phase 4: Validate

### The 7-Question Gate

All 7 must be yes before a report is written. Any no stops the report path; demote to Lead/Signal with a next evidence action or drop it.

1. Can I exploit this right now with a real PoC and exact HTTP request?
2. Does it affect a real user who took no unusual actions?
3. Is the impact concrete: money, PII, ATO, RCE, privileged state change, or equivalent?
4. Is this in scope for the active target set and policy context?
5. Did I check disclosed reports, changelog, source, and obvious duplicates?
6. Is this not standalone on the always-rejected list?
7. Would a tired triager say “yes, that is a real bug” from the evidence alone?

If a primitive appears in both never-submit and conditionally-valid tables, defer to `skills/triage-validation/SKILL.md`: proven chain → report; concrete next hop but unbuilt → chain required; bare primitive → do not report.

### 4 Pre-Submission Gates

| Gate | Check |
|---|---|
| 0 Reality | Reproducible from scratch, in scope, raw request/response evidence saved |
| 1 Impact | Concrete attacker action, real victim or asset, more than non-sensitive data |
| 2 Duplicate | Program reports, issues, changelog, docs, and recent disclosures checked |
| 3 Quality | Title, steps, evidence, severity, remediation, and wording are triager-ready |

### CVSS / Severity Calibration

| Bug | Typical severity when impact is proven |
|---|---|
| IDOR read PII | Medium |
| IDOR write/delete | High |
| Auth bypass to admin | Critical |
| Stored XSS | Medium to High depending context |
| SQLi data exfil | High |
| SSRF to cloud metadata or privileged internal read | High to Critical |
| Race condition with double spend or quota bypass | High |
| GraphQL field-level auth bypass with sensitive data | High |
| JWT signature/key-source bypass to privileged role | Critical |

Severity must match business impact and program policy; do not overclaim by class name alone.

## NEVER SUBMIT / CHAIN REQUIRED SUMMARY

Use `skills/triage-validation/SKILL.md` as canonical. Standalone examples that usually fail:

Missing CSP/HSTS/SPF/DKIM/DMARC, version/banner disclosure without working CVE exploit, clickjacking on non-sensitive pages, tabnabbing, CSV injection, CORS wildcard without credentialed exfil, logout CSRF, self-XSS, open redirect alone, mobile OAuth client secret alone, SSRF DNS-only, host header injection alone, no rate limit on non-critical forms, session not invalidated on logout, concurrent sessions, internal IP disclosure, weak ciphers, missing cookie flags alone, broken links, autocomplete on password fields.

Conditionally valid with a proven chain:

| Low primitive | Required chain |
|---|---|
| Open redirect | OAuth code/token theft or sensitive trusted navigation |
| Clickjacking | Sensitive action with PoC |
| CORS wildcard | Credentialed sensitive response exfiltration |
| CSRF | Sensitive state change or account takeover path |
| No rate limit | OTP/account recovery brute-force path within controlled rules |
| SSRF DNS-only | Internal access or read-back proof |
| Host header injection | Password reset poisoning or cache/session impact |
| Self-XSS | Victim-deliverable chain such as login CSRF to stored execution |

## Phase 5: Report

Route full drafting to `skills/report-writing/SKILL.md`; keep these compact formulas here.

### Report Title Formula

```text
[Bug Class] in [Exact Endpoint/Feature] allows [attacker role] to [impact] [victim scope]
```

Good title examples use exact feature, actor, and impact. Bad titles say only “XSS found” or “security issue”.

### Impact Statement Formula

```text
An [attacker with X access level] can [exact action] by [method], resulting in [business harm]. This requires [prerequisites] and leaves [detection/reversibility].
```

### Minimal Report Shape

```text
Title: [class] in [endpoint/feature] allows [actor] to [impact]
Summary: two or three sentences with location, root cause, and impact
Steps: exact reproducible HTTP requests and observed responses
Evidence: screenshot/video/raw request-response showing actual impact
Impact: concrete harm and affected victim/asset scope
Severity: CVSS/program severity with rationale
Fix: one or two concrete remediation sentences
```

### Human Tone Rules

- Start with impact, not the vulnerability name.
- Use active voice and concrete evidence.
- One concrete example beats three abstract paragraphs.
- Avoid filler words such as comprehensive, leverage, seamless, and ensure.
- Keep report text short enough for triage.

### The 60-Second Pre-Submit Checklist

```text
[ ] Title follows formula
[ ] First sentence states exact impact
[ ] Steps include exact HTTP request or deterministic script command
[ ] Response showing the bug is included
[ ] Two identities used when identity boundary matters
[ ] Severity matches impact and policy
[ ] Recommended fix is concrete
[ ] Endpoint and parameter names are exact
[ ] No target secrets, unrelated data, or noisy payload dumps included
[ ] Report is concise and human-readable
```

## Finish / Write-Back

Before ending a session:

1. Summarize coverage by target, lane, and state model.
2. Save raw evidence references for Candidates and Validated Findings.
3. Write back reusable lead/next/dead-end notes to the target layer.
4. Promote only reusable route gaps, evidence gates, seeds, stop conditions, or de-noising regressions into project memory.
5. Discard noisy, redundant, ordinary, or lab-overfit content.
