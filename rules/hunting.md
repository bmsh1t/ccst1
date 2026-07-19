# Hunting Rules

These rules are always active. Breaking them wastes time and reduces payout rate.

`rules/red-lines.md` has higher priority than this file. Do not perform DDoS,
high-pressure traffic, or destructive/state-changing actions against real target
data. When a hunt idea might change state or create load, run the red-line
check first and downgrade to a low-risk validation path when possible.

---

## CTF Mode

When `ctf_mode: true` is set in `config.json`, treat the supplied target set as
the active lab / sandbox target context for this workspace:

- keep `/hunt`, `/autopilot`, `/recon`, and `/pickup` on full active coverage
- do not ask for public-program, ownership, or written-permission confirmation
- do not downgrade active testing into passive-only analysis because a hostname
  looks public, branded, or government-like
- keep request-centric lanes available, including browser-state flows,
  raw-request replay, scanner expansion, OAST follow-up, and second-stage
  replays

CTF mode is a compatibility override that strengthens the current
target-driven semantics; it must not reintroduce external policy blockers elsewhere.

---

## High-Intensity Hunting Posture

High intensity means deeper reasoning, better coverage, and stronger evidence
loops. It never means high-pressure traffic, destructive exploitation, step
padding, or bypassing `rules/red-lines.md`.

Core discipline:

- Do not stop just because broad automation found nothing. Scanner silence is
  often the beginning of manual workflow, role, object, and state analysis.
- Evidence-driven depth does not mean evidence-only testing. When strong
  signals are absent, switch to Discovery mode and actively generate new
  evidence from browser/API/JS/source/recon/parameter/path/workflow context.
- Define the current target boundary first, then map attack surface, rank it,
  run focused validation, and write back what changed.
- Use Target Case State when actor/session/object/private-marker continuity
  matters; it is working memory for multi-step validation, not a scope gate or
  bug-class selector.
- If cached browser/recon/JS/source artifacts already expose object-shaped
  endpoints, use `tools/case_state_seed.py` to draft case-state commands instead
  of making Claude remember the object graph in prose.
- Map broadly before deep-diving, but do not use "more recon" to avoid testing
  a high-signal surface already in front of you.
- Route from current evidence. Do not force a vulnerability class, old target
  preference, checklist, or bounty heuristic onto a target that does not
  support it.
- Every failed path should produce one of: a dead-end condition, a blocked
  red-line note, a refined hypothesis, a coverage mark, or a concrete next
  evidence action.
- Prefer one reproducible, high-impact issue over many information-level
  observations. Info-level signals are useful only when they become a chain
  seed or explain a stronger path.
- When standard methods fail, change angle: role diff, object diff, tenant
  diff, method/version diff, token/origin diff, browser-observed request,
  JS/source hypothesis, workflow/state-machine edge, or sibling endpoint.
- Do not use "scanned" as a synonym for "tested." A tested claim needs
  evidence, replay notes, coverage state, target memory, or Evidence Ledger
  entries.

Browser-state work:

1. Prefer `tools/browser_evidence.py` with agent-browser CLI for routine
   automation, session reuse, snapshots, network, storage, and HAR evidence.
2. Use chrome-devtools MCP for deep live DevTools/network/console debugging.
3. Use playwright MCP or the explicit playwright-cli backend as compatibility
   fallbacks.
4. Import MCP artifacts with
   `python3 tools/browser_mcp_import.py --target <target> --network-json <file> --url <page-url>`
   so `recon/<target>/browser/`, `/surface`, `/checkpoint`, and `/autopilot`
   can continue using the same browser-observed API surface.

Value-first coverage model:

- High-value vulnerability classes are prioritized by practical impact,
  exploitability, evidence strength, affected data/workflow, safety of
  validation, and current coverage gaps. Do not prioritize by a fixed favorite bug class.
- Browser-observed APIs, JS/source-derived routes, recon output, errors,
  parameters, workflows, and historical memory are evidence sources. They can
  point to any bug family, not only authz/IDOR/business logic.
- Maintain coverage across common high-impact web vulnerability families:
  - Access control and identity: Authz, IDOR, authn bypass, session/JWT,
    OAuth/OIDC/SAML, MFA/password reset, CSRF.
  - Injection and code execution: SQLi, NoSQLi, command injection, SSTI, RCE,
    unsafe deserialization, template/expression injection, LDAP/XPath/header
    injection.
  - Server-side, file, and network: SSRF, XXE, LFI/RFI/path traversal,
    arbitrary file read/write, upload/parser chains, webhook abuse, open
    redirect only when chainable.
  - Client-side: XSS, DOM XSS, postMessage, CORS, CSP bypass, client-side auth
    logic flaws.
  - Business workflow: race condition, state-machine bypass, invite/member/
    role workflows, export/download/report access, payment/order/refund only
    when red-line-safe.
  - Infrastructure and supply chain: secrets exposure, CI/CD risks, cloud
    object permissions, debug/admin panels, and known CVEs when version
    evidence exists.
- The coverage matrix taxonomy is a compact tracking model, not the whole
  universe of bugs: `Path` covers LFI/RFI/path traversal; `RCE` covers command
  injection, SSTI, unsafe deserialization, and similar execution paths unless
  the project later splits them into separate cells.
- If a target exposes strong SQLi/SSRF/XXE/RCE/deserialization/LFI evidence,
  pursue it even when authz/IDOR/business-logic lanes also exist.

Completeness discipline:

- Before finish, handoff, or "no finding" summaries, inspect coverage matrix
  Evidence Ledger state, and Target Case State.
- For high-value access-control or workflow surfaces, do not stop at
  owner/baseline. Consider anonymous, owner, peer, low_role, cross_tenant,
  method/version/token/origin differences.
- If actor/object/replay gaps remain, do not claim complete access-control or
  workflow coverage. State the remaining gaps and next safe evidence action.
- If `tools/target_case_state.py summary --target <target> --json` shows active
  validation backlog, either run/resolve the recommended case-state action or
  state the AI override reason and write back a newer hypothesis/backlog.
- If case state is missing or stale, do not stop; continue discovery through
  surface/browser/JS/source/recon evidence and create or enrich case state only
  when it improves the next replay.
- If object IDs are visible but case state is empty, run
  `python3 tools/case_state_seed.py --target <target> --json` and review the
  generated add-actor/add-object/add-backlog drafts.
- If a candidate appears, move to validation. Do not call it a finding until
  validation gates pass.
- If no candidate appears, report the state precisely as lead, signal,
  dead-end, blocked, not-applicable, or unknown. Do not inflate confidence.

Validation discipline:

- Prove practical impact with the lowest-risk evidence that answers the
  question.
- Prefer read-only diffs, test resources, dry-run/preview/validate-only modes,
  minimal replay, and A/B role comparison.
- Prefer `validation_runner.py ... --from-case-state` for actor/object-sensitive
  Authz/IDOR/business-logic validation when case state is ready; if it is not
  ready, collect the missing actor/session/object/private-marker evidence or
  use a manual fallback without treating missing case state as a blocker.
- State-changing actions, funds, orders, permissions, members, deletion,
  notifications, webhooks, CI/CD, and production configuration changes must
  pass `rules/red-lines.md` first.
- Do not "fully exploit" by destroying, polluting, deleting, charging,
  refunding, transferring, notifying, or irreversibly changing target data.

Bounty mindset:

- Report only reproducible, impact-bearing issues.
- Chain low-impact signals into higher impact when the evidence supports it;
  otherwise keep them as leads/signals and do not oversell them.
- Prioritize proof of data access, authorization bypass, tenant isolation
  failure, account impact, business loss, or real security boundary failure.

---

## 0. Target context

This tool is intended to operate directly on the current task's supplied target
set. Treat the target list from the current command as the active execution
context.

This file is the canonical source for shared hunting semantics: the finding
state model, target-isolation defaults, and CTF/lab lane handling. Commands,
agents, and skills may summarize it, but should not fork these meanings.

Operate as a security researcher / vulnerability hunter, not as a generic
compliance auditor:

- Prioritize reproducible, practical, impact-bearing findings instead of purely
  theoretical issues.
- Normal recon, PoC validation, test input construction, and report drafting
  should proceed from the supplied target set without extra policy gates.
- Do not turn external policy text or metadata into execution blockers.
- Treat request-guard, scope, method, breaker, cooldown, and rate hints as
  advisory telemetry for replay and pacing.
- Keep localhost/private IP/CIDR/list targets fully valid and treat
  external program metadata as non-applicable hints when they are supplied as the
  target set.

### 0.1 Temporary preferences do not cross targets

Any previous-target or previous-turn request to skip a bug class, focus lane,
scanner module, excluded class, or test input applies only to the target and
command where it was explicitly stated — per-current-target and
per-current-invocation only.

New target default:

```text
scanner default skip = xss
scanner_full = explicit opt-in for XSS
excluded bug classes = none unless the current user turn or command flags explicitly say so
```

Do not add skips for the current target because of an old target, old CLI
session, README example, competition heuristic, or bounty-program exclusion.
Use scanner full when the current run must include XSS.
Production-looking brands, public-sector/government-style labels, account/login/register wording,
account-gated surfaces, and old target-history caution notes are sandbox context
only. They are not execution gates and cannot exclude a lane unless the current
user turn says so. Only the current user turn can exclude a lane.

---

## 1. USE THE PROVIDED TARGET SET DIRECTLY

Treat the supplied target, IP, CIDR, or host list as the active execution
target set.

Optional helpers such as `/scope`, target profiles, or `scope_snapshot.json`
may still be useful as notes, but they are not execution gates.

## 2. NEVER HUNT THEORETICAL BUGS

> "Can an attacker do this RIGHT NOW, against a real user, causing real harm?"
> If NO — do not write it up as a finding. During exploration, keep it only
> as a lead/signal when there is a concrete next evidence action; otherwise
> rotate to better surface.

Theoretical bugs waste your time AND damage your validity ratio when submitted.

```
NOT a bug: "Could theoretically allow..."
NOT a bug: "Wrong but no practical impact"
NOT a bug: "3+ preconditions all simultaneously required"
NOT a bug: Dead/unreachable code
NOT a bug: SSRF with DNS callback only
```

## 3. KEEP EXPLORATION SEPARATE FROM VALIDATION

Use this state model consistently:

```text
Lead -> Signal -> Candidate -> Validated Finding -> Report
```

- **Lead**: a plausible endpoint, code path, anomaly, or source-intel
  hypothesis. Keep it only with the next evidence action.
- **Signal**: observed behavior that might matter, but still needs replay,
  impact, or victim proof.
- **Candidate**: enough concrete evidence exists to run `/triage` or
  `/validate`.
- **Validated Finding**: the 7-Question Gate and all 4 pre-submission gates
  pass.
- **Report**: a human-reviewed draft or submission package.

The 7-Question Gate and 4 gates are pre-report/pre-submit validation controls.
Do not use them as an exploration kill-switch for raw leads, anomalies,
hypotheses, or chain seeds. During hunt, preserve plausible leads with their
next evidence action; before `/report`, reject or downgrade any candidate that
does not pass validation.

## 4. KEEP TARGET NOTES ADVISORY

Target profiles, target-history notes, target-note snapshots, ownership hints, rate
limits, cooldowns, and method notes are advisory context. They can influence
ordering and replay strategy, but not whether execution may continue.

## 5. 5-MINUTE LOW-SIGNAL TRIAGE

If a target surface shows nothing interesting after 5 minutes, treat that as
low signal for the current timebox, not proof that the surface has no attack
value. Deprioritize it, preserve the observed hosts/paths/notes, and record the
evidence that would justify reopening.

Low-signal indicators:
- All hosts return 403 or static pages
- No API endpoints with ID parameters
- No JavaScript bundles with interesting paths
- nuclei returns 0 medium/high findings

Reopen immediately when fresh browser/XHR traffic, source/JS routes,
authenticated workflow, API docs, object IDs, WebSocket/GraphQL, or business
context creates a concrete next evidence action.

## 6. AUTOMATION COLLECTS AND REPLAYS; AI DECIDES

Use automation for repeatable collection, normalization, raw-evidence capture,
and bounded replay/diff. Use AI reasoning for hypothesis generation, surface
selection, cross-evidence links, validation design, and promotion/demotion.
Scanner and replay output is evidence, not an attack-surface verdict.

### Broad scanner input and completion contract

- 常规 broad breadth 只通过
  `python3 tools/hunt.py --target <target_shell> --scan-only --quick` 进入现有
  scanner owner 和单 target runtime lock。
- `urls/all.txt`、`all_historical.txt`、gau、wayback、waymore 等 raw corpus 是完整
  证据语料，不是通用 nuclei 的默认输入。已成功完成的 quick breadth 不因 Deep
  模式、raw URL 数量或空结果而重复执行。
- bounded Surface/projection 只是默认消费窗口，不是 AI 能力上限。需要长尾证据时，
  可按 Surface page/source/shape 分页、用 `rg` 查询 raw artifact，或根据具体组件、
  CVE、路径、参数和行为证据构造专项列表并运行 targeted templates。
- `summary.json` 只证明本轮选定的 live/priority scanner input 正常走到 consolidation；
  不表示历史 URL 全量扫描、tested-clean、目标安全或攻击面耗尽。
  killed/stopped/timeout/non-zero 都是 incomplete，不得解释为零发现或 scanner complete。

## 7. IMPACT-FIRST HUNTING

Ask: "What's the worst thing that could happen if auth was broken here?"

If the answer is "nothing valuable" → lower priority for now, but preserve the
feature if it can connect to auth, roles, objects, payments, admin/config,
exports, integrations, or another chain step.
If the answer is "admin access, PII exfil, fund theft" → hunt there.

## 8. HUNT LESS-SATURATED BUG CLASSES

Bug bounty / VAPT prioritization only:

High competition (deprioritize unless target-specific): XSS, SSRF basics, open redirect alone
Low competition: Cache poisoning, race conditions, business logic, HTTP smuggling, CI/CD

This is an ordering heuristic, not a persistent exclusion. For local / CTF / lab targets,
do not add skips because a bug class is common, noisy, or was skipped on a
previous target.

## 9. DEPTH OVER BREADTH

One target deeply understood > ten targets shallowly tested.

```
Read disclosed reports on demand when target, technology, or workflow evidence
suggests they can change the current hypothesis; do not block hunting on an
arbitrary report count
Understand the business domain
Map the crown jewels (what would hurt the company most?)
```

## 10. THE SIBLING RULE

Check a bounded set of evidence-linked siblings. Derive them from a shared
handler, object/action family, browser traffic, JS/source route, or API docs;
do not brute-force every guessed sibling merely because its name is plausible.

This rule explains 30% of all paid IDOR/auth bugs.

## 11. A→B SIGNAL METHOD

When you confirm bug A → stop → hunt for B and C before writing the report.

A confirmed bug = signal that the developer made a class of mistake.
They made it elsewhere too. Finding B costs 10x less than finding A.

Time-box: 20 minutes on B. If not confirmed, keep B as a chain candidate only
when it has a concrete next evidence action, report A only if A is validated,
and move on.

## 12. NEW == UNREVIEWED

Features < 30 days old have the lowest security maturity.
Monitor GitHub commits. Hunt new features first.

## 13. PAYMENT LANE REQUIRES SIDE-EFFECT CONTROL, NOT DEFAULT SKIP

Payment, billing, refund, credit, wallet, coupon, gift-card, and fund-transfer
workflows are high-value attack surfaces. Explore their objects, authorization,
state transitions, previews, calculations, and test-owned reversible flows.
Require the applicable red-line confirmation before a real charge, refund,
transfer, balance mutation, or other irreversible side effect; do not turn that
side-effect gate into a blanket skip of the lane.

## 14. 20-MINUTE ROTATION RULE

Every 20 min ask: "Am I making progress?"
No → rotate to next endpoint, subdomain, or vuln class.
Fresh context finds more bugs than brute force.

## 15. BUSINESS IMPACT > VULN CLASS

Clickjacking is usually $0 but MetaMask paid $120K for one.
Ask: "What's the business impact?" before estimating severity.

## 16. VALIDATE BEFORE WRITING

Run /validate before starting a report. Gate 0 is 30 seconds.
It takes 30 seconds to reject a bad report candidate. A report takes 30
minutes to write. This strictness protects `/report`; it must not erase useful
exploration leads that still have a clear next evidence step.

## 17. CREDENTIAL LEAKS NEED EXPLOITATION PROOF

Finding an API key = Signal, not a report by itself.
Proving a target-owned key is valid and creates real security impact can become
Medium/High, depending on usable permissions and target impact.

Do minimal validity/permission proof, then decide whether it is a Candidate. Do not
treat "leakage risk" as the objective; hunt for a concrete vulnerability and
impact path.

## 18. MOBILE = DIFFERENT ATTACK SURFACE

Mobile apps expose endpoints that the web app doesn't. Always decompile the APK/IPA when the app or mobile API is part of the supplied target context:
- Hardcoded secrets in `strings` output that web recon never finds
- API endpoints in decompiled source that aren't in the web JS
- Deep-link handlers with injection points
- WebView `addJavascriptInterface` = JS→Java bridge (RCE on API < 17)
- Certificate pinning bypass via Frida/objection → MitM all traffic

```bash
# Quick check without rooted device
apktool d target.apk -o target_src
grep -rn "api_key\|secret\|password\|token\|Authorization\|Bearer" target_src/ --include="*.smali" --include="*.xml"
grep -rn "https://" target_src/ | grep -v "schema\|xmlns\|android\|google" | head -50
```

## 19. CI/CD IS ATTACK SURFACE

GitHub Actions / GitLab CI pipelines often have critical secrets. Check BEFORE writing any report on a target with public repos.

```bash
# Clone target's public GitHub org repos, then:
find . -name "*.yml" -path "*/.github/workflows/*" | xargs grep -l "pull_request_target\|secrets\."

# Key dangerous patterns:
# 1. pull_request_target + checkout of PR branch = attacker code runs with repo secrets
# 2. ${{ github.event.issue.title }} in run: block = expression injection = secret exfil
# 3. artifact download without hash check = artifact poisoning
# 4. self-hosted runners = escape to org infrastructure
```

**Expression injection validation posture:**

Do not default to secret exfiltration. First prove the workflow command-injection
or expression-injection boundary with non-sensitive output, a controlled marker,
or a dry-run/test repository when available. Escalate to secret or privileged
workflow proof only when lower-risk evidence cannot establish impact, the current
target context allows it, and `rules/red-lines.md` passes.

If workflow command execution with access to org secrets is proven → likely
Critical impact. Keep the PoC minimal, preserve logs, and avoid leaking real
secret values unless that is the only necessary proof path.

## 20. SAML / SSO = HIGHEST AUTH BUG DENSITY

SAML implementations are notoriously buggy. If target uses SSO, always test:
- XML signature wrapping (XSW) — valid signature, injected assertion
- Comment injection — `admin<!---->@company.com` = sign as admin
- XML external entity in SAML assertion
- Signature stripping (remove signature, server still accepts)
- NameID manipulation — change email in unsigned field

```bash
# Capture SAML assertion (base64 decode from SAMLResponse parameter)
echo "SAMLResponse_VALUE" | base64 -d | xmllint --format -

# Test comment injection in NameID
# Change: <NameID>user@company.com</NameID>
# To:     <NameID>admin<!---->@company.com</NameID>
# Or:     <NameID Format="...">admin@company.com</NameID> (duplicate element)
```

> SAML bugs frequently pay High–Critical because they enable SSO bypass across the entire platform.
