---
name: triage-validation
description: Finding validation before writing any report — 7-Question Gate (all 7 questions), 4 pre-submission gates, always-rejected list, conditionally valid with chain table, CVSS 3.1 quick reference, severity decision guide, report title formula, and pre-submit checklist. Use BEFORE writing any report. Route complete evidence to REPORT, missing connectors to CHAIN_REQUIRED, impact-only gaps to DOWNGRADE, and failed reportability gates to DO_NOT_REPORT without erasing exploration context.
---

# TRIAGE & VALIDATION

Any non-pass stops the current claimed report or severity. Route it explicitly
to CHAIN_REQUIRED, DOWNGRADE, or DO_NOT_REPORT; keep a Lead/Signal only when a
concrete next evidence action remains.

The seven questions and four gates are evidence gates, not a timer or a global
coverage claim. A gate passes only when the target identity, request/response,
impact, and reproducibility required by that gate are present. Elapsed time alone never makes a Candidate report-ready, validated, rejected, or complete;
preserve the current evidence and next action when a bounded review is
interrupted.

## 四层记忆接入

本 Skill 是 Candidate 到 Validated Finding 的质量 gate。执行时遵守 `skills/runtime-protocol.md`：

1. 先读取目标层，确认 Candidate 对应的 target、surface、evidence 和 next action。
2. 只验证 Candidate，不把普通 Lead 强行包装成报告。
3. 如需补充漏洞类别判断，按需读取 `knowledge/index.md` 和相关知识卡。
4. 验证失败时写回目标层为 lead、dead-end 或 next action；验证通过后再进入 `/remember` 和报告流程。

---

## SCOPE OF THIS SKILL

Use this skill when a possible issue is being promoted toward a report:

```text
Lead -> Signal -> Candidate -> Validated Finding -> Report
```

- Exploration/hunt may keep plausible leads, anomalies, hypotheses, and chain
  seeds.
- `/triage` and `/validate` act on Candidates and decide whether they become
  Validated Findings.
- A failed reportability gate means **do not report** the current claim. A Q6
  proof gap may instead downgrade the demonstrated primitive, and a Q7 chain
  gap may remain CHAIN_REQUIRED.
- Chain seeds on the never-submit list stay chain candidates when there is a
  specific next hop to prove.

---

## THE 7-QUESTION GATE

Ask IN ORDER. A non-pass stops the current claim, then routes by meaning:

- Q1-Q5 failure, or Q7 with no valid chain path → **DO_NOT_REPORT**.
- Q6 proves only a lower impact → **DOWNGRADE** to that demonstrated impact.
- Q7 has a concrete but unproven connector → **CHAIN_REQUIRED**.
- All required evidence passes → **REPORT**.

---

### Q1: Can an attacker reproduce this RIGHT NOW, step by step?

Complete this template:
```
1. Setup:   I need [own account / another user's ID / no account]
2. Artifact: [request/response, browser trace, frame, state transition, OOB artifact, or equivalent replayable record]
3. Result:  I can [read / modify / delete / trigger] [exact observed result]
4. Impact:  The real-world consequence is [account takeover / PII read / money stolen]
5. Effort:  Preconditions are [auth/no-auth/role/object ID], with [single request / multi-step flow]
```

**If the artifact is not target-bound and reproducible → keep the Candidate open and record the missing evidence action; do not treat the wire format alone as a rejection.**

---

### Q2: Is the impact concrete and clearly demonstrated?

Use the supplied target as the active target record. Use observed exploitability,
evidence, and reproducibility as the validation basis.

Common tiers:
- **Critical**: Any-user ATO without interaction, RCE, SQLi with data exfil, admin auth bypass
- **High**: Mass PII exfil, privilege escalation, internal SSRF with data, stored XSS all users
- **Medium**: IDOR on specific user non-critical data, XSS on sensitive page requiring click
- **Low**: Non-sensitive info disclosure, clickjacking with PoC

**If the impact is still vague or only theoretical → DO NOT REPORT.**

---

### Q3: Is the root cause tied to the supplied target context?

Confirm:
- Vulnerable domain / URL / workflow matches the supplied target set
- The path being validated is the one you actually tested
- The root cause is not just borrowed from an unrelated dependency description

**If the candidate drifts away from the supplied target context → DO NOT REPORT.**

---

### Q4: Are the attacker preconditions reachable and in scope?

- Record the exact account, role, device, victim action, or prior state required.
- An admin-only action is not an authorization break by itself; a lower-privileged
  or unauthenticated actor crossing that boundary can be valid when reproduced.
- Physical access, an MFA device, or a test-owned/compromised account is not an
  automatic rejection; evaluate reachability, scope, user interaction, and impact.
- Multiple steps are acceptable when each transition is reproducible and the
  claimed impact depends on the complete flow.

---

### Q5: Is this already known or accepted behavior?

Search:
1. For an external bounty submission, check the program's disclosed reports and
   target-repository security issues for the endpoint and bug class.
2. For every delivery mode, check the target's changelog, API docs, and design
   docs for documented behavior.
3. For local/lab work, record external-program checks as not applicable rather
   than treating their absence as a validation failure.

**If acknowledged/design decision → DO NOT REPORT.**

---

### Q6: Can you prove impact beyond "technically possible"?

- Use the lowest-risk artifact that answers the impact question:
  - XSS → show execution in the affected security context; cookie/session proof
    is only needed when it changes the demonstrated impact and is contained.
  - SSRF → show server-side fetch impact beyond DNS-only, such as a safe
    internal response, non-sensitive fingerprint, or controlled callback data.
  - SQLi → show safe read-only query control first (boolean/result/error/timing
    differential); extract table data only when necessary and allowed.
  - IDOR → show the smallest private field or state delta needed to prove the
    identity boundary, not an unnecessarily broad data copy.

**If you can only show "technically possible" → DOWNGRADE severity, not kill.**

---

### Q7: Is this a known-invalid bug class?

Check the NEVER SUBMIT list below, then route with this precedence:

1. On NEVER SUBMIT **and** it also appears in the CONDITIONALLY VALID chain
   table, **and** the candidate already demonstrates the full chain end to end
   → **REPORT** at the chained severity.
2. On NEVER SUBMIT **and** chain-eligible, chain **not yet built** but a
   concrete next hop exists (e.g., open redirect + an OAuth `redirect_uri` to
   test) → **CHAIN_REQUIRED**, not DO_NOT_REPORT. Build and prove the chain first.
3. On NEVER SUBMIT, not chain-eligible, or no concrete next hop
   → **DO NOT REPORT.**

"Standalone / alone" in the NEVER SUBMIT list means the primitive **by itself**
is not reportable — it does not forbid the chained finding. The CONDITIONALLY
VALID table lists common chain shapes, not an exhaustive allowlist; an
evidence-backed connector outside the table remains eligible for review.

---

### Q7b: Verify the identity boundary

For authenticated candidates, record at minimum:

```text
1. Session ID used
2. Identity role (attacker / victim / low-priv / high-priv)
3. Anonymous repro result
4. Cross-identity repro result
5. Logged-out or stale-session repro result
```

IDOR/BOLA must cross a real identity boundary, priv-esc must work from the
lower-privileged identity, and auth bypass must survive without a valid session.
Use `session_id` / audit artifacts to confirm the same request under each identity.

---

## 4 PRE-SUBMISSION GATES

Run in sequence. Every applicable gate must pass. Gate 2 is delivery-mode
conditional: external bounty metadata is required only for external submission;
local/lab validation must still record the target-local documentation checks.

### Gate 0: Reality Check
Use Q1's reproduction record as the source of truth: require a target-bound
replayable artifact, target match, fresh reproducibility, and the appropriate
evidence medium. Do not repeat the Q1 template here.

### Gate 1: Impact Validation
```
[ ] Can answer: "What can attacker DO that they couldn't before?"
[ ] Answer is more than "see non-sensitive data" (unless program pays for info disclosure)
[ ] Real victim: another user's data, company's data, financial loss
[ ] Not relying on victim doing something unlikely
```

### Gate 2: Deduplication Check
```
[ ] External submission: searched the program's disclosed reports and target-repo
    security issues for this endpoint and bug class
[ ] All modes: checked changelog, API/design docs, and recorded whether behavior
    is documented or intentionally accepted
[ ] Local/lab: external bounty checks recorded as not applicable, not as a blocker
```

### Gate 3: Report Quality
```
[ ] Title: [Bug Class] in [Endpoint] allows [actor] to [impact]
[ ] Steps to Reproduce: exact replayable artifact (HTTP when applicable; browser, frame, state, or OOB equivalent otherwise)
[ ] Evidence: target-bound artifact showing the actual impact (not just a status code)
[ ] Severity: matches the recorded `cvss.version`/`cvss.score`/`cvss.vector` and program definitions
[ ] NEVER used "could potentially" or "may allow"
```

---

## NEVER SUBMIT LIST

Submitting these destroys your validity ratio.

> **Routing note:** Items below marked "alone / standalone / without ..." are
> chain-eligible — see the CONDITIONALLY VALID table. Apply Q7 precedence: a
> demonstrated chain → REPORT; a concrete-but-unbuilt chain → CHAIN_REQUIRED;
> only a bare primitive with no next hop → DO NOT REPORT.

```
Missing CSP / HSTS / security headers
Missing SPF / DKIM / DMARC
GraphQL introspection alone (no auth bypass, no IDOR demonstrated)
Banner / version disclosure without working CVE exploit
Clickjacking on non-sensitive pages (no sensitive action PoC)
Tabnabbing
CSV injection (no actual code execution shown)
CORS wildcard (*) without credential exfil proof of concept
Logout CSRF
Self-XSS (only exploits own account)
Open redirect alone (no ATO or OAuth theft chain)
OAuth client_secret in mobile app (known, expected)
SSRF DNS callback only (no internal service access or data)
Host header injection alone (no password reset poisoning PoC)
Rate limit on non-critical forms (search, contact, login with Cloudflare)
Session not invalidated on logout
Concurrent sessions
Internal IP in error message
Mixed content
SSL weak ciphers
Missing HttpOnly / Secure cookie flags alone
Broken external links
Autocomplete on password fields
Pre-account takeover (usually — very specific conditions required)
```

---

## CONDITIONALLY VALID — CHAIN REQUIRED

Build the chain first, prove it works end to end, THEN report.

> If the candidate **already** proves the chain end to end, it is no longer
> "chain required" — verdict is **REPORT** at the Valid Result severity. Use
> **CHAIN_REQUIRED** only when the connecting hop still needs to be built.

| Standalone Finding | Chain Required | Valid Result |
|---|---|---|
| Open redirect | + OAuth redirect_uri → auth code theft | ATO (Critical) |
| Clickjacking | + sensitive action + working PoC | Medium |
| CORS wildcard | + credentialed request exfils user PII | High |
| CSRF | + sensitive non-payment action (change email, delete account) | High |
| Rate limit bypass | + OTP/reset token brute force succeeds | Medium/High |
| SSRF DNS-only | + internal service access + data returned | Medium |
| Host header injection | + password reset email uses injected host | High |
| Prompt injection | + reads other user's data (IDOR) | High |
| S3 bucket listing | + JS bundles contain API keys or OAuth secrets | Medium/High |
| Self-XSS | + CSRF to trigger it on victim without their knowledge | Medium |
| Subdomain takeover | + OAuth redirect_uri registered at that subdomain | Critical |
| GraphQL introspection | + auth bypass mutation or IDOR on node() | High |

---

## Scoring Reference

`tools/validate.py` writes the structured `cvss` result consumed by reports.
Calibration rows and metric guidance live in `rules/reporting.md`; this Skill
only decides whether the demonstrated impact is ready for scoring.

---

## PRE-SEVERITY GATE

Before assigning **High** or **Critical**, record all four:

1. **Complete chain** — attacker precondition → primitive → connector → final outcome.
2. **Concrete outcome** — exact affected identity, data, privilege, money, or system control.
3. **Repeatability** — reproduce from a fresh session/state and preserve the replay evidence.
4. **Remaining boundary** — state what is still untested, assumed, environment-specific, or role-dependent.

Route incomplete claims without inventing a new gate status:

- A missing connector required to make the primitive reportable → **CHAIN_REQUIRED**.
- A valid primitive whose claimed impact is not yet proven → **DOWNGRADE** to the demonstrated outcome.
- A bug-class name, scanner severity, theoretical blast radius, or unbuilt chain never justifies High/Critical by itself.

This calibrates severity after Q1-Q7; it does not erase the Candidate or create Q8.

---

## RETRACTION DISCIPLINE

If later replay disproves a report-ready or validated Candidate:

1. Preserve the original signal, request, response, and evidence references; do not overwrite or delete them.
2. Attach the disproving evidence and the exact control/test difference, including identities, sessions, and relevant state.
3. Record the false-positive cause and decision date in the validation evidence.
4. Use the canonical finding owner to set `validation_status=rejected`; retain the prior validation summary, digest, and owner provenance.
5. Reopen only when new evidence directly addresses the recorded cause, and link the old and new evidence.

Retraction is an auditable correction, not silent removal of an inconvenient result.

对于源码支持的 Candidate，只用文字声称 guard 存在不足以构成反证。canonical owner 写入
`validation_status=rejected` 前，必须绑定 `result=rejected` 的 validation summary，并在
`source_guard` 中记录真实 `source_file`、从 1 开始的 `line_number` 和单行精确 `quote`。
quote 必须是该行可执行、具有 guard 形态的代码；文件缺失、注释、转述或仅引用共同 token
时，Candidate 必须保持开放。该 cite-check 只证明引用的 guard 确实存在；验证记录仍需单独
解释它为何阻断所声称的 source-to-sink 路径。

---

## FAST NO-REPORT RULES

Use the gates above as the detailed check. The short form is:

1. **Evidence-completeness rule**: an incomplete Q1 stays a Candidate with a next evidence action.
2. **Precondition and impact**: record reachability and a tangible demonstrated outcome.
3. **Admin/design checks**: admin-only behavior or documented behavior is not a report by itself.
4. **Repeated bounded failure**: a repeated progress fingerprint without a reproducible PoC stops the report path and records what would reopen it.

---

Report-writing anti-patterns and title guidance are owned by `rules/reporting.md`;
this Skill stops at the validation verdict and write-back decision.
