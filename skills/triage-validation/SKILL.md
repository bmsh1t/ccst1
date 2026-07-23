---
name: triage-validation
description: Finding validation before writing any report — 7-Question Gate (all 7 questions), 4 pre-submission gates, always-rejected list, conditionally valid with chain table, CVSS 3.1 quick reference, severity decision guide, report title formula, 60-second pre-submit checklist. Use BEFORE writing any report. Route complete evidence to REPORT, missing connectors to CHAIN_REQUIRED, impact-only gaps to DOWNGRADE, and failed reportability gates to DO_NOT_REPORT without erasing exploration context.
---

# TRIAGE & VALIDATION

Any non-pass stops the current claimed report or severity. Route it explicitly
to CHAIN_REQUIRED, DOWNGRADE, or DO_NOT_REPORT; keep a Lead/Signal only when a
concrete next evidence action remains.

## 四层记忆接入

本 Skill 是 Candidate 到 Validated Finding 的质量 gate。执行时遵守 `skills/runtime-protocol.md`：

1. 先读取目标层，确认 Candidate 对应的 target、surface、evidence 和 next action。
2. 只验证 Candidate，不把普通 Lead 强行包装成报告。
3. 如需补充漏洞类别判断，按需读取 `knowledge/index.md` 和相关知识卡。
4. 如果验证需要状态改变、真实数据修改、高频请求或破坏性动作，必须先按 `rules/red-lines.md` 降级或暂停。
5. 验证失败时写回目标层为 lead、dead-end 或 next action；验证通过后再进入 `/remember` 和报告流程。

> "N/A hurts your validity ratio. Informative is neutral. Only submit what passes all 7 questions."

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

### Q1: Can an attacker use this RIGHT NOW, step by step?

Complete this template:
```
1. Setup:   I need [own account / another user's ID / no account]
2. Request: [exact HTTP method, URL, headers, body — copy-paste ready]
3. Result:  I can [read / modify / delete] [exact data shown in response]
4. Impact:  The real-world consequence is [account takeover / PII read / money stolen]
5. Effort:  Preconditions are [auth/no-auth/role/object ID], with [single request / multi-step flow]
```

**If you CANNOT write step 2 as a real HTTP request → DO NOT REPORT.**

---

### Q2: Is the impact concrete and clearly demonstrated?

For local, lab, or supplied target-set runs, use the supplied target as the
active target record. External policy text and accepted-vulnerability lists are
non-applicable. Use task rules and observed exploitability instead; if no
task-specific exclusions exist, continue to evidence and reproducibility checks.
Keep that coverage independent from bug bounty/VAPT scope, method, rate,
cooldown, or impact-category gates.

Common tiers:
- **Critical**: Any-user ATO without interaction, RCE, SQLi with data exfil, admin auth bypass
- **High**: Mass PII exfil, privilege escalation, internal SSRF with data, stored XSS all users
- **Medium**: IDOR on specific user non-critical data, XSS on sensitive page requiring click
- **Low**: Non-sensitive info disclosure, clickjacking with PoC

**If the impact is still vague or only theoretical → DO NOT REPORT.**

---

### Q3: Is the root cause tied to the supplied target context?

For local, lab, or supplied target-set runs, the provided target, IP, CIDR, or
host list is the active target context. Do not kill a finding because there is
no external bug bounty policy page or ownership notes.

Confirm:
- Vulnerable domain / URL / workflow matches the supplied target set
- The path being validated is the one you actually tested
- The root cause is not just borrowed from an unrelated dependency description

**If the candidate drifts away from the supplied target context → DO NOT REPORT.**

---

### Q4: Does it require privileged access that an attacker can't realistically get?

- "Admin can do X" = centralization risk = **DO NOT REPORT** (on 99% of programs)
- "Non-admin can do X that only admin should do" = valid
- "Requires physical access / MFA device" = usually invalid
- "Requires compromised victim account to work" = questionable, low severity at best

---

### Q5: Is this already known or accepted behavior?

Search:
1. Program's HackerOne/Bugcrowd disclosed reports: Ctrl+F endpoint name + bug class
2. GitHub issues on target repo: `is:issue label:security ENDPOINT_NAME`
3. Changelog/CHANGELOG.md — does it mention this behavior?
4. API docs / design docs — is it documented as intended?

**If acknowledged/design decision → DO NOT REPORT.**

---

### Q6: Can you prove impact beyond "technically possible"?

- XSS → show actual cookie theft or session hijack, not just `alert(1)` or `alert(document.domain)`
- SSRF → hit an internal endpoint that returns data, not just DNS ping
- SQLi → show actual data exfil from a real table, not just error message
- IDOR → show actual other-user's data in response, not just a 200 status code

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
is not reportable — it does not forbid the chained finding. Chain eligibility is
defined by the CONDITIONALLY VALID table below.

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

Run in sequence. ALL 4 must PASS.

### Gate 0: Reality Check (30 seconds)
```
[ ] Bug is REAL — confirmed with actual HTTP requests, not code reading alone
[ ] Bug matches the supplied target context
[ ] Reproducible from scratch — can reproduce starting from fresh session
[ ] Evidence ready — screenshot, response body, or video
```

### Gate 1: Impact Validation (2 minutes)
```
[ ] Can answer: "What can attacker DO that they couldn't before?"
[ ] Answer is more than "see non-sensitive data" (unless program pays for info disclosure)
[ ] Real victim: another user's data, company's data, financial loss
[ ] Not relying on victim doing something unlikely
```

### Gate 2: Deduplication Check (5 minutes)
```
[ ] Searched HackerOne Hacktivity for this program + similar bug title/endpoint
[ ] Searched GitHub issues for target repo
[ ] Read most recent 5 disclosed reports for this program
[ ] Not a "known issue" in their changelog or public docs
[ ] Google: "TARGET_NAME ENDPOINT_NAME bug bounty"
```

### Gate 3: Report Quality (10 minutes)
```
[ ] Title: [Bug Class] in [Endpoint] allows [actor] to [impact]
[ ] Steps to Reproduce: copy-pasteable HTTP request
[ ] Evidence: screenshot/video of actual impact (not just 200 status)
[ ] Severity: matches CVSS 3.1 score AND program's severity definitions
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

## CVSS 3.1 QUICK REFERENCE

### Common Score Examples

| Finding | Score | Severity | Vector |
|---|---|---|---|
| IDOR read PII, any user, auth required | 6.5 | Medium | AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N |
| IDOR write/delete, any user | 8.1 | High | AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N |
| Auth bypass → admin panel | 9.8 | Critical | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H |
| Stored XSS → cookie theft, stored | 8.5 | High | AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:N |
| SQLi → full DB dump | 9.1 | Critical | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N |
| SSRF → cloud metadata | 10.0 | Critical | AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N |
| Race → double spend | 6.8 | Medium | AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:N |
| GraphQL auth bypass | 8.1 | High | AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N |
| JWT none algorithm | 9.8 | Critical | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H |

### Metric Quick Guide

| What you have | Metric | Value |
|---|---|---|
| Exploitable over internet | AV | Network (N) |
| No special timing or race | AC | Low (L) |
| Free account needed | PR | Low (L) |
| No login needed | PR | None (N) |
| Admin needed | PR | High (H) |
| No victim action | UI | None (N) |
| Victim must click | UI | Required (R) |
| Reads all data | C | High (H) |
| Reads some data | C | Low (L) |
| Modifies all data | I | High (H) |
| Crashes service | A | High (H) |
| Affects only app | S | Unchanged (U) |
| Affects browser/OS/cloud | S | Changed (C) |

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

The goal is to QUICKLY disqualify bad report candidates so you hunt real bugs:

1. **5-minute rule**: If you can't fill in Q1's template in 5 minutes → move on
2. **Precondition count**: More than 2 preconditions simultaneously required → do not report
3. **Impact test**: "What does attacker walk away with?" — if nothing tangible → do not report
4. **Admin bypass**: "Admin can do X" is NEVER a bug → do not report
5. **Design doc test**: If it's documented behavior → do not report
6. **Rabbit hole signal**: 30+ min on Q6 with no reproducible PoC → stop the report path

---

## ANTI-PATTERNS THAT LOSE MONEY

```
Writing a report before confirming the bug exists (most common)
Submitting theoretical impact without proof
"The API returns more fields than necessary" (sensitivity matters — is it actually sensitive?)
Chaining A+B into one report when they're separate bugs (two separate payouts)
Reporting B saying "similar to A in my other report" — fresh Gate 0 for every bug
Overclaiming severity — triagers trust you less next time
Under-describing impact — triager doesn't understand why it matters
```
