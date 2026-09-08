# Reporting Rules

This file owns cross-cutting reporting checks and scoring calibration.
`skills/triage-validation/SKILL.md` owns validation verdicts;
`skills/report-writing/SKILL.md` owns presentation, delivery modes, titles,
word budgets, and follow-up wording. Do not maintain another format here.

---

## 1. Claim Presentation

Apply the Writing Rules in `skills/report-writing/SKILL.md`. Unproven impact
stays an evidence gap, not a stronger claim created during report drafting.

## 2. RUN 7-QUESTION GATE BEFORE WRITING

Apply Q1-Q7 and the four gates in `skills/triage-validation/SKILL.md` before
reporting. That Skill owns REPORT, CHAIN_REQUIRED, DOWNGRADE, and DO_NOT_REPORT
precedence; this file does not redefine the verdict.

## 3. ALWAYS INCLUDE PROOF OF CONCEPT

The PoC must prove real impact, but it should use the lowest-risk evidence that
answers the triager's question. Do not hard-ban stronger proof: when minimal
proof is not enough to establish impact, escalate deliberately and document why.

Default proof ladder:

- IDOR → show authorization boundary failure with two actors and private data
  evidence; minimize copied victim data to the smallest field/sample needed.
- XSS → show execution in the affected security context; cookie/session proof is
  only needed when it changes impact and the test is authorized and contained.
- SSRF → show server-side fetch impact beyond DNS-only, such as a safe internal
  endpoint response, controlled callback metadata, or non-sensitive service
  fingerprint.
- SQLi → show query control with safe read-only evidence first, such as boolean
  diff, bounded row count, DB fingerprint, current user/version, or a controlled
  marker. Extract actual table data only when it is necessary, authorized, and
  minimized.
- Secret / CI/CD / cloud → prove ownership and usable permissions with the least
  sensitive action. Secret exfiltration, privileged workflow execution, or cloud
  data access is reserved for cases where lower-risk proof cannot establish
  impact and `rules/red-lines.md` allows the action.

Escalated proof requirements:

1. Explain why lower-risk proof is insufficient.
2. Keep scope to test accounts, test resources, non-sensitive metadata, or the
   smallest necessary data sample.
3. Preserve exact request/response or workflow evidence.
4. Record cleanup or rollback steps when state changes are involved.

A "technically possible" finding without PoC is an Informational at best; an
unnecessarily invasive PoC is also a bad report.

## 4. STRUCTURED CVSS IS THE SCORING OWNER

Don't claim Critical for a Medium bug. Triagers trust you less for every overclaim.
Don't claim Medium for a Critical — you're leaving money on the table.

`tools/validate.py` is the only scoring producer. Reports must render the
selected finding's recorded `cvss.version`, `cvss.score`, and `cvss.vector` from
its validation summary. Legacy CVSS 3.1 records remain readable, but prose,
templates, and model estimates must not recalculate or overwrite a stored
result. Any examples elsewhere are calibration references only.

### CVSS 3.1 Calibration Reference

These examples calibrate common claims only. They never override the structured
score recorded by `tools/validate.py`.

| Finding | Score | Severity | Vector |
|---|---:|---|---|
| IDOR read PII, any user, auth required | 6.5 | Medium | AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N |
| IDOR write/delete, any user | 8.1 | High | AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N |
| Auth bypass → admin panel | 9.8 | Critical | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H |
| Stored XSS → cookie theft, stored | 8.5 | High | AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:N |
| SQLi → full DB dump | 9.1 | Critical | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N |
| SSRF → cloud metadata | 10.0 | Critical | AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N |
| Race → double spend | 6.8 | Medium | AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:N |
| GraphQL auth bypass | 8.1 | High | AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N |
| JWT none algorithm | 9.8 | Critical | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H |

Use the observed preconditions and demonstrated impact to select metrics; do not
infer severity from a bug-class name or a scanner label.

## 5. NEVER SUBMIT FROM THE ALWAYS-REJECTED LIST

Use the NEVER SUBMIT list and Q7 chain precedence in
`skills/triage-validation/SKILL.md`; do not maintain a second class list here.

## 6. VERIFY DATA ISN'T ALREADY PUBLIC

Before submitting an information disclosure finding:
1. Open the target in an incognito browser (not logged in)
2. Can you see the same data without authentication?
3. If yes → not a bug

## 7. TWO TEST ACCOUNTS FOR IDOR

Never test IDOR with only one account (testing yourself).
- Account A = attacker (your account doing the request)
- Account B = victim (whose data you're reading)

For an identity-boundary claim, report must show the smallest reproducible
actor/object differential, for example: Account A's session reached Account B's
private object. Use an equivalent artifact when the boundary is not HTTP.

## 8. Delivery

Use `skills/report-writing/SKILL.md` for platform structure, title wording,
length, independent submissions, and clarification responses. Delivery choices
do not change the validation result, recorded CVSS, or evidence requirements.
