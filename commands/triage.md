---
description: Quick 7-Question Gate triage on a report candidate before writing a report. Rejects N/A submissions before they happen. Faster than /validate — for quick go/no-go decisions. Usage: /triage
---

# /triage

Quick triage to decide: report, downgrade, or keep hunting?

## When to Use

Use this before spending time writing a full report. If triage passes, run
`/validate` for the full 4-gate check, then `/report`. Do not use `/triage`
as an early exploration kill-switch for raw leads, anomalies, hypotheses, or
chain seeds.

## Usage

```
/triage
```

Describe the finding in one sentence. Example:
- "I can read other users' orders by changing user_id in /api/orders/{id}"
- "The /api/export endpoint returns 200 with data even with no auth header"
- "I found X-Forwarded-Host is reflected in the password reset email"

## Validation Contract

Read `skills/triage-validation/SKILL.md` before deciding. It is the sole owner
of the Q1-Q7, Q7b identity-boundary, never-submit/chain, and four-gate rules;
this command is only their fast, protocol-neutral entrypoint. Use any
target-bound reproducible evidence artifact, not an HTTP-only shortcut. For
authenticated candidates, record the Q7b identity boundary and use the
lowest-risk evidence that answers the impact question; there is no universal numeric cutoff.
Report-path evidence must be `Confirmed with a target-bound replayable artifact`.
For external delivery, external disclosed-report checks are performed; record
them as not applicable for local/lab delivery.

## Output

**GO:** "All 7 pass. Run /validate for full check, then /report."

**KILL [reason]:**
- "Q1 fails — no target-bound reproducible artifact yet"
- "Q4 fails — the required precondition is unreachable or out of scope"
- "Q7 fails — open redirect alone is not submittable. Chain it with OAuth theft first."

**DOWNGRADE:**
- "Q6 — the current artifact does not prove the claimed impact. Collect the lowest-risk missing differential before reporting."
