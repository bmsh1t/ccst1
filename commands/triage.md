---
description: "Advisory 7-Question Gate triage on a report candidate from its description and evidence. Gives a quick go/no-go without recording validation or publishing a report. Usage: /triage"
---

# /triage

Quick advisory triage to decide: validate, downgrade, or keep hunting?

## When to Use

Use this when a quick review will change whether to prepare a full decision.
It records no assessment or publication and is optional before `/validate`.
If triage passes, select the existing Store Finding and follow `/validate`.
Single-step success already publishes its authored report; deferred text or a
new delivery need uses `/report`. Do not use `/triage`
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

Read `skills/src-hunter/modules/triage-validation.md` before deciding. It is the sole owner
of the Q1-Q7, Q7b identity-boundary and never-submit/chain rules;
this command is only their fast, protocol-neutral entrypoint. Use any
target-bound reproducible evidence artifact, not an HTTP-only shortcut. For
authenticated candidates, record the Q7b identity boundary and use the
lowest-risk evidence that answers the impact question; there is no universal numeric cutoff.
Report-path evidence must be `Confirmed with a target-bound replayable artifact`.
For external delivery, external disclosed-report checks are performed; record
them as not applicable for local/lab delivery.

## Output

**GO:** "Evidence supports validation. Run /validate and consume its receipts;
use /report when deferred text or a new delivery is needed."

**KILL [reason]:**
- "Q1 fails — no target-bound reproducible artifact yet"
- "Q4 fails — the required precondition is unreachable or out of scope"
- "Q7 fails — open redirect alone is not submittable. Chain it with OAuth theft first."

**DOWNGRADE:**
- "Q6 — the current artifact does not prove the claimed impact. Collect the lowest-risk missing differential before reporting."
