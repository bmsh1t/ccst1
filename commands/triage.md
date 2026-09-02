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

## The 7 Questions (Fast Version)

Use `skills/triage-validation/SKILL.md` as the contract owner. This shortcut
keeps the same verdicts but accepts any target-bound reproducible evidence
artifact; it is not a second HTTP-only gate.

Answer YES or NO to each. First NO = stop the report path immediately.

```
Q1: Can I reproduce this RIGHT NOW with a target-bound artifact?
    YES: I have request/response, browser, frame, state, OOB, or equivalent replay evidence
    NO: I need one concrete evidence action first → keep the candidate open

Q2: Is the impact concrete and clearly demonstrated?
    YES: Actual user/data/action impact is shown
    NO: Only theoretical or policy-only framing → KILL

Q3: Is the vulnerable asset tied to the supplied target context?
    YES: Domain / URL / workflow matches the current target set
    NO: The finding drifted away from the supplied target → KILL

Q4: Are the attacker preconditions reachable and in scope?
    YES: Record the exact account, role, device, victim action, or prior state
    NO: The required boundary is unreachable or out of scope → KILL Q4

Q5: Is this NOT already known/disclosed/documented behavior?
    YES: Not documented in target materials; external disclosed-report checks are
         performed when the delivery mode is an external bounty submission
    NO: It's documented as intended → KILL

Q6: Can I prove impact beyond "technically possible" with the lowest-risk evidence?
    YES: The smallest necessary data, state, execution, or callback differential is shown
    NO: I only have a status, error, or weak signal → DOWNGRADE or record the next proof action

Q7: Is this NOT on the never-submit list?
    YES: It's a real bug class
    NO: Missing headers, self-XSS, open redirect alone, etc. → KILL or CHAIN
```

For authenticated candidates, record the Q7b identity boundary before GO:

```text
Session ID, actor role, anonymous result, cross-identity result, and
logged-out/stale-session result. For unauthenticated candidates, record why
the identity-boundary check is not applicable.
```

## Fast No-Report Checklist

Do not report immediately if ANY of these are true:
```
[ ] An admin-only action is not an authorization break unless a lower boundary is crossed
[ ] "Could theoretically lead to..." = no PoC = not a bug
[ ] Preconditions are recorded with reachability and scope; there is no numeric cutoff
[ ] Finding is a missing header, missing flag, missing DMARC
[ ] SSRF with DNS callback only, no data returned
[ ] Open redirect with no OAuth chain or ATO path
[ ] Self-XSS (only affects your own account)
[ ] Introspection only (no IDOR, no auth bypass shown)
[ ] Rate limit on login/contact/search (Cloudflare covers it)
```

## Conditional Chain Required

If it's on the never-submit list BUT you can chain it, use these as common
examples rather than a complete chain allowlist:
```
Open redirect → OAuth code theft → ATO        = report the chain
SSRF DNS → internal service access = data     = report the chain
CORS → credentialed data exfil PoC            = report the chain
Prompt injection → IDOR via chatbot           = report the chain
```

If you can't build the chain today → keep it only as a chain candidate with a
specific next evidence action, or drop it from the report path.

## Output

**GO:** "All 7 pass. Run /validate for full check, then /report."

**KILL [reason]:**
- "Q1 fails — no target-bound reproducible artifact yet"
- "Q4 fails — the required precondition is unreachable or out of scope"
- "Q7 fails — open redirect alone is not submittable. Chain it with OAuth theft first."

**DOWNGRADE:**
- "Q6 — the current artifact does not prove the claimed impact. Collect the lowest-risk missing differential before reporting."
