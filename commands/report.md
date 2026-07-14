---
description: Draft a submission-ready vulnerability report from validated evidence. Supports H1/Bugcrowd/Intigriti/Immunefi styles, CVSS 4.0, PoC, and impact. Run /validate first. Usage: /report
---

# /report

Generate an editable, submission-ready report draft from validated evidence.

This is the preferred primary reporting workflow; legacy report-generation entrypoints are compatibility paths only.

## Pre-Conditions

Run `/validate` first. The selected finding's recorded
`<artifact-key>.validation-summary.json` must show both:

- `seven_question_gate_passed: true`
- `four_validation_gates_passed: true`

`all_gates_passed: true` is the combined report-readiness signal. If the
7-Question Gate is `chain_required`, `needs_review`, or `kill`, do not draft a
standalone report; continue chain-building or evidence collection instead.

Never write a report before validating. N/A submissions hurt your validity ratio.

Use the exact summary path stored in the selected canonical row, or the path
returned by that finding's `/validate` invocation, as starting context and
include its gate status in the evidence section. `findings/last-validate.json`
is only a latest pointer and must not bind a report to a finding. If no matching
summary exists, ask the user for the missing endpoint, evidence, impact, and
reproduction details before drafting.

When the validation summary contains `finding_id`, `finding_source_file`, or
`finding_summary`, include those references in the evidence section so the
report draft remains traceable back to the scanner candidate.

If `findings/<target>/findings.json` exists, prefer it as the candidate index:
use `id`, `type`, `url`, `severity`, `confidence`, and `source_file` to pick the
finding, then still require concrete validation evidence before finalizing the
report.

Reports generated from structured findings include a `Finding Reference` block
with the candidate id, source artifact, confidence, and summary when available.
When `generate_reports` runs through the Claude Code agent, its summary also
surfaces `reports/<target>/INDEX.json` so you can see report id → finding id →
markdown file mapping without opening the directory manually.
The corresponding `findings.json` item is updated with `report_status`,
`report_id`, and `report_file` for later `/pickup` or agent continuation.

## Local / Lab / Supplied Target Reports

Use the supplied target set as the target record. External bounty
metadata such as policy text, accepted impact lists, or platform submission
requirements is non-applicable unless the user requests that format. A local
write-up should show:

- exact setup and target state
- exact request or exploit path
- exact response, artifact, or state change
- why the behavior satisfies the task objective or demonstrates impact

Use local write-up language by default; switch to a bounty-platform
submission format only when the user explicitly requests that format.

## Usage

```
/report
```

Provide when prompted:
- Platform (HackerOne / Bugcrowd / Intigriti / Immunefi)
- Bug class
- Affected endpoint
- Your two test accounts and their IDs
- The exact HTTP request that demonstrates the bug
- The exact response that shows the impact
- Tech stack (for severity context)

## What This Generates

1. Title following the formula: `[Bug Class] in [Endpoint] allows [actor] to [impact]`
2. Summary paragraph (impact-first, no "could potentially")
3. Vulnerability details with CVSS 4.0 score and vector string
4. Steps to Reproduce with copy-paste HTTP requests
5. Impact statement with quantification
6. Supporting materials section
7. Evidence references from `findings/`, screenshots, response snippets, or validation summary when available

## Platform Selection

### HackerOne Format
- Markdown sections: Summary, Vulnerability Details, Steps to Reproduce, Impact
- Include CVSS 4.0 score + vector string
- Include two test account setup instructions
- Keep under 600 words

### Bugcrowd Format
- Title with VRT category: `[VRT Category] > [Subcategory] > P[1-4]`
- Expected vs Actual Behavior section
- Severity Justification section referencing Bugcrowd VRT

### Intigriti Format
- CVSS score prominent at top
- Clear reproduction steps
- Business impact focused

### Immunefi Format (Web3)
- Root cause in Solidity code
- Foundry PoC test included
- Concrete security impact backed by evidence
- Comparison evidence (same check present elsewhere, missing here)

## Writing Rules

1. **Never use:** "could potentially", "may allow", "might be possible"
2. **Always prove:** show actual data/action, not just "200 OK"
3. **Impact first:** sentence 1 = what attacker gets, not what the bug is
4. **Quantify:** how many users affected, what data type, $ amount
5. **Short:** triagers skim. < 600 words.
6. **Human:** write to a person, not a system

## CVSS 4.0 Calculation Guide

Common patterns:
```
IDOR read PII (any user, auth needed):
→ CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N = 7.1 High

Auth bypass → admin (no auth):
→ CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N = 9.3 Critical

SSRF → cloud metadata:
→ CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:H/SI:N/SA:N = 7.7 High

Stored XSS (any user, victim views page):
→ CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:P/VC:L/VI:L/VA:N/SC:H/SI:L/SA:N = 6.2 Medium
```

## Escalation Language

Use when payout is being downgraded:
```
"This requires only a free account — no special privileges."
"The exposed data includes [PII type], subject to GDPR/CCPA requirements."
"An attacker can automate this — all [N] records in [X] minutes with a simple loop."
"This is exploitable externally without any internal network access."
"The impact is equivalent to a full data breach of [feature/data type]."
```

## Final Checklist Before Submitting

```
[ ] Title follows formula
[ ] First sentence states exact impact
[ ] HTTP request is copy-pasteable
[ ] Response showing impact included
[ ] Two accounts used (not self-testing)
[ ] CVSS 4.0 calculated and included
[ ] No typos in endpoint/param names
[ ] Under 600 words
[ ] Severity matches impact (no overclaiming)
[ ] NEVER used "could potentially"
```
