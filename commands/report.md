---
description: Draft a validated bounty submission, local write-up, or formal penetration-test report. Supports evidence traceability, CVSS, retest, and closeout. Run /validate first. Usage: /report
---

# /report

Generate an editable, submission-ready report draft from validated evidence.

This is the primary reporting workflow.
`skills/report-writing/SKILL.md` is the report-only contract owner for structure,
tone, platform rendering, and evidence presentation; this command owns only
entry, source selection, and generator invocation.
The generator rejects statusless structured rows and raw legacy scanner files by
default. `--allow-legacy-drafts` is an explicit compatibility path; those drafts
do not update canonical finding or action-queue lifecycle state.

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
include its gate status and structured `cvss` object in the evidence section.
`findings/last-validate.json`
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
- exact replayable request, browser/frame trace, workflow path, or equivalent artifact
- exact response, artifact, or state change
- why the behavior satisfies the task objective or demonstrates impact

Use local write-up language by default; switch to a bounty-platform
submission format only when the user explicitly requests that format.

## Formal Penetration-Test Delivery

When the requested deliverable is a formal engagement report, keep the same
validated finding lifecycle and render an engagement-level document with:

1. Executive Summary
2. Scope
3. Limitations
4. Assumptions
5. Methodology and Coverage
6. Attack Chains
7. Technical Findings
8. Retest and Closeout
9. Evidence Manifest
10. Strategic Recommendations

Do not create a second report status or copy evidence into a new store. Build
the report from the existing target scope, finding index, Evidence Ledger,
validation summaries, target memory, and report index. State exact in-scope and
excluded assets, testing window, access/credential assumptions, unavailable or
blocked coverage, and residual uncertainty.

Attack-chain narratives must reference the validated finding IDs and evidence
artifacts for every step; do not turn an unvalidated lead into a chain link.
Retest/closeout records the UTC retest time, tested version/environment, result
(`fixed`, `partially_fixed`, `not_fixed`, or `not_retested`), residual risk, and
supporting artifact references without changing the canonical finding status.

The Evidence Manifest lists the existing artifact path, UTC capture time,
collector/source, purpose, and SHA-256. Redact credentials, session material,
tokens, PII, and unrelated customer data in the delivered copy while retaining
traceability to the controlled original. Never place raw secrets in the report
or hash manifest.

## Usage

```
/report
```

Provide when prompted:
- Delivery format (formal penetration test / local write-up / HackerOne / Bugcrowd / Intigriti / Immunefi)
- Bug class
- Affected endpoint
- Relevant actors/roles/objects and their IDs when the claim crosses an identity boundary
- The exact replayable artifact that demonstrates the bug
- The exact observed result that shows the impact
- Tech stack (for severity context)

## What This Generates

1. Title following the formula: `[Bug Class] in [Endpoint] allows [actor] to [impact]`
2. Summary paragraph (impact-first, no "could potentially")
3. Vulnerability details with the recorded CVSS version, score, and vector
4. Steps to Reproduce with the exact replayable artifact
5. Impact statement with quantification
6. Supporting materials section
7. Evidence references from `findings/`, screenshots, response snippets, or validation summary when available

## Report Contract

The report-only Skill owns platform structure, tone, evidence presentation, and
the final checklist. This command only selects the validated source and invokes
the generator. Render the recorded `cvss.version`, `cvss.score`, and
`cvss.vector`; do not calculate a score here or copy a static calibration table.

Use the protocol-appropriate replayable artifact: HTTP when applicable, or a
browser, frame, stream, state, callback, or equivalent target-bound record for
other protocols. Keep the report tied to the canonical finding and do not create
a second lifecycle.
