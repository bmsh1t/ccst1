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

## Delivery Contract

Load `skills/report-writing/SKILL.md` for the requested delivery mode. Local/lab
delivery uses the supplied target record and its setup, target state, replayable
artifact, exact result, demonstrated
impact, and limitations. Keep the existing target scope, finding index,
Evidence Ledger, validation summaries, target memory, and report index as the
inputs; do not create a second report status or evidence store.

Keep every chain step tied to a validated finding and artifact. Record retest
time, version/environment, result, residual risk, and artifact refs without
changing canonical finding status. The manifest carries path, UTC time,
collector/source, purpose, and SHA-256; redact credentials, session material,
tokens, PII, unrelated customer data, and raw secrets from the delivered copy.

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

## Report Contract

This command only selects the validated source and invokes the generator.
Render the recorded `cvss.version`, `cvss.score`, and
`cvss.vector`; do not calculate a score here or copy a static calibration table.

Use the protocol-appropriate replayable artifact: HTTP when applicable, or a
browser, frame, stream, state, callback, or equivalent target-bound record for
other protocols. Keep the report tied to the canonical finding and do not create
a second lifecycle.
