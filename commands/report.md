---
description: Draft a report from current validated Store evidence and an independent delivery decision. Usage: /report
---

# /report

Generate an editable report artifact for a selected, technically confirmed Finding.
Load `skills/report-writing/SKILL.md` for report structure, delivery format, tone and evidence presentation.
This command selects the source and invokes the generator.

## Current evidence and delivery

Run `/validate` first. Read the selected Finding from its target Store:

```bash
python3 tools/target_store.py findings --repo-root <repo-root> --target <target> --id <finding-id>
```

Automatic generation requires the current confirmed assessment, an eligible delivery decision bound to that
assessment, and intact target-owned evidence. A validation-summary file or a legacy status alone cannot grant
report eligibility. Technical validity and destination eligibility are separate: a known, duplicate or accepted-risk
issue may remain technically confirmed without being eligible for that destination.

Use the exact observation, assessment and delivery references returned for the Finding. Review the associated
validation summary for the boundary, impact, gate reasoning and reproducible evidence. `findings/last-validate.json`
is only a latest pointer; it cannot bind a report to a Finding. Missing evidence remains an explicit gap.

## Generate and inspect

```bash
python3 tools/report_generator.py <repo-root>/findings/<target-key>
```

The generator reads the Store associated with that findings directory. `findings.json` and raw scanner claims
are not the current candidate or report-status owner. `--allow-legacy-drafts` has been removed.

Report Markdown is published before the artifact and its assessment/delivery bindings are registered in the
same target Store. Registration failure retains the document for retry. `reports/<target-key>/INDEX.json` and
`SUMMARY.md` are rebuildable views; generating or registering a report does not submit it externally or complete
an Action. Submission is a separate explicit delivery event with its own receipt.

Manual drafts use `report_generator.py --manual --type <type> --url <url> --evidence <text>` and live under
`reports/<target-key>/drafts/`. They carry no Store report registration or delivery eligibility. A draft can retain
an incomplete analysis without presenting it as a validated submission.

## Delivery contract

Keep each claim and chain step tied to the selected Finding and raw artifact. Include the requested destination,
actors/objects, exact replay, observed result, demonstrated impact and limitations. Preserve target scope and
redact credentials, session material, unrelated personal data and raw secrets from the delivered copy.

Use the protocol-appropriate evidence: HTTP, browser, frame, stream, state transition, callback or another
recorded target-bound artifact. Retest notes identify time, version/environment, result and residual risk;
new technical judgments use the explicit assessment API rather than edits to report indexes.

Render recorded CVSS fields only when present and required by the destination. If needed, fill the report's
CVSS field from the destination's current rules without rewriting execution facts or copying a static table.
