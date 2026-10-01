---
description: Author and publish an evidence-backed report for a current confirmed Finding and eligible destination. Usage: /report
---

# /report

AI authors the report; the tool checks owner bindings, publishes exact bytes and indexes current reports.
Load `skills/report-writing/SKILL.md` for evidence standards, destination format and writing guidance.
There is no category-based narrative, default impact, remediation or severity generator.

## Current evidence and delivery

Read the selected Finding from its target Store:

```bash
python3 tools/target_store.py findings --repo-root ROOT --target TARGET --id FINDING_ID
```

Publication requires its current confirmed assessment, intact target-owned evidence, and an eligible delivery
bound to that assessment and destination. Use `/validate` if the technical judgment is still missing; a legacy
status or validation-summary file alone cannot grant eligibility. A known, duplicate or accepted-risk issue
may remain technically confirmed without being eligible for a particular destination.

Use the exact observation, assessment and delivery IDs returned by the Store. Every claimed boundary crossing
and impact must have reproducible evidence; a scanner match or plausible chain is not sufficient. Preserve
assumptions and missing connectors rather than embellishing the claim. `findings/last-validate.json` is only a
latest pointer, not a binding. The publisher enforces existing judgments, not the semantic truth of prose.

## Inspect current reports and missing drafts

```bash
python3 tools/report_generator.py ROOT/findings/TARGET
```

Without a body submission, this only rebuilds `reports/TARGET/INDEX.json` and `SUMMARY.md` from the Store.
`pending_drafts` lists each current eligible Finding/assessment/delivery pair that has no registered report.
Missing text remains `needs_draft`; it does not block indexing other valid reports or cause template fallback.
CLI output always shows the missing-draft count and canonical INDEX/SUMMARY paths, including mixed results.
Damaged or stale registered reports remain historical Store records and are not silently recreated.
`findings.json`, raw scanner claims and index entries are not lifecycle owners.

## Author and publish

Write the destination-specific Markdown draft using the native editor. Follow the report Skill, cite actual
artifacts, and remove credentials, session material, unrelated personal data and raw secrets from the delivered
copy. Preserve controlled originals separately. The tool does not rewrite or sanitize submitted prose.

Publish the draft with all four explicit inputs:

```bash
python3 tools/report_generator.py ROOT/findings/TARGET \
  --finding-id FINDING_ID --assessment-id ASSESSMENT_ID --delivery-id DELIVERY_ID \
  --body-file ROOT/reports/TARGET/drafts/report.md
```

The body must be non-empty UTF-8. Each destination gets its own explicit submission; no body is automatically
reused for another destination. The IDs must still select the current confirmed assessment and eligible
delivery, with intact evidence. `/validate`'s own authored-report publication remains unchanged.

Published Markdown bytes are immutable. Complete file publication precedes Store registration; interruption
retains the file for retry with the same IDs and identical body. Different bytes under the same publication ID,
unknown/truncated existing files, symlinked output, stale IDs or invalid evidence are refused, not overwritten.
A new judgment requires new owner IDs. Existing reports and prior destination decisions are never rewritten.

The index retains all current registered reports, including reports registered through `/validate` or the
explicit Store API. Severity is read only from each registered body's declaration; absent/invalid/conflicting
values remain unknown. CVSS is optional destination metadata, not an automatic severity calculator.
Publication does not submit a report externally or complete a Queue Action. External submission has its own
explicit delivery event and receipt.

## Manual notes and screenshots

```bash
python3 tools/report_generator.py --manual --type TYPE --url URL --param PARAM --evidence TEXT
```

This records supplied inputs under `reports/TARGET/drafts/` with an unassessed label. It creates no technical
conclusion, severity, impact or remediation. `--body-file FILE` can instead seed an editable authored draft.
Manual filenames are opaque IDs; do not rely on the retired per-category numeric naming scheme.

`--poc-images IMAGE ...` attaches content-addressed screenshots to a manual draft, never to a registered report
(including stale reports registered directly under `drafts/`). Symlinked, hardlinked or nonregular draft files
are refused; damaged existing Store state does not fall back to an unregistered interpretation.
Before publication, finalize its text and evidence presentation. The publisher copies the draft's adjacent
`poc_screenshots/` directory without changing relative links or overwriting different image bytes. Keep unrelated
files out of that directory. Other relative attachment links must already resolve from the published report's
directory. Screenshots used as technical proof still require the normal observation/artifact registration.

## Scope of retirement

`generate_report()` and the category templates/narrative helpers are retired, not moved to another registry.
Call `process_findings_dir(..., finding_id=..., assessment_id=..., delivery_id=..., body_file=...)` for publication;
its existing `(total_reports, report_index)` result is retained. Calling it with only the directory indexes current
reports and pending drafts. No historical body, raw evidence, Store schema or report eligibility rule is migrated.
