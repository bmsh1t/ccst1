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

If these IDs do not exist yet, use `/validate` with `report` replaced by exactly
`{"mode":"deferred"}`. Fill the existing judgments/evidence, optionally preflight,
then apply the decision. This runs the full validation checks and commits assessment
and delivery without a report body. All technical/destination gates must pass for
eligible delivery; selecting deferred writing alone does not grant eligibility.
Successful JSON exposes `validation_sync.assessment.id` and `validation_sync.delivery.id`;
default text shows the same committed IDs and summary path. Preflight IDs are not receipts.
Then query the Finding above, cite the actual operation/observation and judgment IDs
in the author's Markdown, and publish below. No separate assessment/delivery CLI is needed.

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
Deferred `/validate` retains `report_path=null` and `report_ready=false` even when replayed
after this publication: its summary records that invocation, not the current report owner.
Replaying the original deferred decision never rewrites the published body or changes
the delivery status/reason. `/remember --from-validate` may still prefill partial from that
summary; use Store/INDEX for current judgments and report status.

Published Markdown bytes are immutable. Complete file publication precedes Store registration; interruption
retains the file for retry with the same IDs and identical body. Different bytes under the same publication ID,
unknown/truncated existing files, symlinked output, stale IDs or invalid evidence are refused, not overwritten.
A new judgment requires new owner IDs. Existing reports and prior destination decisions are never rewritten.
If deferred validation only committed its assessment, it returns retry/nonzero, not successful
delivery IDs. Query Store and retry the unchanged decision after the failure is resolved;
genuine concurrent predecessor changes require a newly authored decision. Publication
failure likewise retains committed judgments and any complete published bytes for retry.
The legacy `/validate` and explicit publisher report-ID schemes remain distinct; this
workflow does not promise cross-entry deduplication or migrate old reports.

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
Before publication, finalize its text and evidence presentation. Screenshots are optional: the publisher copies
only the selected body's standalone tool-style image links, `![label](poc_screenshots/SHA256.ext)`, with the full
64-character lowercase content digest and an optional safe extension. Repeated links share one copy. Bodies
without these links do not access the screenshot directory; other drafts' files and unrelated broken entries
are ignored. Markdown bytes stay unchanged, and different existing image bytes are never overwritten.
Selected files must be nonempty regular files without symlink path components and match their filename digest.
Missing or changed published copies make the report stale, remove it from the current index, and block new
delivery events. Historical bodies/events remain; publication retry never repairs a damaged registered copy.
Registered retries never republish files or require the original draft screenshots to remain present; the
published copies are rechecked by Store. Revoked/unavailable report bodies also reject direct registration replay.
Code examples and external images are not managed attachments. Arbitrary inline layouts, reference-style images,
HTML and other relative links are not parsed or copied; they remain the author's responsibility. Old images
without content-addressed names are not silently trusted or migrated. Screenshots used as technical proof still
require the normal observation/artifact registration; delivery-copy damage does not rewrite that evidence.

## Scope of retirement

`generate_report()` and the category templates/narrative helpers are retired, not moved to another registry.
Call `process_findings_dir(..., finding_id=..., assessment_id=..., delivery_id=..., body_file=...)` for publication;
its existing `(total_reports, report_index)` result is retained. Calling it with only the directory indexes current
reports and pending drafts. No historical body, raw evidence, Store schema or report eligibility rule is migrated.
