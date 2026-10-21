---
description: "Record an evidence-bound AI validation decision, separating technical validity from destination eligibility. Usage: /validate"
---

# /validate

Review a selected Candidate before `/report`. AI judges evidence and impact; the tool checks
schema, owner bindings and integrity, then records the explicit decision. It does not run tests.

Load [triage-validation](../skills/src-hunter/modules/triage-validation.md) for Q1–Q7, Q7b, impact,
chain and retraction rules. Registration, replay, Browser/Case context and Action claim
binding are documented in [Evidence Runners](../docs/evidence-runners.md).

## 1. Select the Finding and scaffold

An initialized target Store and an existing Finding are required. Fresh initialization
belongs to `/hunt` or explicit Store init; validation never imports or falls back to legacy
`findings.json`. If there is no Candidate yet, continue hunting rather than inventing an ID.

```bash
python3 tools/target_store.py findings --target TARGET --id FINDING_ID
python3 tools/validate.py --target TARGET --finding-id FINDING_ID --scaffold --json > /tmp/validate-decision.json
```

Scaffold stdout is the decision object itself, not an envelope. It prefills known identity,
evidence references and a report path; judgment fields remain empty. Preserve target,
Finding ID, endpoint, method, class, `store_preconditions.assessment_id` and
`store_preconditions.delivery_id` (`null` means no predecessor). Resolve scaffold warnings before preflight.

`--target` selects `findings/<target-key>`; `--findings-dir` can select that explicit
target-owned directory instead. Report paths must remain within the selected target directory.

Evidence must bind a complete Store operation with linked observations and intact raw
artifacts matching the target/Finding/endpoint/method. A `candidate`, `tested_clean`,
native experiment or request pair without `expected` is reviewable: do not relabel it or
repeat requests just to gain admission. Runner labels and wire assertions do not prove impact.
For already-executed but unregistered material, use
[native registration](../docs/evidence-runners.md#native-evidence-registration) first.
Partial, unbound or damaged operations are refused even for a non-confirming review.

## 2. Fill the AI decision

Fill `impact`, `evidence.summary`, every Q status/basis and every gate's explicit
`passed` boolean, with notes where useful. Do not submit the empty scaffold.
The machine fields map to the Q answers as follows:

| Machine gate | AI judgment |
|---|---|
| `gate1` | Target-bound reproducibility (Q1) |
| `gate2` | Matches the supplied target context (Q3) |
| `gate3` | Reachable preconditions, exploitability and demonstrated impact (Q2/Q4/Q6) |
| `gate4` | No duplicate at the destination (Q5 search record) |

Gates 1–3 and Q1/Q2/Q3/Q4/Q6 determine the technical verdict. Gate 4 and Q5/Q7 determine
destination eligibility separately. A real violation may remain `confirmed` while delivery
is `ineligible` or `deferred`; `DO_NOT_REPORT` is not technical refutation.
Failed/unknown technical evidence produces `inconclusive`, not `refuted`.
Internal delivery (no declared external destination) records Q7 as `pass` with basis
`internal delivery: not-applicable`; Gate 4 then covers only documented-behavior and
known-issue checks, and eligibility is never deferred for a missing platform policy.

Choose the report-writing mode:
- **Default single-step:** provide `report.path` and fill `report.content` with the authored
  body, following [report-writing](../skills/src-hunter/modules/report-writing.md). Omit `mode`.
- **Judge before writing:** replace the **entire** `report` object, keeping all other
  decision fields, with the following fragment:

```json
{"report": {"mode": "deferred"}}
```

Deferred permits no other keys or mode values, including empty `path`/`content`.
All evidence, judgment and predecessor checks still apply. Even `confirmed` + `eligible`
can have `report_path=null`, `report_ready=false`, `all_gates_passed=false` and
`report_draft_status=not_written`: these describe absent text, not ineligibility.

Optional `severity` is `info|low|medium|high|critical` and must match the body's Severity
field in single-step mode. Omission reads that field, or yields `unknown` in deferred mode.
CVSS is optional external metadata, never a severity fallback; the scaffold and new summaries omit it.

## 3. Preflight, then apply

```bash
python3 tools/validate.py --target TARGET --finding-id FINDING_ID \
  --decision-json /tmp/validate-decision.json --preflight --json
python3 tools/validate.py --target TARGET --finding-id FINDING_ID \
  --decision-json /tmp/validate-decision.json --json
```

Preflight is read-only: success is `status=preflight_ok`; invalid input exits `2` with
`status=preflight_invalid` and an `errors` list. Fix the input before applying.
Apply rechecks bindings, current raw integrity and predecessor CAS; preflight is not a receipt.

## 4. Consume receipts and recover failures

Successful apply returns `status=updated`, the Finding-owned `summary_path`, and committed
`validation_sync.assessment.id` / `validation_sync.delivery.id`. For deferred writing,
cite those real IDs and operation/observation references, then follow
[`/report`](report.md) for authorship, publication eligibility and current report status.

- **Partial writes:** single-step mode publishes the body before the separate assessment,
  delivery and report-registration commands; deferred mode creates no body or report record.
  Files and Store commands are not one transaction. Sync failure exits `2` with
  `status=retry` / `retry=true`; preserve committed facts and any complete files.
  A summary's planned `store_command` is not a success receipt.
- **Exact retry:** query Store, fix the failure and reuse the unchanged decision, including
  its original predecessors. Do not regenerate a scaffold for the same decision, even if
  assessment succeeded before delivery failed. If another judgment advanced the Store,
  query current facts and explicitly author a new decision with fresh predecessors.
- **Current truth:** use returned per-Finding summaries/notes for this invocation only,
  never `findings/last-validate.json` as evidence; Store/INDEX own current report status.


## Retire an already reviewed Runner candidate

When a specific evidence bundle keeps resurfacing after review, use
[explicit candidate review](../docs/evidence-runners.md#候选材料的显式复核) to close that bundle.
This records review consumption only; Finding assessment, delivery and report state remain Store-owned.
New material stays reviewable, and an explicit reopen preserves review history.
