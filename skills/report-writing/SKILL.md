---
name: report-writing
description: Report-only rendering contract for validated findings. Selects the requested delivery format, preserves evidence traceability and canonical CVSS fields, and produces concise impact-first output without creating a second lifecycle.
---

# REPORT WRITING

This is a `report-only` Skill. Use it after validation has selected a canonical
finding. Render the existing finding, Evidence Ledger, validation summary, and
target record; do not create a second finding/report lifecycle or replace
structured validation with model judgement.

## Preconditions

Before drafting a standalone report, resolve the finding's exact validation
summary from its canonical `validation_summary` field or the matching
`/validate` result. The summary must contain:

- `seven_question_gate_passed: true`;
- `four_validation_gates_passed: true`;
- `all_gates_passed: true`; and
- a structured `cvss` object with `version`, `score`, and `vector`.

If the result is `chain_required`, `needs_review`, or `kill`, keep the missing
evidence or connector as the next action. Do not produce a standalone report.
`findings/last-validate.json` is only a latest pointer and never binds a report
to a finding.

## Canonical Inputs

Use the existing owners as read-only report inputs:

| Input | Use |
|---|---|
| Finding Index | finding ID, target, type, lifecycle, and report binding |
| Evidence Ledger | operation identity, actors, artifacts, timestamps, and hashes |
| Validation summary | gate results, demonstrated impact, and structured CVSS |
| Target/Case State | scope, roles, objects, session and workflow context |
| Report Index | cumulative report ID and file mapping |

Every claim must point to a target-bound artifact. Preserve the exact target,
operation/method, actors, preconditions, observed result, and impact connector.
Use the smallest necessary sample and retain the controlled original outside the
delivered copy.

## Delivery Modes

Choose the format requested for this deliverable; the finding lifecycle is the
same for every mode.

| Format | Required emphasis |
|---|---|
| Formal assessment | Executive Summary, Scope, Limitations, Assumptions, Methodology and Coverage, Attack Chains, Technical Findings, Retest and Closeout, Evidence Manifest, Strategic Recommendations |
| Local/lab write-up | Setup, target state, replayable artifact, exact result, demonstrated impact, and limitations |
| HackerOne | Summary, Vulnerability Details, Steps to Reproduce, Impact, and recorded CVSS; use the platform's requested length |
| Bugcrowd | VRT classification, description, reproduction, Expected vs Actual, and severity justification |
| Intigriti | Specific title, prominent recorded CVSS, reproduction, and business impact |
| Immunefi | Root cause, affected contract/function, reproducible PoC artifact, state/value impact, and required comparison evidence |

Platform conventions affect rendering only. They do not change evidence gates,
scope, severity, or canonical status.

## Report Contract

Include, as applicable:

1. A title naming the test class, exact endpoint/operation, actor, and
   demonstrated impact.
2. An impact-first summary with factual scope and preconditions.
3. Vulnerability details tied to the selected finding ID and source artifact.
4. Reproduction steps using the exact artifact and the exact observed result.
5. Impact limited to what the evidence demonstrates, with measured quantities
   only when they are recorded.
6. Remediation or retest notes without changing the canonical finding status.
7. An Evidence Manifest containing artifact path, UTC capture time,
   collector/source, purpose, SHA-256, and redaction note.

## Reproduction Artifacts

Use the medium that preserves the tested state:

- HTTP request/response when the operation is HTTP;
- browser trace or state transition for browser workflows;
- frame/handshake/stream/trailer transcript for realtime or RPC protocols;
- controlled callback/OOB artifact for blind server-side behavior; or
- an equivalent target-bound record for another medium.

Do not convert a non-HTTP test into a fabricated HTTP request. Do not treat a
status code, scanner match, model explanation, or generic output as impact proof.

## CVSS Rendering

`tools/validate.py` is the only scoring producer. Copy the selected finding's
`cvss.version`, `cvss.score`, and `cvss.vector` unchanged from its validation
summary. This Skill does not calculate, infer, or override CVSS from prose,
platform examples, or a static table.

## Evidence and Redaction

- Keep credentials, tokens, session material, secrets, and unrelated customer
  data out of the delivered report and hash manifest.
- Use a redacted copy while preserving a reference to the controlled original.
- Include actor comparison whenever the claim crosses an identity boundary.
- State unavailable accounts, blocked paths, untested branches, assumptions,
  and residual uncertainty instead of implying exhaustive coverage.
- For a chain, reference a validated finding ID and evidence artifact for every
  transition; a Lead or Signal is not a chain link.

## Retest and Closeout

Record UTC time, tested version/environment, result (`fixed`,
`partially_fixed`, `not_fixed`, or `not_retested`), residual risk, and artifact
references. Retest notes are report content and must not create a second status
or overwrite the canonical finding lifecycle.

## Writing Rules

- State the demonstrated action or data in the first sentence.
- Use exact facts and target terminology; do not turn theory into impact.
- Quantify only what the evidence supports.
- Keep bounty submissions concise when the platform requests a length limit;
  formal assessment reports may be longer when their scope requires it.
- Never include raw test secrets or unrelated target data.

## Final Checklist

```text
[ ] Canonical finding and exact validation summary selected
[ ] seven_question_gate_passed, four_validation_gates_passed, and all_gates_passed are true
[ ] Target, operation, actors, preconditions, and artifact references match
[ ] Protocol-appropriate replayable artifact and observed result are included
[ ] Demonstrated impact is separated from untested or theoretical impact
[ ] Recorded cvss.version, cvss.score, and cvss.vector are copied unchanged
[ ] Evidence manifest has path, UTC time, source, purpose, SHA-256, and redaction note
[ ] No raw secrets, unrelated customer data, or second lifecycle state is created
```
