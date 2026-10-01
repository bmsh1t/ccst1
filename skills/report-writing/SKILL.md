---
name: report-writing
description: Draft reports from a current confirmed Store assessment, intact evidence, and an independent eligible destination decision. Preserves evidence traceability and canonical lifecycle; CVSS is optional destination metadata.
---

# REPORT WRITING

This is a `report-only` Skill. Use it after validation has selected a canonical
finding. Author the report from the existing finding, Evidence Ledger, validation summary, and
target record; do not create a second finding/report lifecycle or replace
structured validation with model judgement.

## Preconditions

Before publishing a standalone report, query the selected Finding through
`commands/report.md`. Require its current confirmed assessment, intact
target-owned evidence, and an eligible delivery decision bound to that
assessment and destination. Preserve their exact IDs and artifact references.
Historical validation-summary booleans are diagnostics, not report authority.
AI writes destination-specific Markdown; `report_generator.py` does not fill in category narratives.
Submit its body with explicit Finding, current assessment and eligible delivery IDs using
`commands/report.md`. Missing text stays pending; finalize screenshots and wording before
publication because registered bytes are immutable. A draft may record uncertainty without
claiming a reportable vulnerability. The publisher checks bindings, not the truth of prose.
Known, duplicate, or accepted-risk status may reject one destination without
refuting the technical conclusion or blocking another eligible destination.

CVSS is not a validation-summary precondition. If the destination platform
requires it and the summary lacks it, the Agent follows that platform's current
requirements in the delivered report without rewriting the canonical summary.

If the claimed impact needs an unproven connector, preserve the evidence gap;
do not present that chain as confirmed. An independently confirmed A can be
saved and reported immediately; investigation of B/C does not block it.
`findings/last-validate.json` is only a latest pointer and never binds a report
to a finding.

## Canonical Inputs

Use the existing owners as read-only report inputs:

| Input | Use |
|---|---|
| Finding Index | finding ID, current technical assessment, independent destination decisions, and report binding |
| Evidence Ledger | operation identity, actors, artifacts, timestamps, and hashes |
| Validation summary | gate results and demonstrated impact; historical CVSS is optional read-only metadata |
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

Platform conventions affect rendering and eligibility at that destination.
They do not rewrite scope, evidence integrity, or the technical assessment.

## Report Contract

Include, as applicable:

1. A title naming the test class, exact endpoint/operation, actor, demonstrated
   impact, and scope: `[Bug Class] in [Exact Endpoint/Feature] allows [attacker role]
   to [impact] [scope]`.
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

## Optional CVSS Rendering

When a destination platform requires CVSS, copy any recorded `cvss.version`,
`cvss.score`, and `cvss.vector` unchanged; if none were recorded, supply the
platform-specific field only in the delivered report based on its current rules.
Do not rewrite historical values or the canonical validation summary. Missing
CVSS does not block core validation or local reporting.

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
- Do not fill evidence gaps with "could potentially allow", "may allow", or
  an unproven chain. State the demonstrated action, method, and bounded impact.
- Quantify only what the evidence supports.
- Aim for under 600 words for a bounty submission unless the user or platform
  requires a different length. Formal assessment reports follow their scope
  and required sections, not this bounty word budget.
- Separate independent root causes into separate bounty submissions; a formal
  assessment may contain separate finding sections. Combine steps as one chain
  only when the demonstrated outcome depends on those steps.
- Answer clarification or severity disputes with recorded preconditions,
  artifacts, and measured impact; do not invent reachability or scale.
- Never include raw test secrets or unrelated target data.

## Final Checklist

```text
[ ] Canonical finding and current confirmed assessment selected
[ ] Intact evidence and eligible destination decision bind that assessment
[ ] Target, operation, actors, preconditions, and artifact references match
[ ] Protocol-appropriate replayable artifact and observed result are included
[ ] Demonstrated impact is separated from untested or theoretical impact
[ ] If requested by the destination platform, recorded CVSS fields are copied unchanged
[ ] Evidence manifest has path, UTC time, source, purpose, SHA-256, and redaction note
[ ] No raw secrets, unrelated customer data, or second lifecycle state is created
```
