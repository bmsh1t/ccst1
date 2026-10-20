# REPORT WRITING

内部完整方法，按当前问题读取；不是独立原生 Skill，不自动启动执行或委派。
返回 [src-hunter 调查主干](../SKILL.md)；恢复/写回仍归 `skills/runtime-protocol.md`。

适用：Draft reports from a current confirmed Store assessment, intact evidence, and an independent eligible destination decision. Preserves evidence traceability and canonical lifecycle; CVSS is optional destination metadata.

This is a `report-only` module. Use it after validation has selected a canonical
finding. Author the report from the existing finding, Evidence Ledger, validation summary, and
target record; do not create a second finding/report lifecycle or replace
structured validation with model judgement.

## Preconditions

Before publishing a standalone report, query the selected Finding through
`commands/report.md`. Require its current confirmed assessment, intact
target-owned evidence, and an eligible delivery decision bound to that
assessment and destination. Preserve their exact IDs and artifact references.
Historical validation-summary booleans are diagnostics, not report authority.
Before drafting, directly read the complete `rules/vuln-report-format.md`
and `docs/ccst-runtime-adapter.md`.
The original 6k rule owns default SRC prose, language, chapters and layout;
this module binds that authored body to CCST evidence/publication. Already-read
complete bodies at the same version may be reused. `report_generator.py` does not
fill in category narratives.
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

## Default SRC Format and Explicit Alternatives

For SRC use the complete 6k report-format tables: Chinese first-person wording,
the eight content blocks, full URLs and provenance, necessary reproducible artifacts,
full-width ＃ separators and CRLF. The report rule defines controlled secrets,
evidence-backed impact, severity, target-owned paths and immutable revisions;
`commands/report.md` supplies the current publisher inputs.
Do not substitute an English title formula, generic summary template or a 600-word cap.
Finalize bytes before publication; publisher preserves the submitted UTF-8 body.

Only when the user or selected destination explicitly requires a different format,
use that delivery's actual fields. These alternatives retain the same Finding,
assessment, evidence and independent delivery decision:

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

## Evidence Binding

Keep exact Finding, current assessment, eligible delivery and operation/artifact
IDs in their existing Store/Ledger owners. Tie every body claim to those artifacts;
do not add a second lifecycle or a mandatory ninth prose block. UTC capture times,
hashes, source and redaction notes remain traceable through the existing evidence.
Report content must distinguish demonstrated actions from supported permission
inferences and untested boundaries. Source report severity is a writing/admission
convention; it does not overwrite technical assessment or destination eligibility.

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

- Default external/shared copies redact credentials, session material and unrelated
  personal data, with a binding to controlled originals. Exact values requested by
  the source format are limited to an explicitly selected target-private controlled
  delivery and its necessary sample, as defined by the runtime adapter.
- Never place secrets in shared knowledge, public artifacts or tool logs.
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
- Separate independent root causes into separate bounty submissions; a formal
  assessment may contain separate finding sections. Combine steps as one chain
  only when the demonstrated outcome depends on those steps.
- Answer clarification or severity disputes with recorded preconditions,
  artifacts, and measured impact; do not invent reachability or scale.
- Follow the runtime adapter for private originals versus external/shared copies.

## Final Checklist

```text
[ ] Canonical finding and current confirmed assessment selected
[ ] Intact evidence and eligible destination decision bind that assessment
[ ] Target, operation, actors, preconditions, and artifact references match
[ ] Protocol-appropriate replayable artifact and observed result are included
[ ] Demonstrated impact is separated from untested or theoretical impact
[ ] If requested by the destination platform, recorded CVSS fields are copied unchanged
[ ] Complete 6k report-format and adapter applied, or explicit destination alternative
[ ] Existing evidence references preserve UTC, source, purpose, SHA-256 and redaction
[ ] Delivery privacy boundary respected; no second lifecycle state is created
```
