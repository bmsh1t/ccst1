---
description: Validate a report candidate — runs the 7-Question Gate + 4-gate checklist. Rejects weak candidates before report writing. Prevents N/A submissions that hurt validity ratio. Usage: /validate
---

# /validate

Run full validation on the current finding before writing a report.

## Use When

- A Lead/Signal has become a real Candidate
- You are preparing to write or queue a report
- You need a strict REPORT / CHAIN_REQUIRED / DOWNGRADE / DO_NOT_REPORT decision instead of more exploration

## Do Not Use When

- You are still broad-hunting and only have weak hypotheses
- You need recon, ranking, or enrichment rather than report gating
- The only evidence is code reading or intuition without a target-bound replayable artifact

## Inputs

> 谁思考：Q1-Q7 判定、四 gate 布尔、影响评估全部是 **AI 判断**（权威
> 在 `skills/triage-validation/SKILL.md`）；decision JSON 的 schema 校验、
> canonical 绑定、report 路径约束是 **机械** gate。

- Candidate endpoint, vuln class, impact claim, and reproduction details
- Exact request/response, browser/frame, state, or OOB evidence when available
- An existing Store Finding bound by `--finding-id` and registered operation evidence
- Current target/runtime context from repo-local config and disk artifacts

## Outputs

- Validation decision and reasoning
- 当前 finding 独占的 `<artifact-key>.validation-summary.json`
- Store technical assessment, independent destination decision and registered report when eligible
- Current queries expose validation progress from those same facts

## Artifacts Written

- 报告同目录的 `<artifact-key>.validation-summary.json`
- 报告同目录的 `<artifact-key>.submission-notes.md`
- `findings/last-validate.json`（仅为最近一次运行的 convenience pointer）
- Store assessment/delivery/report records and their command receipts
- `state/<target>/session.json` runtime breadcrumbs; no automatic Pattern calibration writes

## Resume Source

- Finding/assessment/report linkage from the target Store
- The report-local summary path returned by this validation invocation
- PASS cases hand off to `/report`; non-PASS cases hand off back to hunt with a
  concrete next evidence step

Use `/validate` when a Lead or Signal has become a Candidate, or when preparing
`/report`. It is a strict pre-report/pre-submit gate, not a hunt-phase
kill-switch for raw leads, anomalies, hypotheses, or chain seeds.

## Target-Driven Validation

Validation uses the supplied target as the active target record. External
bounty metadata is optional context, and write-up quality fields are report
controls rather than execution blockers.

## What This Does

1. Runs the 7-Question Gate and routes each non-pass by its meaning
2. Checks against the always-rejected list
3. Runs 4 pre-submission gates
4. Calculates and records validation context where applicable
5. Outputs: REPORT, CHAIN_REQUIRED, DOWNGRADE, or DO_NOT_REPORT

Before deciding, load `skills/triage-validation/SKILL.md` and treat its Q7
precedence, PRE-SEVERITY GATE, and RETRACTION DISCIPLINE as authoritative. The
condensed checklist below must not override those rules.

`tools/validate.py` records the 7-Question Gate in the current finding's
`<artifact-key>.validation-summary.json`.
Claude supplies explicit Q1-Q7 and four-gate judgments in `--decision-json`.
The tool does not prompt interactively or infer missing judgments.

## Usage

```
/validate
```

## Machine Decision Path

Bind a complete machine decision to an existing Store Finding. Legacy Finding
JSON is not an input or write destination:

```bash
python3 tools/validate.py --target <target> --finding-id <canonical-id> \
  --decision-json /tmp/validate-decision.json --json
```

`--target` resolves only `findings/<target-key>`; `--findings-dir` is the
equivalent explicit path. The decision JSON schema (schema_version, gate1–gate4,
Q1–Q7, impact, evidence, report fields; optional `cvss` metadata) is owned by `tools/validate.py`
(`MACHINE_DECISION_SCHEMA_VERSION` and its preflight errors) — do not
hand-reconstruct it from scratch; generate the skeleton, fill only the judgment
fields, then verify it with `--preflight` before applying:

```bash
python3 tools/validate.py --target <target> --finding-id <canonical-id> --scaffold --json
```

The scaffold machine-fills every mechanical field (schema_version, target,
finding_id, endpoint, runner summary bound to the latest owner-bound run, unique
report path) and leaves `impact`/`gates`/`seven_question_gate` empty for
AI judgment. The scaffold omits CVSS; legacy `decision.cvss`, if supplied, is
validated but not written to a new summary. A destination-specific CVSS field
belongs in the external report when that platform requires it.
Claude may set `severity` explicitly from the demonstrated impact; if omitted,
the existing Finding severity is carried forward, not inferred from CVSS.
Hand-writing the full JSON remains valid; the scaffold is an
output-only generator, validation code is unchanged. The target, ID, endpoint and class must match
the canonical row before any write occurs; the report path stays below that
row's `findings/<target>/` directory.

The runner summary must be a candidate-ready `tested_finding` from
`validation_runner` schema v1. Its target, finding, endpoint and method must
match the decision; its self path, stable operation ID, request/response
artifact SHA-256 bindings, canonical Finding summary/operation binding, and
Finding owner provenance must all verify before preflight succeeds.

For already-executed browser, probe, raw or multi-step evidence, first register
the saved observations against this Candidate without sending requests again:

```bash
python3 tools/validation_runner.py record-evidence --target <target> \
  --finding-id <canonical-id> --evidence-json /tmp/native-observations.json --json
```

The observation fields and side-effect flags are documented in
`docs/evidence-runners.md#native-evidence-registration`. Registration uses the
same schema-v1 witness; then use the scaffold/preflight/decision path above.
Request-diff is optional, not the admission test for a valid experiment.
For a claimed Store execution Action, pass `--action-id ACTION_ID --claim-token
CLAIM_TOKEN --actor OPERATOR` to either runner lane. The operator must be the
claimant; observed `runs[].actor` roles remain separate. Registration preserves
the claim without completing it; explicit resolve cites `store_operation_id`.
Native registration retries keep the original attempt ID and argv. A real
request-diff rerun requires a new attempt ID.

Store scaffolds include `store_preconditions.assessment_id` and `delivery_id`.
Keep these when filling a decision: null means no prior judgment. Identical
decision retries reuse the same commands, including after assessment succeeds
but delivery fails. A changed decision requires a fresh scaffold with the
current predecessors; stale input fails before report/summary writes.
Only the chosen runner operation's linked observations enter the assessment.
Preflight checks their current integrity and refuses foreign or partial proof.

On Store targets, Gates 1–3 and Q1/Q2/Q3/Q4/Q6 establish the technical verdict.
Gate 4 (duplicate), Q5 (known/documented), and Q7 (destination exclusions) govern
delivery separately. A real, evidenced boundary violation can remain confirmed
while delivery is ineligible or deferred. Known behavior alone neither confirms
nor refutes a violation; a missing technical gate still prevents confirmation.
Report generation requires both confirmation and current eligible delivery.

To check a decision before applying it, add `--preflight`. This reads the
decision and canonical finding, reports all independent schema/binding errors,
and never writes a report, summary, finding, ledger, queue, or runtime state:

```bash
python3 tools/validate.py --target <target> --finding-id <canonical-id> \
  --decision-json /tmp/validate-decision.json --preflight --json
```

Successful preflight returns `status: "preflight_ok"`; invalid input returns
exit `2` with `status: "preflight_invalid"` and an `errors` list. Remove
`--preflight` to apply the unchanged validation path.

The command requires an initialized Store and records the technical assessment
and destination decision separately. When eligible, it atomically publishes the
AI report body and registers its artifact against those exact decisions. If
registration fails, the body and committed decisions remain available for an
idempotent retry. Report registration never submits externally or completes an
Action. Legacy targets require explicit import; no legacy fallback is consulted.
Use the returned summary/artifact binding rather than reconstructing a path from
a global pointer.
`findings/last-validate.json` is only a latest pointer and is never canonical
evidence. Calls without `--decision-json` fail closed without creating report,
finding, queue or runtime state.

## Browser-State Priority

During validation, prove that a real user can reproduce the behavior in the
current state:

- Browser evidence follows the shared browser lane contract in `commands/hunt.md` (chrome-devtools for live inspection, Playwright for interaction/sessions/multi-actor, `tools/browser_mcp_import.py` for artifact import) so `/surface`, `/checkpoint`, `/autopilot`, and validation summaries reuse the same observed API surface.
- Exact non-browser requests can use `curl` / `urllib` / local helpers for lightweight replay.
- Burp/Caido history is auxiliary replay and comparison context; missing Burp/Caido should not block validation.

Reproducibility and evidence quality matter here.

An explicitly registered Finding ID binds the machine decision:

```bash
python3 tools/validate.py --findings-dir findings/target.com --finding-id sqli_abc123 \
    --decision-json /tmp/validate-decision.json --json
```

For a candidate list or a selected Finding's current assessment/evidence:

```bash
python3 tools/target_store.py findings --target target.com
python3 tools/target_store.py findings --target target.com --id sqli_abc123
```

When validation finishes, the returned per-finding validation summary keeps the
linkage back to the scanner candidate when available:

- `finding_id`
- `finding_source_file`
- `finding_summary`

This lets `/report`, `/remember --from-validate`, and later review steps trace
the validated issue back to the original scanner evidence without reparsing the
raw finding files.

Subsequent `/surface` and Store Finding queries show the recorded technical and
delivery/report status. Damaged supporting evidence invalidates current delivery
eligibility without deleting the historical claim, judgment or report.

Include in the explicit decision:
- The endpoint
- The bug class
- What the PoC shows
- The target program
- The exact replayable artifact and observed result if available

If you already ran `/validate` and it passed, `/report` must use the selected
finding's recorded summary path (or the path returned by that exact invocation),
not a repo-global latest pointer from another finding.

Optional deterministic replay/diff helpers live in `docs/evidence-runners.md`.
Use them when they make evidence reproducible, but keep `/validate` as the
report guidance: Claude still decides impact, preconditions, and whether
the issue is worth reporting.

## Case-State-Assisted Validation

Target case state is runtime context that feeds deterministic evidence runners:
actors, sessions, objects, private markers, and hypotheses. It holds no backlog
and no route score — action identity, claim, and execution state live in the one
action source. It is not a substitute for `/validate`, not a scope gate, and not
a reason to reject a replayable candidate. Use it only when it improves
continuity or reduces header/object drift.

Useful paths:

```bash
python3 tools/target_case_state.py summary --target <target> --json
python3 tools/target_case_state.py add-session --target <target> --session <ref> --actor <actor> --header-name <name> --header-value <value>
python3 tools/action_queue.py next --target <target>
```

Validate the underlying evidence of any candidate with the same 7-question gate
below. If live evidence is stronger than cached Case context, state the AI
override and continue with the stronger proof path.

## The 7-Question Gate

The command is a thin entry point. Apply the authoritative Q1-Q7, Q7b, chain,
and four-gate rules in `skills/triage-validation/SKILL.md`; do not maintain a
second checklist here. A non-pass keeps the Candidate open or routes it to
`CHAIN_REQUIRED`, `DOWNGRADE`, or `DO_NOT_REPORT` according to that Skill.

The gate covers, in order: target-bound replayability, demonstrated impact,
target context, reachable preconditions, known behavior, impact beyond a bare
possibility, and never-submit/chain status. Authenticated candidates also record
the Q7b identity boundary. Gate 2 remains delivery-mode conditional as described
above; local/lab external checks are `not applicable`, not a blocker.

## Output

**REPORT:** "All 7 questions pass. All 4 gates pass. Proceed to /report."

**CHAIN_REQUIRED:** "Q7 has a concrete connector, but the end-to-end chain is not yet proven. Keep the Candidate and collect [exact missing evidence]."

**DO_NOT_REPORT:** "Q[N] fails because [reason]. Do not report this candidate. Move on or demote only with a concrete next evidence action."

**DOWNGRADE:** "Q6 only shows a boundary signal. Use the lowest-risk missing differential, then re-triage the claimed impact."

## Source-Rejection Cite-Check（机器契约）

对于源码支持的 Candidate，只用文字声称 guard 存在不足以构成反证。canonical owner 写入
`validation_status=rejected` 前，必须绑定 `result=rejected` 的 validation summary，并在
`source_guard` 中记录真实 `source_file`、从 1 开始的 `line_number` 和单行精确 `quote`。
quote 必须是该行可执行、具有 guard 形态的代码；文件缺失、注释、转述或仅引用共同 token
时，Candidate 必须保持开放。该 cite-check（`tools/finding_index.py` 的 rejection gate
机械执行）只证明引用的 guard 确实存在；验证记录仍需单独解释它为何阻断所声称的
source-to-sink 路径。
