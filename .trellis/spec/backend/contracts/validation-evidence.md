# Validation and Evidence Contracts

> 有界验证、证据门禁和执行 runner 契约。

## Scenario: AI-selected parser/WAF replay

### 1. Scope / Trigger

Use when a target-owned JSON, query, form, or other HTTP request shows a
parser/WAF boundary worth one focused follow-up. AI selects the exact
baseline/variant and execution medium; no fixed matrix or WAF-plan executor is
created.

### 2. Signatures

```text
python3 tools/validation_runner.py request-diff --target TARGET \
  --request-spec REQUEST_SPEC.json --repeat 2
```

`REQUEST_SPEC.json` is the existing request-diff contract: AI supplies the
target-owned baseline/variant pair, one active dimension, expected signal, and
repeat count. Unsupported wire formats remain raw/manual evidence.

### 3. Contracts

- The selected execution boundary validates target Scope/Auth, side-effect
  review, request budget, raw artifacts, and any owner write-back before I/O.
- A status/body/header change is an observation only. Promotion requires a
  stable backend, content, permission, or business-impact differential.
- WAF/vendor context is advisory evidence; it never selects an unbounded
  dictionary or turns a reaching response into a finding.

### 4. Validation & Error Matrix

| Condition | Result |
|---|---|
| invalid request spec, target mismatch, off-scope endpoint | exit `2`, no request |
| unsupported wire format or missing exact pair | `manual_required`, no clean result |
| `429`, transport error, or block persists | record observation and stop that focused replay |
| variant reaches app without stable protected/permission differential | signal/edge observation, not finding |

### 5. Good / Base / Bad Cases

- Good: AI uses a stored WAF/response artifact to choose one boundary variant,
  request-diff replays the exact pair, and the summary records lineage.
- Base: the request does not fit request-diff; AI preserves raw evidence and
  creates a target-owned finding claim/checkpoint action.
- Bad: submit an off-target URL or turn a 200/status change into a finding.

### 6. Tests Required

Cover request-spec scope/auth/side-effect rejection, exact-pair replay, raw
artifact lineage, unsupported-wire manual handling, and Autopilot/Checkpoint
projection of the resulting evidence.

### 7. Wrong vs Correct

```text
Wrong: WAF block -> model emits an unbounded payload list -> direct requests.
Correct: WAF context + target artifact -> one AI-selected pair -> shared
       request boundary gates Scope/Auth/budget -> response evidence -> owners.
```
- Recon WAF fingerprinting must publish a target-owned structured `live/waf_context.json`
  with detector status, sampled vendor observations, source hash, and raw artifact
  references. `wafw00f_hits.txt` remains a sampled host-level view; neither it nor a
  response-classifier vendor match is a vulnerability or bypass conclusion. AI may
  use the context to choose one bounded, evidence-linked next probe, while stable
  content/permission/route evidence remains the promotion gate.
- POST/JSON SQL coverage is AI-selected from observed fields and request
  semantics. Use request-diff for one exact same-method pair; use
  `timing_sql_runner.py` only for a time-shaped candidate. A budget boundary or
  WAF-only response is not a clean result.
- Scanner artifacts that feed `findings.json`, `surface.py`, and `checkpoint.py`
  must be idempotent per run. A rerun must overwrite or clear lane-local files
  such as `auth_bypass/unauth_api_access.txt` and
  `manual_review/unsafe_skipped.txt` instead of appending historical duplicates;
  empty manual-review files should be removed before summary generation.
- DNS permutation/brute force is an AI-selected Recon lane, not baseline
  breadth. `tools/dns_expand.py` requires an evidence-based reason, bounds seed,
  candidate, rate, and wall-time budgets, and uses the existing Recon phase lock.
  Only target-owned, wildcard-filtered names successfully resolved by `puredns`
  may be atomically merged into `subdomains/all.txt`/`resolved.txt`; failures
  preserve candidates and must not publish stale resolved output.
- Rebuilding `findings.json` must keep direct findings target-owned and must
  preserve existing validation/report state for unchanged finding IDs. External
  GitHub/Docker/CDN/OAuth/webhook URLs belong in chain-context artifacts, not in
  direct findings.

## Validation Runner and Store Evidence Contracts

### Scope and signatures

Use `validation_runner.py request-diff --target TARGET --request-spec SPEC` for
an AI-selected exact request pair, or `record-evidence --target TARGET
--finding-id ID --evidence-json FILE --attempt-id ID` for already-executed native
material. Both support `--repo-root`, explicit claim identity and side-effect
facts. Native registration sends no requests. Shared auth inputs retain the
AuthSession origin/scope rules; raw headers override only on the initial URL.

### Contracts

- Request-diff specs with different baseline/variant URLs must declare
  `subject_side` (`baseline` or `variant`). The selected side is the sole
  Finding/Action/attempt identity anchor; omission is rejected before I/O.
- Native `subject_step` explicitly selects a zero-based run index. Without it,
  only one exact endpoint/method match is accepted; ambiguous runs reject before
  any attempt or artifact publication.
- Schema-11 observations persist `identity_status`, `identity_technique`,
  `identity_v2` and `detail.evidence_role`. Native multi-step registration assigns
  identity only to the explicitly selected exact endpoint/method anchor; other steps remain
  control/none. Identity status and technique are never inherited from siblings.
- `closure_records()` exposes version-3 event envelopes and immutable
  `operation_id:step` IDs with request/response artifact hashes. Only complete
  subject v3 identities with matching raw technique authorize exact closure.
  V3 retains the absolute asset URL, method and all declared conditions; v2 is
  readable historical metadata only and is never implicitly upgraded.
  Legacy status/technique absence and control rows never close a family grid.
- `tests/test_native_first_replay.py` covers temporary Store replay, explicit
  schema-10 upgrade, all-family dimension isolation, native subject/control,
  publication manifests and changed-byte suppression. No live target is used.

- Normal operation requires one initialized, healthy target Store. Target and
  store generation are checked before execution/publication and at registration
  under the target switch lock. First attempt creation checks current claim/operator;
  original-command retries retain the existing attempt relation, including after
  explicit claim release. State transitions check claimant/token/version separately.
  Registration does not impose a new current-claim check. Preview/legacy/damage reject.
- A real execution has its own attempt ID. A registration retry reuses the
  attempt and immutable raw material; the request lane never resends a started
  attempt. Operation is a Store registration receipt, not an HTTP request ID.
- Runner summary/diff files are internal target analysis artifacts, not public
  exports. Their subject, request-pair and per-step URLs preserve exact query
  values, duplicate keys and encoding. Raw requests and auth/error-log boundaries
  are unchanged; public export redaction remains a separate responsibility.
- New digest-bound private request identities carry `url_representation=exact`;
  registration compares their requested URL exactly against each published step.
  Historical unmarked identities retain shape-only summary compatibility on
  registration/retry without rewriting old evidence or inventing missing values.
  The immutable identity, not mutable summary metadata, selects the comparison.
  Unknown representations reject. Native anchors still exactly match Finding
  endpoint/method; both lanes register actual per-step endpoints and methods.
- Raw requests/responses live in private target-owned files. Native evidence may
  reference other target-owned existing nonempty artifacts. Registration checks
  published digests before consuming them. Changed/missing raw material rejects,
  retains the attempt and creates no operation.
- `record_execution` atomically persists operation, observations, artifacts,
  explicit Finding links and audit. An error rolls back metadata, not raw files.
  `sync.status=partial` is retryable by registration, never by blind replay.
- Open family names are preserved. A canonical Coverage alias is optional;
  unknown names cannot accidentally close a standard coverage cell.
- An observation is not a technical verdict. Unspecified/unmet expectations
  remain `candidate`; only explicit clean-intent observations may be clean.
  Complete evidence is required for machine review admission. A transport
  failure with no published observations is unknown; earlier complete steps
  survive a partial run without authorizing completion.
- When a different-URL variant subject fails after baseline publication, retain
  only the real baseline control and its original URL/method/actor/identity/raw;
  do not attach it to the subject Finding. A bound partial needs a matching Action
  family, not the missing subject endpoint; complete/nonempty unknown still need
  one endpoint/family match. The exact admission matrix and caller-declared
  association limit live in `transactional-target-state.md`; registration does not
  prove request-plan membership. Saved-summary sync returns `updated` once
  (operation/revision +1), then `deduplicated` without more requests, raw changes
  or attempts, including after explicit blocked recovery. Pending sibling attempts
  still prevent claim release; registration itself never releases the claim.
- Explicit `state_changing=true` requires `redline_checked`; method names do not
  imply effect. Unknown effect remains unknown. Redirects stay within target;
  sensitive headers require destination-origin authorization.
- Runner never assesses technical truth, decides destination eligibility,
  registers an external delivery event, or resolves an Action. Explicit claim
  completion requires its complete operation or a valid work proof.
- Scaffold and preflight read only the Store. `/validate --decision-json` binds
  target/Finding/endpoint/method/family and a complete linked Store operation,
  checks current raw integrity, and requires explicit gates, Q1–Q7 basis and
  impact. Optional CVSS does not determine core technical truth. Runner
  `result`/`candidate_ready` and declared `expected` are not review admission
  gates: complete candidate, tested-clean and native operations may be reviewed
  without relabeling evidence or sending another request. Explicit technical
  gates determine confirmed versus inconclusive; failed/unknown technical gates
  do not mean refuted. Partial operations still reject even for negative review.
- AI report bytes are atomically published before separate assessment,
  destination decision and eligible report registration. Their deterministic
  command IDs allow partial retries; a new judgment requires predecessor IDs.
  Same-decision/same-body retry preserves inode and bytes. Other Finding,
  stale judgment, missing registered body or changed bytes rejects.
- `/report` indexes registered AI text; missing bodies remain `pending_drafts`.
  Publishing new text requires explicit body/Finding/current assessment/current eligible
  delivery inputs. It never generates category narratives or implies external submission
  or Queue completion.
- Validation refresh preserves runtime breadcrumbs and explicit
  `source_knowledge_refs` without generating pattern scores or appending to
  `hunt-memory/pattern_calibration.jsonl`. Historical calibration inspection
  remains explicit; existing files are neither rewritten nor deleted.
- Each index entry reads an explicit Severity declaration from that report's
  immutable, hash-checked body. Missing, invalid or conflicting declarations
  display `unknown`, never a category/default medium. A new decision with explicit
  severity must match its report field at preflight; an omitted severity/CVSS is
  allowed. Different reports/destinations never share a guessed Finding severity.
- Raw target ownership is shared by Action/native/Store through
  `target_paths.target_raw_artifact_path`: target-local evidence/recon/findings/reports
  and private validation/browser roots only. Target words elsewhere in a path,
  cross-target references or symlink escapes are not evidence ownership.
- The old Ledger/Finding/Queue compensation and `runner_witness.py` are retired.
  Historical Ledger JSONL diagnostics remain explicit import/history inputs.

### Validation matrix and tests

| Input/failure | Required result |
|---|---|
| off-target request, bad claim, redline missing | reject before network/material side effects |
| same attempt/material | one operation; idempotent registration |
| changed raw after publication | partial registration; no metadata commit |
| partial/no-response execution | partial/unknown; preserve existing steps |
| variant subject fails after different-URL baseline | register original control as partial; no subject identity/Finding evidence fabrication |
| saved partial/unknown summary replay after explicit blocked | deduplicated against post-blocked revision; no request replay or new attempt |
| unknown family | save evidence; no unrelated Coverage closure |
| assessment/delivery/report command interrupted | retain body and committed receipts; retry only missing commands |
| report publication interrupted | no partial public body; retryable |
| known/duplicate/ineligible destination | technical confirmation can remain confirmed |
| preflight on legacy/missing/fenced/broken Store | explicit failure; no migration or report output |

`tests/test_validation_runner.py`, `tests/test_validate_target_mode.py`,
`tests/test_finding_index.py` and `tests/test_target_store.py` cover these
boundaries, real CLI restart/recovery, current evidence integrity and report
text preservation. `tests/test_response_diff.py` covers structural diffs;
`tests/test_current_truth.py` ensures damaged evidence cannot authorize closure.
`test_partial_variant_subject_registration_recovers_claim` uses a real temporary
Store and mocks only HTTP for zero/one responses; it checks original raw/identity,
first registration, summary reload/replay, explicit claim recovery and completion
refusal. Same-URL partial tests alone do not cover this different-subject boundary.

## Scenario: ASP.NET ViewState captured-response known-key check

### 1. Scope / Trigger

Use when target-owned browser or response evidence contains `__VIEWSTATE`. This
branch is independent of Telerik routes or components.

### 2. Signatures

```bash
python3 tools/aspnet_viewstate_knownkey.py \
  --body-file CAPTURED_BODY \
  --page-url PAGE_URL \
  [--cookies-file PRIVATE_COOKIES] \
  [--reveal-key]
```

```python
match_aspnet_viewstate_response(
    body,
    *,
    page_url,
    cookies=None,
    reveal_keys=False,
) -> dict
```

### 3. Contracts

- The tool reads a captured body and optional private cookie JSON only. It makes
  zero network requests and does not mutate Action Queue, Evidence, or Findings.
- Badsecrets 1.2.1 `ASPNET_Viewstate` performs parsing, key derivation, MAC,
  encryption, and ViewStateUserKey handling. The project-local
  `aspnet_machinekeys.txt` remains the key resource.
- Default JSON returns resource counts, matched source line, algorithms, mode, and
  key fingerprints. `--reveal-key` explicitly returns the matched validation and
  decryption key material so an approved validation can use it.
- Callers may keep revealed keys in target-private validation artifacts. They must
  not copy key material into Action metadata, Checkpoint prose, public reports, or
  the global knowledge base.
- Missing Telerik `WebResource.axd` closes only the Telerik branch. A known-key miss
  closes only the weak/default-machineKey branch; neither condition makes an
  observed ViewState or the whole deserialization capability `N/A`.

### 4. Validation & Error Matrix

| Condition | Result |
|---|---|
| body over 1 MiB, invalid URL, unreadable/invalid cookie file | CLI error, exit `2` |
| Badsecrets dependency missing | explicit CLI error; no fallback parser |
| no recognizable ViewState | `viewstates_recognized=0`, no match |
| known validation/decryption key | source line, algorithm/mode, fingerprint; key only with `--reveal-key` |
| MAC disabled | `kind=mac-disabled`; no fabricated key |
| no Telerik route but `__VIEWSTATE` exists | keep ViewState review actionable |

### 5. Good / Base / Bad Cases

- Good: captured same-page response and page URL produce a known-key match; a
  controlled validator explicitly reveals and uses that key while reports remain
  redacted.
- Base: ViewState is recognized but no bundled key matches; continue integrity and
  consume/state controls, then close only the known-key branch if clean.
- Bad: mark deserialization `N/A` because Telerik is absent, reimplement ViewState
  cryptography locally, or automatically print matched keys into reports.

### 6. Tests Required

- `tests/test_aspnet_viewstate_knownkey.py` covers a project-resource match, source
  line/fingerprint output, explicit key reveal, MAC-disabled classification, CLI
  file input, and zero network/queue effects.
- `tests/test_context_pack.py` proves `__VIEWSTATE` loads the ViewState tool without
  requiring or loading the Telerik tool.
- `tests/test_checkpoint.py` proves the existing ViewState review remains actionable
  and does not accept Telerik absence as `N/A`.

### 7. Wrong vs Correct

```text
Wrong: no Telerik endpoint -> deserialization N/A.
Correct: __VIEWSTATE -> offline machineKey check -> integrity/consume validation;
         Telerik is a separate optional branch.
```

## Scenario: Telerik captured-response known-key check

### 1. Scope / Trigger

Use only after target-owned browser, recon, or private response evidence contains
`Telerik`, `AsyncUpload`, `SerializedParameters`, or `DialogParameters`.

### 2. Signatures

```bash
python3 tools/telerik_knownkey.py --body-file CAPTURED_BODY [--max-values 1..8]
```

### 3. Contracts

- The tool accepts captured response files only: no target URL, HTTP client, state
  write, Action Queue mutation, external key input, or automatic candidate/finding
  promotion.
- It delegates matching to `tools/vendor/badsecrets_telerik/telerik_hashkey.py`, a
  minimal project-local passive copy using `aspnet_machinekeys.txt` and
  `telerik_hash_keys.txt`. Output exposes index and SHA-256 fingerprint, never key
  material.
- Context Pack adds the tool and its advisory only when the Telerik signal is present;
  a match is a ConfigurationHashKey reuse signal and still requires separate,
  controlled impact evidence.

### 4. Validation & Error Matrix

| Condition | Result |
|---|---|
| body exceeds 1 MiB, invalid UTF-8, unreadable file | CLI error, exit `2`, no target effect |
| malformed/JWT-like value | `recognized=false`, no match |
| more than 8 captured values | CLI error, exit `2`, no target effect |
| valid explicit match | offline JSON match only; no lifecycle transition |

### 5. Good/Base/Bad Cases

- Good: a captured Telerik response matches Badsecrets' default local key lists, then
  moves to a separately approved controlled-impact check.
- Base: ordinary ViewState evidence remains the existing baseline/format-control/
  one-byte-tamper integrity review.
- Bad: send a default dictionary against a target, treat a signature match as a finding,
  or wire this tool into default recon/scanning.

### 6. Tests Required

- `tests/test_telerik_knownkey.py` covers a Badsecrets default-key signature,
  malformed-value rejection, and zero network/queue fields.
- `tests/test_context_pack.py` proves Telerik evidence loads the tool and advisory only.

### 7. Wrong vs Correct

```text
Wrong: Telerik banner -> automatic network key dictionary probe -> Finding.
Correct: captured response -> offline default-key fingerprinted match
         -> separate controlled impact proof -> existing validation gate.
```

## Local comparison fixture request-budget observations

### 1. Scope / Trigger

Applies to the isolated `09-20-native-first-practical-optimization/research/online_*`
comparison harness, not production target responses or request authorization.

### 2. Signatures

`Fixture.respond()` emits `X-Request-Limit`, `X-Request-Count`, and
`X-Request-Remaining` in stages 1/2. The generated `http_record.py ACTOR /path`
preserves the response and exposes `request_budget={limit, used, remaining}`.

### 3. Contracts

`online_fixture.REQUEST_LIMIT=40` owns the cap. Count includes the current request;
remaining is `max(0, limit-used)`. All arms see identical metadata without an
extra request or client-side budget ledger. The manifest records
`budget_observation_version=1`; report protocol v2 and evidence scoring stay unchanged.

### 4. Validation & Error Matrix

- Request 40: handled normally, remaining 0; request 41: recorded 429, budget failed.
- New stage: count resets; historical stage 0: budget headers absent.
- Missing, non-integer, nonpositive limit/count, or inconsistent remaining:
  preserve raw evidence, return `request_budget=null` and
  `budget_status=unknown_missing_or_invalid_headers`, never infer unlimited budget.

### 5. Good/Base/Bad Cases

Good: show the response's remaining allowance. Base: use own tools with the same
headers. Bad: raise the cap, expose oracle answers, or turn old failed runs into passes.

### 6. Tests Required

`test_online_compare.py::OnlineComparisonTests.test_recorder_reports_server_budget_without_extra_requests_or_invented_defaults`
exercises real HTTP/recorder calls at 39/40/41, stage reset, invalid/absent headers,
preserved raw fields, and exactly one request per invocation. Run via
`online_compare.py --offline-check`; it never invokes a model.

### 7. Wrong vs Correct

Wrong: missing budget → zero/unlimited, or retry success → replace original score.
Correct: missing budget → explicit unknown with evidence retained; each new facility
version gets a separate manifest/run and leaves historical primary scores untouched.

## Local comparison interruption summaries

### 1. Scope / Trigger

The same isolated comparison harness may resume after its parent process exits.
This concerns research evidence, not production execution recovery.

### 2. Signatures

`online_compare.py --output RUN_ROOT --resume` skips existing stages.
`summarize_pair.py RUN_ROOT --output NEW_JSON` verifies two- or four-arm v2 runs.
`diagnose_online.py RUN_ROOT --output NEW_JSON` emits event diagnostics v3.

### 3. Contracts

Before resuming, verify no old process remains and preserve the original status,
server logs and artifact hashes. The frozen manifest must match. An existing
`running` stage becomes `interrupted`, never a rerun or a successful replacement.
Missing finalized score is accepted only for an explicitly interrupted stage;
requests come from its existing server-log cell, while score, expected coverage
and wall time remain null. Final usage/cost remain null when absent from the stream.
Diagnostics do not substitute event intervals for missing total wall time.
Completed records still require oracle/raw/argv/usage consistency and full quality
plus valid budget for paired comparisons. No result modifies primary stage files.

### 4. Validation & Error Matrix

- Missing score with `running`/`complete` status: reject; do not silently omit a stage.
- Interrupted stage: retain a failed/incomplete row; no expansion-gate pass.
- Missing paired metric: delta is null, not zero or a claimed saving.
- Existing output file: exit 2 before reading or rewriting experiment results.
- Source drift: report it and keep the expansion gate false.

### 5. Good/Base/Bad Cases

Good: resume only unstarted stages. Base: retain partial tool/request evidence with
unknown final costs. Bad: retry a started stage or invent a zero-cost completion.

### 6. Tests Required

`test_four_arm_summary_preserves_interruption_and_requires_full_quality` checks all
eight stage rows, three baselines, partial metrics, incomplete-coverage rejection,
read-only evidence and output preservation. The diagnostic message-usage regression
also checks null wall time and retained tool calls after interruption.

### 7. Wrong vs Correct

Wrong: stale running record → rerun → replace failure with its successful result.
Correct: preserve partial evidence → interrupted row → run only unstarted cells.

## Scenario: Review admission independent of Runner labels

### 1. Scope / Trigger
`/validate --decision-json` preflight and apply share owner-bound evidence admission.

### 2. Signatures
`_validate_machine_runner_witness(...) -> tuple[Path, str]` returns the summary
path and verified Store operation ID; decision schema and Store APIs are unchanged.

### 3. Contracts
A complete linked operation, not `result` or `candidate_ready`, authorizes review.
AI must still supply explicit gates and impact basis. Review never reruns requests
or rewrites the original Runner summary. Assessment and delivery remain separate.

### 4. Validation & Error Matrix
- Missing expected/candidate/tested_clean/dead_end label: not an admission error.
- Partial operation or no observations: reject before writes, even for negative review.
- Unbound Finding/endpoint/method, changed raw artifacts or stale CAS: reject.
- Failed/unknown technical gates: inconclusive, no eligible report; not refuted.

### 5. Good/Base/Bad Cases
Good: review a complete no-expected pair as inconclusive without new execution.
Base: unchanged tested_finding review. Bad: rename candidate to manufacture proof.

### 6. Tests Required
`test_machine_review_admission_is_independent_of_native_labels`,
`test_machine_reviews_request_diff_without_expected_or_new_execution`, and
`test_candidate_admission_keeps_operation_guards` in `test_validate_target_mode.py`
check explicit verdicts, no preflight writes, unchanged evidence, no requests,
and partial/unbound/tampered rejection in both preflight and apply.

### 7. Wrong vs Correct
Wrong: missing expected means existing evidence cannot be assessed.
Correct: verify actual operation and provenance, then record the explicit judgment;
wire declarations never substitute for impact evidence.

## Local integrity failure boundary

### 1. Scope / Trigger

Changes to acquired evidence integrity, closure, or actor-coverage projections.

### 2. Signatures

`current_cell_projection(repo_root, target, *, _store=None)` returns the checked
truth including `invalid_event_ids`. `build_summary(..., _truth=None)` consumes
that snapshot. `actor_matrix_status(entries, requirements, *,
invalid_event_ids=frozenset())` remains a pure reducer.

### 3. Contracts

`current_cell_projection` validates all artifacts on its captured Store snapshot.
Known damaged operations invalidate their own subject/control-dependent closures
only after latest-record reduction. Never remove damaged input first: doing so
would resurrect old evidence. Unknown identities or truncated acquisition still
suppress all closure authority. History and diagnostics remain readable.

The same acquisition returns JSON-safe `invalid_event_ids`: `[]` for no integrity
denial, a sorted complete list for operation-local denial, or `null` for global
denial. This scope is shared with actor coverage; `health.invalid_rows` is only a
five-item display sample. Controls deny their whole operation. Neither the scope
nor the captured health is an authorization cache; later reads recheck raw bytes
and artifact events even at the same Store revision.

`build_summary(..., _truth=...)` requires this scope in a supplied snapshot and
does not infer it or reread missing fields. Actor reduction first removes
owner-superseded registrations, selects the latest matching record, then checks
integrity. Denied matches become `pending` while retaining their original
result/time/reference; absent matches stay `missing`. Never remove damaged input
before latest selection or revive an older result. Independent healthy actor
coverage survives local damage, including failures beyond the diagnostic sample.

Actor matching and result semantics remain separate from closure identity:
healthy historical v2/incomplete identities and signal/candidate observations keep
their existing actor meaning. No new subject-only or v3 gate is introduced.
The two-argument records API is retained; the production summary always passes
acquired scope.
Context Pack and Checkpoint reuse that answer without new reads, hashes, domain
writes, or automatic actions. History and result counts are not filtered.

### 4. Validation & Error Matrix

| Condition | Result |
| --- | --- |
| Intact evidence, empty denial scope | Existing actor result mapping |
| Selected event denied, or global denial | `pending`; preserve result/time/reference |
| No current matching record | `missing`; empty latest fields |
| Supplied truth lacks `invalid_event_ids` | `KeyError`; no fallback or recheck |
| Missing/unreadable Store | Existing explicit Store failure, not empty health |

### 5. Good/Base/Bad Cases

Good: control damage denies its subject while independent healthy actors remain
covered. Base: healthy v2 evidence retains actor meaning without closing v3 cells.
Bad: interpreting five diagnostic samples as the complete authorization scope.

### 6. Tests Required

`tests/test_evidence_ledger.py` covers changed/missing/unavailable/revoked material,
controls, restoration, supersession, and historical actor states.
`test_local_damage_preserves_independent_closure_without_resurrecting_history`
checks six invalid operations beyond five samples and prevents old-result revival.
Current-truth tests cover global denial, JSON roundtrip, and no-I/O snapshot reuse;
Context Pack/Checkpoint actor tests check gaps, retained counts, and no writes/actions.

### 7. Wrong vs Correct

Wrong: filter damaged history, then select the latest remaining actor result.
Correct: exclude owner-superseded registrations, select latest, then apply the
same acquisition's complete denial scope without rewriting the historical result.

## Registration succession precedes closure interpretation

`TargetStore.closure_records` exposes owner-derived `superseded` for each historic
observation using operations.supersedes, including replacements with zero rows.
Projection drops superseded registrations from authorization before interpreting
identity, without deleting history. Invalid v3 identity in the current
registration is a visible integrity error; it never reactivates the predecessor.
Artifact verification for current closure excludes superseded operations. A new
attempt remains a separate execution; this rule does not merge similar attempts.
Actor coverage also excludes superseded registrations before indexing, even for
zero-observation or backdated replacements. Other unsuperseded attempts still
participate in the existing timestamp/revision/step order; succession does not
create an actor-key tombstone. Superseded-only requirements become `missing`.


## Scenario: Authored report publication without narrative templates

### 1. Scope / Trigger
An eligible destination needs a report body or the report index needs refreshing.
AI owns method/impact reasoning and wording; deterministic owners retain eligibility,
evidence integrity and publication. Category templates and `generate_report()` are retired.

### 2. Signatures
`process_findings_dir(findings_dir, *, finding_id="", assessment_id="", delivery_id="", body_file=None)`
returns the unchanged `(total_reports, report_index)` tuple. The CLI exposes those
four inputs as `--finding-id`, `--assessment-id`, `--delivery-id`, `--body-file`.
The no-input call only indexes; the four-input call publishes then indexes.
`hunt.generate_reports(domain)` returns an integer count or raises
`ReportGenerationError`. `hunt.main() -> int` propagates through
`raise SystemExit(main())`; report-only failure exits `2`, success exits `0`.

### 3. Contracts
All four publication inputs are explicit; no implicit latest judgment selection.
The Finding must have a current confirmed assessment and current eligible delivery,
with intact linked observations. Publish the provided UTF-8 bytes unchanged before
Store registration. Existing target/Finding/assessment/delivery report IDs remain
stable; retry only identical bytes. Never guess completeness from narrative markers.
INDEX/SUMMARY include derived `pending_drafts` per unreported eligible destination;
no new state table. Missing text does not block other valid reports. Registered stale
bodies are omitted from the current index, retained on disk and in history.
Manual mode records supplied inputs or a supplied draft without default impact,
remediation or severity. Attachments go to manual drafts; known `poc_screenshots/`
assets are copied with no-overwrite publication so relative links survive. Attachment
edits reject linked/nonregular/out-of-layout drafts and consult existing Store report
refs under its mutation lock, including stale reports registered directly in drafts.
An absent Store permits new manual notes; a damaged existing Store never downgrades.
Hunt consumes only successful `Indexed N current reports` or legacy `Generated N reports`
output, including zero. Missing findings directories remain no-work success without
starting a child. Batch report-only sorts target directories, processes every target
despite report failures, and preserves successful results; ordinary hunt does not report.

### 4. Validation & Error Matrix
- Missing any of the four inputs, empty/non-UTF8 body: reject; no report metadata.
- Wrong/stale assessment/delivery, unconfirmed or ineligible destination, damaged
  evidence: reject before report publication. Store rechecks at registration.
- Existing different bytes, nonregular/symlinked output or invalid registered artifact:
  reject, retain old bytes; never recreate a deleted registered body on explicit retry.
- Registration/index failure: retain complete body/committed receipts; identical retry.
- Missing draft: needs_draft in derived index; no automatic report or owner mutation.
- Invalid/absent severity declaration: unknown, not a category-derived fallback.
- Hunt child nonzero/timeout/start failure: `ReportGenerationError` with target,
  `execution` category and child diagnostic, even if output contains a count.
- Hunt child succeeds without a parseable count (including empty output): same error
  with `protocol` category; no historical Markdown fallback. CLI emits target/retry
  diagnostics to stderr; any failed batch target makes the final exit code `2`.
- Missing/empty findings root or no target directories: report-only exits `0`.

### 5. Good/Base/Bad Cases
Good: two independently eligible destinations receive explicitly submitted, distinct
bodies. Base: /validate's existing registered body is indexed without rewriting it.
Bad: infer administrative impact from a marker or create text because an item is eligible.
Hunt: valid zero is success; a failed child is not zero, and a later successful batch
target still runs without clearing earlier failures.

### 6. Tests Required
`tests/test_finding_index.py` covers explicit CLI input, all-destination publication,
exact CRLF/Unicode bytes, pending drafts alongside valid reports, stale/foreign IDs,
raw tampering, no-overwrite retry and manual screenshot relocation.
`tests/test_validate_target_mode.py` and `tests/test_validation_runner.py` preserve
/validate's own report path. Hunt counts successful indexed reports, not stale files.
Its helper regressions retain zero/legacy counts, execution/protocol diagnostics and
missing-directory no-child behavior. `tests/test_hunt_initialization.py` runs an
unmodified temporary Hunt copy via `runpy(..., run_name="__main__")` in real subprocesses
to assert exit `2`, batch continuation/preserved output, and zero/no-work success;
lightweight tests preserve non-report dispatch and expected error exits. All tool,
auth/config and network interactions are isolated; wrapping `main()` in a test-only
`sys.exit()` does not prove the production entrypoint propagates its result.

### 7. Wrong vs Correct
Wrong: family=auth_bypass -> critical impact paragraph -> registered report.
Correct: evidence-backed explicit judgments -> AI-authored destination text ->
owner-bound immutable publication; no text means an unresolved draft, not a finding.
Wrong: `return count if count is not None else 0` hides execution/protocol failures.
Correct: successful integer or domain error -> CLI aggregate -> actual process exit.
