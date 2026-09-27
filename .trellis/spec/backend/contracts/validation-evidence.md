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

- Normal operation requires one initialized, healthy target Store. Target,
  store generation and claim are checked before execution/publication and again
  at registration under the target switch lock. Preview/legacy/damage reject.
- A real execution has its own attempt ID. A registration retry reuses the
  attempt and immutable raw material; the request lane never resends a started
  attempt. Operation is a Store registration receipt, not an HTTP request ID.
- Public summaries contain URL shapes; exact requested URLs are private,
  digest-bound identity artifacts. Native anchor must exactly match Finding
  endpoint/method. Both lanes register actual per-step endpoints and methods;
  empty/redacted query values cannot stand for an exact observed query.
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
  Complete evidence is required for candidate-ready validation. A transport
  failure with no published observations is unknown; earlier complete steps
  survive a partial run without authorizing completion.
- Explicit `state_changing=true` requires `redline_checked`; method names do not
  imply effect. Unknown effect remains unknown. Redirects stay within target;
  sensitive headers require destination-origin authorization.
- Runner never assesses technical truth, decides destination eligibility,
  registers an external delivery event, or resolves an Action. Explicit claim
  completion requires its complete operation or a valid work proof.
- Scaffold and preflight read only the Store. `/validate --decision-json` binds
  target/Finding/endpoint/method/family and a complete linked Store operation,
  checks current raw integrity, and requires explicit gates, Q1–Q7 basis and
  impact. Optional CVSS does not determine core technical truth.
- AI report bytes are atomically published before separate assessment,
  destination decision and eligible report registration. Their deterministic
  command IDs allow partial retries; a new judgment requires predecessor IDs.
  Same-decision/same-body retry preserves inode and bytes. Other Finding,
  stale judgment, missing registered body or changed bytes rejects.
- `/report` consumes registered AI text and rebuilds its index. Report
  generation never means external submission or Queue completion.
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
