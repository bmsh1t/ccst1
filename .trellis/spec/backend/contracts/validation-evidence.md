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

## Validation Runner Contracts

### 1. Scope / Trigger

Use deterministic validation runners when a lead needs repeatable replay/diff
evidence before `/validate`. Runners are the execution plane only: Claude still
chooses the hypothesis, explains the impact, chains evidence, and decides
upgrade/downgrade.

`tools/runner_witness.py` is the shared verifier for the immutable runner
summary, artifact digests, operation material, and Ledger replay consumed by
both `/validate` and `report_generator.py`. Keep this boundary independent of
the report projection so either consumer cannot weaken the other's finality
checks.

A dedicated lane is admitted only when existing shared runners cannot express
the required input, observation, or evidence semantics and the execution is
stable, repeatable, and reusable across targets. Keep one-off target cases as
bounded AI-selected evidence actions instead of promoting them to lanes.

### 2. Signatures

- `python3 tools/validation_runner.py authz-public-exposure --target <target> --url <url> [--method GET] [--header 'Name: value'] [--body <text>] [--browser-observed] [--no-ledger]`
- `python3 tools/validation_runner.py request-diff --target <target> --request-spec <spec.json> [--repeat N] [--browser-observed] [--no-ledger]`
- `python3 tools/validation_runner.py marker-replay --target <target> --url <url> --expect-marker <inert-marker> [--baseline-url <neutral-control-url>] [--baseline-body <text>] [--vuln-class RCE] [--method GET] [--body <text>] [--repeat N] [--browser-observed] [--state-changing] [--no-ledger]`
- `python3 tools/validation_runner.py idor-actor-pair --target <target> --url <same-object-url> --owner-header 'Authorization: ...' --peer-header 'Authorization: ...' [--expect-marker <owner-private-marker>] [--repeat N] [--browser-observed] [--state-changing] [--no-ledger]`
- `python3 tools/validation_runner.py idor-actor-pair --target <target> --from-case-state --backlog-id <val_id> [--repeat N]`
- `python3 tools/validation_runner.py idor-actor-pair --target <target> --from-case-state --owner-actor <actor> --peer-actor <actor> --object-ref <ref> [--repeat N]`
- `python3 tools/validation_runner.py idor-actor-pair --target <target> --from-case-state --backlog-id <val_id> --complete-case-state [--repeat N]`
- Shared auth inputs: `[--auth-file <json-or-env>] [--header 'Name: value']`;
  explicit raw headers override AuthSession only on the initial URL.

### 3. Contracts

Runner output must include:

- `result`: `tested_finding`, `candidate`, `tested_clean`, or `dead_end`
- `candidate_ready`: boolean
- raw request/response artifact paths under `evidence/<target_key>/validation/<finding-id>/`
- `evidence_rubric` where applicable
- `ledger_record` unless `--no-ledger`
- stable `operation_id`; Ledger rows also carry the derived `event_id`
- persisted path-independent `operation_material`; consumers recompute
  `operation_id` from that material and the current request/response artifact
  kind+SHA-256 bindings
- deterministic `artifact_bindings[]` for existing raw artifacts, with `kind`,
  repo-owned `ref`, and SHA-256; request/response bindings are mandatory for a
  runner witness consumed by non-TTY `/validate`
- `ai_next.hypothesis`, `ai_next.next_action`, and `ai_next.stop_condition`
- `sync` unless `--no-sync`: ordered Ledger -> Finding -> Action Queue owner
  reconciliation. Each owner reports `updated|deduplicated|skipped|error`; any
  owner error makes top-level `status=partial`, and replay fills only missing work.
- A runner-declared Ledger `write_status=skipped` remains `sync.ledger.status=skipped`;
  sync must not replay that intentionally incomplete record or turn it into `partial`.
- Runner request facts are normalized before network I/O. `state_changing=true`
  requires `--redline-checked`; `state_changing=false` is authoritative even
  for `PUT`, `PATCH`, and `DELETE` when the caller has evidence that the replay
  is a preview/inert/read-only action. If the effect is omitted, the runner
  preserves it as unknown and does not infer a gate from the method name; the
  caller may record the fact later. Method names, CVE/PoC labels, and component
  identity never substitute for an actual side-effect fact.
- WebSocket, gRPC, LLM/RAG and other protocol-specific observations remain
  AI-selected actions through the existing browser, HTTP, MCP, subprocess, or
  source boundary. A protocol name alone does not create a runner; when a
  transport cannot be expressed by an existing boundary, preserve the raw
  observation as a candidate/manual action with the same target, evidence,
  budget, side-effect, and owner-sync requirements.

### 4. Validation & Error Matrix

- Authz public exposure promotes to `tested_finding` only when status is 200
  and sensitive/admin/config markers appear in the response body, not only in
  the path. Body-backed markers should come from structured config/auth field
  names or strong secret-value shapes, not from challenge/tutorial prose that
  merely mentions words like `password`, `admin`, or `oauth`.
- The anonymous public-exposure lane is a baseline-only exposure observation.
  `tested_clean` closes only that exposure hypothesis; it does not establish
  anonymous denial on a protected resource. Its Ledger variant is `baseline`,
  while `unauth_denied` is reserved for an explicit protected-resource denial.
- Authz role replay may return `candidate` even without owner/peer difference
  when anonymous is denied, both authenticated actors can read the same
  collection, and that collection has account/identity/authz-shaped fields
  such as email/username plus role/permissions/token-like keys. This is not a
  finding by itself; it requires policy, role expectation, or object-specific
  evidence before report promotion.
- SQLi result diff promotes to `tested_finding` only when the variant is
  injection-shaped and every repeat has a material status/count/field/length
  difference. Ordinary search/filter differences are `tested_clean`.
- Marker replay promotes to `tested_finding` only when the exact
  operator-provided request returns the expected inert marker in every repeat.
  When `--baseline-url` is supplied, every target-owned control response must
  be successful and non-truncated, must not contain the marker, and the marker
  must pass the minimum uniqueness check; otherwise the result remains a
  `candidate` signal, never `tested_clean` or `tested_finding`. The runner must
  not generate RCE/SSTI/command payloads on its own.
- IDOR actor-pair promotes to `tested_finding` only when owner succeeds, peer
  succeeds, and every repeat shows either an operator-provided private marker in
  the peer response or exact non-trivial owner-body match. Peer access without a
  marker/body match is `candidate`, not `tested_finding`; consistent 401/403/404
  is `tested_clean`.
- If the owner baseline itself fails or is unstable, IDOR actor-pair must return
  `dead_end`, not `tested_clean`. A failed owner request proves the replay
  precondition is invalid, not that authorization is safe.
- `--from-case-state` must fail fast if the referenced backlog/object/actor or
  usable actor session is missing. It reads public case metadata plus the
  `private_ref` session artifact through `load_case_state()`; header values must
  not be stored in `state/<target_key>/case_state.json` or read from skills,
  knowledge cards, or docs.
- `--complete-case-state` is local state write-back only. It requires
  `--from-case-state --backlog-id`, writes the runner result and summary path via
  `complete-backlog`, and must not alter remote target state.
- Redirects remain target-owned. On an origin change, caller-sensitive headers
  are stripped; AuthSession headers are replayed only when the destination
  origin is explicitly authorized by that session.
- Replaying one summary uses the same operation/event IDs. Ledger append is
  locked, one-line, fsynced, and event-ID idempotent; Finding and Queue retain
  their own monotonic lifecycle and deduplicate by `runner_operation_id`.
- Finding runner replay may deduplicate by `runner_operation_id` only after
  `verify_finding_owner_provenance()` succeeds. If canonical `findings.json`
  was written but `mutation-events.jsonl` append failed, replay must fall
  through the owner mutation path, append the missing event once, and only then
  become idempotent.
- A damaged Ledger row reports bounded path/line/reason diagnostics. Valid rows
  remain inspectable, but any partial/unreadable Ledger withholds `closed_cells`
  so corruption cannot authorize closure.
- Runner state sync maps final outcomes conservatively:
  - `tested_finding` -> finding `validation_status=candidate`, queue `candidate`;
    `/validate` remains the only owner that promotes the Finding to `validated`
  - `tested_clean` -> finding `validation_status=rejected`, queue `tested`
  - `candidate` -> finding `validation_status=candidate`, queue `candidate`
  - `dead_end` -> finding `validation_status=rejected`, queue `dead-end`
  - request diff without a canonical Ledger family -> Ledger `skipped`, never `partial`
  Missing `findings.json` rows or absent queue actions are `sync.status=skipped`,
  not runner failures.
- Scanner SAML signature stripping is finding-grade only when
  `BBHUNT_SAML_PROTECTED_URL` is an explicit same-target protected resource,
  the anonymous baseline is denied/redirected, the stripped assertion response
  issues a Cookie, and a Cookie-backed read-back returns a non-empty, different
  HTTP 200 response. An ACS `200/302`, login redirect, error page, SPA fallback,
  absent Cookie, or failed read-back is written only to
  `manual_review/saml_signature_review.txt`.
- Ledger/Finding/Queue owner exception -> `sync.status=partial`; persist the
  summary witness and retry the same operation rather than reporting `updated`.
- Non-TTY `/validate --decision-json` schema v2 accepts only a schema-v1 runner
  summary that is `tested_finding` and `candidate_ready=true`. The summary must
  self-bind its path, match target/finding/endpoint/method, verify every artifact
  digest, and match the canonical Finding's `validation_summary` and
  `runner_operation_id`; `verify_finding_owner_provenance()` must pass before any
  report, summary, Ledger, Queue, Finding, or runtime write.

### 5. Good/Base/Bad Cases

- Good: browser-observed search endpoint replayed with baseline `q=` and one
  injection-shaped perturbation, repeated twice, stable JSON count diff.
- Good: exact template-render request replayed twice and both responses contain
  a harmless marker chosen before replay.
- Good: owner order endpoint replayed as peer, peer response contains the known
  owner-private marker in every repeat, and raw owner/peer requests are saved.
- Good: Queue write fails after Ledger/Finding succeed; replay deduplicates those
  owners, completes Queue once, and converges without lifecycle downgrade.
- Base: anonymous admin/config URL returns 200 but body contains only generic
  `{"ok": true}`; keep as `tested_clean` because the marker is path-only.
- Bad: ordinary `q=apple` changes product count and is recorded as SQLi. That
  is normal application filtering, not injection evidence.
- Bad: runner invents a command/template payload instead of replaying an exact
  operator-provided safe marker request.
- Bad: owner and peer contexts are identical; the runner must fail fast instead
  of treating a self-replay as actor-diff evidence.
- Bad: a cross-origin redirect copies raw Authorization/Cookie headers merely
  because the destination is another in-scope subdomain.
- Bad: an AI-selected protocol observation is promoted from a transport/status
  signal without raw request/response evidence or a reproducible impact.

### 6. Tests Required

- `tests/test_validation_runner.py` must cover finding and clean outcomes for
  every runner lane.
- Regression tests must assert artifact paths, ledger writes, body-backed marker
  behavior, and injection-shaped probe gating.
- `tests/test_response_diff.py` must cover JSON count/field snapshots and
  baseline-vs-variant structural diff output.
- Runner sync regressions must assert that a replay can close active
  `validation`, `candidate-evidence-gap`, `ranked-surface`, and `coverage-gap`
  queue items without requiring a human to run `/validate` only to update state.
- Fault-injection regressions must fail after each Ledger/Finding/Queue step,
  replay the same summary, and assert one Ledger event, one Finding mutation,
  one Queue attempt, stable operation IDs, and converged owner status.
- Request-diff regressions must assert that a missing canonical Ledger family
  remains skipped during sync while a canonical family still replays normally.
- Non-HTTP observations must assert that the selected existing boundary retains
  raw input/output, target scope, and owner-sync metadata, or remains a manual
  candidate when that boundary is unavailable.
- Ledger tests must cover invalid JSON/UTF-8 diagnostics, continuous valid
  prefix offset, warning bounds, and fail-open closure projection.

### 7. Wrong vs Correct

#### Wrong

Promote a lead because `/admin/ping` contains `admin` in the URL or because a
normal search term changes result count.

#### Correct

Treat path-only markers and ordinary business filtering as clean/dead-end
evidence. Promote only when the response body and controlled probe shape satisfy
the lane-specific evidence gate, then let `/validate` make the report decision.
Resolve headers per URL and replay the same owner operation until all three
existing state owners converge; do not invent a cross-file transaction owner.
For protocol observations, use the existing boundary that can actually preserve
the input/output and auth context; otherwise retain a manual candidate instead
of inventing a transport-specific runner or silently dropping headers.

## Scenario: Versioned Action Queue runner observation

### 1. Scope / Trigger

Use when a Checkpoint action has `activation_required=true` and AI has claimed
it with `depth_contract_version=1`.

### 2. Signatures

- `_sync_action_queue(summary, *, repo_root) -> dict`
- Versioned observation metadata: `last_outcome`, `tested_dimensions`,
  `runner_operation_id`, `summary_ref`, `evidence_ref`, `observed_difference`,
  and `at`.

### 3. Contracts

- Runner sync requires a prior running claim and target-owned summary/evidence
  refs; it never activates a queued action or decides AI terminal status.
- The action remains `running` after observation. AI later calls Queue resolve
  with one continuation or a supported kill.
- Same operation ID is idempotent; an older `generated_at` cannot overwrite a
  newer `last_outcome`. Differences are bounded summaries or hashes, never raw
  request/response secrets. Versioned observations require a non-empty operation
  ID and reject concrete credential, Authorization, Cookie, token, password, or
  API-key values before Queue mutation.
- A versioned observation must include a controlled response difference from the
  replay (explicit difference, run diff, or observed response fields). An
  explicitly declared `baseline_only` observation may write replayable baseline
  context with `observation_kind=baseline_only`, but it remains running and
  cannot satisfy a kill resolve.

### 4. Validation & Error Matrix

| Condition | Result |
|---|---|
| queued `activation_required` action | `blocked`, no queue mutation |
| missing operation ID | `blocked`, action remains running |
| observation contains credential/header values | `blocked`, queue bytes unchanged |
| missing/off-target summary or evidence ref | `blocked`, action remains running |
| stale operation timestamp | `stale`, newer outcome preserved |
| undeclared baseline-only versioned summary | `blocked`, action remains running |
| explicit `baseline_only` observation | `updated`, action remains running; continuation required |
| valid observation | `updated`, action remains running |
| repeated operation ID | `deduplicated` |

### 5. Good/Base/Bad Cases

- Good: a stable response diff is stored as `observed_difference` and the next
  AI decision reads it from durable Queue metadata.
- Base: a legacy versionless action keeps its existing terminal runner mapping.
- Bad: `tested_clean` from one request closes a versioned hypothesis before its
  active dimension and replay evidence are written.

### 6. Tests Required

- `tests/test_autopilot_hypothesis_replay.py` must assert pre-claim blocking,
  target ownership, operation identity, secret-value rejection, stable diff
  write-back, stale protection, and running state.
- `tests/test_validation_runner.py` must retain Ledger/Finding/Queue replay and
  legacy status mapping regressions.

### 7. Wrong vs Correct

```text
Wrong: Runner maps one negative request directly to Queue tested/dead-end.
Correct: Runner records a bounded observation; AI supplies the next bounded
         continuation or kill through the existing Queue owner.

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
```
