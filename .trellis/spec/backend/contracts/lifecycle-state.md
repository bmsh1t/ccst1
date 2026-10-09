# Lifecycle and State Contracts

> 身份、checkpoint、case、observation 和 queue 生命周期契约。

## Shared domain and projection boundaries

- Normal domain reads and writes require `runtime_store() -> TargetStore`.
  Explicit initialization/import/history/recovery are separate operations.
- Queue owns Action identity, claim and completion; Case owns context;
  Store operations/observations own execution; assessment and delivery decisions
  remain separate. Checkpoint and Pack are disposable read-only projections.
- `claim --id` is explicit. Old `--from-evidence`, Ledger `record/from-probe`,
  Checkpoint ingestion, automatic pivot and Skill-route admission are retired.
  AI supplies judgment; the Store validates target, claim, proof and identity.
- Dependencies remain one way: coordinators call domain commands and queries;
  domain storage does not import coordinators, CLI or Runner.
- `/distill` reads bounded Store evidence/conditional experience; AI writes a
  card draft, then existing audit/promote validates provenance and redaction.
  Target memory is not a second Finding/Action lifecycle.
- Validation: Store/current-truth, Action Queue, memory-loop, distillation and
  explicit migration regressions prove the corresponding contracts.
- Action Queue `kind` is an owned Store lifecycle field (`work` or `execution`),
  independent of descriptive `type`; execution actions require endpoint and
  family, while work actions reject those execution identity fields.

## Target Path Canonicalization Contracts

### 1. Scope / Trigger

Any tool that writes or reads target-scoped state under `recon/`, `findings/`,
`state/`, `memory/goals/targets/`, `reports/`, or `evidence/` must use
`tools.target_paths.canonical_target_value()` and `target_storage_key()` rather
than ad-hoc string sanitization.

### 2. Signatures

- `canonical_target_value(target: str) -> str`
- `classify_target(target: str) -> dict`
- `target_storage_key(target: str) -> str`
- `legacy_list_storage_key(target: str) -> str`
- `migrate_legacy_list_storage(repo_root: str | Path, target: str) -> dict`

### 3. Contracts

- URL-form targets normalize to host or host:port before classification:
  `http://127.0.0.1:3002/#/login` -> `127.0.0.1:3002`.
- URL path, query, and fragment do not participate in the target storage key.
- Host casing is normalized through URL parsing: `https://Example.COM/a` ->
  `example.com`.
- CIDR, IP, host:port, and domain keys stay compatible.
- A readable list key is `<sanitized-stem>--<10-char sha256>` where the digest
  is computed from the canonical real path. List contents are not part of the
  key, so editing one scope file continues the same batch; two same-stem files
  in different directories never share state.
- `recon_engine.sh` must import `target_storage_key()` for batch keys. It must
  not carry a shell-local or embedded-Python copy of the key algorithm.
- A legacy stem-only `state/` and `recon/` tree may be renamed only when its
  `session.json.target` resolves to the current list path. Unverified legacy
  directories remain untouched instead of being merged into a possibly
  unrelated same-stem batch.
- Canonicalization applies at every target-scoped artifact boundary, including
  recon/intel lookup, evidence output, report summaries, worker scratch state,
  sibling queues, and finish gates. A caller accepting URL-form targets must not
  rely on another command having normalized the value first.
- `evidence/<target_key>/intelligence.md` is a shared artifact. Local extraction
  and identity intel must update distinct managed sections and preserve unknown
  sections; neither producer may overwrite the whole document or append an
  unbounded duplicate section on rerun.

### 4. Validation & Error Matrix

- Empty target -> domain with empty target.
- Readable file -> `kind=list`, absolute path, storage key from stem plus
  canonical-path digest.
- Owned stem-only list state -> migrate `state/` and `recon/` to the digest key
  and update `session.json.storage_key`.
- Stem-only state without a matching `session.json.target` ->
  `status=owner_unverified`; do not rename it.
- Invalid numeric IP/CIDR-like target -> `ValueError("invalid IP/CIDR target")`.
- URL with valid host and port -> equivalent bare host:port target.
- URL with valid host and no port -> equivalent bare host target.

### 5. Good/Base/Bad Cases

- Good: `/autopilot http://127.0.0.1:3002/#/` and
  `/autopilot 127.0.0.1:3002` share the same state tree.
- Good: `/tmp/a/scope.txt` and `/tmp/b/scope.txt` receive different keys even
  when both contain the same targets.
- Base: `https://example.com/admin?x=1` stores under `example.com`.
- Bad: creating `recon/http:_127.0.0.1:3002` or
  `state/https:_example.com_admin_x_1`.
- Bad: deriving every readable `scope.txt` as `state/scope`.

### 6. Tests Required

- Core target-path tests must assert URL -> host/host:port canonicalization.
- Core target-path and autopilot-state tests must assert same-stem list
  isolation, independent runtime wait markers, and owned legacy migration.
- Recon shell tests must assert the batch branch imports the shared Python API.
- Hunt target type tests must assert `hunt.classify_target()` inherits the same
  target-path behavior.
- Any future tool that introduces target storage should reuse these helpers
  instead of adding a local sanitizer.
- Intel tests must cover URL-form target lookup plus both producers rerunning
  without losing or duplicating each other's section.

### 7. Wrong vs Correct

#### Wrong

```python
safe = re.sub(r"[^A-Za-z0-9._:-]+", "_", raw_target)
```

#### Correct

```python
resolved = canonical_target_value(raw_target)
key = target_storage_key(resolved)
```

## Explicit historical migration

`target_migration.py` owns preview, import, quarantine disposition and cutover.
`load_legacy_finding_index` and Ledger JSONL diagnostics are read-only historical
inputs, never ordinary runtime fallback. Import preserves explicit IDs,
provenance and unresolved conditions; uncertain/invalid finality cannot become a
new trusted assessment. Normal queries neither migrate nor overwrite old files.
List-key runtime migration still verifies the owning canonical list path.
See `transactional-target-state.md` for manifests, fence, receipt and recovery.

## Canonical Finding and Report Identity Contracts

### APIs and ownership

- `TargetStore.create_finding` saves an explicit ID/endpoint/method/family claim.
- `record_execution(candidate=...)` links exact observed identity atomically.
- `assess` and `decide_delivery` append separate judgments with predecessor IDs.
- `register_report` binds published bytes to the current assessment/delivery.
- `record_delivery_event` records an explicit external submission/receipt.
- `finding_index.load_finding_index` / `find_finding` are Store read adapters.
- `index_scanner_material` publishes immutable material review work; it does
  not invent Findings or execution from scanner prose.
- `report_generator.process_findings_dir` consumes current report eligibility
  and rebuilds report indexes. Old JSON writer/upsert/status/Queue-sync APIs
  have been removed.

### Contracts

Explicit identity, not endpoint/text similarity, controls claim reuse. Two IDs
may describe the same endpoint; the same ID with changed identity conflicts.
Unknown family is preserved even if a renderer uses the generic template.
Source revision changes produce separately attributable material work, retaining
older snapshots. Claims without a concrete execution identity remain review
material; saving a claim never counts as a tested endpoint.

Current confirmed assessment, current eligible destination decision and intact
raw evidence jointly authorize report registration. Changes make old report
bindings stale; history is retained. Publication happens before registration,
so an interrupted registration preserves recoverable text. Identical valid
replay creates no new fact; changed registered bytes are never silently repaired.

Generate a separate artifact for every current eligible delivery of the current
assessment. An existing `(assessment_id, delivery_id)` report is immutable, even
when damaged; skip that pair, not the whole Finding. Retry fills other eligible
destinations and preserves earlier report bytes and registration receipts.

Validate retains AI-authored content. `/report` reuses it without rendering a
replacement template; generated template reports are for eligible claims with
no current report. Report indexes are cumulative, root-bound, rebuildable and
never owners of lifecycle state. No report action is resolved automatically.

External chain context can be saved as a conditional Experience linked to the
Finding. Resume renders its provenance/conditions without changing target,
Scope, counts, Queue or Coverage. It never becomes an instruction or permission.

### Validation

`test_finding_index.py` covers explicit IDs/conflicts/concurrency, scanner
material revisions, historical reads, eligibility, publication recovery and
stale/damaged registered reports. `test_validate_target_mode.py` and native
Runner CLI tests cover exact binding, decision retries, report ownership,
private endpoint identity and preservation of AI text through `/report`.
Report generation and evidence registration leave Action completion and
external delivery events unchanged.

## Runtime-v2 Checkpoint Witness Contracts

### 1. Scope / Trigger

Use this contract whenever checkpoint output, runtime-v2 session state, or the
`/autopilot` pressure validator changes, including Closure evidence acquisition
before review or round-witness publication.

### 2. Signatures

- `build_checkpoint(repo_root, *, target, ...) -> dict`
- `write_checkpoint_witness(repo_root, target, checkpoint) -> dict`
- `begin_round(repo_root, target, *, max_lanes) -> dict`
- `record_round_lane(repo_root, target, *, lane, max_lanes) -> dict`
- `prepare_round(repo_root, target, max_lanes) -> dict`
- `settle_round(repo_root, target, *, note="", refresh_coverage=True) -> dict`
- `load_closure_projection(repo_root, state, ...) -> dict` raises
  `coverage_matrix.CoverageEvidenceChangedError(StoreError)` for mismatched acquisitions.
- `record_global_review(repo_root, target, *, status, snapshot_digest, evidence_refs, cross_source_links, residual_unknowns, decision, next_action) -> dict`
- `validate_round_progress(payload, *, allow_invalid_completed_evidence=False) -> dict`
- `check_autopilot_run.py --repo-root <repo> --target <target>`
- Witness: `state/<target_key>/checkpoint_latest.json`

### Target-wide final review witness

After the existing owner projections are otherwise ready to finish, Closure requires
one cross-source review in the same Checkpoint witness. The review is optional while
durable work is pending, but a target cannot claim exhaustion without a valid
`global_review` object:

```json
{
  "status": "complete|follow_up",
  "snapshot_digest": "<closure snapshot digest>",
  "evidence_refs": ["evidence/<target_key>/..."],
  "cross_source_links": [],
  "residual_unknowns": [],
  "decision": "...",
  "next_action": "<active Queue id or action when follow_up>"
}
```

`snapshot_digest` is computed from the current Queue, Coverage, Store observation
projection (the read-only Ledger view), Finding,
Surface, Recon and enrichment projections; the `global_review` field itself is
excluded from digest material so recording it cannot invalidate its own attestation.
Every evidence reference must resolve to a non-empty file owned by the target.
Global-review CLI accepts `--evidence-refs-json`, not lane-result's single-value
`--evidence-ref`. Explicit use of the latter (including empty/repeated values or
with valid JSON) fails before the mutation owner. Lane-result retains its empty
default and last-value semantics. Evidence-list validation failures identify
`state_changes[].field=evidence_refs` with an `expected` constraint.
`follow_up` must name an existing active Queue action. Missing, malformed, stale, or
unmapped reviews project `global_review_required`, `global_review_invalid`, or
`global_review_stale`; those are Checkpoint handoffs, not external permission gates.
Any owner write that changes the digest invalidates the prior review. No new state,
Queue, controller, or state machine is introduced.

Closure hashes a semantic copy of Coverage: omit only root `as_of`/`last_updated`
and `source_snapshot.as_of`, then recompute the source fingerprint. Keep all cells,
Store generation/revision, discovery bindings and evidence health; never substitute
the high-value-gap fingerprint used by the stagnation guard. The acquired matrix
and its diagnostic timestamps remain unchanged. Time-dependent validity changes
still affect current evidence and decisions; freezing the clock is not a fix.

Full and bounded state use the same stat-only Recon readiness and exact-hit Surface
decision inputs. Full diagnostics retain exact counts; an explicit Closure expands
bounded Recon through its existing owner before hashing. Resume's duplicate Recon
subtree is excluded only because Closure binds it directly. Enrichment binds the
deduplicated tool identities, not presentation reasons. Inventory health and Surface
metadata come from the same readers. Caller-supplied decision facts remain bound;
do not reload an entire state to erase an inconvenient difference.
Bootstrap, full-state acquisition (including Checkpoint's direct call), and Closure
resolve `repo_root` before deriving paths or default memory locations. Absolute,
relative and symlink spellings of one physical root share digest/basis; explicit
memory-dir/environment overrides retain their semantics. No hash fields are
removed, different physical roots are not merged, and historical noncanonical
reviews may require an explicit re-review rather than automatic witness rewriting.

`record_global_review` still strictly compares the submitted digest with its locked
recalculation. Recording the review must not change that digest or its basis. Old
reviews may need one explicit re-review after the binding semantics change.

### 3. Contracts

- Runtime-v2 `session.json` stores only non-derivable breadcrumbs. It must not
  regain v1 `context_pack`, selected-skill, card, surface, or queue snapshots.
- `build_checkpoint()` is read-only. An explicit `write_checkpoint_witness()`
  atomically replaces a small witness containing
  `schema_version`, `kind=autopilot_checkpoint_witness`, `generated_at`,
  `target`, `target_key`, and `context_pack` recommendation fields.
- Witness context includes the card catalog, card recall compatibility fields,
  `reference_hints`, and `required_checks`; it does not duplicate full surface,
  finding, evidence, or queue bodies. Context Pack no longer emits
  `selected_skill`/`skill_route`; Checkpoint also omits the retired shell.
  Skill discovery and loading belong to the native platform.
- Explicit witness publication preserves the prior `global_review` while
  owner writes change its digest; Closure then reports it stale until the
  current snapshot is reviewed again.
- `round_progress` is the same witness's bounded execution budget. Reads and
  mutations use the checkpoint target lock; active rounds retain their original
  max and unique claimed lane IDs across CLI/context restarts.
- `settle_round()` holds that same target lock from its Closure preflight through
  read-only Checkpoint/current Coverage queries, round closure and final projection.
  The lock is same-thread reentrant so existing checkpoint owner functions remain
  the only mutation paths. A concurrent lane claim waits, then is rejected after
  the round becomes completed; it cannot enter between preflight and first write.
  Missing, malformed or stale Surface does not block or defer round closure;
  settle still completes and keeps the Surface-backed advisory lead open until
  a later explicit refresh. Settle never
  refreshes Surface or synchronizes Queue as a side effect. Owner-marker drift
  retries snapshot acquisition once, then reports failure instead of mixing inputs.
- Closure uses Coverage's `require_matching_truth(matrix, truth)` before witness
  processing and digest construction. `autopilot_state.main()` and the coordinator's
  `_closure_snapshot()` catch only `CoverageEvidenceChangedError` around that loader
  call and rebuild state plus Closure once. This uses their existing two-attempt
  budget, shared with marker drift, not a nested retry loop or external-action replay.
  `record_global_review()` and `record_round_closure()` propagate it before writing.
- `checkpoint.py` mutations and `autopilot_state.py` Closure projection use the
  same `checkpoint_witness.validate_round_progress()` structural validator.
  The reader-only recovery flag may expose historical completed lanes with
  invalid evidence for repair, but it never relaxes schema, `1..MAX_LANES`,
  derived-count, lane-order, bounded-text, timestamp, or terminal-field checks.
- New explicit passive claims (`idle:*`, `monitor:*`, `verify:idle*`,
  `verify:no-change*`, or `idle-no-change`) are rejected before budget mutation;
  duplicate legacy passive lanes keep their started/terminal recovery semantics.
- The pressure validator reads the witness, Store Queue and paged operations,
  checking each operation's current raw bytes. Raw Finding claims and legacy
  validated JSON cannot create work or prove execution. It validates structural
  workflow evidence, not exploitability or value.

### 4. Validation & Error Matrix

- Runtime-v2 session plus complete witness -> context check passes.
- Session exists but witness is missing -> context check fails and loses the
  context-pack score; do not inspect deprecated v1 session fields.
- Witness has no required card/reference detail -> context check fails with the
  precise missing field. Skill route fields are retired.
- Atomic witness publication fails -> the explicit writer fails fast; a successful
  read-only Checkpoint does not claim that a witness was saved.
- Corrupt JSON, invalid `round_progress`, duplicate lane IDs, contradictory
  derived counts, or a max outside `1..MAX_LANES` fail before mutation.
- Missing lane timestamps fail in both the mutation owner and read-only Closure
  projection; historical invalid completed evidence remains a non-exhaustive
  repair handoff only through the explicit reader recovery flag.
- A lane claim racing with `settle_round()` blocks on the checkpoint target lock;
  after settle completes it fails because the round is no longer active.
- Missing or stale `global_review` after a completed substantive round must
  project a Checkpoint handoff; a valid digest-matched review must permit the
  existing Closure verdict, while an active Queue follow-up remains durable.
- Repeated reads across seconds and full/bounded modes -> identical digest/basis
  for unchanged facts, including after completed-lane/round/review writes.
  Equivalent root spellings also preserve digest/basis and cross-root-form review
  validity; real Store revision mismatches still invalidate Surface.
  Queue/Coverage/discovery changes and damaged raw evidence -> old review stale;
  raw damage must invalidate without requiring a Store revision change.
- Raw damage or restoration between Coverage and truth reads -> direct loader
  raises the typed mismatch, with no digest or witness mutation. Transient mismatch
  -> CLI/coordinator reassemble once; a second mismatch -> propagate/CLI exit `2`.
  Ordinary Store/I/O errors do not gain retries. Two stable partial reads still
  return the existing `store_partial` diagnostic and suppress closure. Store-mode
  partial/unreadable evidence resolves to the same `evidence-ledger` owner,
  `repair_evidence_ledger` action and reason frontier as the legacy `ledger_*`
  reasons.
- `material_sources.sources.workflow_leads` carries Surface `status`, `reason`,
  `refresh_command`. Missing/stale/invalid projection means `total=null`,
  `remaining=null`, no usable items, and `evidence_reviewed.surface=false`.
  Valid empty input means integer zero. Text must show unavailable/count unknown
  and the refresh command, not claim a successful empty material review.
- The explicit post-lane `--loop-check --projection-only` projection returns the
  existing `loop_guard` plus a bounded `control` object (`hard_gate`,
  `priority_frontier`, `next_action`, `fallback_action`, and `selection_mode`).
  The controller may use this as its refreshed frontier state; it must not issue
  a second ordinary state read for the same heartbeat unless the command fails or
  a later owner write requires a fresh snapshot. The projection is derived only
  and creates no owner state.

### 5. Good/Base/Bad Cases

- Good: `build_checkpoint()` reads the current facts without writing; explicit
  witness publication lets the pressure validator inspect its bounded context.
- Base: an early witness retains its card catalog and reference hints even when
  no Action has been selected. It does not claim a Skill has been loaded.
- Good: settle sees no started lane, holds the witness lock across all owner calls,
  closes the round, and a waiting late claim observes the completed round.
- Good: a stable re-acquisition recovers after one evidence mismatch without
  changing the witness or replaying completed work.
- Bad: tests hand-inject v1 `context_pack` into `session.json` while production
  runtime-v2 writers never create that shape.
- Bad: settle checks `unfinished_lanes`, releases or never acquires the witness
  lock, then permits a concurrent `record_round_lane()` before checkpoint write.

### 6. Tests Required

- `tests/test_checkpoint.py` must assert read-only query behavior and explicit
  publication's witness path, kind and parity with the supplied Checkpoint.
- Round projection tests must prove that writer-invalid max-lane and timestamp
  shapes are also rejected by the read-only Closure path.
- Coordinator tests must race a lane claim against settle and assert the claim
  cannot finish until closure releases the lock, then fails on completed status.
- `tests/test_autopilot_run_contract.py` must use `update_runtime_state()` plus
  the real witness writer and include one real `build_checkpoint()` projection.
- The missing-witness regression must retain runtime-v2 `session.json` and fail
  only the context check.
- Global-review tests must cover missing/stale/invalid evidence, digest
  self-exclusion, Queue-bound `follow_up`, and prepare/settle idempotency.
  Evidence failures identify their field without Store/witness changes; wrong CLI
  flags fail before the owner, valid JSON persists refs, and lane single-value
  behavior remains unchanged.
- `tests/test_closure_snapshot_stability.py` advances a controlled read clock,
  compares full/bounded empty/URL/JS/empty-FFUF/whitespace cases across Surface
  missing/valid/stale states, and exercises real completed-lane/round/review and
  owner/evidence invalidation. Checkpoint tests distinguish unknown counts from
  valid zero and retain unchanged Store binding.
  Path tests use `chdir` and absolute/`.`/`./`/symlink roots in both modes, direct
  bootstrap and Checkpoint acquisition, and bidirectional recording/validation.
- Mixed-evidence tests damage and restore registered raw bytes in a real temporary
  Store, assert unchanged revision/owner markers, and reject direct Closure,
  review and round publication with byte-identical prior witnesses. CLI/coordinator
  tests assert state/Closure call order, the two-attempt ceiling and no Store/I/O
  retry; pending-action expansion and lane recovery/idempotence remain covered.

### 7. Wrong vs Correct

#### Wrong

```python
session["context_pack"] = build_context_pack(...)
```

#### Correct

```python
checkpoint = build_checkpoint(repo, target=target)
write_checkpoint_witness(repo, target, checkpoint)
# state/<target_key>/checkpoint_latest.json is the bounded runtime witness.
```

Wrong: duplicate `round_progress` field validation in Checkpoint and Closure readers.

Correct: both consumers call `validate_round_progress()`; only the read-only
historical-evidence repair path enables its explicit compatibility flag.

Wrong: treat the no-started-lane preflight as sufficient without holding the
checkpoint witness lock across subsequent writes.

Correct: `settle_round()` acquires the existing witness lock once and reuses the
same owner functions under its same-thread reentrant scope.

Wrong: hash acquisition time, strip every owner field until reads agree, or retry
review writes until they happen in the same second.
Correct: bind the same current semantic inputs in all modes and retain strict
locked digest validation plus real-change regression tests.

Wrong: treat unchanged Store revision/owner markers as proof that raw evidence
still matches, or retry every `StoreError` as a race.
Correct: call `require_matching_truth(matrix, truth)` before digest/witness work;
only its typed mismatch receives the existing single read retry.

## Target Case State Contracts

### Storage and commands

Actors, sessions and objects use Store Case tables. Current premises are
Experience hypotheses linked to Case entities. `target_case_state.py` exposes
`summary`, `show`, `add-actor`, `add-session`, `add-object` and `add-hypothesis`;
ordinary reads/writes never recreate `case_state.json`. Historical Case backlog
is handled only by explicit migration, which maps real work into Action Queue.

### Contracts

- Case has no separate backlog, next-action selection, route score or automatic
  replay. An open premise is context, not an executable action or completion.
- Sessions/objects store private references; credentials and private markers
  remain protected files (0600, directories 0700). Queries check reference
  ownership, bytes and binding. Missing/corrupt/off-path material fails visibly.
  Public summaries/CLI output redact secrets; private headers hydrate only for
  explicit in-memory consumers.
- Repeated context updates preserve unrelated headers/object status and use
  Store commands/audit. Different content under one command ID conflicts;
  concurrent metadata updates cannot silently lose a committed write.
- Case adapter commands bind their ID to the Store revision and requested material.
  A→B→A→B is four mutations, not a replay of the first A→B transition. Before
  writing, compare Store-normalized material (trimmed strings, sorted actor IDs,
  JSON metadata with scalar types preserved); a same-value retry changes no revision.
  Keep the existing immutable hypothesis premise conflict; mutable context/status
  updates do not authorize rewriting its original family/conditions.
- Hypothesis family is open. Descriptive metadata is bounded and secret-free;
  it does not forge observations, technical judgments or Skill execution.
- `summary` exposes actors/sessions/objects/open hypotheses, authz context and
  object samples. `case_state_seed` reads object-shaped observations with their
  sources. Neither creates an action, chooses an actor, guesses private data,
  selects a runner or generates a registration command.
- Missing identity context limits the affected comparison. Other discovery,
  source/browser work and AI-selected hypotheses remain available.
- Knowledge suggestions are advisory. An actor matrix is requested only from
  explicit observed or active-action families; an empty class list means no
  actor matrix, not an implicit Authz/IDOR method choice.

### Validation

`tests/test_target_case_state.py`, `tests/test_case_state_seed.py`,
`tests/test_context_pack.py` and `tests/test_checkpoint.py` cover Store-only
context, secret boundaries, stale private references, unknown families,
object observations and no automatic backlog/Queue creation. Historical
backlog mapping and damaged legacy input belong to `test_target_migration.py`.
Repeated-cycle and normalized-retry regressions cover actors, sessions, objects
and mutable hypothesis context; command-ID conflicts remain Store-owned.

## Neutral Observation Inventory Contracts

### 1. Scope / Trigger

Use these contracts when recon artifacts must remain reviewable beyond the
bounded Claude prompt window. The inventory preserves discovery completeness;
it does not decide exploit value or replace execution/evidence state.

### 2. Signatures

- `python3 tools/observation_inventory.py sync --target <target>`
- `python3 tools/observation_inventory.py summary --target <target> [--json]`
- `python3 tools/observation_inventory.py list --target <target> [--status <status>] [--limit <n>]`
- `python3 tools/observation_inventory.py page --target <target> [--status <status>] [--kind <kind>] [--source <source>] [--limit <n>] [--cursor <cursor>]`
- `python3 tools/observation_inventory.py touch --target <target> <observation-id> --status <status> [--notes <text>]`

### 3. Contracts

- Persist state at `state/<target_key>/observations.json` with stable SHA-256
  identities, source-artifact references, lifecycle timestamps, and
  `untouched|reviewing|reviewed|parked` status.
- Persist the small derived `observations-summary.json` after each successful
  body mutation. It binds schema/target, source fingerprint, body size/mtime/
  revision, counts, and a bounded neutral sample. `summary`/bootstrap validates
  this sidecar with stat/fingerprint and never parses the monolithic body on a hit.
- Sidecar missing, corruption, target mismatch, source change, or body binding
  mismatch is `missing|stale|invalid` plus `needs_sync`, never a zero inventory.
  Only explicit sync/list/page/touch paths may pay the full body load cost.
- Re-ingesting an unchanged artifact keeps item count, status, notes, and
  `seen_count` stable. A changed artifact refreshes presence/last-seen metadata
  without resetting review state.
- `page` binds its opaque cursor to target, filters, and inventory revision. A
  stable snapshot makes every matching observation reachable exactly once;
  revision/filter changes fail-fast. Page reads never update lifecycle.
- Claude-facing outputs expose counts and a bounded neutral sample. They must
  not map observations to vulnerability Skills, rank attack value, or enqueue
  actions automatically.
- Action queue entries remain executable work. Evidence-ledger entries remain
  replay/test conclusions. `reviewed` is never equivalent to `tested_clean`.

### 4. Validation & Error Matrix

- Invalid status -> reject the touch operation without changing state.
- Unknown observation ID -> fail explicitly.
- Malformed inventory JSON -> report an explicit warning/error and preserve the
  existing file; never replace it with an empty inventory.
- Concurrent sync/touch -> serialize with the target lock and atomically replace
  the state file.
- Sidecar missing/corrupt/stale -> summary reports needs-sync without loading the
  body; explicit sync rebuilds it. Body write succeeds but sidecar write fails ->
  next read detects binding mismatch and does not consume the old summary.
- Cursor target/filter/revision mismatch -> fail explicitly and restart paging
  from the current snapshot; never guess an offset.
- No live hosts but recon observations exist -> autopilot still reports inventory
  counts while retaining the `recon_no_live_hosts` decision.

### 5. Good/Base/Bad Cases

- Good: recon adds a URL, inventory records it as untouched, Claude reviews it,
  and a later explicit replay creates a separate action/evidence record.
- Base: repeated autopilot polling validates the small sidecar/stat without
  opening the observation body or increasing `seen_count`.
- Bad: a URL regex automatically routes every untouched item to a Skill or marks
  it tested after an AI-only review.

### 6. Tests Required

- `tests/test_observation_inventory.py` must cover stable identity, lifecycle
  preservation, sidecar hit/missing/stale/corrupt/body/source binding, malformed
  state, atomic writes, locking, stable cursor traversal, filter/revision reject,
  and zero lifecycle mutation on page reads.
- Surface/autopilot/checkpoint tests must assert bounded summaries, no-live-host
  visibility, and suppression of false exhaustion while untouched items remain.
- Claude runtime staging must install `/observations`; localhost pressure must
  exercise inventory sync without a second controller/subagent.

### 7. Wrong vs Correct

#### Wrong

Treat every recon string as an executable vulnerability hypothesis and inject
the entire raw list into Claude context.

#### Correct

Persist a neutral, bounded inventory; let Claude choose valuable hypotheses;
record chosen execution in the action queue and actual replay facts in the
evidence ledger.

---

## Autopilot Queue Closure Contracts

### Action and Checkpoint

- Action Queue adapts `TargetStore.actions`; there is one lifecycle, no JSON
  fallback. Missing initialization, legacy import required, damaged Store and
  empty initialized Store remain distinct. All reads preserve recovery faults.
- AI explicitly selects `claim --id`; running work remains visible ahead of
  unclaimed suggestions. Claims use Store CAS and operator/token identity.
  Re-claim is idempotent; another operator or stale claim is a conflict.
- Execution completion requires a complete operation from the current claim.
  Work completion requires its registered artifact or domain-command receipt.
  Partial/unknown execution, an arbitrary existing file, or a prose reason
  cannot forge completion. Blocking closes no Coverage cell.
- Checkpoint reads pending/blocked actions as a stable-ID page with total,
  remainder and a root-bound expansion command. It never ingests prose,
  generates candidates/actions, reconciles old owners or automatically chains
  primitives. Empty queue returns `continue` with no chosen action; AI decides
  the next step from visible material. Live phase locks may return wait.
- Coverage gaps, scanner claims, actor gaps, Case observations and Surface
  material remain visible outside Action Queue. Their presence does not select
  a route or prove execution. Explicit material indexing creates immutable
  review work, not a confirmed Finding.

### Evidence and closure

- `current_truth` acquires Store records and verifies current raw evidence.
  `closure_projection`/`closure_resolver` define identity and closure once;
  consumers do not infer finality from report text, paths or cached status.
- Unknown/generic families remain open; Authz/IDOR and distinct parameters,
  methods, actors or object contexts cannot close one another by path alone.
  Preserve explicit family-aware identities without guessing dimensions.
- Evidence damage remains visible, suppresses authorization and forbids a
  terminal finish. A same-revision file change requires a new integrity read.
- Coverage authored reviews are advice unless supported by admissible execution
  evidence. Dead-end/blocked actions do not imply tested-clean or n_a.
- Raw Surface evidence remains reviewable even after one exact cell closes.
  Historical observations are context, not a path-wide exclusion or ROI score.
- Closure reads current Queue/evidence/Case and runtime inputs after mutations.
  Its actor-context gap is local to affected comparisons, not a blanket ban on
  anonymous or unrelated work. Unknown/partial work is never reported finished.

### Findings and reports

- A saved claim is not execution, technical confirmation or delivery eligibility.
  New evidence never downgrades an existing assessment implicitly.
- Technical assessment, destination decision, report artifact and external
  submission are independent facts. Changed assessment/delivery makes older
  reports stale; current integrity is required to authorize delivery.
- Validate atomically publishes AI report bytes and registers an eligible
  artifact after explicit judgments. `/report` reuses registered text and
  rebuilds cumulative INDEX/SUMMARY from the Store, including empty results.
  It uses the input Store root and never overwrites registered bodies.
- Publication/registration/index failure preserves recoverable artifacts.
  Neither report generation nor evidence registration resolves Queue work.

### Validation

Queue tests cover explicit claims, concurrency/CAS, metadata trust, proof-bound
completion and closed-action history. Checkpoint tests cover pages/expansion,
claimed recovery, no implicit work, current evidence health and private
same-call read reuse. Finding/Report and Validate tests cover explicit identity,
unknown families, stale/corrupt reports and interrupted publication/registration.
`test_target_migration.py` retains explicit legacy import/cutover/recovery tests.

## Scenario: 真实 Claude CLI Candidate 的断点恢复

### 1. Scope / Trigger

当修改 `commands/autopilot.md`、`tools/autopilot_state.py`、`tools/checkpoint.py`、
`tools/action_queue.py`、Evidence Ledger 或 target memory 的任一候选交接路径时，必须做
一次 fresh target -> candidate -> 新 Claude 会话恢复的 localhost 验证。只验证 checkpoint
文件存在不够；本场景验证的是当前会话结束后下一次 `/autopilot` 是否仍然选择候选。

### 2. Signatures

```bash
/autopilot <localhost-target> --deep --normal
python3 tools/autopilot_state.py --target <localhost-target> --json
python3 tools/checkpoint.py --target <localhost-target> --no-refresh-coverage --json
python3 tools/action_queue.py ingest-checkpoint --target <localhost-target>
python3 tests/skill-validator/check_autopilot_run.py --target <localhost-target> --json
```

### 3. Contracts

- Candidate 存在时，下一次 `autopilot_state` 的 authoritative `next_action` 必须优先选择
  candidate evidence/validation 或 durable action，不能被 generic `resume_untested` 覆盖。
- `checkpoint.next_action_queue` 有 executable candidate 时，controller 必须通过
  `action_queue` owner 建立可恢复动作，或提供同等强度的结构化 state；不能只保留 Markdown
  或 target-memory prose。
- Candidate 在进入 `/validate` 前必须保留 raw request/response 或可定位 `evidence_ref`。
  `raw_endpoint` 只能证明路径曾被观察，不能单独证明可重放证据。
- 目标 memory、action queue、structured finding 和 runtime breadcrumb 的 target identity
  必须一致；旧 `active.json` 不得让另一个 target 的状态抢占或掩盖当前 target 的候选。

### 4. Validation & Error Matrix

| 条件 | 正确行为 |
|---|---|
| ledger 有 candidate，checkpoint 有 A1 validation action | 下次 state 选择 validation/queue resume |
| target memory 有 `/validate` next action，但 durable queue 尚未写入 | 输出明确的 candidate-resume action；不能回退为 generic resume |
| candidate 只有 `raw_endpoint`，没有 raw artifact/evidence ref | 维持补证据状态，不标为可验证完成 |
| action queue 有 executable action 但没有 final row | runtime validator 失败并指出 `final_status` |
| 没有 candidate、queue 或 runner evidence | 正常进入 surface/recon resume |

### 5. Good / Base / Bad Cases

- Good：Claude 结束本轮后，下一会话读取同一 target，先显示 candidate 的最小 replay 和
  stop condition，再考虑未测 surface。
- Good：checkpoint 的 A1 通过 `ingest-checkpoint` 进入 action queue，队列有 executable
  command、evidence pointer 和最终状态。
- Base：候选 evidence 不足时 state 选择 `collect_candidate_evidence`，不报告也不假装完成。
- Bad：candidate 只写入 `memory/goals/targets/<target>.json`，而 authoritative next action
  仍是 `resume_untested`。
- Bad：真实运行的 `session.json` 仍只显示旧 recon breadcrumb，导致 resume summary 忽略
  已产生的 candidate/handoff。

### 6. Tests Required

- `tests/test_autopilot_state_tool.py`：target-memory candidate action 在 fresh/new-session
  state 中优先于 generic resume；旧 active target 不影响显式 target。
- `tests/test_checkpoint.py` 与 `tests/test_action_queue.py`：A1 validation proposal 被
  owner 幂等 ingestion 后成为 substantive action，并可被 resolution 关闭。
- `tests/test_autopilot_run_contract.py`：candidate-only ledger 缺 raw artifact 时不能把
  evidence-path 判为完整通过。
- 新增 localhost real-runtime/staged regression：fresh recon 后产生 candidate，第二次
  slash invocation 必须选择 validation/queue resume，而非仅检查静态 prompt 文本。

### 7. Wrong vs Correct

#### Wrong

把 Candidate 写进 ledger 或 target memory 后直接结束会话，假设下次 Claude 会自行从大量
surface 文本中重新找到它。

#### Correct

由 state/queue owner 把 candidate 转成有 identity、evidence、command 和 stop condition 的
可恢复动作；下一会话以该动作作为 authoritative 起点，随后才扩展普通 surface。

---

## Scenario: 真实 Claude CLI fresh 交接与声明一致性

### 1. Scope / Trigger

当修改 fresh recon、`commands/autopilot.md`、`tools/autopilot_state.py`、验证/报告同步或
terminal summary 文案时，必须验证“fresh 启动后台 recon -> 新 Claude 会话 -> evidence/报告
判断”的完整交接。模型终端文字不是状态 owner，不能替代 ledger、finding 或 queue。

### 2. Signatures

```bash
/autopilot <localhost-target> --deep --normal
python3 tools/autopilot_state.py --target <localhost-target> --json
python3 tools/autopilot_bootstrap.py --json -- <localhost-target> --deep --normal
python3 tests/skill-validator/check_autopilot_run.py --target <localhost-target> --json
```

### 3. Contracts

- fresh 会话若只负责启动后台 recon，recon artifact ready 后的下一次 compact state 必须给出
  surface/context/hunt 的明确下一步，不能退化为无动作的 `handoff` 而要求模型从长文自行猜测。
- checkpoint 有 executable candidate 时，controller 必须以 owner API 建立 durable action；
  structured finding 可以补充恢复，但不能让 action queue 永久为空并使 runtime 验收失效。
- 终端中使用 `confirmed`、`validated`、`ready for report` 等字样的每一个漏洞，必须可映射到
  同 target 的 structured finding 与 raw request/response 或 `evidence_ref`。仅存在于
  `active_leads` 的内容只能称为 lead/candidate。
- 含 `[INSERT ...]`、`[PASTE ...]` 等未填占位符的报告草稿不是 report-ready；验证 summary
  不能把它写成 `all_gates_passed=true` 的可提交结论。

### 4. Validation & Error Matrix

| 条件 | 正确行为 |
|---|---|
| fresh recon 已完成、surface 尚未建立 | 下一 state 指向 surface/context/hunt，不是 handoff |
| terminal 有未落盘的漏洞声明 | 降级为 lead，并附下一条 raw-evidence action |
| 验证 summary 有 raw evidence、但 queue 未建 | 建立/同步 validation action，或明确记录同强度 durable owner |
| report draft 含占位符 | `report_status=not_generated` 且不可声称可提交 |
| 云端模型/网关拒绝 | 保留 `terminal_reason`/provider error，不能伪造 completed runtime 状态 |

### 5. Good / Base / Bad Cases

- Good：fresh 只启动 recon 后，existing session 的 bootstrap 已明确给出 surface/context 路径。
- Good：模型文字中的 confirmed finding 与 Store Finding/assessment、operation 和 raw artifacts 一一对应。
- Base：模型被 provider 拦截；现有 durable state 不变，验收按最后可验证阶段失败或部分通过。
- Bad：模型把 target-memory prose lead 写成 critical finding，而 durable owner 没有任何证据。

### 6. Tests Required

- staged/localhost fresh -> existing 回归：断言 recon ready 后不存在无因 `handoff`，并实际得到
  context-pack 或明确的可执行 surface action。
- 真实或 fixture controller 回归：解析 terminal claim identity，逐项核对 finding/ledger/evidence
  identity；没有 raw evidence 的 claim 必须标为 lead。
- 报告草稿回归：占位符存在时不得设置 report-ready/all-gates-passed 的提交语义。
- runtime validator 回归：candidate-only `raw_endpoint` 不能满足完整 evidence-path gate。

### 7. Wrong vs Correct

#### Wrong

把模型最终自然语言、target-memory prose 或带占位符模板视为漏洞闭环，因此忽略 queue、raw
evidence 和 structured finding 的缺失。

#### Correct

以 target-owned durable evidence 为唯一确认来源；模型只负责解释和选择下一步，任何无法落到
owner artifact 的内容保持为可复核 lead。

---

## Scenario: 非交互验证、finding provenance 与 bounded Autopilot invocation

### 1. Scope / Trigger

当修改 `tools/validate.py`、`tools/finding_index.py`、`tools/structured_findings.py`、
`tools/report_generator.py`、`tools/validation_runner.py`、`tools/runtime_state.py`、
`tools/autopilot_args.py`、`tools/autopilot_bootstrap.py`、`commands/autopilot.md` 或
`commands/autopilot-round.md`、`agents/autopilot.md` 时，必须验证 machine validation、
canonical lifecycle、单次 deep invocation 的 batch 边界和 native `/loop` 的单轮投影。
目标是让 Claude 的判断可审计，但不另建第二套 finding 或 loop state machine。

### 2. Signatures

```bash
python3 tools/validate.py --target <target> --finding-id <id> \
  --decision-json <decision.json> --json
python3 tools/autopilot_bootstrap.py --json -- \
  <target> --deep --normal --max-lanes <N>
python3 tools/autopilot_bootstrap.py --json --round-defaults -- <target> [formal args]
python3 tools/checkpoint.py --target <target> --record-round-lane --lane <id> --max-lanes <N> --json
python3 tools/checkpoint.py --target <target> --record-round-lane-result --lane <id> \
  --lane-status <completed|blocked> --decision <text> --evidence-ref <path|none> \
  --next-action <text|none> --json
python3 tests/skill-validator/check_autopilot_run.py --target <target> --json

/loop 10m /autopilot-round <target> --normal --deep --max-lanes 8
```

Python 入口保持 `parse_autopilot_args(argv, *, round_defaults=False)` 和
`build_autopilot_bootstrap(..., round_defaults=False)`；round 只通过同一 parser/bootstrap
切换默认值，不新增参数解析器。

### 3. Contracts

- non-TTY `/validate` 没有 `--decision-json` 必须在任何 target-owned write 前失败。decision
  必须绑定 canonical target、finding ID、endpoint、漏洞类，包含四个显式 bool gate、完整
  Q1–Q7 basis、impact、至少一个存在的 raw evidence ref 及受 bound findings dir 约束的
  report path/content。`decision.severity` 可选（显式值只能是 info/low/medium/high/critical，
  不提供时沿用 Finding 已记录值）；`decision.cvss` 可省略，若存在只作兼容输入校验，
  不写入新摘要或参与核心证据门禁。报告生成不能从历史 CVSS 重算并写回 Finding severity。
- machine binding 只读当前 Store 的 Finding 和 linked operation，不迁移 legacy payload。
  原始材料完好、精确 endpoint/method/family/target 与报告归属通过后才允许写入。
- 成功路径先原子发布 AI 正文，再分别调用 Store assess、decide_delivery、register_report。
  同命令重试幂等；新判断需要当前 assessment/delivery 前置 IDs，不能覆盖旧裁决。
- report path 首次原子 exclusive publish；已登记报告只有同 Finding、同裁决、完好且
  相同字节可复用，不重写 inode/mtime。跨 Finding、过时裁决、缺失/改字节都拒绝。
- summary/notes 和 latest pointer 是可重建材料，不是裁决 owner。登记失败保留正文并返回
  retry；不重发请求、不自动完成 Action，也不生成外部 submission event。
- `--max-lanes N` 仅在 `--deep` 下有效，`N` 为 1..32。bootstrap 的
  `invocation_batch={bounded,max_lanes,handoff}` 是唯一 command/agent 输入；达到 N 个命名
  substantive lane 后显式保存未决 work，再读取 checkpoint、说明 handoff 并结束本次 invocation。
  新发现留给下一次 invocation，不是永久 coverage 上限。
- `/autopilot-round` 省略参数时只把同一 parser 的 cadence/deep/max-lanes 默认值切为
  `normal/true/8`，用户显式 cadence 与 max-lanes 优先；普通 `/autopilot` 默认值不得变化。
  round 读取并服从 `commands/autopilot.md`，后者仍是唯一完整 hunt controller contract。
- `/autopilot-round` 的 substantive lane 必须按 `claim/start -> target work -> terminal heartbeat
  -> loop guard` 排序。active started lane 跨 context/process loss 优先恢复且不重复计预算；
  completed/blocked lane 不重放。terminal heartbeat 只保留有界单行 decision、owner evidence ref、
  next action 和时间戳；completed evidence 必须是 repo-local、target-owned、位于允许 evidence root
  且非空的现存文件。冲突 terminal rewrite、失效 completed evidence 或 unfinished closure 都必须
  fail-closed。历史 witness 的失效 evidence 由只读 closure 投影为明确 handoff，不把整个 checkpoint
  读取变成崩溃，也不静默改写 witness。heartbeat 不替代 Action Queue；unresolved terminal next action
  在封轮前必须写回既有 owner/Queue。
- 新 lane claim 只能使用 owner-selected substantive identity；`idle:*`、`monitor:*`、
  `verify:idle*`、`verify:no-change*` 和 `idle-no-change` 返回结构化拒绝且不消耗 budget。
  已存在的 legacy passive started/terminal heartbeat 保持恢复与幂等语义；普通
  `verify:<candidate>` 仍可执行。`hunt_p1/hunt_p2` 由 controller 选择一个具体有界候选；没有
  可执行候选时写回既有 blocker/handoff，不把方向选择交给 operator，也不用 passive monitoring
  代替 owner-selected work。
- `/loop 10m ...` 创建 fixed-interval recurring cron；round 只负责一次有界调用。任何 target action
  前先执行不带 `--max-lanes-reached` 的 closure precheck：`finish`、`blocked` 立即投影终态并
  停止，只有 `handoff` 可进入 canonical round；缺失、损坏、矛盾或未知 verdict 返回 ERROR。
- target exhaustion 必须先由 coverage owner rebuild，再显式读取
  `autopilot_state.py --bounded --closure --json` 的只读投影；只有非空、结构合法、无高价值 gap
  且无 runtime/queue/finding/report/intel/surface/source/JS 待办时可返回 `finish`。缺失或部分状态
  返回 `handoff`，终止型前置失败返回 `blocked`；达到 lane budget 只结束本轮 target work，随后
  仍从当前 owner 状态重新计算 Closure。rotation hint 仅供 AI 换 lane，不得新增状态 owner 或修改
  Surface/coverage。
- `hunt_p1/hunt_p2` 只有在当前有界 Surface candidate 的 path 全部存在于 matrix、没有高价值
  gap，且每条 exact endpoint identity 都有 Action Queue final status 时，closure 才可把 action
  投影为 `handoff`。Evidence Ledger terminal 只供 lane closure、Checkpoint 和 Surface advisory
  消费，不得 author generic Surface finality。该投影不删除、重写或给 raw Surface identity 标 final。
- Ledger health 为 `partial|unreadable` 时，closure 必须保留有效历史供诊断但投影
  `ledger_partial|ledger_unreadable`，禁止 `finish`；loop guard 必须 `continue`，禁止
  `rotate`。损坏状态不是空 Ledger，必须在 JSON projection 中保留 bounded diagnostics。
- 当前 Store 或证据准入失败时 `--closure --json` 必须返回
  `closure.verdict=error` 且 exit `2`；不得把损坏状态当 empty/handoff/finish。
- round 结束按只读 Checkpoint → 当前 Coverage/Closure 快照 → 显式 runtime round closure 排序；
  经验、证据登记与缓存刷新由各自显式命令完成，settle 不补写 Queue 或 Surface。lane budget
  不参与终态选择，Closure 必须从最新 owner 状态重新计算。STATUS 仅由 closure owner 字段投影：
  `finish + can_claim_exhausted + reported>0 -> DONE`，`reported=0 -> EXHAUSTED`，
  `handoff -> CONTINUE`，`blocked -> BLOCKED`，其它 shape -> ERROR。DONE/EXHAUSTED 的
  residual blind spots 最多五项且只能来自 bootstrap/state；`none-recorded` 不表示普遍不存在盲区。
  STATUS 只读 closure owner 字段和 canonical reported count；blind-spot 输出可额外读取有界的
  browser/source/recon/observation/capability facts，但不得反向改变 STATUS。
- bootstrap 非 continue action 不读取 closure 或执行 target action，投影 ERROR 后进入同一
  terminal cleanup。terminal STATUS 前 `CronList` 一次，只 `CronDelete` prompt 精确等于展开后
  `/autopilot-round $ARGUMENTS` 的 recurring job；deferred cron tools 只通过 ToolSearch 精确加载
  这两个名称；CONTINUE 不读写 cron。无匹配表示直接调用或
  已清理，list/delete 失败返回 `ERROR reason=loop-cancel-failed`。重复 terminal invocation 保持
  state-only、幂等；中断后的下一轮只从磁盘 checkpoint/state 恢复，不读取 legacy
  当前 Claude 会话的 checkpoint/state。既有 report 提交、凭据、破坏性/不可逆动作和当轮确认边界不变。
- 每个 substantive lane 写回证据后必须显式读取
  `autopilot_state.py --bounded --loop-check --json`。最近三条同 endpoint-family 与 vuln-class 的
  `tested_clean/dead_end` 返回 `rotate`，禁止本轮继续该组合；runtime wait、candidate validation、
  report 和 durable queue 的 authoritative next action 优先。普通 bounded 读取不得隐式加载 ledger。
- 显式 round closure 的 stagnation fingerprint 必须读取忽略当前 active heartbeat 的 post-round
  Closure；普通 precheck/recovery/final Closure 仍投影 round recovery。`next_action_pending` 和
  `coverage_high_value_gaps` 进入既有三轮 guard；fingerprint 绑定 semantic Coverage、Ledger、Queue、
  Observation 和有界 Surface candidate/review identity，忽略 Coverage rebuild timestamp。阈值处有
  target-owned adjacent Surface 候选则沿用 rotation；没有任何 authoritative 或 eligible continuation
  时返回 non-exhaustive `blocked/stagnant_prerequisite`。
- Queue semantic fingerprint 忽略 Queue 容器的 `created_at/updated_at`，但保留 action 排序和证据
  字段；Observation 绑定 summary sidecar 的 `inventory_binding.sha256`。纯记账时间不能重置三轮
  guard，同数量但正文不同的新 Observation 必须重置。

### 4. Validation & Error Matrix

| 条件 | 正确行为 |
|---|---|
| non-TTY 未给 decision | exit `2`，零 report/ledger/queue/runtime/finding write |
| decision 与 canonical finding 的 target/ID/endpoint/class 不匹配 | exit `2`，保持既有状态不变 |
| legacy payload 上的 decision binding 失败 | exit `2`，不得把 list 迁移为 object，也不得创建 event/artifact |
| summary 被删除或内容 digest 改变 | verifier 失败；所有 finalized consumer 降级 |
| 两个 finding 请求同一 machine report path | 第二个在首个 write 前失败；原 report/summary/state 不变 |
| `--max-lanes` 缺 `--deep`、为 0/负数/超 32/重复 | bootstrap `stop_invalid_arguments`，不启动 target work |
| bounded invocation 达到 N | checkpoint + action queue sync + terminal handoff；不启动 lane N+1 |
| round precheck 发现 active started lane | `handoff/round_lane_unfinished`，恢复同一 lane，不选新 lane |
| round precheck 发现 active 且全部 lane terminal | `handoff/round_closure_pending`，零目标重放并完成 closure |
| terminal lane 再次 claim | `allowed=false`，保留 decision/evidence_ref/next_action |
| terminal heartbeat 冲突，或 completed evidence 缺失/为空/越 target/越 repo | exit `2`，不覆盖已有 heartbeat |
| 历史 completed Lane 的 evidence 后续失效 | closure `handoff/round_lane_evidence_invalid`，`can_claim_exhausted=false`；显式封轮与 Round start/resume 均拒绝且不改写 witness |
| round precheck 为 `finish` 且 `structured_findings.reported>0` | `STATUS: DONE` + 有界 blind spots；零 target action |
| round precheck 为 `finish` 且 reported=0 | `STATUS: EXHAUSTED reason=evidence-bounded` + 有界 blind spots；零 target action |
| round precheck 为 `blocked` | `STATUS: BLOCKED reason=<bounded>`；零 target action并取消 recurrence |
| round precheck/final 为 `handoff` | 最多消费本轮 lane budget；`STATUS: CONTINUE next_action=<bounded>` |
| closure 缺失、损坏、字段矛盾或 verdict 未知 | `STATUS: ERROR reason=<bounded>`；停止本轮并取消 recurrence |
| Surface candidate 缺 matrix path、高价值 gap 或 exact Queue final outcome | closure `handoff`；保留 candidate |
| bootstrap 非 `continue` | 不读取 closure/target；精确清理 matching cron 后 `STATUS: ERROR` |
| terminal cleanup 无 exact prompt match | 视为 direct/already-clean，保留计算出的 terminal STATUS |
| CronList/CronDelete 失败 | `STATUS: ERROR reason=loop-cancel-failed`，不隐藏调度残留 |

### 5. Good / Base / Bad Cases

- Good：runner 将 raw request/response 写入 canonical candidate；machine decision 经
  `/validate` 产生 owner event，queue resolution 与 report follow-up 能回放同一 finding。
- Good：同一 validated 目录连续验证两个 finding，二者 summary/notes 路径和 digest 各自独立；
  同 finding 显式重跑可恢复。
- Good：`/autopilot localhost --deep --normal --max-lanes 2` 在两条 substantive lane 后留下
  durable queue，并以 handoff 自然结束；下一会话从 queue 继续。
- Good：`/loop 10m /autopilot-round localhost` 每轮默认只消费三条 lane；终态从 owner 投影为
  DONE/EXHAUSTED 后取消 recurrence，重复调用不再执行 target action。
- Good：lane 工具完成并写 evidence 后、final closure 前发生 context loss；下一轮读取 terminal
  heartbeat，跳过重复网络请求并继续其 next action/closure。
- Good：当前 Surface path 的 matrix 无 gap，且 exact Queue identity 已写终态，closure 才允许 finish。
- Base：precheck 为 handoff，但最后一条 lane 新增了下一项 substantive queue work；最终 Closure
  从 Queue 返回 CONTINUE，下一轮从磁盘继续。若没有 owner 工作则可直接 DONE/EXHAUSTED/BLOCKED。
- Base：decision 的 evidence 已通过但 report draft 仍有 placeholder，finding 保持 validated，
  action 指向 draft completion，不能称 report-ready。
- Bad：EOF 被默认当作四 gate 通过；或模型直接编辑 `findings.json` 再生成报告。
- Bad：两个 finding 共用 `validation-summary.json`，后一次验证覆盖前一个 finding 的 canonical
  证据，或 caller 用 `last-validate.json` 绑定报告。
- Bad：browser/source 新候选让 bounded invocation 忽略 lane cap，或将 cap 错当全目标 coverage
  已完成。
- Bad：为 `/loop` 新增 Python repeater/manifest，按模型终局文案判定完成，或把
  evidence-bounded EXHAUSTED 表述为所有 payload/身份/时序均已穷尽。
- Bad：执行一条 Surface lane 后仅凭 `next_action=hunt_p1` 或 raw URL 仍存在就直接 finish。
- Bad：只持久化 claimed ID，无法区分 started/completed；恢复时重复 SQL/browser 请求，或跳过
  尚未完成的高价值 lane 后错误 EXHAUSTED。

### 6. Tests Required

- `tests/test_validate_target_mode.py`：non-TTY zero-write、decision 的目标/主张/操作绑定、
  未初始化与 legacy 拒绝、私有材料完整性、裁决重试与 report path ownership。
- `tests/test_finding_index.py`：Store 明确身份、材料版本、报告资格/登记/索引中断恢复；
  `tests/test_target_migration.py`：显式历史导入与隔离 finality。
- `tests/test_structured_findings.py`、`tests/test_autopilot_state_tool.py`、
  `tests/test_runtime_state.py`、`tests/test_surface_tool.py`、`tests/test_validation_runner.py`、
  `tests/test_report_generator_manual.py`：所有 consumer 的 candidate downgrade/正向 owner 路径。
- `tests/test_autopilot_args.py`、`tests/test_autopilot_bootstrap.py`、
  `tests/test_claude_runtime_integration.py`：flag parser、compact batch projection 与 installed slash
  command `$0..$8` wiring。
- `tests/test_autopilot_round_contract.py`：round defaults 及 CLI flag 传递、canonical controller
  复用、bootstrap error stop、terminal no-op precheck、DONE/EXHAUSTED/CONTINUE/BLOCKED/ERROR
  投影、lane-cap closure、residual blind spots、exact prompt cron cleanup、CONTINUE scheduler
  no-op、native loop cancellation/disk resume、lane terminal heartbeat 和原有 pause boundaries。
- `tests/test_checkpoint.py`：started/result schema、legacy claimed normalization、terminal 幂等与
  冲突、completed evidence gate、terminal replay prevention、unfinished closure、CLI JSON、
  多进程 claim/result 原子性及反复中断恢复。
- `tests/test_autopilot_state_tool.py` 与 `tests/test_autopilot_inline_contract.py`：显式 closure 的
  finish/handoff/blocked、Surface matrix + queue/ledger terminal gate、malformed owner ERROR、
  source/JS pending、rotation hint、max-lanes 覆盖和 ordered slash wiring。
- 修改 runtime prompt 后运行 `runtime_doctor.py --sync --prune`、`--fail-on-drift`，并在新隔离
  localhost target 以显式 `claude-opus-4-6` 完成 `--deep --normal --max-lanes N` smoke/pressure
  run，保存 terminal JSON、state 前后快照、queue、finding event 与 validator 输出。

### 7. Wrong vs Correct

#### Wrong

```text
Claude 在无 stdin 时沿用 prompt 默认值，直接手改 findings.json 为 validated，
然后继续新增 lane，最后把占位草稿称为 report-ready。
```

#### Correct

```text
Claude 提交完整 --decision-json；只读 binding 全通过后 validate 写 per-finding summary/notes，
finding_index 写带 summary digest 的 canonical row + matching event；consumer 先 verify 再消费
finality。bounded deep 的每条 lane 先写 started、证据落盘后写 terminal heartbeat；lane cap 后
checkpoint/sync queue 并 handoff。native /loop 反复调用同一 thin round，round 的 precheck/final
closure 只投影 owner STATUS，unfinished lane 先恢复，并在终态取消 recurrence。
```

---

## Endpoint Path Identity Projection

- `tools.closure_resolver.extract_endpoint_parts()` owns URL/path/fragment parsing;
  `extract_endpoint_path()` projects only its path. Scheme/host, query, and ordinary fragment data do
  not participate in endpoint paths.
- `canonical_endpoint_path()` adds the shared closure identity rules: leading slash and no trailing
  slash except for `/`. Autopilot and Checkpoint must delegate to it instead of copying parsing rules.
- Coverage Matrix may retain extracted-path formatting where persisted matrix compatibility requires
  it, but must reuse `extract_endpoint_path()` for URL parsing.
- When repeated dynamic paths are folded, the Coverage row keeps the route
  template as its persisted identity and may expose a concrete
  `representative_endpoint` for replay. Findings and Queue write-back must
  target the template/`coverage_endpoint`; the representative is execution
  input only. A finding for `/orders/123` must not create a second exact row
  when `/orders/{id}` is already the canonical Coverage row.
- Evidence Ledger may preserve SPA hash-route identity such as `/#/search`; its adapter must reuse
  `extract_endpoint_parts()` and contain no second general URL parser.
- Focused tests must cover absolute URL, query, ordinary fragment, relative path, root, trailing slash,
  SPA hash-route behavior, and finding rehydration into an existing folded
  route template without creating a concrete-path duplicate.

## Scenario: Versioned Family-Aware Closure Identity

### 1. Scope / Trigger

This contract applies when Store evidence views, ClosureResolver, Checkpoint,
Autopilot, or coverage projections create or consume terminal closure state.
It extends the legacy endpoint x vulnerability projection without changing
target storage keys, Surface raw URL identity, or Finding IDs.

### 2. Signatures

```python
build_closure_cell(endpoint, family, dimensions) -> IdentityBuildResult
TargetStore.record_execution(..., observations=[{"identity_dimensions": ...}]) -> dict
ClosureResolver.is_closure_closed(identity_v2) -> bool
ClosureResolver.closed_result(endpoint, family, *, identity_v2=None) -> str
```

### 3. Contracts

- Store persists authored `identity_dimensions`, actor/object scope, method,
  family, result and artifact references. `closure_records()` returns those
  facts; `closure_projection.derive_identity_fields()` is the single derivation
  of `identity_status`, missing/conflicting fields and complete `identity_v2`.
  Current writers do not persist another derived identity status or create an
  Action from a conflict.
- A complete projected key has `schema_version=2`, `kind=closure_cell`, a valid
  EndpointKey, canonical family and that family's required dimensions.
  `identity_contract.py` validates encoding and family policy; malformed or
  incomplete keys never authorize v2 closure. Unknown legal families remain
  saved and readable without acquiring a canonical terminal cell.
- Planned Runner identity is checked against the actual endpoint, family and
  method before registration. Conflicting AI-supplied dimensions cannot replace
  observed facts. Corrected evidence uses a new explicit registration; historical
  observations are retained.
- `closed_cells_v2` contains only complete, supported family-aware identities.
  Records without an identity claim can contribute to the endpoint-level
  `closed_cells` view, but cannot close a method/parameter/actor/object-specific
  v2 key. Coverage preserves explicit keys and does not infer them from display
  text or a path-only terminal.
- Explicit legacy inspection can preserve historical `identity_candidate`,
  `identity_follow_up_action` and `identity_replacement` metadata. The shared
  projection understands those historical inputs without reviving a legacy
  writer or generating current work. Its shadow differences and follow-up
  diagnostics are views, not a second queue or stored identity owner.
- Store and artifact integrity failures remain explicit. Partial/unreadable
  evidence suppresses closure authorization while preserving historical facts
  for diagnosis. A hash proves bytes, not the truth of an AI interpretation.

### 4. Validation & Error Matrix

| Input | Result |
|---|---|
| Complete policy dimensions and intact terminal evidence | Derived complete key eligible for `closed_cells_v2` |
| Missing required dimension | Incomplete diagnostic; no v2 closure |
| Endpoint/family/method disagreement | Conflict or registration rejection; no automatic Action |
| Unknown family | Facts preserved; no canonical v2 terminal |
| Path-only terminal | Endpoint view only; no v2 closure |
| Malformed identity | No terminal authorization |
| Evidence partial/unreadable | Closure suppressed; explicit recovery diagnostic |

### 5. Good/Base/Bad Cases

- Good: SQLi `GET /search` with parameters `q` and `term` produces distinct keys.
- Base: endpoint-level evidence remains readable while a complete v2 key stays
  open until its own required dimensions and evidence exist.
- Bad: a path-only terminal, AI guess or display summary closes every actor,
  object, parameter, sink or workflow-specific cell.

### 6. Tests Required

- `tests/test_identity_contract.py`: encoding, family policy, missing/conflicting
  dimensions and candidate validation.
- `tests/test_target_store.py` and `tests/test_current_truth.py`: durable authored
  dimensions, derived identity, unknown family preservation and damaged evidence.
- `tests/test_closure_resolver.py`: exact v2 matching, path-only non-closure,
  SPA/query separation and explicit historical replacement inputs.
- Runner, Autopilot and Checkpoint tests: bound identity and projection visibility
  without generated follow-up Actions or extra durable identity fields.

### 7. Wrong vs Correct

```text
Wrong: closed_cells endpoint=/api/search, vuln=SQLi -> close every parameter.
Correct: closed_cells_v2 compares EndpointKey + family + method + parameter.

Wrong: an AI candidate naming parameter=q immediately marks it tested_clean.
Correct: record observed dimensions and evidence, then derive only the exact
         terminal identity supported by intact facts.
```

## AI-owned hypothesis metadata and explicit continuation

`action_queue.py add/claim/resolve --metadata-json` accepts bounded descriptive
JSON. Family, technique, expected learning, risk, stop conditions and knowledge
references express the AI's hypothesis; they are not evidence of execution.
Sensitive content, forged Runner fields, identity conflicts and unsupported
completion remain rejected by the shared Store/Queue boundary.

No Skill files, `skill_route`, `route_required` or preset `required_dimensions`
participate in admission. Historical route fields stay opaque. There is no
Checkpoint-created child/primitive-review action. AI explicitly creates any
follow-up and saves reusable conditional experience through the memory API.
Actual observations retain their tested dimensions and complete provenance.

Tests: Action Queue, primary action consumers, native Runner and Checkpoint
exercise route-free claims, explicit proof, no automatic continuation and
unchanged actions after registration/reporting.

## Scenario: Keep AI-selected knowledge refs advisory after family closure

### 1. Scope / Trigger

Use when the Context Pack publishes its card catalog and an owner-backed action
later records a card selected by the AI, including after the related canonical
family is `tested` or `not_applicable`.

### 2. Signatures

- Context input: `card_catalog[{file,id,layer,load,purpose}]`
- Compatibility projection: `knowledge_cards=[]`, `deferred_knowledge_cards=[]`,
  `knowledge_card_recall=[]`
- Claim input: `selected_knowledge_refs[]`
- Diagnostic output: `_project_knowledge_effect_trace(checkpoint, actions) -> dict`

### 3. Contracts

- Preserve the card catalog as a discovery surface; do not turn catalog order
  into selected/deferred recall or an automatic read order.
- `hypothesis_seeds` and `alternative_angles` remain diagnostic/advisory context.
  None of these suggestions or catalog entries may create an Action Queue row or
  an activation `hypothesis_seed` by presence alone.
- A normal owner-backed action may expose recommended `knowledge_refs`, but only
  the AI claim records `selected_knowledge_refs` and turns the effect trace from
  `pending` into a selected action/result.
- Family closure is unchanged by later recall. Keep the terminal Matrix
  disposition while the recall and pending effect remain visible to Claude.
- Existing persisted `knowledge-signal-review` rows remain readable and
  resolvable for restore compatibility; new Checkpoints do not generate them.

### 4. Validation & Error Matrix

| Input | Result |
|---|---|
| Catalog/seed exists without an owner action | keep advisory projection; Queue unchanged |
| Context Pack is built | Card selection/recall compatibility fields remain empty |
| AI selects a recommended card on claim | effect trace links the selected action/result |
| Family disposition is terminal | disposition remains unchanged; selected ref stays auditable |
| Historical `knowledge-signal-review` exists | restore and resolve through compatibility path |

### 5. Good/Base/Bad Cases

- Good: RCE is `tested`; a later AI-selected SSTI card ref remains visible in
  the claim/effect trace without reopening RCE or creating work.
- Base: an owner-backed SQL action can carry recommended context while its
  actual card selection remains an AI claim decision.
- Bad: a seed or unselected card creates a Queue item, activation hypothesis,
  or new technique Matrix dimension.

### 6. Tests Required

- Context Pack/Checkpoint tests must prove the catalog and seeds remain visible,
  semantic Card selection fields stay empty, and no action is fabricated.
- Claim/effect-trace tests must preserve AI-selected refs after terminal family dispositions.
- Effect-trace tests must cover pending, selected, and terminal result stages.

### 7. Wrong vs Correct

```text
Wrong: catalog/seed -> generated durable Queue review or automatic selected card.
Correct: keep the catalog/suggestion advisory; only an AI-selected,
owner-backed action records the card ref and enters the Queue.
```

## Invocation-local Autopilot owner projections

- Public `build_autopilot_state`, bounded bootstrap and `build_context_pack`
  discard caller-supplied owner dictionaries and acquire current owners.
- Within one Checkpoint call, private `_build_autopilot_state` and
  `_build_context_pack` accept only the Queue/Case/Surface/Coverage/candidate/
  truth values acquired by that orchestrator. There is no global cache or
  reuse across calls. Owner revision drift aborts the assembled result.
- Every new public query performs fresh raw-integrity checks, even when Store
  revision has not changed. Snapshot reuse does not authorize later writes.
- Closure binds its next-action display and active count to one acquired Queue;
  a caller's preloaded pointer cannot override it. Round guard locking order
  remains checkpoint witness then Queue mutation lock.
- Closure digest includes each decision input (Case, Recon, Finding, Browser,
  Source/Intel/JS/SQL/JSON, Observation, Surface and Queue). Drift yields an
  explicit stale/error result; evidence is never truncated to gain speed.
- Required tests: owner read budget, public forged/stale snapshot rejection,
  same-revision raw damage between calls, claimed-action recovery and direct
  versus reused output equivalence. Offline measurements record connections,
  materialized rows, process I/O, median/p95, output bytes and backup recovery.

## Exact asset and declared-condition identity (v3)

This supersedes the v2 family-policy closure authorization described above.
`EndpointKey` v3 requires an absolute HTTP(S) URL without credentials; it preserves
scheme, host, explicit port, path encoding, query bytes/delimiters and fragments.
`canonical_endpoint_identity` remains the historical/display path function, not an
asset authorization key. Store observations keep their raw endpoint independently.

`ClosureCellKey` v3 requires an explicit method and technique plus an authored,
bounded string-condition map (16 fields, 64-character names, 256-character values,
4096 serialized bytes). All declared conditions participate in equality. Families
are open, no Python/YAML family schema prescribes method-specific fields, and
condition equality does not prove semantic completeness or technical truth.
Unknown families can be assessed and queried exactly but never map themselves to
a canonical Coverage class. Attempt/step IDs remain independent execution facts.

Existing `identity_v2` JSON containers and `closed_cells_v2` projection names carry
the explicit inner schema version; no DDL or automatic data conversion occurs.
V2 keys remain decodable history, but cannot authorize closure. Missing origins
are never guessed from target identity. Recovery requires a new explicitly bound
registration with evidenced v3 conditions, preserving the prior operation.

Native evidence may declare `subject_step` as a zero-based run index. It must
match the Finding's exact endpoint/method. Omission is accepted only with one
matching run; ambiguous, invalid or mismatched selection fails before attempt or
artifact publication. Only the selected step receives subject identity.

Regression: `tests/test_exact_evidence_identity.py`, `test_identity_contract.py`
and `test_native_first_replay.py` cover exact assets/methods/extra conditions,
unknown families, subject ambiguity, separate attempts and read-only v2 history.

Resume targets are not suppressed by a finalized Finding's path. Such a path
loses asset, method and declared-condition dimensions and cannot rule out other
work. Current assessments remain queryable for AI judgment; concrete placeholder
filtering and bounded deduplication do not imply technical finality.

## Surface review completion identity

`_surface_review_completion` uses absolute endpoint identity, explicit method,
family, auth_context and semantic_shape_id when matching a final Queue record.
Missing method cannot authorize completion; missing context is not a wildcard.
Relative/folded Coverage paths remain display/grouping data and cannot establish
another asset's completion. Unresolved advisory candidates remain non-blocking;
explicitly blocking candidates retain their blocker until identity is supplied.

Surface's exact completion evidence comes from `matrix.closure_projection`, not
`matrix.endpoints` (a path-only display grid). A candidate supplies a validated v3
identity consistent with its URL/method/family; the shared resolver verifies that
identity's current closure. Final Queue metadata must carry the same identity
and review context. Missing identity remains unresolved, not a path fallback.
Regression must include actual `read_matrix` output, not just hand-built grids.
