# Transactional Target State

## 1. Scope / Trigger

Read before changing `tools/target_store.py`, evidence identity, or wiring a legacy
consumer to the new backend. Foundation APIs are implemented and tested only in
isolated fixtures. Case context tables/adapters are implemented in the isolated
store, while migration/cutover and all-consumer replacement are still in
progress. Do not initialize a store in an active legacy target.
`docs/architecture-contract.md` is the target architecture authority.

## 2. Signatures

- `TargetStore(repo_root, target, allow_preview=False)`: strict target identity,
  no I/O at construction; preview domain writes require explicit isolated import.
- `target_backend(repo_root, target)`: `legacy|preview|primary`, or a visible fault.
- `initialize(allow_legacy=False)`: exclusive empty database creation; normally
  refuses known legacy state. Explicit isolated imports create preview stores.
- `create_action(command_id, action_id, intent, execution_key, actor,
  endpoint=None, family=None, kind="execution", subject=None, priority=None,
  repeat_of=None, repeat_reason="", metadata=None)`: keyword arguments. Metadata is
  bounded action detail; it never owns execution, observation, assessment or delivery state.
- `transition_action(command_id, action_id, expected_version, status, actor,
  reason="", claim_token=None, completion=None, metadata=None)`: owner assigns claim
  token as claim command ID; completion requires an explicit proof reference. Claim
  metadata is versioned detail and Runner-owned observation fields are rejected.
- `create_finding(command_id, finding_id, endpoint, method, family, title, claim,
  actor)`: save an unassessed claim independently of any observation.
- `start_attempt(attempt_id, source, started_at, actor, action_id=None, claim_token=None)`.
- `record_execution(attempt_id, outcome, observations, actor, candidate=None,
  expected_operation=None)`: publish files before invocation.
- `assess(command_id, finding_id, verdict, reason, boundary, impact, evidence,
  actor, expected_assessment)`: explicit technical judgment, not a detector.
- `decide_delivery(command_id, finding_id, assessment_id, destination, status,
  reason, actor, expected_decision)`: separate destination policy.
- `remember(command_id, kind, statement, conditions, reopen_when, next_intent,
  evidence, actor, action_id=None, finding_id=None)`: no implicit action creation.
- `upsert_case_actor(command_id, actor_id, role, label, notes, actor)`;
  `upsert_case_session(command_id, session_id, actor_id, kind, source, validity,
  last_checked, notes, private_ref, actor)`; `upsert_case_object(command_id,
  object_ref, object_type, object_id, owner_actor, endpoint, status, notes,
  private_ref, actor)`: Case identity/context commands using the same audit and
  idempotency transaction. Secrets are never accepted as database fields.
- `remember_hypothesis(command_id, hypothesis_id, vuln_class, endpoint, object_ref,
  actor_ids, why_now, status, metadata, actor)`: stores a hypothesis as an
  `experiences(kind='hypothesis')` row plus explicit Case relations; it never
  creates an action.
- `register_report(command_id, report_id, finding_id, assessment_id, delivery_id,
  artifact, actor)`: hash/register a target-owned report artifact only when it
  binds an existing eligible delivery for the referenced current assessment.
  The report row, artifact relation and audit receipt commit together; report
  generation remains separate from external submission.
- `record_delivery_event(command_id, event_id, report_id, external_ref,
  submitted_at, actor, receipt_artifact="")`: append an explicit external
  submission fact for the current eligible registered report. It may reference
  a target-owned receipt artifact; generating/registering a report never calls
  this command and never implies an external submission.
- `case_context()` / `case_state()`: read-only actor/session/object/hypothesis
  views with target/store revision; private references are checked before they
  can authorize a consumer. `case_state()` is a compatibility projection, not
  a writable JSON owner.
- `page(kind, limit=50, cursor=None, status=None)`; `action(id)`; `finding(id)`; `execution(id)`;
  `experience(id)`; `verify_operation(id)`; `backup(destination)`.
- `coverage_matrix.read_matrix(target, repo_root=None, *, as_of=None)`: primary
  read-only projection; legacy loads its existing matrix. `as_of` labels the
  current read, not a request to reconstruct historical state.
- `import_target_staged(source_root, destination_root, target, *,
  disposition_ledger=None)`: isolated migration import. When supplied, the
  ledger must bind the canonical target and source manifest SHA-256, cover
  every stable quarantine ID exactly once, and record non-placeholder
  `operator`, `decision`, and `decision_ref` values.

`finding()`/`finding_page()` derive delivery and report freshness at read time:
the current assessment, current destination decision, supporting operation bytes,
and report artifact bytes must all still match. Historical rows remain visible;
an invalidated evidence or report artifact sets `stale=true` and
`artifact_available=false` where applicable, so consumers cannot treat an old
report as the current deliverable. `register_report()` repeats the current
assessment/delivery binding check and rejects stale or superseded decisions.

All write parameters are keyword-only. Command receipts include revision,
command_id, command, entity_id, actor, content_sha256, recorded_at and replayed.
Command IDs and audit actors reject surrounding whitespace: normalizing just the
audit would leave mutation-owned claim tokens and receipt references inconsistent.

## 3. Contracts

Database path: `state/<target_storage_key>/metadata.sqlite3`; database mode 0600,
target directory 0700; symlinked database paths rejected. SQLite schema v8 is
pre-cutover, with target/store identity and monotonically increasing revision.
Unsupported schemas are not automatically upgraded or overwritten. Rebuild
unpublished preview fixtures from preserved inputs in a new isolated destination.

Primary stores require a matching private `state/<key>/legacy-frozen.json` fence:
`schema_version=1`, canonical `target`, 32-character lowercase-hex `store_id` and
64-character `source_manifest_sha256`. Fresh empty stores use the digest of `[]`.
The fence is exclusively created and fsynced before the database schema commits;
initialization failure retains it for explicit recovery. Missing DB + fence,
primary + absent/mismatched fence, preview + fence, malformed/non-private/non-regular
fence or symlink traversal all fail closed. Only no DB + no fence means legacy.
`current_truth` uses this one role check rather than its own existence fallback.
This is not full cutover isolation: ordinary Store, Queue, Case, Ledger,
runtime, coverage, unsafe-review and target-memory mutations now take the
target's shared `target-switch.lock` before their owner-specific lock/
transaction, while `target_cutover_lock()` takes that file exclusively. The
public Queue/Finding/Case/Ledger/target-memory legacy writers reject
preview/primary targets, but complete consumer and bypass-writer admission is
still outstanding. The exclusive lock is a coordination boundary, not proof
that an unmodified external process has stopped writing.
The explicit `action_queue.py` add/claim/resolve/list entry points are a thin
primary adapter over `TargetStore.actions`; they do not recreate the legacy
JSON queue. Primary completion still requires a claim-bound operation, artifact,
or domain-command receipt.
Finding mutation admission binds the actual destination directory owner, not an
unchecked caller-supplied target. Explicit target overrides must match that owner;
custom output paths remain within its non-symlinked directory. The shared switch
lock covers the owner lock and the final backend check, including implicit legacy
list migration. `load_finding_index(migrate_legacy=False)` remains a non-migrating
read. Ledger admission is likewise repeated inside its shared switch lock.

Runner request execution, native evidence registration and sync take the shared
switch lock before backend admission or generated artifacts. Preview/fenced/broken
stores reject rather than fall through to legacy. Published summaries carry
`backend_binding={target, backend, store_id}`; primary registration requires this
binding and rejects a different backend or Store generation. The CLI holds the
shared lock through execution and registration, without a database transaction
across network I/O. Registration failure preserves raw material for retry.
`allow_preview=True` asserts an isolated import; it is not a filesystem sandbox
or permission to migrate a live target.

Explicit tables own actions (with bounded metadata detail), attempts, operations, observations, artifact bindings,
and append-only artifact availability/provenance events,
action completion references, findings/observation links, technical assessments, destination decisions,
conditional experience, Case entities/relations, report artifacts and audit. No universal JSON payload table or ORM.

Artifact rows are immutable byte identities. `record_artifact_event()` appends a
typed `availability` (`available|unavailable`) or `provenance`
(`trusted|revoked`) fact; current availability and authorization are derived from
the latest event plus a fresh byte/hash check. Invalidated or revoked artifacts
remain queryable history and never become an absent record.

Observation envelopes have a closed, strongly typed relational head (target,
operation, timestamp, actor, outcome, family and artifact bindings) plus a
bounded canonical `detail` object for extension. Query and relationship keys are
never inferred from that detail object.

A command uses one `BEGIN IMMEDIATE` transaction for facts, relationships, revision
and audit. Identical replay returns the original receipt without mutation; content
or actor changes under the same command ID conflict. Claim versions and assessment/
delivery predecessor IDs prevent silent stale overwrites. Active execution keys
are unique; repeat intentions require a terminal predecessor and explicit reason.

Action kind describes mechanical proof requirements, not a category or route:

- `execution` remains the default and requires target-owned HTTP endpoint/family.
  Missing identity is never silently reinterpreted as non-execution work.
- `work` requires exactly one subject: `{target}`, `{url}`, `{artifact}`,
  `{finding_id}` or `{experience_id}`. Target/URL ownership, artifact bytes/hash
  and entity foreign keys are checked. Its family is null; its endpoint is null
  except for a URL subject. No attempt, observation or Finding is fabricated.
  Only execution actions may own execution attempts. Case entities now have
  explicit identity/context tables and relations; work is still not a second
  Case queue.
- Completion is independent of recording results. `completion={operation_id}`
  for execution must identify a complete, unsuperseded operation from this claim,
  with currently intact files. An arbitrary file cannot complete an execution.
- Work uses `completion={artifact}` (a nonempty target-owned published result) or
  `completion={command_id}`. Currently a receipt must be a `remember` mutation
  linked to this action, authored by its claimant and committed after the current
  claim. Claim/create receipts, another action/operator's result and prior-claim
  receipts cannot complete it. Report receipts still await their domain
  command; Case mutations have their own audited receipts but do not complete
  actions implicitly.
- `action_completions` binds exactly one proof to the action, claim token and
  expected action version. Proof, optional artifact, state update and audit commit
  together. Reason alone never completes work. Result content is the author's
  assertion, not mechanically proved relevance or technical validity.

Attempt IDs distinguish real executions. Registration IDs bind normalized content
including the attempt ID, so identical bytes in different attempts stay distinct.
Supplemental evidence for the same attempt requires `expected_operation` naming
the current registration. Old registrations remain immutable; unknown external
effects can be supplemented without replaying a request. No automatic action
completion, finding confirmation, report eligibility or next-action generation.

Observation required keys: endpoint, method, family, observed_at, description,
artifacts. Optional keys: actor, object_scope, variant, error, truncated,
state_changing, redline_checked, result, identity_dimensions. Unknown fields fail
rather than disappear. Results use the shared Ledger vocabulary; dimensions are
bounded authored facts, not stored closure authority.
Artifacts map kind to nonempty target-owned file. Raw directories are evidence,
recon, findings, reports and `.private/validation/<target-key>`; a target string
appearing anywhere in another target's path is not ownership. Hash streaming and
file-change checks occur before the write transaction. Existing raw files are
never rewritten or deleted by registration.

Outcomes are complete/partial/unknown. Complete rejects errors/truncation; only
unknown permits no observations. family accepts valid unknown labels (nonempty
string, at most 256 characters, no control characters). `coverage_family()` returns
a canonical label or None; unknown families and Workflow cannot close canonical
Coverage. Existing known aliases and exact endpoint normalization are unchanged.

Candidate keys: id, endpoint, method, family, title, claim. `create_finding` needs
no attempt or observation and creates no judgment. When registering execution,
an exact matching observation anchors the candidate. Both entry points share
identity checks; existing IDs cannot change their claim or original creation time.
Assessment references are `{operation_id, step}` and must belong to that finding.
Technical verdicts: confirmed/refuted/inconclusive. Confirmation requires complete,
intact evidence, no unchecked known state change, and explicit boundary/impact
reasoning; byte integrity does not establish the reasoning's truth. Destination
eligibility never rewrites this verdict. Old destination decisions become visibly
stale when a newer technical assessment exists.

Queries open mode=ro + query_only snapshots. They do not initialize missing stores,
write domain rows, refresh caches or generate tasks. Primary Surface can derive
technology inventory from raw observations only in memory; its `persist=False`
path is required for primary reads, while legacy cache refresh remains an explicit
compatibility behavior. SQLite WAL/SHM auxiliary
bookkeeping is not a domain mutation. Pages return stable ID order, exact total,
remaining, has_more and next_cursor; cursor binds target/store/revision/kind/filter.
Finding/action queries return recorded judgments/proofs. Finding delivery/report
projections additionally re-check supporting operation and report artifact bytes to
derive `stale`; consumers that need the detailed reason can call `verify_operation`.
Primitives retain conditions/links even without a continuation hint. Negative
experience requires reopening conditions. Secrets remain in private raw files;
this private metadata API is not a redacted public export surface.

Primary Coverage queries rebuild in memory through `read_matrix`; they do not
publish matrix/summary caches. Saved cells and structural N/A defaults remain
historical advice, and an unassessed Finding only preserves its endpoint. Current
authorization comes from `current_truth` and `ClosureResolver`. `dead_end`,
`not_applicable` and `blocked_redline` suppress matching actionable gaps without
being renamed `tested_clean`; query/hash/v2 identities cannot close a broader
path/family grid cell. Gap counts use the same iterator as the displayed gaps.
The primary `source_snapshot` records Store binding, observation/immutable
operation identities, evidence health, authorization fingerprint, discovery and
historical-matrix inputs, and one explicit `as_of`. Immutable operations bind the
registered artifact digests; current truth rechecks bytes. Input drift fails
visibly. This is not a filesystem transaction or historical-time query.

Primary Context Pack does not trust caller-provided Surface/Coverage/runner/truth
shortcuts: it reloads current owners and revalidates artifacts even at the same
Store revision. Legacy retains those reuse shortcuts. Checkpoint compares its
Store binding across the complete assembly and publishes no witness/cache in its
primary read path. Primary round settlement skips legacy root-claim/Queue
compensation and implicit Surface refresh; its only settlement mutation is the
explicit runtime round closure. Replay is read-only.

Explicit Surface review holds the shared switch lock across index, context,
manifest, ranking and publication. Primary freezes inputs before context reading;
legacy may synchronize its sidecars before freezing. Both retain drift checks.
Primary reports use stable target/Finding/assessment/delivery-bound identities,
never rewrite registered bodies, and rebuild INDEX/SUMMARY from current Store
reports, including the empty set. The index includes `source_binding` and `as_of`;
publication checks the binding under the target mutation lock after registration.
Preview reports reject before output creation. Artifact/index publication failure
remains retryable and never creates an external delivery event or closes an action.

### Migration Quarantine Disposition Contract

**Scope / Trigger**: Any attempt to turn a staged migration with quarantined
legacy rows into a publishable preview.

**Contracts**:

- Quarantine identity is a bounded hash of owner, reason, path, event/id,
  endpoint, evidence reference, line, status and family. Reordering the report
  does not change the identity; changing a fact does.
- `decision` is limited to `preserve_verdict`, `permanent_quarantine`, or
  `operator_review`. All decisions require a non-placeholder operator and
  decision reference; `operator_review` is not a technical judgment.
- The ledger must contain every quarantine ID exactly once. Missing or unknown
  IDs keep the report `partial`; no decision can create an assessment,
  completion, delivery, or observation.

**Validation & Error Matrix**:

| Condition | Required result |
|---|---|
| Ledger target or source manifest differs | `StoreError`; no staging database is created |
| Missing/duplicate/unknown quarantine ID | `StoreError`, or `partial` when rows are omitted; never publish |
| `PENDING`, placeholder operator/reference, or unsupported decision | `StoreError`; never publish |
| Complete, matching, fact-preserving ledger | report/receipt may become `ready`/`complete` and proceed to explicit publish |
| No ledger supplied while quarantine exists | report remains `partial`; legacy verdicts stay quarantined |

**Good/Base/Bad Cases**:

- Good: every terminal queue verdict is explicitly preserved or permanently
  quarantined with an operator and audit reference.
- Base: preview without a ledger reports all quarantine rows and remains
  publish-blocked.
- Bad: treating a count, endpoint similarity, or `PENDING` row as a decision.

**Tests Required**:

- `tests/test_target_migration.py` asserts complete disposition clears only
  quarantine and produces a complete receipt; missing rows, pending decisions,
  target/manifest mismatch, and placeholder references fail closed.
- Invalid ledger binding fails before the destination Store is created.

**Wrong vs Correct**:

```python
# Wrong: aggregate approval or endpoint similarity authorizes a terminal row.
ledger = {"items": [{"decision": "PENDING"}]}

# Correct: exact quarantine identity plus an auditable, bounded disposition.
item = {
    "quarantine_id": QUARANTINE_ID,
    "decision": "preserve_verdict",
    "operator": "OWNER",
    "decision_ref": "AUDIT_REF",
}
```

## 4. Validation & Error Matrix

| Input/failure | Required behavior |
|---|---|
| Missing/corrupt/foreign/schema-mismatched DB | StoreError; never empty history |
| Legacy owner file on initialize | Reject; no automatic migration |
| Fenced primary DB lost, or fence inconsistent | Stop; no legacy fallback or reinitialization |
| Normal domain command on preview | Reject; only explicit isolated importer may write |
| Audit insert fails after metadata inserts | Entire transaction rolls back; raw files remain |
| Same command replays / same command changes | Original receipt / ConflictError |
| Concurrent claims with same expected version | Exactly one succeeds |
| Work missing subject, or execution missing HTTP identity | Reject; never guess the action kind |
| Execution completed with a file, foreign-claim or superseded operation | Reject; require this claim's complete operation |
| Work completed without a result or with stale/unrelated receipt | Reject; action and audit unchanged |
| Completion audit fails | Roll back proof, artifact binding and status; keep raw output |
| Same bytes, distinct attempts | Distinct operations |
| Unknown then recovered evidence | Explicit predecessor; no new execution implied |
| Empty/foreign/changed raw file | Reject or explicit integrity error; existing delivery/report projections become stale |
| Unknown valid family | Persist; canonical Coverage label absent |
| Bad type/unknown observation field | Reject before committed metadata |
| Partial evidence / unknown effect | Not confirmation or automatic completion |
| Known duplicate at destination | Can be technically confirmed, delivery ineligible |
| Stale cursor or judgment predecessor | Conflict; caller reloads |
| Backup destination exists | Refuse overwrite; SQLite backup reads committed WAL |
| Explicit Finding target/output belongs to another owner or traverses symlinks | Reject before writing either owner's files |
| Cutover occurs after optimistic legacy admission | Recheck under shared switch lock; no stale legacy write |
| Preview runner/report input | Reject before request or generated artifact |
| Runner summary names another backend/Store generation | Reject registration; retain existing raw material |
| Primary query receives foreign/old shortcut data or raw changes at same revision | Re-read owner and integrity; do not relabel shortcut as bound |
| Primary report index source revision changes before publication | Conflict; preserve registered bodies and retry projection |

## 5. Good / Base / Bad Cases

- Good: native tools publish raw files; explicit attempt/registration binds them;
  a later assessment cites the observation steps; delivery policy remains separate.
- Good: source-reading work names a target-owned source artifact, then explicitly
  completes with its published review or action-linked handoff receipt, without HTTP.
- Good: primary report replay preserves bodies and revision while rebuilding a
  bound index; a damaged report stays historical and leaves the current index.
- Base: a saved Coverage N/A note remains inspectable but does not authorize
  primary closure without the current evidence owner.
- Base: empty initialized target returns a zero-total page; query of a nonexistent
  store fails without creating directories.
- Bad: wrap the old cross-file sync in a try/except and call it transactional, or
  initialize a second live backend before all consumers can use it.

## 6. Tests Required

`tests/test_target_store.py`: atomic audit rollback, receipt idempotence, concurrent
claims/registration, distinct attempts, unknown recovery, strict input/target/file
binding, partial evidence, judgment separation/CAS, read-only snapshot paging,
conditional facts without new actions, damaged files, append-only artifact event
authorization, backup and dependency direction.
Report regressions must cover assessment supersession, delivery/report `stale` projection,
report-artifact tampering, and rejection of registration against an old delivery.
Work regressions cover target/URL/artifact/entity subjects, no fabricated attempt,
claim-scoped receipt validation, completion rollback and currently intact execution
proof. Role tests cover lost DB, missing/bad/private/symlink/FIFO fences and preview
write refusal. Missing-role fixtures use `SCHEMA_VERSION` so they exercise role
validation rather than accidentally failing the unrelated version check first.
`test_record_evidence_accepts_unknown_family_without_closing_canonical_coverage`
proves the existing native registration path admits an unknown family.
Existing Coverage/Closure/identity tests protect known taxonomy and endpoint semantics.
Consumer regressions also cover report/index partial failure and stale delivery,
cross-target/output fences, late cutover admission, preview execution refusal,
post-context manifest drift, supplied foreign/stale snapshots, default-refresh
Checkpoint/round zero writes, fixed-as-of Coverage reproducibility, and damaged
raw suppressing current closure without a Store revision change. When a runner
summary signature changes, update all fixture callers as well as production
callers; focused runner tests alone do not cover validation's witness fixtures.

## 7. Wrong vs Correct

Wrong: same response hash -> same execution; unknown category -> discard evidence;
report destination says duplicate -> technically refute; SELECT -> implicit repair.
Correct: explicit attempt identity -> immutable registrations; open family -> optional
Coverage mapping; separate judgments; snapshots and explicit commands.

Wrong: copy metadata.sqlite3 during WAL writes, or roll back by selecting stale JSON.
Correct: SQLite backup snapshot; after cutover, export current truth or fix forward.

Wrong: missing HTTP identity -> guess work; `reason="done"` -> complete; any audit
receipt -> completion proof; lost primary DB -> revive leftover JSON.
Correct: explicit work subject and claim-bound proof; explicit recovery of fenced
current state; no automatic downgrade, completion or backend fallback.

Wrong: check backend before a lock, accept the caller's target for another output
directory, or declare a supplied snapshot current because the live revision is stable.
Correct: bind the actual owner, check under the switch lock, and revalidate each
current authorization source before publishing an explicitly bound projection.
