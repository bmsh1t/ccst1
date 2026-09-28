# Transactional Target State

## 1. Scope / Trigger

Read before changing `tools/target_store.py` or domain consumers. Normal
runtime is Store-only; legacy data is available through explicit import,
history inspection and recovery. The task records one authorized cutover on
2026-09-22; code changes do not authorize more real-data operations.
`docs/architecture-contract.md` is the architecture authority. The native-first
engineering task is archived; online capability gains remain unproven and separate
from consumer correctness or this audit's repairs.

`runtime_store()` rejects uninitialized, legacy, preview, fenced/missing and
broken state. `hunt_target()` explicitly initializes before target execution;
ordinary writers/readers and target selection never initialize implicitly.
Existing non-private target directories are rejected, not chmod-repaired.
Locks acquired before explicit initialization must not create a non-private
target directory that prevents that later initialization.

Current Case premise is the most recently created hypothesis: creation timestamp,
then its first `remember_hypothesis` audit revision, then stable ID for imported
ties without a receipt. Replaying/updating an older hypothesis does not recreate
it. Ordinary experience pages retain `created_at_desc,id_desc` cursor order.
Distillation preserves current truth's source, health and truncation alongside
historical verdicts; broken raw never loses its warning at the AI view boundary.
Knowledge recall reports unavailable registry or partial card reads in text/JSON,
while retaining usable target experience and refusing unregistered-card fallback.

Closure acquisition batches operation/artifact bindings and verifies each immutable
artifact identity once on that metadata snapshot. Its local results expire on return;
the next query rereads raw bytes even if revision is unchanged. Existing owner handles
can avoid repeated admission reads, but source acquisition and publication freshness
checks remain. Public Context Pack callers cannot supply cached truth to authorize
the current view; metadata/discovery drift still rejects assembly.

Current memory consumers use Store-backed `show`, ordinary target memory
writes, bounded recall and `/remember` experience writes. Staged import maps eligible historical target-memory entries
to Experience IDs and records original field/position in the migration receipt;
the explicit `--backfill-memory-source` path replays the same import for an active
Store against its cutover manifest. Unbound historical negative/pattern entries
remain labeled unverified advice, not invented execution. Three new-process
checkpoint/pickup rounds with explicit handoffs have a no-echo regression;
Resume renders a bounded Store window with conditions and expansion. Primary
Resume requests its five-entry page at the shared loader instead of truncating
a 20-entry page; counts and cursor describe exactly the displayed entries.
Resume text includes experience kind, evidence refs and recorded author. The
loader supplies a shell-quoted `recall_command` binding the absolute root,
canonical target and requested limit; Resume, show and Pack reuse it.
Primary Resume does not list retired Queue/Case files as canonical sources;
Autopilot counts Store facts, not empty Store initialization, as hunt memory.
Primary Resume derives confirmed Finding counts from Store assessments, not
historical journal results; absent current payout facts are not shown as $0.
Resume's default Finding/tested/untested arrays contain at most five items each.
`domain_windows` gives each collection's exact total/returned/remaining, limit,
order and an executable full expansion command. `owner_projection` carries
source/authority metadata without duplicating these arrays. `load_resume_summary`
and `load_pickup_summary` accept `full_domain_context=False`; the explicit
`resume.py --json --full` query restores complete arrays. `--full` without JSON
is rejected. Default Resume and Pack obtain exact Finding counts and at most
five preview claims from `finding_summary()`, plus at most two follow-up claims
outside that window. Full current Coverage acquisition is still measured
independently. Autopilot reuses
the freshly read Resume Finding summary rather than querying it again, and
renders untested totals from the window, not the preview length.
Primary Context Pack displays five current Store experiences with kind, conditions,
reopen condition, next intent, evidence refs, exact remainder and CLI continuation;
the SQLite file is not a `must_read` text source. The shared memory loader keeps
its 20-entry default for other consumers and accepts an explicit smaller page.
Primary Checkpoint retains that Pack window and active goal in its disposable
output, using the same experience text renderer without another query or write.
Checkpoint and standalone Pack each acquire Coverage once and pass it only
through private assembly functions. Pickup reuses the Resume summary assembled
inside its Checkpoint; `--full` selects complete domain arrays in that same call.
If Checkpoint fails, Pickup can still return independently acquired Resume plus
the explicit Checkpoint error. Public query parameters never admit a fabricated
Coverage or Queue snapshot. Store revision drift rejects assembly; a later
current-truth acquisition differing in source, health or closure projection also
rejects reused Coverage, including raw changes without revision changes.
`coverage_matrix.require_matching_truth(matrix, truth)` owns that comparison and
raises `CoverageEvidenceChangedError(StoreError)` with the existing rebuild-view
message. Closure calls it immediately after acquiring truth, before reading its
witness or constructing a digest. Direct callers propagate the failure; they do
not publish a mixed snapshot with a stale flag. Stable partial evidence still
retains its damage diagnostics and cannot authorize closure. The guard compares
acquired inputs only: it adds no query, hash rule or filesystem transaction.
This is per-call input reuse, not an authorization cache.

Default Checkpoint/Autopilot use `action_summary(limit=5)`: five nonterminal
actions ordered by ID, exact total/pending counts, the original oldest active
action (running first, then created_at/ID), a separately selected ID-first running
action, and all distinct active families. Running work outside the preview is
never lost. Full `load_queue()` / list / closure expansion still read all stored
actions. Filtered pages bind statuses and descriptive action type to the cursor;
`action_context.type` is distinct from Store `kind=work|execution`.
Intel reads only final intel-advisory rows; Surface reads latest final endpoint
advice, not the discarded metadata history. Neither is a closure authority.
Summary/filtered readers reject corrupt metadata even in terminal history.
Store Queue generations hash target/store_id/revision so a bounded and complete
view agree. This changes the previous content-hash encoding: old witnesses become
stale and require a fresh read; no persisted facts are rewritten. Legacy material
retains its content hash. An unrelated Store write already changed the old queue
projection revision and continues to invalidate this generation.
An explicit `--backfill-pattern-source` import pins PatternDB files (including rotated backups)
in a pending receipt before writing only this target's historical rows as unverified
Store notes; completed receipts map Experience IDs to file/line/digest. These
offline contracts do not establish online learning gains or complete M8 costs. The
distillation view now renders Finding claim/family/endpoint, technical verdict,
destination decision and bounded conditional experience without blank aliases.
Fresh stores
use schema v10 with advisory `note`, `active_goal` and structured Coverage reviews;
existing v8 stores retain their old domain APIs but require explicit
`upgrade-memory --backup ABSOLUTE_PATH` before using those new memory APIs.
The plan adds no context table, keyed-note replacement chain or per-entry
provenance table by default. Use the task's M1-M8 consumer gate, not Store unit-
test counts, for acceptance.

## 2. Signatures

- `finding_summary(limit=5)` returns a revision-bound claim preview, exact
  `counts` (`total`, `confirmed`, `pending_validation`,
  `validated_pending_report`, `reported`), and stable-ID `next_validation` /
  `next_report` claims. Counts, preview and follow-ups share one read snapshot;
  no complete history is materialized to compute them.
- `finding_state_page(limit=50, cursor=None)` pages claims with their latest
  recorded assessment and `report_recorded` boolean. It shares the ordinary
  Finding ID/revision cursor. Neither this page nor the summary expands raw
  evidence, delivery decisions or report history. A recorded assessment or
  historical report is not current evidence validity or delivery authority.
  `finding()` / `finding_page()` and current truth remain the checked expansion
  and authorization paths; stale reports stay recorded, not silently erased.
- `action_summary(limit=5)` returns one-snapshot `items`, exact `counts`,
  `next_action`, `running_action` and `active_families`. It validates stored JSON
  without materializing full terminal histories. SQLite aggregation/scanning is
  still measured; bounded returned rows do not imply constant storage work.
- `action_page(statuses=None, action_type=None, limit=50, cursor=None)` filters
  before stable-ID pagination; no filter returns complete history. Invalid state
  filters, malformed cursors and changed target/filter/revision are errors.
- `final_action_endpoints()` returns ID-ordered latest final action per absolute
  URL as only `id/endpoint/status`, preserving subsequent path-collapse ordering.
- `closure_records(limit=20000, verify=False)` preserves the ordinary facts-only
  query. `verify=True` explicitly acquires integrity for every operation on the
  same metadata connection/snapshot and returns `invalid_operations` separately
  from historical records. Current truth requires that checked read; a missing
  verifier is never treated as permission to skip integrity. Truncated prefixes
  remain damage and cannot authorize closure. Subsequent queries recheck bytes
  and artifact events even when the Store revision has not changed.

- `TargetStore(repo_root, target, allow_preview=False)`: strict target identity,
  no I/O at construction; preview domain writes require explicit isolated import.
- `target_paths.open_target_lock_file(repo_root, target, filename, *, create=True)
  -> TextIO`: open a regular single-link lock beneath the trusted repo root.
  Callers own flock and handle closure. `create=False` opens read-only without
  creating directories/files or changing permissions; this is not Store admission.
- `runtime_store(repo_root, target) -> TargetStore`: final runtime admission;
  returns an active validated Store or raises `StoreError`. It never returns
  None or hides a fence/receipt/damaged database behind a legacy fallback.
- `target_backend(repo_root, target)`: existing low-level admission and
  migration/recovery inspection; returns `legacy|preview|primary`, or a visible
  fault. Runtime admission reuses its checks rather than duplicating DB-existence
  predicates; business consumers do not implement a backend driver switch.
- `initialize_target_store(repo_root, target) -> str`: existing explicit
  creation primitive; success retains the internal `primary` return value.
  `python3 tools/target_store.py init --store --target TARGET` exposes it.
  Fresh creation and active idempotence succeed; legacy/preview/recovery states
  reject. No domain writer calls it as a fallback.
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
- `active_goal()` / `set_active_goal(command_id, goal, actor, expected_revision)`:
  v9+ singleton target intent; the update is audited, idempotent and rejects
  a stale Store revision.
- `upgrade_memory_schema(backup_path)`: explicit primary v8-to-v9 transaction;
  backup must be a new absolute file in a private directory outside target state.
- `upgrade_schema(backup_path)`: explicit v8/v9-to-v10 upgrade using the same
  verified backup and rollback protocol; ordinary query/init never upgrades.
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
  a writable JSON owner. `case_state(include_hypotheses=False)` returns the
  same verified entities and omits the `hypotheses` key entirely; the default
  still returns complete hypothesis history. Distillation uses the entity-only
  view because it renders hypotheses through the separate Experience window.
- `case_summary()` / `case_object_refs()`: read the same verified entity
  snapshot without materializing hypothesis history. Summary counts open Case
  hypotheses in SQL and keeps the existing eight object samples. Object seed
  reads only the registered refs; full Case history remains explicitly readable.
  Missing or damaged private session/object material still fails both queries.
- `page(kind, limit=50, cursor=None, status=None)`; `action(id)`; `finding(id)`; `execution(id)`;
  `experience(id)`; `verify_operation(id)`; `backup(destination)`.
  Operation verification reads artifact metadata and invalidation events through
  one Store read snapshot, reusing `_artifact_status(conn, artifact)` for each
  registered artifact. It still hashes every current file and enforces explicit
  availability/provenance events; it must not reopen the database per artifact
  or cache an earlier query's byte validity.
  `finding_page()` batches the current page's assessment/destination/evidence/report
  relations; `finding()` uses the same projection. Supporting operations are checked
  once per query through `_verify_operation(conn, id)`, on that query's metadata
  snapshot. No nested connection may combine an old assessment/revision with a new
  artifact event. The next query checks current bytes/events again; this is not a
  cross-query validity cache. Pages still expose all linked Finding observations,
  while single-ID expansion additionally exposes the selected assessment's evidence.
  `finding(id)` raises `FindingNotFoundError(StoreError)` only for a missing
  valid ID. Its current `assessment.evidence` contains precisely that
  assessment's `{operation_id, step}` references; outer `evidence` retains
  every observation linked to the Finding. Consumers must not catch arbitrary
  Store errors to infer absence or authorize a replacement write.
- `coverage_matrix.read_matrix(target, repo_root=None, *, as_of=None)`: primary
  read-only projection; `as_of=None` is captured once at the source-acquisition
  boundary and the resulting snapshot carries that explicit value. Projection
  code never reads the wall clock. Legacy matrix loading is confined to explicit
  migration or historical inspection, never a normal current-state query.
- `import_target_staged(source_root, destination_root, target, *,
  disposition_ledger=None)`: isolated migration import. When supplied, the
  ledger must bind the canonical target and source manifest SHA-256, cover
  every stable quarantine ID exactly once, and record non-placeholder
  `operator`, `decision`, and `decision_ref` values.

`finding()`/`finding_page()` acquire current authorization inputs before
projection: the current assessment, current destination decision, and an
explicit validation of supporting operation/report bytes with captured digest,
health and `as_of`. Projection rendering consumes this closed input and does not
read the filesystem or clock. Historical rows remain visible; an invalidated
evidence or report artifact sets `stale=true` and
`artifact_available=false` where applicable, so consumers cannot treat an old
report as the current deliverable. `register_report()` repeats the current
assessment/delivery binding check and rejects stale or superseded decisions.

Domain command method parameters are keyword-only; initialization uses the
explicit signatures above. Command receipts include revision,
command_id, command, entity_id, actor, content_sha256, recorded_at and replayed.
Command IDs and audit actors reject surrounding whitespace: normalizing just the
audit would leave mutation-owned claim tokens and receipt references inconsistent.

## 3. Contracts

Database path: `state/<target_storage_key>/metadata.sqlite3`; database mode 0600,
target directory 0700; symlinked database paths rejected. Initialization must not
silently repair an existing non-private target directory. New stores use SQLite
schema v10; v8/v9 retain their existing operations, with an explicit upgrade
required before Coverage review queries/writes. The recorded target has already cut over. Do
not change schema merely to hide the `primary` label.
Unsupported schemas are not automatically upgraded or overwritten. Rebuild
unpublished preview fixtures from preserved inputs in a new isolated destination.

Switch/mutation, runtime phase/session and checkpoint locks share
`open_target_lock_file`. It traverses state/key/locks through directory FDs with
O_NOFOLLOW; new target/locks directories use 0700, existing directory modes stay
unchanged. The basename-only leaf is opened nonblocking without following links,
checked as a regular single-link file, then fchmod'ed through its FD to 0600 for
writes. No path chmod, implicit DB/fence or process umask changes. Existing lock
inodes, migration coordination, lock order, reentrancy and FD inheritance remain.

Primary stores require a matching private `state/<key>/legacy-frozen.json` fence:
`schema_version=1`, canonical `target`, 32-character lowercase-hex `store_id` and
64-character `source_manifest_sha256`. Fresh empty stores use the digest of `[]`.
The fence is exclusively created and fsynced before the database schema commits;
initialization failure retains it for explicit recovery. Missing DB + fence,
primary + absent/mismatched fence, preview + fence, malformed/non-private/non-regular
fence or symlink traversal all fail closed. Only no DB + no fence + no published
receipt may be unclaimed during migration; final normal runtime still requires
explicit initialization rather than defaulting to legacy.
All runtime entries preserve the same role/fence/receipt check. Store mutation
uses the shared `target-switch.lock` before its target mutation lock/transaction;
cutover takes the switch lock exclusively. This coordinates cooperating code,
not unmodified external writers. Legacy domain writers have been retired;
Queue add/claim/resolve/list are thin Store adapters and create no old JSON queue.
Primary completion still requires a claim-bound operation, artifact,
or domain-command receipt.
The adapter stores descriptive producer fields in bounded action metadata, not
another lifecycle. Old add receipts replay their original content without silent
backfill; unrelated open metadata cannot override domain status/identity or break
all queue reads. Material-review actions bind exclusively published content-addressed
JSON snapshots, so overwriting a producer's latest summary does not change older
work. Registration failures retain the snapshot. OAST process/callback updates use
action-linked handoffs even after an action terminates, without reopening it.
Finding admission binds the actual destination directory owner. Explicit target
overrides must match it; custom paths remain within its non-symlinked directory.
`load_finding_index` reads Store only; explicit historical readers/importers
are the sole consumers of old Finding/Ledger formats.

Runner request execution, native evidence registration and sync take the shared
switch lock before backend admission or generated artifacts. Preview/fenced/broken
stores reject rather than fall through to legacy. Published summaries carry
`backend_binding={target, backend, store_id}`; primary registration requires this
binding and rejects a different backend or Store generation. The CLI holds the
shared lock through execution and registration, without a database transaction
across network I/O. Registration failure preserves raw material for retry.
Both Runner lanes accept `action_id`, `claim_token`, and `command_actor`
(`--action-id`, `--claim-token`, `--actor`). Binding is explicit, paired, and
matches an execution Action's endpoint/family; `start_attempt` enforces the
current claim/operator before requests or material publication. Summary and
registration retries retain that operator separately from observation actors.
Old unbound summaries keep their identity shape. A request execution refuses a
replayed start receipt; native registration may replay an existing attempt even
after explicit completion. Native timestamps retain fractional seconds.

Scaffold, preflight and apply use `load_finding_prefill(..., target=target)` for
the same owner and root. Store preflight does not read legacy Finding/report
ownership. Validation atomically publishes AI report bytes, commits independent
judgments and registers eligible artifacts. Same-decision retry keeps the bytes;
the report generator consumes that report and rebuilds indexes under the input
Store root, never the tool checkout's global output directory. `test_primary_native_claim_cli_through_validation_report_and_resume`
exercises these actual CLIs in fresh processes with no legacy owners, including
registration retry, explicit completion, and Checkpoint/Resume without revision
changes. This is an engineering fixture, not online capability evidence.
Pack, Checkpoint and Resume carry `source_queries` through JSON and default
text: the Surface index's count/revision/complete first-page command and the
Coverage gap total/order/full-query command. Evidence anchors are labelled as
previews, not index pages; no cursor may skip an unseen first page. Reuse the
source's root-bound command and retain external relation URLs. The pickup
regression exercises all three CLIs on empty and multi-page input and checks
exact sets, unchanged Store revision, and raw bytes.

Store Validate binds commands to the original decision JSON, Store identity,
and selected operation's linked observation references. Apply timestamps and
new unrelated Finding evidence cannot change that command. Scaffold captures
`store_preconditions={assessment_id, delivery_id}` (null for a first decision);
preflight and apply accept those predecessors or the same already-applied
commands, never silently replace them with the current judgments. Summary
`machine_decision.store_command` retains the IDs/preconditions for partial
registration retries; old primary summaries without it require a fresh
scaffold. Failed delivery can retry the already-committed assessment receipt
without superseding it or invalidating reports. Stale authored decisions reject
before generated files. Store remains the only mutation/receipt authority.

Primary preflight verifies complete operations, exact Finding linkage and an
observed endpoint/method match (not just the first step), plus current artifact
integrity. Technical judgment uses Gates 1–3 and Q1/Q2/Q3/Q4/Q6; Gate 4, Q5 and Q7
only constrain destination eligibility. Explicit duplicate/known/excluded input
is ineligible, unresolved report gates are deferred, and eligible still requires
complete report material. The summary's `delivery_judgment` supplies that
separate decision and reason; it cannot turn a missing technical gate into a
confirmation. Tests exercise both interrupted judgment steps, time-independent
replay, explicit predecessor updates, changed/tampered/foreign/partial inputs,
selected-operation-only evidence and report suppression for ineligible/deferred
findings.
`allow_preview=True` asserts an isolated import; it is not a filesystem sandbox
or permission to migrate a live target.

Explicit creation validates target and scope/auth prerequisites before execution
side effects. `hunt_target()` reuses the creation primitive for each actual
target, never list parsing; legacy refusal propagates without matching exception
text. Ordinary domain APIs require initialized state; queries, checkpoint,
resume, help and dry-run never initialize. Raw-only inspection/production is not
automatically reclassified as a domain creation operation.

The entire initialization check/create/fence/schema publication interval is
serialized through the existing target lock discipline. Concurrent successful
callers observe one complete store_id; active retries preserve revision and
facts. An outer held lock must not be reacquired incompatibly on a new file
descriptor or upgraded from SH to EX. Exclusive file creation alone does not
serialize backend inspection. A failure after publishing a fence is a recovery
state, not permission to delete the fence or retry on legacy.

Explicit tables own actions (with bounded metadata detail), attempts, operations, observations, artifact bindings,
and append-only artifact availability/provenance events,
action completion references, findings/observation links, technical assessments, destination decisions,
conditional experience, Case entities/relations, report artifacts and audit. No universal JSON payload table or ORM.

Artifact rows are immutable byte identities. `record_artifact_event()` appends a
typed `availability` (`available|unavailable`) or `provenance`
(`trusted|revoked`) fact; current availability and authorization are derived from
the latest event plus an explicit fresh byte/hash validation. This source-
acquisition step captures the checked digest, health result and one `as_of` value
for the ensuing projection; projection code does not read the live filesystem or
clock. Invalidated or revoked artifacts remain queryable history and never
become an absent record.

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
path is required for current reads. Raw-material indexes may be refreshed by
explicit commands; this never revives legacy domain owners. SQLite WAL/SHM auxiliary
bookkeeping is not a domain mutation. Pages return stable ID order, exact total,
remaining, has_more and next_cursor; cursor binds target/store/revision/kind/filter.
Finding/action queries return recorded judgments/proofs. Finding delivery/report
queries explicitly revalidate supporting operation and report artifact bytes
before projection to derive `stale`; the check result/time is part of that
snapshot, so it may differ at one Store revision. Consumers that need the
detailed reason can call `verify_operation`.
Primitives retain conditions/links even without a continuation hint. Negative
experience requires reopening conditions. Secrets remain in private raw files;
this private metadata API is not a redacted public export surface.

Primary Coverage queries rebuild in memory through `read_matrix`; they do not
read or publish matrix/summary caches. Authored reviews come from Store;
legacy saved cells require explicit import and remain historical advice.
Structural N/A defaults are advice, and an unassessed Finding only preserves its endpoint. Current
authorization comes from `current_truth` and `ClosureResolver`. `dead_end`,
`not_applicable` and `blocked_redline` suppress matching actionable gaps without
being renamed `tested_clean`; query/hash/v2 identities cannot close a broader
path/family grid cell. Gap counts use the same iterator as the displayed gaps.
Coverage reads plain `page("findings")` claims, not the full `finding_page()`
authorization projection. Claim endpoints/parameters remain visible without
loading unrelated report/delivery history; observation integrity is still
rechecked through `current_truth`, including when raw bytes change at one revision.
Claim pages are consumed incrementally. Within one rebuild, endpoint lookup uses
an insertion-ordered mapping shared by claims, observations and closure projection,
not repeated scans of the growing endpoint list. Scanner acquisition may append
new endpoints, so rebuild the lookup after `_apply_scanner_pass`; preserve its
advisory cells when observations subsequently refer to the same endpoint.
The mapping is a local index, not a persisted cache or a new authority. Complete
endpoint output, review/parameter merging, order and evidence verification remain
unchanged; full Coverage still has cost proportional to its material and cells.
The primary `source_snapshot` records Store binding, observation/immutable
operation and review identities, evidence health, authorization fingerprint,
discovery inputs, and one explicit `as_of`. If the caller omits `as_of`,
the acquisition boundary captures it exactly once and records it in the snapshot;
downstream projection code never reads the clock. Immutable operations bind the
registered artifact digests; current truth explicitly revalidates bytes and
records that result as an input. Input drift fails visibly. This is not a
filesystem transaction or historical-time query.

Primary Context Pack does not trust caller-provided Surface/Coverage/runner/truth
shortcuts: it reacquires current owners and explicitly revalidates artifacts
before building a snapshot, even at the same Store revision. The captured
results and `as_of` are bound inputs to the projection. Only private assembly
within one Checkpoint call can reuse its acquired owner inputs. Checkpoint compares its
Store binding across the complete assembly and publishes no witness/cache in its
primary read path. Primary round settlement skips legacy root-claim/Queue
compensation and implicit Surface refresh; its only settlement mutation is the
explicit runtime round closure. Replay is read-only.

Explicit Surface review holds the shared switch lock across index, context,
manifest, ranking and publication. Store inputs are captured before context reading and retain drift checks;
normal refresh does not synchronize historical owner sidecars.
Primary reports use stable target/Finding/assessment/delivery-bound identities,
never rewrite registered bodies, and rebuild INDEX/SUMMARY from current Store
reports, including the empty set. The index includes `source_binding` and `as_of`;
publication checks the binding under the target mutation lock after registration.
Preview reports reject before output creation. Artifact/index publication failure
remains retryable and never creates an external delivery event or closes an action.

### Memory Consumer Contract

#### 1. Scope / Trigger

Applies to target-memory/remember commands, Experience queries, Context Pack,
Checkpoint/Resume, legacy memory import and knowledge distillation. These are
adapters of the existing domain core, not another MemoryStore or Agent runtime.
Daily commands and recovery consumers use the Store-only path. C4/C5 retirement
and measurement evidence is recorded in the active task; online capability
comparison remains a separate acceptance requirement.

#### 2. Signatures

Reuse existing `TargetStore.remember(...)`, `experience(id)`, Case/Action APIs
and `load_goal_memory(repo_root, target)`. The additions are limited to the
existing Experience model and Store singleton row. The schema/API additions
exist since v9 and are consumed by the current command/query adapters:

- `load_goal_memory(repo_root, target, experience_limit=20)` returns the
  primary `source.experience_window.recall_command` alongside its counts and
  cursor. Pack and Resume explicitly request five; `show` retains twenty.
  The command is `python3 tools/experience_recall.py --repo-root ABSOLUTE_ROOT
  --target TARGET --limit LIMIT`, shell-quoted for execution from the checkout.
  It uses `TargetStore.memory_context(limit=20)`: goal, current Case premise
  and the experience page share one read transaction. The premise retains
  the existing stable Case ID order; it is not an automatically chosen action.
  This advisory view does not load full Case actors/sessions/objects or claim
  readiness; the separate Case query retains private-material checks.
  `case_context()` still returns complete Case context in one read transaction,
  with batch reads for hypothesis actor/object links. SQL statement count must
  not grow by two for each hypothesis; private-material validation and stable
  ID/actor order remain unchanged.
  Default Case summary and seed consumers use `case_summary()` and
  `case_object_refs()` so increasing hypothesis history does not increase Python
  row materialization there; the SQL count still visits matching records.

- Advisory `kind="note"` in the existing `experiences` table is for explicitly
  saved human notes that must not be mislabeled as a primitive or hypothesis.
  Do not add a general note key or overwrite semantics.
- `active_goal` belongs to the existing `store` singleton row and
  `set_active_goal(command_id, goal, actor, expected_revision=None)` as an
  audited update. This is the one target-level mutable intent; it does not own
  scope/auth, runtime phase, action status or arbitrary keyed facts. Do not add
  a separate `target_context` table.
  When revision is omitted, the owner uses an existing command receipt's
  revision minus one for replay, or captures the current revision for a new
  command. The same CAS/content/actor checks still apply. A replay after a
  newer goal returns the old receipt without overwriting the newer intent.
- `TargetStore.experience_page(kinds=None, query="", limit=20, cursor=None)`
  extends the existing experience paging logic; no separate query framework.
  `experience(id)` remains full expansion, including existing evidence and
  domain links even when a row leaves the default working set.
- `build_recall_view(repo_root, *, target, query="", kinds=None, limit=20,
  cursor=None)` uses this page. The cursor is for target experience only;
  other sources have independently labeled windows/expansion, not a synthetic
  cursor across unrelated stores. Historical PatternDB input is explicitly
  imported into this target experience source; it is not a second current writer.
- Existing `target_memory.py` subcommands are thin domain adapters with
  explicit target/root and JSON output support. The recall CLI exposes
  `--limit`, `--cursor` and `--id` expansion in addition to target/query/kind.
  Write commands expose the conditions/reopening/evidence required by their
  domain kind; they reject incomplete new negative/primitive input rather than
  constructing an observation or accepting prose as evidence.
  The implemented signature is `target_memory.py --repo-root ROOT --json
  COMMAND ...`; both flags also work after the subcommand. Root selection is
  passed through helpers, never installed by mutating module globals. Primary
  writes return `{target, receipt}`; selection also returns `selection_status`
  and a null receipt when no goal mutation was requested. JSON `show` returns
  the same `load_goal_memory` projection used by text output.
- `build_checkpoint(...)` carries `context_pack.active_goal` and
  `context_pack.target_experiences` from the primary Context Pack;
  `format_target_experiences(experiences) -> list[str]` is shared by Pack and
  Checkpoint text output. It performs no source I/O.
- Read-only CLI expansion uses `target_store.py findings --repo-root ROOT
  --target TARGET [--limit 10] [--cursor CURSOR | --id FINDING_ID]` and
  `target_store.py case --repo-root ROOT --target TARGET`. They return the
  existing `finding_page`/`finding`/`case_state` JSON, not another query model;
  uninitialized/preview/damaged targets fail without creation or fallback.
  Distillation exposes these plus recall commands in its windows, with an
  absolute shell-quoted root, exact remainder and the original revision cursor.
  ID and full Case expansion are fresh reads; Case never returns raw private
  session material. Finding technical/delivery fields keep their owner semantics.

#### 3. Request / Response / Storage Contracts

- Target goal uses the `store.active_goal` field; note/fact/scope notes use the
  advisory `note` kind; lead uses hypothesis; next/handoff uses handoff;
  dead-end and pattern use negative/primitive when their required evidence
  exists. A legacy `fact` name does not confer technical authority. Retired
  mode/phase write flags identify the actual runtime owner rather than
  silently storing copies.
- `target_memory.py set TARGET` selects an already initialized target and
  publishes only target-selection metadata to the global pointer. It does not
  mutate `active_goal`; only an explicitly supplied `--goal` updates that
  Store field. Retired mode/phase/hypothesis/skill/knowledge flags are routed
  to their actual owner or rejected. If the Store update commits but pointer
  publication fails, return the Store receipt and selection error separately.
- CLI help must describe accepted Store writes, not advertise retired flags.
  Parser failures retain JSON `{error}` / exit 2 and include usage plus the
  relevant `--help` entry. `set TARGET` takes a positional target; note and
  other append commands accept `--target TARGET`. A rejected `dead-end` explains
  `--conditions`, `--reopen-when` and `--operation-ref OPERATION_ID:STEP` together;
  STEP is zero-based and must reference an existing execution observation.
  A raw path is not a substitute. Without registered evidence, explicitly save
  `note --target TARGET 'Unverified observation'`; do not auto-convert the failed
  negative or register observations implicitly. Rejection leaves the Store
  revision and selection pointer unchanged. The real-process regression is
  `test_memory_cli_explains_failed_negative_and_recovers_as_advisory_note` in
  `tests/test_target_memory_cli.py`, alongside successful evidence-backed writes.
- Each returned experience preserves `id`, `kind`, `statement`, `conditions`,
  `reopen_when`, `next_intent`, `created_at`, `recorded_by`, `evidence` and
  existing action/finding relations. Evidence uses `{operation_id, step}`.
  New operator entries expose their author and command receipt. Imported
  entries preserve source identity in the bounded, durable import manifest
  keyed by Experience ID; it must resolve to the original stable ID/location.
  If the existing manifest is only file-level, extend that same manifest with
  the minimum ID/location mapping. Do not copy source bodies or create a
  per-entry Store table.
- New negative/primitive require operation references; notes/hypotheses/
  handoffs may lack them. Missing note conditions render as unknown; negative
  conditions and reopening criteria must not be empty. No next intent is valid
  for a primitive and does not exclude it from recall.
- Same command/content is idempotent; changed content conflicts. A correction
  is a new Experience ID and may cite the earlier ID; both remain queryable.
  No keyed-note current pointer or `supersedes` chain is required. Different
  conditions/attempts are not merged by text or URL similarity.
- Experience pages use `order="created_at_desc,id_desc"` and preserve target,
  store_id, revision, normalized kinds/query binding, items,
  total, remaining, has_more and next_cursor. Filter before limiting. Coarse
  query matching is advisory and documented; unfiltered paging and ID expansion
  remain available. The existing generic `page()` retains its explicit ID order.
- Consumers choose the display limit before querying, then retain the whole
  returned page. Do not slice its entries again while keeping the original
  `remaining`/cursor: that hides rows and makes continuation skip them. Build
  continuation/ID commands from the shared root/target/limit-bound command;
  append shell-quoted cursor or ID arguments, not unbound target-only commands.
- Aggregate sources expose `status`, window counts and expansion separately;
  unknown counts are null with a reason, never zero. Required Store failure is
  an error; optional knowledge-source failure is visibly unavailable and must
  not trigger a directory-glob bypass of registry admission.
- Text and JSON render the same object, including all decision conditions and
  refs. Any excerpt is marked with a usable full-expansion reference. A raw
  `.sqlite3` pathname is not the only expansion instruction. List queries load
  bounded rows and batch links; raw bodies are read on demand. No N+1 expansion
  of the entire history merely to print one page.
- Primary Checkpoint preserves the Pack's five-entry window, `total`,
  `remaining`, `has_more`, `next_cursor`, `next_command` and `expand_command`.
  Commands retain the actual `--repo-root` and target; checkpoint `--note`
  remains invocation intent, not a replacement for the saved active goal.
  These fields belong only to the disposable output, not the runtime witness,
  session state or an automatic handoff write. Legacy output stays unchanged.
- Primary Checkpoint's `next_action_queue` displays five stored nonterminal
  actions in ID order, including blocked work. `action_queue_window` binds
  the Store identity/revision and reports total/returned/remaining plus the
  shell-quoted `action_queue.py --repo-root ROOT list --target TARGET --json`
  expansion. This is a fresh full query, including terminal history, not a
  cursor promising an old snapshot. It retains the owner metadata/command hints.
  The primary path does not generate, rank or automatically persist proposals;
  an explicit claim alone fills the current-action compatibility pointer,
  even when its ID is outside the display window. Resume preserves the window
  and does not promote its first queued/blocked item to selected work. Runtime
  wait locks still control execution, without hiding the stored pending rows.
- Legacy import separates proven experience from historical advice; preserve
  unsupported statements as note/hypothesis/handoff with source role and an
  explicit unverified label. Stable entry/source identity stays in the import
  manifest and command receipt, not a parallel provenance table. Corruption,
  foreign identity and ambiguous mappings go to inspectable disposition, not
  invisible loss or invented evidence. For an active Store, supplemental import
  binds the source manifest, is idempotent, and never overwrites post-cutover
  facts/re-promotes.
- Schema changes are limited to the `active_goal` column and advisory `note`
  kind; a source-reference field requires a C0 consumer that the manifest and
  receipt cannot satisfy. Use explicit versioning and isolated backup/upgrade
  verification, and never auto-upgrade on query/init. Global active-target
  selection remains separate: a pointer
  publication failure reports the committed Store receipt and failed selection,
  not fictional cross-file atomicity. No new env flag restores legacy runtime.

#### 4. Validation & Error Matrix

| Input / failure | Required result |
|---|---|
| Initialized Store has 7 hypotheses; show/recall limit is 5 | Same source; 5 visible plus remaining=2 and executable expansion |
| New negative has no observation/conditions/reopen criteria | Reject before commit; no invented proof or successful note substitution |
| Valid old note has no operation binding | Import as labeled advice with source; do not declare it verified or discard it |
| Stored primitive has no next_intent | Still queryable; no automatic Action |
| Text rendering receives Store conditions/reopen_when/next_intent | Show those fields, not only old next/stop_condition aliases |
| Source optional registry fails | Explicit unavailable result, not successful zero cards or unregistered fallback |
| Cursor changes target/store/revision/kinds/query/order/filter | Conflict; restart query, never silently skip rows |
| Imported Experience is opened after its source moves to archive | Experience ID resolves through the durable manifest to the original stable ID/location; no archive-wide scan |
| Store schema upgrade is interrupted or validation fails | Old Store remains usable or admission fails closed with verified-backup recovery; ordinary query/init never upgrades. Existing real targets require separate data-change authorization |
| Correction records a newer interpretation | Append a distinct Experience; preserve and expose both entries |
| Evidence/source bytes later disappear | Historical entry stays visible with health failure; no current authorization |
| Supplemental import is replayed / source changes under same identity | Idempotent / conflict or explicit revised mapping; no overwrite |
| Distillation receives a Finding | Preserve claim/family/endpoint/assessment and separate delivery; no blank-success alias mismatch |
| Checkpoint repeats or working projection is deleted | No echo/implicit write; reconstruction uses current owner facts |
| Primary Checkpoint has zero / seven saved experiences | Text and JSON show zero / five with two remaining; no fabricated next page for zero; saved goal remains visible |
| Resume has seven / twenty-three experiences | Five visible, two / eighteen remaining; CLI continuation visits every remaining ID exactly once, including rows beyond the old twenty-entry window |
| Memory JSON CLI has invalid argv, empty content or retired flags | Structured `error`, exit 2, no successful mutation |
| Goal committed but active pointer publication failed | JSON includes `target`, `receipt`, `selection_status=failed`; retry the original command/content/revision without a new mutation |
| A writer commits while memory context is assembled | Goal, premise, experience rows and revision all remain on the original read snapshot |
| Primary Checkpoint has 12 ready actions | Five original IDs plus remaining=7 and executable full expansion; no synthetic A1 or type-priority filtering |
| A claimed action lies beyond the window / another is blocked | Claimed ID remains current work; blocked row and reason remain visible, cancelled rows stay historical |
| Distillation clips Finding/Experience or Case context | Exact window remainder and executable continuation/ID/full-Case commands retain root/target; a stale Finding cursor fails with exit 2 |

#### 5. Good / Base / Bad Cases

- Good: an operator records a scoped hypothesis, a new process recalls its
  conditions and original ID, then expands the referenced evidence as needed.
- Base: an old failed attempt lacks actor conditions; preserve it as historical
  unverified advice with its original role, not a universal negative result.
- Bad: show reads legacy JSON while writes use Store; slicing 7 to 5 reports no
  truncation; a default text renderer discards structured reopening conditions.

#### 6. Tests Required

PRD M1-M8 is the acceptance matrix. Extend existing target-memory, recall,
resume/checkpoint, distillation, Store and migration tests; cover real CLI/API
and new-process recovery, not only mocked adapters. Assert field equality in
JSON/default text, the 7/5/2 boundary, hint-free primitive recall, stable source
manifest mapping, idempotent command/import replay, source isolation and zero
implicit actions. Repeat three checkpoint/handoff rounds without projection echo and
delete only rebuildable fixture projections before restart. Test schema upgrade
failure/recovery and loss of fenced DB. Measure query/connection counts, output
size and recovery time without dropping integrity checks or accessible history.
Knowledge review/registry gates keep their existing focused regressions.
`test_primary_checkpoint_cli_preserves_goal_and_conditional_memory` runs fresh
Checkpoint processes for text/JSON with corrupt legacy memory. It checks the
saved goal, conditional negative evidence, exact IDs returned by continuation
and expansion commands (including a root containing spaces), unchanged Store
binding and absence of implicit Queue/witness writes.
`test_primary_resume_memory_window_is_complete_and_root_bound` covers empty,
7-entry and 23-entry Stores, actual text-emitted expansion/continuation commands,
per-page remainder, conditional negative evidence and unchanged Store binding.
The `show` regression executes its emitted continuation and ID template as well;
the original three-round pickup and Pack/Checkpoint regressions remain applicable.
`tests/test_target_memory_cli.py` exercises all daily commands in fresh processes,
root paths containing spaces, active-pointer isolation, stable receipt IDs with
`replayed=true`, invalid input and pointer-publication failure after commit.
`tests/test_decision_scaffold.py` checks that primary scaffold `vuln_class`
equals the canonical Finding `family` (including open/custom families); legacy
`type` remains readable and judgment fields stay empty.
`test_target_memory_reads_one_bounded_snapshot_without_loading_full_case` rejects
full Case expansion for a five-item display. `test_memory_context_uses_one_snapshot_during_concurrent_write`
commits a new goal/note between reads and checks that the returned snapshot
remains internally consistent. The task-local memory query benchmark counts
connections, SQL statements and Python-materialized SQLite rows; it does not
claim to measure internal SQLite scan rows or complete recovery cost.
`test_primary_checkpoint_restores_pending_actions_without_generated_routes`
rejects the old proposal generator, checks exact stored IDs/metadata, executes
the full expansion, and verifies claim/blocked/cancelled behavior through
Checkpoint and Resume without owner writes.
`test_primary_distill_cli_emits_executable_root_bound_expansions` runs real
processes for the default distillation output, both continuation commands,
Finding/Experience ID expansion and full Case. It checks exact tail IDs,
conditions/author, unchanged revision, stale-cursor rejection and zero creation
for queries against an uninitialized root.

#### 7. Wrong vs Correct

Wrong: archive every legacy note because it lacks an operation; relax the
negative evidence gate so it imports; add a second memory database to recover it.
Correct: preserve sourced advisory notes in the same domain model, retain
stronger proof requirements for negative/primitive, and expose history explicitly.

Wrong: map Store fields into a legacy template independently in each consumer,
or let a checkpoint projection become the next round's source fact.
Correct: shared page/expansion values feed all renderers; source identity and
explicit owner writes prevent echoes. Default context is disposable, facts are not.

Wrong: query twenty, display five, then reuse the twenty-row cursor.
Correct: request five at the shared loader and display that complete page;
continuation uses its cursor and original root binding.

### Migration Quarantine Disposition Contract

**Scope / Trigger**: Any attempt to turn a staged migration with quarantined
legacy rows into a publishable preview.

**Contracts**:

- Quarantine identity is a bounded hash of owner, reason, path, event/id,
  endpoint, evidence reference, line, status, family, result, declared/expected
  target. Report position is not part of it: reordering the report does not
  change the identity, and changing a fact does. Rows that agree on every
  bounded field are told apart by occurrence count inside that group.
- The ledger may carry `quarantine_roster_sha256`, a digest over the complete
  identity set of the source report. When present it must match the input, so a
  decision table generated for one report cannot be re-bound to another.
  Bare payloads without it remain usable only at the caller's own risk.
- A payload declaring `kind: target_cutover_quarantine_disposition_ledger` must
  also carry a finalized `status` (a placeholder such as `pending` is refused)
  and a `count` equal to its `items` length.
- `decision` is limited to `preserve_verdict`, `permanent_quarantine`,
  `rebind_after_export_verification`, or `operator_review`. All decisions
  require a non-placeholder operator and decision reference. Only
  `preserve_verdict` and `permanent_quarantine` are terminal: they close the
  item and may clear the publish gate. `rebind_after_export_verification` and
  `operator_review` are recorded as `recorded_decision` on a still-quarantined
  row and keep the report `partial`; they assert that work remains.
- The ledger must contain every quarantine ID exactly once. Missing or unknown
  IDs keep the report `partial`; no decision can create an assessment,
  completion, delivery, or observation.
- Preserved report artifacts stay artifacts. They are copied and digest-listed
  but never auto-registered; staged receipts record them under
  `unregistered_artifacts` so the preserved-but-unregistered fact survives the
  run instead of living only in the in-memory report.

**Validation & Error Matrix**:

| Condition | Required result |
|---|---|
| Ledger target, source manifest, or declared roster differs | `StoreError` before any staging import |
| Missing/duplicate/unknown quarantine ID | `StoreError`, or `partial` when rows are omitted; never publish |
| `PENDING`, placeholder operator/reference, or unsupported decision | `StoreError`; never publish |
| `status` is a placeholder, or `count` disagrees with `items` | `StoreError`; never publish |
| All decisions terminal, complete and fact-preserving | report/receipt may become `ready`/`complete` and proceed to explicit publish |
| Any decision non-terminal (`operator_review`, `rebind_after_export_verification`) | row stays quarantined, report stays `partial`; never publish |
| No ledger supplied while quarantine exists | report remains `partial`; legacy verdicts stay quarantined |

**Good/Base/Bad Cases**:

- Good: every terminal queue verdict is explicitly preserved or permanently
  quarantined with an operator and audit reference.
- Base: preview without a ledger reports all quarantine rows and remains
  publish-blocked.
- Bad: treating a count, endpoint similarity, or `PENDING` row as a decision.
- Bad: recording `operator_review` and reading the run as approved, or reusing a
  decision table generated against a different manifest or roster.

**Tests Required**:

- `tests/test_target_migration.py` asserts complete terminal disposition clears
  only quarantine and produces a complete receipt; missing rows, pending
  decisions, target/manifest/roster mismatch, placeholder references, mismatched
  governance metadata, and non-terminal decisions all fail closed.
- Identity is asserted to be order-independent, and a changed fact is asserted
  to change the roster digest.
- Binding and governance checks fail before the destination Store is created;
  item-level decisions are validated after the staged import, whose failed
  staging root is retained for diagnosis and never published.

**Wrong vs Correct**:

```python
# Wrong: aggregate approval or endpoint similarity authorizes a terminal row.
ledger = {"items": [{"decision": "PENDING"}]}

# Wrong: `operator_review` recorded as if it closed the item.
ledger = {"status": "complete", "items": [{
    "quarantine_id": ID, "decision": "operator_review",
    "operator": "OWNER", "decision_ref": "AUDIT_REF",
}]}  # accepted, but the row stays quarantined and the gate stays shut

# Correct: exact quarantine identity plus an auditable, bounded, terminal decision.
item = {
    "quarantine_id": QUARANTINE_ID,
    "decision": "preserve_verdict",
    "operator": "OWNER",
    "decision_ref": "AUDIT_REF",
}
```

### Legacy Reference and Migration Input Contract

**Scope / Trigger**: Importing a target whose legacy writers recorded an
absolute `evidence_ref`, a path-form Case endpoint, a pre-contract private
material file, or a runtime lock inside a target-owned root.

**Contracts**:

- An absolute `evidence_ref` is rebased only when it provably resolves under the
  declared migration source root and the resulting relative path has readable
  material inside the copy. `import_target_staged` passes its export root as
  `source_root`; the importer never infers a source root from the references it
  is validating. Every rebase is recorded under
  `legacy.rebased_references` with the original value, the rewritten value, and
  a `source-root:<digest>` marker. A reference outside the declared root, or one
  whose rebased path has no material in the copy, stays quarantined.
- A path-form Case object endpoint is resolved against the single origin
  observed in the target's own raw material, exactly like a ledger endpoint.
  With no single provable origin the object is quarantined; no scheme or host is
  invented.
- Private material written before the current contract declares neither `target`
  nor `content_sha256`, so the Store cannot verify it. Migration never rewrites
  private material: the Case record is imported without the binding and the
  omission is listed under `legacy.private_bindings_dropped` with the legacy
  reference. This preserves the fact without weakening the Store's private
  material check.
- The manifest and the copy step share one predicate for what a migration input
  is. Runtime locks (any path segment `locks`/`.locks`) and store/fence/receipt
  files are excluded from both. A file the manifest hashes but the copy omits
  makes promotion report a vanished input, so the two sets must be defined once.
- A completed activation is identified by its own durable markers: the SQLite
  role commit, the fence, and a receipt whose `activation_status` is `active`,
  all naming the same store and manifest. `promote_target` re-entered on such a
  target returns the idempotent `recovered` result without reading archive
  bytes, so cleaning up historical archive material after a cutover is not
  treated as damage. The archive stays the recovery input for an *interrupted*
  activation, where it is still required and verified byte for byte.

**Validation & Error Matrix**:

| Condition | Required result |
|---|---|
| Absolute reference outside the declared source root | Quarantine; no rebase recorded |
| Rebased path has no material in the copy | Quarantine; no rebase recorded |
| Path-form Case endpoint with no single observed origin | Quarantine the object; no invented host |
| Pre-contract private material (no target/digest) | Import the record without the binding; list it under `private_bindings_dropped`; never rewrite the file |
| Runtime lock under a target-owned root | Excluded from manifest and copy alike |
| Manifest and copy disagree on a path | Promotion must fail; fix the predicate, never the manifest alone |

**Tests Required**:

- `tests/test_target_migration.py` covers: an absolute reference rebased onto the
  copy with the notice recorded; a rebased path with no material staying
  quarantined; an absolute reference outside the declared root staying rejected;
  a path-form Case object endpoint resolved through the observed origin; the
  same endpoint without an origin staying quarantined; a pre-contract private
  session importing without the binding while the file is left byte-identical;
  manifest/copy agreement on runtime locks verified through a promote; promote
  staying idempotent after the archive is removed once activation is `active`;
  and an interrupted activation still refusing to recover without its archive.

**Wrong vs Correct**:

```python
# Wrong: accept an absolute reference by prefix-stripping whatever it starts with.
ref = ref.replace("/root/", "")          # guesses; may leave the copy entirely

# Correct: prove the source root, then require the material to exist in the copy.
rebased, reason = _rebase_source_absolute_ref(source_root, copy_root, ref)

# Wrong: rewrite a pre-contract private file so the Store check passes.
payload["target"] = canonical            # mutates user private material and its digest

# Correct: import the fact, drop the unverifiable binding, report the omission.
private_ref, reason = _carryable_private_ref(root, private_ref, canonical)
```

## 4. Validation & Error Matrix

Runner candidate discovery reads `validation/**/summary.json` and the current
Store. Only a refuted assessment or a currently valid report can retire its
explicitly assessed attempt/material from the review pool. Verify the referenced
operations and match both attempt ID and artifact refs. A new attempt, new
material or a summary without explicit matching refs stays visible, even at
the same URL. Do not infer review from legacy Finding/Ledger files, URL, lane
or category. A Store binding change during the query raises `ConflictError`.

Disclosure search preserves report order and source coverage; similar titles
or categories are not duplicate evidence. Its target-bound recall command uses
`experience_recall.py`, never cross-target PatternDB matching. `--no-mcp`
does not load/search a client or inspect target technology through that client.
Knowledge evaluation discovers direct target directories from Store/fence
files, reads only a bounded regular non-symlink fence as a target hint, then
uses complete `runtime_store` admission and checks the directory identity.
Malformed, missing, symlink/FIFO or damaged state fails explicitly; it is not
a zero-signal result that can support retiring a knowledge card.

Profile and PatternDB writers are retired. `memory.target_profile` and
`memory.pattern_db.PatternDB` support explicit historical inspection only;
constructing the latter does not create directories. Legacy test input is built
through `tests/legacy_fixtures.py`, not a production writer restored for tests.

| Input/failure | Required behavior |
|---|---|
| Missing/corrupt/foreign/schema-mismatched DB | StoreError; never empty history |
| Missing Finding ID / other Store fault | FindingNotFoundError / original Store error; only absence permits create |
| Artifact event commits during a Finding read | Keep one original metadata snapshot; next query observes the event |
| Report/raw bytes change without a Store revision change | Recheck; stale authorization, never an empty Finding |
| Same URL with a new Runner attempt or new raw material | Keep the independent review candidate |
| Knowledge discovery fence is symlink/FIFO | Refuse without following it or blocking |
| Fresh target via explicit init / active target via repeated init | Create one private Store+fence / same store_id and unchanged revision |
| First switch/phase/session/checkpoint lock, umask 022 or 077 | Target directory 0700; no DB/fence; later explicit init succeeds |
| Preexisting target directory 0755 | Preserve mode; ordinary explicit init rejects without DB/fence creation |
| Lock path contains a symlink, hardlinked leaf or nonregular leaf | Reject before changing external bytes/mode; FIFO does not block |
| Read-only phase lock probe: missing / unsafe path | False / None; no creation or chmod |
| Concurrent init calls | One complete Store; no half-schema read, conflicting flock reacquisition or duplicate store_id |
| Fresh or legacy-only target via final ordinary domain API | Explicit not-initialized/import-required error; no Store or legacy owner creation |
| Existing preview via init | Refuse; init is not promote |
| Published migration receipt but missing DB | Recovery error even if no fence; do not return None |
| hunt receives legacy/preview/damaged target | Reject before execution/artifact side effects, not silent continuation |
| List parsing, query, checkpoint/resume, help or dry-run | No initialization, old owner creation or implicit repair |
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
| Legacy absolute reference outside the declared source root, or with no material in the copy | Quarantine; record a rebase only for a proven, material-backed rewrite |
| Manifest and copy disagree about a migration input | Promotion fails; fix the shared predicate, never one side |
| `promote_target` on a target whose receipt is already `active` | Idempotent success from the durable markers (role, fence, receipt); archive bytes are not required |
| Recovery of an interrupted activation (receipt not yet `active`) | Archive receipt and material are required; missing material is a `StoreError` |

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
- Good: explicit init and start-target orchestration share one primitive; a
  subsequent ordinary Action write changes only Store facts and audit.
- Good: a first resource lock leaves a private uninitialized target directory.
- Good: an existing legacy directory can take a cutover lock without mode repair.
- Bad: silently chmod an existing unsafe directory to make initialization pass.
- Bad: initializing in a domain write because a temporary directory looks new,
  or preserving legacy forever so tests need no explicit Store fixture.
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

Admission regression: initialize a Store, create one action, remove only the DB
inside an isolated fixture, and retain its fence. Direct backend inspection,
`runtime_store`, `load_queue` and `current_cell_projection` must all reject;
neither zero actions nor missing legacy ledger is a valid result. Repeat with a
published receipt, corrupt/foreign fence and preview. Keep this in existing
Store/current-truth/consumer tests, not just a temporary audit script.
Initialization regressions cover fresh/active/legacy/preview/damaged states,
concurrent init, interrupted publication, CLI exit behavior and hunt/list entry
ordering. Store-backed consumer tests initialize explicitly; low-level calls
never gain test-environment detection. After retirement, legacy fixtures test
only explicit import/history and fail if a normal consumer reads/writes them.
`test_lock_before_initialization_creates_private_target_directory` covers the
four independent lock entry points with umask 022/077, canonical keys, mode 0700,
no implicit DB/fence, and later explicit init. Preserve the existing unsafe-dir
refusal, concurrent init, cutover exclusion and child FD inheritance regressions.
`test_target_locks_reject_unsafe_paths_without_external_mutation` covers five
writers and state/target/locks/leaf symlinks, FIFO and hardlinks; external bytes,
modes and inode identities remain unchanged. Also cover legacy cutover mode
preservation, basename rejection, side-effect-free phase probes and checkpoint
nested lock reuse. These tests exercise standard flock, not a new lock manager.
`tests/test_target_case_state.py` verifies constant summary/seed row materialization
with 1001 hypotheses, full default history, entity-only equivalence and private
material failures. `tests/test_runner_candidate_store.py` covers exact assessed
material, independent attempts, raw damage and propagation of non-absence faults.
`tests/test_disclosed_pattern_dedup.py` preserves reports while rejecting retired
PatternDB reads; `tests/test_knowledge_eval_draft.py` covers Store-only/CIDR
discovery and unsafe file rejection in a real process with a timeout.
Resume domain-window regressions use an empty Store and more than five Findings,
tested and untested endpoints; execute the emitted full command under a root
containing spaces and compare every exact ID/endpoint, counts and unchanged
Store binding. Default text must report totals independently of preview length.
`test_operation_verification_checks_all_material_in_one_snapshot` requires one
connection for a multi-artifact operation, unchanged Store binding and rejection
when the final artifact changes. Existing invalidation tests retain unavailable,
revoked and restored-event behavior.
`test_finding_page_batches_relations_and_preserves_complete_paging` checks a
60/61-row window, bounded SQL statements, exact tail IDs and stale-cursor rejection.
Finding authorization regressions cover one read connection, only the selected
assessment's operations, report/raw tampering, concurrent provenance revocation,
and independent judgments/destinations across several claims. Coverage's claims-only
regression refuses full Finding expansion while retaining damaged-evidence suppression.
`test_coverage_merges_complete_claim_pages_reviews_and_observations` crosses the
1000-row claim-page boundary and checks exact endpoint membership, parameter union,
review retention, repeated observations, current closure and zero cache writes.
`test_primary_projection_retains_scanner_advice_for_observed_open_cells` must keep
both scanner-only and subsequently observed endpoints with scanner metadata intact.

## 7. Wrong vs Correct

Wrong: recursively create lock parents then open/chmod by path, assuming mode
0700 protects ancestors or a prior resolve check prevents replacement.
Correct: use `open_target_lock_file(root, target, filename)`; directory FDs and
no-follow opens bind traversal, fstat validates the leaf before FD-based chmod.

Wrong: same response hash -> same execution; unknown category -> discard evidence;
report destination says duplicate -> technically refute; SELECT -> implicit repair.
Correct: explicit attempt identity -> immutable registrations; open family -> optional
Coverage mapping; separate judgments; snapshots and explicit commands.

Wrong: reopen the Store per Finding relation or verify its operation again for
each destination/report; read full reports merely to discover claim endpoints.
Correct: batch this page's relations, acquire authorization on its read snapshot,
and use the existing plain claims page for Coverage. Revalidate on the next query.

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

Wrong: replace `target_backend() == "primary"` with a DB-existence helper and
claim backend convergence; keep every old branch under `store is None`.
Correct: share complete admission checks first, migrate useful consumer behavior,
then remove normal legacy paths and tighten the runtime return contract together.

Wrong: a prior assessment at the same URL hides every later experiment, or a
failed knowledge Store read becomes zero signals. Correct: match the assessed
attempt/material exactly and propagate current-owner faults.


## Coverage author input (schema v10)

### 1. Scope / Trigger

`mark-endpoint-kind` and `mark` are explicit authored inputs. Primary reads,
rebuilds, triage and gaps recover them from `coverage_reviews`, never the saved
matrix. This table owns review input only; ClosureResolver owns technical closure.

### 2. Signatures

- `record_coverage_review(command_id, endpoint, kind, value, actor, family=None,
  reason="", source="manual", reviewed_at="", historical=False, candidate=None)`.
- `coverage_review(id)`; `coverage_review_page(endpoint=None, latest=True,
  limit=50, cursor=None)`; `normalize_coverage_review(...)` is pure validation.
- `python3 tools/coverage_matrix.py reviews --repo-root ROOT --target TARGET
  [--endpoint PATH] [--history] [--limit N] [--cursor CURSOR | --id ID]`.
- Both mark commands accept `--command-id` and `--actor`; stable IDs make retries
  idempotent. Omitted IDs create a new review. `mark` returns `advisory`, `review`
  and `receipt`, not a technical cell status. Optional `--write-finding` records
  an unassessed claim in the same transaction.
- `python3 tools/target_store.py upgrade-schema --repo-root ROOT --target TARGET
  --backup ABSOLUTE_BACKUP` upgrades v8/v9 to v10. `upgrade-memory` retains its
  v8-to-v9 contract and remains idempotent on later versions.
- `target_migration.py --backfill-coverage-source SOURCE --repo-root ROOT
  --target TARGET` imports a pinned cutover source into an active Store.

### 3. Contracts

Reviews have a target-owned path, `endpoint_kind` or `cell_status`, optional
canonical family, typed value, reason, source, author, original review time,
historical flag, optional Finding reference, revision and creation time. Absolute
URL ownership is checked before path projection. No query-specific closure is
inferred from this deliberately path-scoped review.

All changes append, with the same command/audit transaction and content conflict
rules as other Store commands. `latest=True` selects the latest revision for each
path/kind/family, preferring current authorship over imported history regardless
of import time. `latest=False` retains every review. Pages filter before limiting;
exact remainder and cursor bind Store, target, revision, endpoint and latest mode.
`untriaged` explicitly restores triage visibility. Kind/status values do not create
attempts, close cells, complete Actions or grant report eligibility. Gaps include
applicable review input without suppressing untested cells.

Legacy import preserves non-default cells/reasons and authored classification as
historical input; untouched default cells remain in the pinned source. The same
normalizer validates preview/import. `coverage_backfill` in the migration receipt
maps each review ID to file digest and JSON pointer; original unknown author/time
remain explicitly legacy/unknown. A Store projection cannot be reimported as
legacy authorship. A later backfill cannot replace a new review. Committed rows
survive receipt-publication failure and replay without duplicate rows.

### 4. Validation & Error Matrix

| Condition | Result |
|---|---|
| v8/v9 Coverage query/write | Explicit upgrade required; no fallback or implicit DDL |
| Invalid kind/status/source, foreign URL, malformed path | Reject before domain mutation |
| Same command ID and content | Original receipt; revision unchanged |
| Same command ID with changed content | Conflict; original review retained |
| Finding insertion or audit failure | Review and claim both roll back |
| Reused Finding identity | Keep original immutable claim; new review retains new reason |
| Source bytes differ from cutover manifest | Reject before import |
| Malformed/foreign legacy row | Quarantine with source pointer; never fabricate proof |
| Upgrade failure before commit | Old schema/facts remain; verified backup retained |

### 5. Good / Base / Bad Cases

Good: classify a route, delete projections, recover that classification in a new
process. Base: historical N/A reason remains visible beside an untested cell.
Bad: turn a human `tested_clean` mark into an execution observation or closure.

### 6. Tests Required

`tests/test_coverage_reviews.py` covers real CLI restart, projection deletion,
retired-owner interception, full history/pagination, identity/replay conflicts,
atomic Finding creation, genuine v8/v9 upgrades with rollback, manifest-bound
staged import/backfill, receipt interruption and preservation of current reviews.
Adjacent Store/migration/Coverage tests retain existing evidence closure behavior.

### 7. Wrong vs Correct

Wrong: save author input into a disposable matrix, or model it as executed proof.
Correct: append structured review input to Store; rebuild views and derive closure
from the existing evidence owner independently.
