# Transactional Target State

## 1. Scope / Trigger

Read before changing `tools/target_store.py` or domain consumers. Normal
runtime is Store-only; legacy data is available through explicit import,
history inspection and recovery. The task records one authorized cutover on
2026-09-22; code changes do not authorize more real-data operations.
`docs/architecture-contract.md` is the architecture authority. The native-first
engineering task is archived; online capability gains remain unproven and separate
from consumer correctness or this audit's repairs.

Action-bound partial registration also applies when a different-URL control was
published but the declared subject failed before publication. Registration must
preserve that partial execution without claiming that the subject ran.

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

`memory_context()` selects `current_handoff` on the same read snapshot as the
bounded experience page, using `created_at DESC,id DESC` and an independent
handoff-only limit of one. No handoff returns null. The shared memory loader
projects `next_actions` as at most one advisory entry whose text is that current
handoff's explicit `next_intent`; an empty intent never revives an older one.
Historical pages and Queue rows remain unchanged. Handoff accepts repeatable
`--operation-ref OPERATION_ID:STEP` through the existing parser and Store foreign
keys; absent evidence remains valid advice, not an inferred path binding.
Regression checks cover cross-process refs/rejections/replay, tied timestamps,
window eviction, empty intent and a concurrent writer between snapshot queries.

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
Fresh stores use schema v17: advisory `note`, `active_goal`, Coverage reviews,
observation identities, exact `experience_versions`, `experience_sources`,
`experience_links` and append-only `experience_link_events`, plus accepted advisory
claims/source refs. Version-bound supersedes/refutes/depends_on never rewrite old
experience or technical judgments; withdrawals do not revive obsolete conclusions.
Origin is not basis. Source revocation/damage propagates through basis/dependencies.
Text correction scope uses exact retained declarations, not semantic equivalence;
different conditions retain a scoped connection, not global invalidation. Claim condition bindings and explicit
validity windows use the v15 tables described below; reviewed knowledge uses v16
external source attachments. v17 adds exact historical origins, never historical
basis or claim support, using the same external-source owner tables.
Existing stores require explicit backup-bound upgrade; v12/v13/v14/v15/v16 development
stores retain explicit upgrade paths.
Use consumer-level save/restart/recall/recovery evidence, not test counts, for acceptance.

### v15 claim applicability and independent recall context (2026-10-12)

1. **Scope / Trigger.** Experience claims, text index lifecycle, relation constraints and
   exact historical counterevidence. No changes to technical judgment or execution ownership.
2. **Signatures.** `remember(claims=[...])` accepts optional `condition_bindings` and
   `validity`. `experience_claim_conditions(claim_id,role,owner,record_id,version,content_sha256)`
   and `experience_claim_validity(claim_id,valid_from,valid_until)` are append-only claim
   attachments. Fresh creation and explicit upgrade share DDL. `experience_contract`
   owns pure declarations; Store owns existence, byte health, transaction and history.
   `build_text_index(..., shared=False, include_knowledge=True, full_rebuild=False)`;
   `query_recall(..., context_limit=20, context_max_bytes=64000)`;
   `recall_context.context_page(root,target,roots=[{experience_id,version}],cursor=...)`.
3. **Contracts.** A condition role is a comparison key, not an inferred actor. It binds
   one exact same-Store entity; 1..32 bindings when supplied, null/omitted means unknown.
   Both timezone-aware validity endpoints are required, normalized to UTC, with a
   half-open interval and `from < until`. No timestamp infers a validity window.
   Free text remains visible and unverified even when identities agree. C8 rejects
   conflicting bound identities and disjoint windows; all paths remain hypotheses.
   Material/basis/condition changes share existing health propagation and invalidate projections.

   Text build separates `state/<key>/recall-index/text` from `.cache/knowledge-recall/text`.
   `--shared` needs no target and opens no Store; it accepts only reviewed knowledge.
   Target build also updates shared knowledge unless `--no-knowledge`. Identical
   source/model/chunking/ranking data reuses FTS rows/vectors and the published generation;
   `--full-rebuild` deliberately creates fresh generations. Current goal/Scope/revision
   are query snapshot bindings, not reasons to re-encode unchanged experience. Target
   acquisition now follows the incremental contract below; shared knowledge still
   performs a full owner audit. Projection reuse and source-read counts are separate.

   `counterevidence` is a direct, exact-version correction/dependency/basis bundle,
   independent of top-k. Same identity has one item with all references; it never
   establishes independent support. `context --id ID --version VERSION` or its separate
   returned cursor continues it. `expand_command` reads the exact full version;
   `context_command` expands another hop. Root status/health stays outside the item-body
   budget, like current facts. Oversized bodies become explicit omitted-content refs;
   remaining, unavailable or omitted items set `context_incomplete`. Total refers to
   this direct bundle only, not a transitive proof. External-byte and historical-peer
   health is checked again before composite query return, not only Store revision.
   Expansion script paths come from the loaded code directory, while `--repo-root`
   remains the target data root. Do not synthesize `TARGET_ROOT/tools/...`: split-root
   callers need real exact-version, history-source and continuation commands without
   copying executables into target state. Validate by executing returned commands,
   including omitted-body expansion, and checking Store/source bytes remain unchanged.
4. **Validation & Error Matrix.** Foreign/unknown entity, empty or malformed binding,
   invalid interval → reject before commit; exact accepted retry remains idempotent.
   Existing v14 memory access → explicit upgrade hint, no auto migration. Old claims
   gain null declarations on read, never inferred values. Missing/stale text index →
   fresh lexical originals plus explicit partition health; current facts survive.
   Unavailable knowledge → preserve previous shared generation, build reports partial
   or unavailable and CLI exits 2. An explicitly requested missing encoder also
   preserves both previous generations and exits 2; no encoder request permits FTS-only
   construction with semantic unavailable. Corrupt existing generation → no incremental reuse;
   explicit `--full-rebuild` required. Independent partition publication is not a
   cross-partition transaction. Query/status never build or download. Stale context
   cursor → reject/restart; unavailable exact history → retain a diagnostic, not latest.
5. **Good / Base / Bad.** Good: current intent changes without re-encoding history;
   conflicting actor or time windows reject a two-hop join. Base: absent structured
   declarations keep legacy claims advisory/unknown. Bad: use observation time as
   validity, inject a private target into shared cache, or replace old rebuttal with latest.
6. **Required checks.** Synthetic Store→CLI→generation→query; cross-target/shared
   isolation, unchanged build, changed source, partial publication, exact historical
   expansion, cursor byte-health invalidation, two-hop condition/time conflicts, and
   explicit v14 backup/upgrade/retry. Existing older-schema fixtures must remove v15
   attachment tables before presenting an actual v11/v12/v13 layout. No real data or
   model invocation is implied by these engineering checks.
7. **Wrong → Correct.** `counterevidence = ranked[:k]` → source-bound independent page;
   `conditions = label` → exact owner identity plus preserved unverified text;
   `revision changed → re-encode everything` → compare source/model/chunking bindings.

### v16 reviewed sources, shared patterns and post-save updates (2026-10-12)

1. **Scope / Trigger.** Accepting reviewed knowledge as experience origin/basis,
   shared method relation projection and explicitly requested post-commit indexing.
   These do not confirm findings, change delivery or authorize execution.
2. **Signatures.** `TargetStore.knowledge_source(id)` returns
   `{owner: "knowledge", record_id, version, content_sha256}`; `remember.sources`
   adds `purpose=origin|basis`. `experience_external_sources` and
   `experience_claim_external_sources` bind external versions with explicit foreign
   keys. The public CLI is `target_memory.py knowledge-source --target TARGET --id ID`.
   `build_relations(root,target=None,shared=False,full_rebuild=False)` and
   `relation-build/query/status/prune --shared` address only the shared namespace.
   Save/publish CLIs accept `--update-index text|relations|all` and optionally
   `--index-encoder PATH` for text/all; `recall_update` owns their post-save composition.
3. **Contracts.** Knowledge `version` is the publication receipt SHA256, not an
   invented integer revision; `content_sha256` binds whole Markdown. The existing
   publication review remains admission authority. Its optional byte-reader callback
   captures registry/body/receipt/review/blind inputs; publication shared locks plus
   stat checks fence Store acceptance without hashing inside the write transaction.
   Exact retry uses the original command receipt even after later source withdrawal.

   Only reviewed Markdown frontmatter may declare `method_relations`. Each item has
   unique `id`, `subject`, `predicate`, `object`, `conditions`, `rationale`; predicates
   are requires/enables/alternative_to/refutes. Local endpoints are `{anchor}`;
   external objects add exact `method_id/content_sha256`. Empty anchor means the
   entire method. Both endpoints must be active, reviewed and resolvable. Shared
   nodes are `{owner: "knowledge-pattern", method_id, content_sha256, anchor}`;
   they never alias Store entities. Relation v4 retains reusable source shards and
   explicit rejected sources. Shared knowledge capture remains a full owner audit.

   Post-save target updates touch only target indexes; publication updates touch only
   shared indexes, after owner locks/transactions exit. Returned `save_status=saved`,
   `index_update` and `partial` preserve the original receipt in both text and JSON.
4. **Validation & Error Matrix.** Unreviewed/changed/retired knowledge → reject new
   basis, diagnose existing bindings; origin never becomes claim support. Changed
   capture → reject before commit. v15 → explicit verified backup upgrade, no query
   migration. Malformed relation/unknown anchor/wrong peer hash → rejected relation,
   not an accepted edge. Missing shared Store is irrelevant: shared commands never
   open one. Corrupt or old graph → explicit full rebuild, not silent reuse. Invalid
   update options → no owner mutation; unavailable encoder/update failure → exit 2,
   committed receipt retained and index-only recovery. Actual unavailable execution
   sources remain visible partial results, not proof of complete graph coverage.
5. **Good / Base / Bad.** Good: a reviewed method supports an advisory claim and its
   later review withdrawal invalidates that basis. Base: no update option preserves
   the existing save behavior. Bad: treat origin as support, import target identity
   into shared nodes, or rerun publication to repair an index.
6. **Required checks.** Real synthetic publication → shared two-hop/no Store;
   knowledge-source → accepted claim → target query/current/counterevidence;
   origin/basis distinction, review/blind withdrawal, v15 backup/upgrade/retry,
   shared incremental/full equivalence, malformed anchors/hash, bad encoder after
   successful save and text/JSON receipts. The architecture guard permits only the
   lower-level knowledge reader from Store and keeps the new pattern contract pure.
7. **Wrong → Correct.** `version = current Store revision` for knowledge → exact
   publication receipt hash; `index failure → undo save` → retained receipt and
   independent partial; registry relationship metadata → reviewed-body declarations.

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
  expected_operation=None)`: publish files before invocation; outcome is
  `complete`, `partial` or `unknown`, and only `unknown` accepts no observations.
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
  generation remains separate from external submission. Standalone tool-managed
  screenshot references additionally bind their published copies through the full
  content digest in each filename; the immutable body commits those references.
  No new table, attachment relation or command-material field is introduced.
- `record_delivery_event(command_id, event_id, report_id, external_ref,
  submitted_at, actor, receipt_artifact="")`: append an explicit external
  submission fact for the current eligible registered report. It may reference
  a target-owned receipt artifact; generating/registering a report never calls
  this command and never implies an external submission. Report/body/managed-copy
  byte acquisition precedes the write transaction. Immediately before insertion,
  report registration and delivery events compare captured file identities and
  reread the body artifact's availability/provenance events on the write connection;
  no large-file hashing or nested mutation lock is introduced.
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
For managed screenshots, report-level `artifact_available`/`artifact_authorized`
cover the body and its declared copies, not just the Markdown file. Shared
`report_attachment_refs(bytes)` recognizes the existing standalone inline-image
protocol; unsafe or malformed managed declarations fail closed, while bodies
without managed references never inspect adjacent screenshot directories.
`_report_rows` rechecks copy bytes on every full Finding/page acquisition, including
at the same Store revision. Missing/changed/nonregular/symlinked copies make only
their report stale; existing delivery events retain history with
`current_binding=false`, and new events reject. Technical assessments, destination
decisions, original evidence and lightweight historical reported counts keep their
separate meanings. Queries never backfill attachment metadata or repair files.
Same-command material and immutable report identity stay unchanged; healthy replay
is idempotent, and explicit publication retry cannot recreate a damaged registered
copy. Registered retries never publish files, and direct registration checks the
registered report's current health before returning an old receipt, including body
availability/provenance denials. Arbitrary Markdown/HTML links and old images without content-addressed names
are not silently enrolled or migrated. Captured file checks reject observed drift,
not all possible filesystem changes after the final check.

Domain command method parameters are keyword-only; initialization uses the
explicit signatures above. Command receipts include revision,
command_id, command, entity_id, actor, content_sha256, recorded_at and replayed.
Command IDs and audit actors reject surrounding whitespace: normalizing just the
audit would leave mutation-owned claim tokens and receipt references inconsistent.

## 3. Contracts

Database path: `state/<target_storage_key>/metadata.sqlite3`; database mode 0600,
target directory 0700; symlinked database paths rejected. Initialization must not
silently repair an existing non-private target directory. New stores use SQLite
schema v15; v8/v9 retain their existing operations, with an explicit upgrade
required before Coverage review queries/writes. Schema v10 remains readable,
but persisting complete observation identity requires `upgrade-schema` with a
verified private backup. Reads never upgrade a Store. The recorded target has already cut over. Do
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
  with currently intact files. Immediately before inserting the completion, the
  same write transaction rereads the latest availability/provenance event for
  every artifact linked to that operation (including control and later steps);
  an unavailable or revoked artifact rejects the completion while preserving the
  claim and the independently committed event. An arbitrary file cannot complete
  an execution. File hashing remains in the pre-transaction verification step;
  this commit-time event guard performs metadata reads only, so unrelated Store
  writes do not invalidate a valid proof and explicit restoration permits retry.
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

For an Action-bound nonempty registration, `partial` requires at least one
observation matching the Action family, but not necessarily its endpoint.
`complete` and nonempty `unknown` require one observation matching both endpoint
and family; separate matching observations are insufficient. Other valid family
observations may coexist. All rows still pass target, artifact, timestamp and
identity validation; an optional Finding candidate still requires its exact
endpoint/method/family. The attempt/action relation is caller-declared attribution,
not proof of membership in a saved request plan or semantic relevance. No source,
side, role or mutable summary can supply that missing guarantee.

First `start_attempt` checks the current claim/operator. Registration retains the
attempt relation without rechecking a current claim, so identical material and
operator can replay after an explicit `blocked` transition. First registration
adds one operation and revision; identical replay adds neither. Registration
does not release a claim: `transition_action` still checks claimant/token/version
and refuses release while any sibling attempt lacks a registration. Neither
partial nor unknown can supply the complete operation required for completion.

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

### Legacy import recovery guards (2026-10-19)

#### 1. Scope / Trigger
Staged legacy import, fresh initialization beside Coverage material, and target-memory backfill.
These guards retain the existing Store/receipt owners; they do not upgrade schemas or migrate live data.

#### 2. Signatures
`import_target_staged(source_root, destination_root, target)` uses `target_backend()` before
creating the destination. `TargetStore.initialize()` and import share the pure
`coverage_authoring.coverage_review_drafts(payload, target)` classifier.
`backfill_target_memory(source_root, repo_root, target)` retains the active migration receipt.
Store/import share `experience_contract.normalize_experience_text(kind, statement, conditions,
reopen_when, next_intent)` for text admission.

#### 3. Contracts
- Only a legacy source may enter staged import. Missing DB plus fence/receipt or damaged identity
  is explicit recovery, not an empty source; rejection must not create source locks or a destination.
- Authored Coverage reviews block fresh init. Default cells, controlled structural N/A and valid
  Store projections are distinct from author input; malformed/unknown material is not empty.
  Explicit import retains review/source identity. Store never imports the migration/view layer.
- Classify memory rows before writing: invalid whitespace/NUL/type/oversized conditions have exact
  quarantine selectors; valid rows before and after them continue, with overall partial status.
  Keep historical kind selection before stripping text (`" unknown "` may already be negative).
- The command ID remains bound to manifest/path/field/position. A committed row without a published
  `memory_backfill` map is replayed with the same normalized content, then its mapping is published.
  No duplicate row, new ID, lost source binding, broad Store-error quarantine or external-action replay occurs.

#### 4. Validation & Error Matrix
| Input / interruption | Required result |
|---|---|
| Primary source, fenced-missing DB, damaged fence/receipt | Reject before destination creation; source unchanged |
| Only authored Coverage review | Fresh init refuses; explicit import preserves the review |
| Valid / bad conditions / valid | Both valid rows mapped; precise quarantine; partial |
| First row committed or all rows committed, mapping not published | Retry fills the map once, preserves old IDs/content and source bytes |

#### 5. Good / Base / Bad Cases
Good: recover the old half-commit and its historical origin; Base: identical completed backfill
returns the saved map; Bad: treat the Base case as proof of recovery before receipt publication.

#### 6. Tests Required
Use synthetic isolated roots, unchanged source hashes and actual Store/receipt queries. Seed the
old first command and interrupt receipt publication; compare row count, revision, IDs, selectors,
map and readable historical source after retry. Include a bound negative with `" unknown "`.

#### 7. Wrong vs Correct
Wrong: normalize conditions before historical kind selection, or infer legacy from DB absence.
Correct: preserve the old command material; use the existing backend/fence owner and exact receipt.

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
- `build_recall_view(repo_root, *, target, query="", kinds=None, limit=5,
  cursor=None, experience_id=None)` uses this page. The cursor is for target experience only;
  other sources have independently labeled windows/expansion, not a synthetic
  cursor across unrelated stores. Historical PatternDB input is explicitly
  imported into this target experience source; it is not a second current writer.
- `history_view(repo_root, *, target, limit=20, cursor=None, experience_id=None)`
  expands the same owner without ranking. Both readers reject simultaneous cursor
  and ID presence before acquiring current facts or opening the Store, including
  an explicitly supplied empty cursor. ID expansion cannot silently ignore a cursor.
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
| Recall/history receives both `--cursor` (including empty string) and `--id` | `ValueError`/exit 2 before current-fact/Store I/O; no state writes |
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
`tests/test_experience_recall.py` covers valid paging and ID expansion, plus both
readers rejecting invalid/empty cursor with an existing ID before current-fact reads;
all saved bytes and the Store binding remain unchanged.
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
Its `test_documented_guidance_reads_current_store_without_mutation` executes
validator/retrospective examples against current, empty and missing Stores,
including selected-Finding relations, poisoned legacy files and unchanged
binding/source bytes; assert the extracted command count to prevent an empty pass.
`test_documented_memory_writes_preserve_conditions_and_reject_incomplete_negative`
executes the documented writes, checks condition/evidence round-trips and explicit
note recovery, and rejects each missing negative prerequisite without mutation.
Tests substitute fixture identities/root/output only, never omitted business flags.
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
  treated as damage. After archive receipt publication, an interrupted activation
  requires its exact verified archive. Before that publication, all original
  manifest bytes must still be present; a matching fence alone does not prove
  archival. See the explicit cutover recovery contract below.

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
| Bound partial with matching family at another endpoint | Register actual observations; preserve claim and caller-declared association limit |
| Partial with matching and other valid families | Accept; at least one matching family, not all rows |
| Bound complete/nonempty unknown without a single endpoint/family match | Reject, including matches split across separate rows |
| Wrong-family partial, off-target observation, or empty partial/complete | Reject; operation and revision unchanged |
| Empty unknown | Register unknown effect; no fabricated observation |
| Partial registered but sibling attempt pending, or wrong claimant/token/version | Explicit claim release still rejects without mutation |
| Identical registration replay before/after explicit blocked | Same operation/revision; no network execution |
| Empty/foreign/changed raw file | Reject or explicit integrity error; existing delivery/report projections become stale |
| Unknown valid family | Persist; canonical Coverage label absent |
| Bad type/unknown observation field | Reject before committed metadata |
| Partial evidence / unknown effect | Not confirmation or automatic completion |
| Known duplicate at destination | Can be technically confirmed, delivery ineligible |
| Stale cursor or judgment predecessor | Conflict; caller reloads |
| Backup destination exists / contains `..` | Refuse overwrite / reject ambiguous path before I/O; SQLite backup reads committed WAL |
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
- Good: only the baseline control survives a variant failure; register partial,
  then explicitly block the Action without attaching control evidence to its Finding.
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
- Bad: relabel control as subject or remove the pending-attempt guard to release
  a claim after a failed registration.

## 6. Tests Required

`tests/test_target_store.py`: atomic audit rollback, receipt idempotence, concurrent
claims/registration, distinct attempts, unknown recovery, strict input/target/file
binding, partial evidence, judgment separation/CAS, read-only snapshot paging,
conditional facts without new actions, damaged files, append-only artifact event
authorization, commit-time completion authorization for subject/control artifacts,
pre-transaction operation hashing, unrelated-write isolation, backup and dependency
direction.
`test_bound_execution_observation_admission` covers the outcome/endpoint/family
matrix, mixed-family acceptance, split-match rejection, rollback and replay.
`test_partial_recovery_requires_all_attempts_registered` covers sibling pending
attempts and claimant/token/version rejection before explicit idempotent blocking.
Runner `test_partial_variant_subject_registration_recovers_claim` combines
different URLs, a variant-bound Action and zero/one published responses using a
real Store: original control identity/raw, no Finding evidence leak, saved-summary
retry without more requests/attempts/revisions, and partial/unknown completion refusal.
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
`tests/test_disclosed_pattern_dedup.py` preserves report acquisition/cache while rejecting
retired PatternDB reads and title-generated hypothesis seeds. `knowledge_eval_draft.py`
and its standalone scoring CLI are retired; `/kb review`, registry and explicit
promotion/retirement remain. Normal validation and idempotent replay do not append
Pattern calibration telemetry; existing summaries retain source references and the
historical calibration module/explicit CLI remains available without implying fresh data.
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

Wrong: require a subject endpoint for every partial registration, fabricate it,
or treat registration as proof that the declared request plan was executed.
Correct: validate actual rows and the outcome-specific Action relation; preserve
the declared-association limit and use explicit claim recovery separately.

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

## Native-first publication projections

### 1. Scope / Trigger

Changes to Finding read models, evidence manifests, or destination-policy views.

### 2. Signatures

`TargetStore.finding(finding_id)` and `finding_page(limit=50, cursor=None)` expose
`technical_conclusion`, `evidence_integrity`, and `destination_decision` alongside
existing fields. No new table or mutation command is introduced.

### 3. Contracts

- `technical_conclusion` is the latest immutable assessment, or null. Raw-byte
  damage and destination rejection never rewrite its verdict/boundary/impact.
- `evidence_integrity={status, assessment_id, references}` has status
  `unassessed|valid|invalid`. It verifies existing assessment-supporting operations
  on this read, not cached summary booleans. References bind operation, step,
  event ID (`operation_id:step`), artifact kind/id/path and SHA-256.
- `destination_decision` retains each current destination's ID, reason,
  assessment binding, native status and staleness; its presentation decision is
  `eligible→accept`, `ineligible→reject`, `deferred→defer`.
- No assessment means no claimed verified evidence manifest. Unassessed findings
  retain their original observation references under `evidence`.
- Page and single-item projections agree and perform no lifecycle writes.

### 4. Validation & Error Matrix

| Input | Result |
|---|---|
| No assessment | null technical conclusion, unassessed integrity |
| Confirmed assessment + rejected destination | confirmed + valid + reject |
| Raw bytes changed after assessment | same technical conclusion, invalid integrity, stale decisions |
| Repeated read / page read | identical projection, unchanged Store revision |

### 5. Good/Base/Bad Cases

Good: publish a confirmed A for its eligible destination while another destination
rejects it. Base: preserve an unassessed claim without invented validity. Bad:
convert destination rejection or missing raw bytes into a rewritten verdict.

### 6. Tests Required

`python3 .trellis/tasks/09-29-validation-closure-scope/research/check_closure_replay.py`
checks native registration → assessment → three destination outcomes → single/page
reads → damaged evidence, including immutable event/hash references and no writes.
Existing report tests cover all eligible destinations and immutable report replay.

### 7. Wrong vs Correct

Wrong: destination rejects → technical verdict refuted.
Correct: immutable confirmed assessment + independently rejected destination.

## Optional card-read telemetry
Native card Read does not require `knowledge_pull_log record`. Explicit record,
`kb_card` read-and-record, historical JSONL and CLI flags remain available.
`kb_review` keeps its list/previous fields and deterministic recorded-count order,
adding `pull_coverage=incomplete`; zero means no readable recorded events, not
unused or low-quality knowledge. Do not reconstruct complete usage from Action
metadata or create another automatic telemetry owner. `tests/test_kb_outbound.py`
checks no-write reads, historic/malformed-log compatibility and unchanged ordering.

## Exact correction scope and owner relation sources (2026-10-12)

### 1. Scope / Trigger

Experience correction admission/health, target relation generation and exact
counterevidence. This slice introduced no schema change (v16 at delivery);
current Store schema is v17 and relation projection remains v4.

### 2. Signatures

`link_experience(... relation, conditions, rationale, expected_revision)` and
`remember(links=[...])` retain their inputs. `experience_version`, page and current
views add the same derived `applicability`; correction refs add
`applicability={conditions,source_conditions,target_conditions,comparison,effect}`.
`acquire_snapshot(...,include_owner_relations=False)` opts target relations into
owner acquisition. `TargetStore.execution(id)` includes original artifact IDs.

### 3. Contracts

- Correction scope must be explicit. The edge scope and both retained endpoint
  declarations must be exactly identical and known for `effect=whole_record` /
  `comparison=identical_declarations`; otherwise effect is `conditional` and
  comparison is `not_established`. This is authored scope, not semantic or actor
  equivalence. Empty/unknown endpoint declarations do not become wildcards.
- Only an incoming whole-record correction changes overall review_state and its
  existing dependency closure. Conditional connections remain visible but do not
  globally invalidate the older method. Withdrawal retains its original scope
  and challenge; depends_on, cycle rejection, CAS and exact retries are unchanged.
- Scope is derived from exact version snapshots, never mutable heads or a new
  persisted validity flag. Corrupt/missing correction snapshots fail explicitly.
- Case actor→session/object requires its actual owner FK. Action→operation uses
  the actual attempt; operation→artifact uses its observation binding. Artifact
  IDs come from Store, never a consumer hash. Edge provenance retains attempt ID
  and step. Experience evidence/dependency uses precise versions. Owner-recorded
  associations do not establish authorization, impact, time overlap or execution
  viability; paths remain hypotheses with unknown constraints.
- Target relation acquisition alone expands executions into owner documents; text
  dependencies may verify referenced operations, but do not enumerate their catalog.
  External source health and bindings participate in source
  hashes and final publication/return checks. Shared methods remain target-free.
- Counterevidence roots include returned Experience nodes and rejected owner
  documents via exact entity DTOs, not parsed source_ref IDs or latest-version
  lookups. Roots are deduplicated. Omitted item bodies retain referenced_by scope,
  endpoint versions and withdrawal; only rationale is removed from the compact
  correction ref. If the reference cannot fit, request a larger context budget.

### 4. Validation & Error Matrix

| Input | Result |
|---|---|
| Different endpoint/scope declarations | Conditional connection; old-scope advice and its dependencies not globally invalidated |
| Correction scope empty/unknown | Reject, no mutation |
| Withdraw whole-record correction | Old conclusion stays challenged; never revive |
| Withdraw conditional correction | Conditional history retained; never broaden its effect |
| External evidence changes without revision | Stale generation; rebuilt graph rejects damaged source with partial diagnostics |
| Legitimate empty owner collection | Ready empty projection; no constant implementation gap |
| Missing seed after partial rebuild | unresolved_seeds plus current and exact available counterevidence |
| Old graph format | Explicit relation-build --full-rebuild required |
| Real challenged basis during --update-index all | Save receipt retained, partial/exit 2 and index-only recovery; repeated rebuild cannot heal the source |

### 5. Good / Base / Bad Cases

Good: B-condition refutation coexists with A-condition advice, while its scope is
visible in current/history/counterevidence. Base: identical declarations retain the
previous supersession behavior. Bad: same display name joins Case records, or an
owner:experience path returns a misleading complete-empty counterevidence page.

### 6. Required Checks

Synthetic owner APIs and CLI: conditional/whole-record corrections, withdrawal,
Case retained versions, unknown declarations, cycles/CAS/replay, current empty
intent, text/JSON and budgeted context. Actual two-hop/reverse attempt/step chains,
false textual joins, raw-byte changes, shared isolation and incremental/full
projection equivalence. Target source acquisition now follows the incremental
contract below. The original owner-provenance/scoped-corrections verification and
the subsequent incremental-acquisition verification retain their separate scopes;
no model, real migration or broad release acceptance is implied.

### 7. Wrong vs Correct

Wrong: remove condition admission checks but leave global health invalidation.
Correct: derive scope once in Store and propagate only whole-record challenges.
Wrong: discover counterevidence roots solely by the old source_ref prefix.
Correct: use exact returned/owner Experience DTOs, including rejected sources.

## v17 historical origins (2026-10-12)

### 1. Scope / Trigger

Exact imported-history origin bindings and expansion, permanent PatternDB original
archives, and explicit v16→v17 upgrade. No implicit import or source promotion.

### 2. Signatures

```python
store.history_source(imported_experience_id, full=False)
store.remember(..., sources=[{**binding, "purpose": "origin"}])
```

```bash
python3 tools/target_memory.py history-source --target TARGET --id ID --json
python3 tools/target_memory.py history-source --target TARGET --id ID --full --json
python3 tools/target_migration.py --backfill-pattern-source SOURCE --repo-root ROOT --target TARGET
python3 tools/target_store.py upgrade-schema --repo-root ROOT --target TARGET --backup ABSOLUTE_BACKUP
```

`experience_external_sources` accepts knowledge/history; history is origin-only at
both DDL and owner admission. Claim external sources remain knowledge-only. Fresh
creation and explicit upgrade share DDL; prior knowledge rows/claims/FKs survive.

### 3. Contracts

- Binding is `{owner:"history",record_id,version,content_sha256}`. `record_id` is
  an already imported same-Store Experience ID. Version SHA256 binds target/store,
  original manifest, file identity, exact mapping and selector, not the mutable
  whole receipt or a movable source/archive root. Memory content hashes the original
  selected JSON value; PatternDB hashes exact line bytes excluding the newline.
- Full available output retains the binding at top level, `source={target,store_id,
  source_manifest_sha256,path,sha256,size}`, `source_kind`, `selector`, `record`,
  `availability="available"` and `verification="unverified"`. PatternDB also returns
  `raw_record`. Unavailable full output returns owner/record_id, null source/kind/
  selector/record and an explicit reason; it invents no digest or verified status.
- `migration_receipts` validates active target/store identity, manifest digest,
  canonical unique paths, file types, selectors and original size/hash. Reject
  symlink components. `target_memory_schema` is the single legacy normalizer;
  migration does not import memory CLI. Imported notes are not original-byte copies.
- Memory expands only the bound legacy archive. PatternDB files are immutable under
  `state/<target-key>/pattern-archive/<source-files-digest>/`, with 0700 directories
  and 0600 files; archive precedes pending receipt/import. Existing receipt
  `source_files`/`experience_map` remain authoritative; `archive_root` is a locator,
  not a second mapping. Exact-source retry can archive old complete/partial receipts
  without calling remember or changing Store revision. No automatic origin edges.
- Receipt SH uses flock on an existing state directory, not a query-created lock
  file. Write acceptance captures bytes before the Store write transaction, then
  checks file identities under receipt SH. WAL read snapshots may precede receipt
  SH. An EX backfill retry uses identity-only `experience_entity`, never health
  expansion that reenters SH. `history_source` verifies target/store_id/revision
  after capture; mixed Store snapshots fail. No hashes inside a write transaction.
- Origin damage is diagnostic and does not globally refute its experience. Exact
  command replay preserves the committed receipt even after later source damage.
  Current facts and historical correction scope retain their existing owners.

### 4. Validation & Error Matrix

| Input | Result |
|---|---|
| Valid original mapped to this Store | Exact binding or full unverified record, no writes |
| History purpose=basis or history claim source | Reject before mutation |
| Missing/ambiguous map, wrong target/selector/digest, symlink, bad original | Binding lookup fails; full expansion diagnoses unavailable, no live fallback |
| Old PatternDB receipt without archive | Explicit same-source backfill recovery instruction |
| Changed source files on retry | Reject; preserve archive, mapping and Store history |
| Unrelated receipt append / supplemental archive locator | Existing source version unchanged |
| Receipt/backfill status has malformed type | Explicit CLI error (exit 2), no TypeError traceback |
| Store replaced or revision changed during source capture | ConflictError; reload and retry |
| v16 history attachment | Explicit backup-bound upgrade required, no query migration |
| Later origin damage / exact save replay | Visible diagnostic / original replay receipt, no duplicate fact |

### 5. Good / Base / Bad Cases

Good: explicitly archive the pinned original, expand its selected line, then save
an advisory note with that origin. Base: a non-imported note does not fabricate a
history source. Bad: expand another target's row from a shared PatternDB file or
use the imported note's normalized defaults as the original content hash.

### 6. Tests Required

Narrow synthetic real-CLI chain: explicit import/archive → history-source → origin
save → retained version/history/counterevidence/current. Assert old archive repair
has no Store revision change, origin is never claim support, malformed/unavailable
inputs are explicit, source identity survives unrelated receipt writes, v16 upgrade
preserves knowledge/FKs and retries, and tools dependencies remain acyclic. WAL
reader/EX-backfill and reader/upgrade contention must finish without a self-deadlock.
Current evidence: parent task `research/history-source-verification.json`. Its
limits retain non-WAL and older-upgrade dynamic coverage gaps; no model, real-data
migration or release acceptance is implied. No new project test framework needed.

### 7. Wrong vs Correct

Wrong: bind the entire mutable migration receipt and later invalidate every origin.
Correct: bind the exact manifest/file/map/selector; receipt status remains an admission check.
Wrong: call `experience()` under EX just to check an imported record exists.
Correct: use public identity-only `experience_entity("experience", id)`; health may reacquire SH.
Wrong: interpret available historical bytes as verified supporting evidence.
Correct: history remains an unverified origin, with exact raw expansion and separate health.

## Incremental target source acquisition (2026-10-12)

### 1. Scope / Trigger

Target text/relation source acquisition and generation reuse. Store stays v17;
no new fact table, lifecycle, event queue, model or implicit mutation. Shared
knowledge acquisition remains a full registry/review/body audit.

### 2. Signatures

```python
store.recall_delta(since_binding, include_owner_relations=False)
# binding, experience_ids, owner_keys, full_acquisition_reason
store.recall_rows(ids, expected_binding=binding)
# binding, items, dependencies, probes, fences
store.recall_probe(refs, expected_binding=binding)
# binding, items, fences
acquire_snapshot(root, target, previous_capture=None, full_acquisition_reason=None,
                 include_knowledge=True, include_owner_relations=False)
validate_capture(capture, target=target, include_owner_relations=False)
same_snapshot(left, right)
```

Existing index-build/query/status and relation commands use these public boundaries.
No environment setting or index-update side effect is added to ordinary saves.

### 3. Contracts

- Recall binding is `{target,store_id,backend,revision,schema_version}`; ordinary
  `binding()` remains unchanged. Row/probe calls require an exact typed binding.
  `recall_rows` accepts at most 1000 unique IDs, rejects absent IDs and returns the
  existing page DTO/order, not `experience()` with extra Case content.
- Delta consumes `(since,current]` from the existing append-only audit, checking
  the consumed watermark and contiguous new revisions. Cold/full acquisition uses
  full SQLite integrity/FK and audit checks; the incremental path does not rescan
  accepted audit history. Unknown commands, gaps, replacement, rollback or schema
  changes have explicit full reasons. This is not a forensic scan of untouched rows.
- Store computes reverse influence, including origin/basis, exact retained versions,
  corrections/withdrawals, claim endpoints/conditions, artifacts/assessments, Action
  and Case changes. Observation attachments are immutable across Case versions, so
  reverse evidence lookup uses their relational links, not all retained JSON bodies.
  Missing touched canonical rows or corrupt retained evidence fail explicitly.
- REF is `{owner,record_id}`. Probe owners are artifact/assessment/operation/session/
  object/knowledge/history and case/context. Operation probes check every step's
  artifacts, not just an experience's selected step. Case probes read real entities
  and their private health, not the entire hypothesis-history catalog. Knowledge
  and history reuse their existing receipt/byte owners; consumers interpret no health.
- Semantic probes are `{ref,fingerprint}` from current owner health and real bytes.
  `fences` has the same shape but hashes ephemeral file identities/stamps, including
  nested material dependencies. It is not a replacement for hashing. Within an
  acquisition and before publish/query/status return, both kinds must remain equal;
  `same_snapshot` is the shared pure comparison, excluding time and read statistics.
  Restored identical bytes may have the original semantic fingerprint but a different
  per-call fence. Private bodies never enter either public result or the capture.
- Capture v1 has exactly `schema_version`, `binding`, `include_owner_relations`,
  `documents`, `experience_dependencies`, `owner_groups`, `probes`. It contains only
  complete public target projections, with empty owner groups retained. Changed
  dependencies invalidate only their consumers; current is always acquired separately.
  Target snapshots/partitions carry ephemeral `source_fences` outside capture.
- The unique immutable-generation publisher writes `capture.json` and its manifest
  `capture_digest`. Required Store fields, types, relation mode and nonnegative
  integer `source_revision` must match exactly. Target partitions supply the watermark
  outside their semantic binding; full snapshots may supply binding.revision. Shared
  generations reject target captures. Query/status never repair a generation.
- Publisher idempotence includes capture digest. A watermark-only advance can publish
  a new capture while reusing projection payload. Document text serializes record keys
  canonically; `token-windows-canonical-parent-v2` prevents stale vector reuse after
  this text-format change. Old JSON key insertion order is not a content change.
- `acquisition` reports mode/full reason, experience_rows_read, owner_groups_read,
  reused_experiences, external_probes and knowledge_acquisition separately from index
  update counters. Zero historical row reconstruction still permits current-page,
  metadata and fresh byte reads; it is not zero total I/O or a speedup claim.

### 4. Validation & Error Matrix

| Input | Result |
|---|---|
| No capture / old generation without capture | Explicit full-acquisition reason; no query-time index write |
| Corrupt digest, malformed REF, wrong Store/schema/mode or missing/Boolean watermark | Capture/generation unavailable; query may use full fresh lexical sources, never trust the bad payload |
| No owner changes or byte/health changes | Reuse historical documents/groups; acquire current and probe bytes again |
| External file damaged/missing, then restored between calls | Localized invalidation/recovery with owner diagnostics, independent of Store revision |
| Source changes or changes-and-restores during one call | Conflict/Store error; do not return mixed health or publish CURRENT |
| Missing canonical dependency / malformed retained observation | Explicit Store error, not a dropped row or successful empty view |
| Unknown audit command / watermark gap / Store replacement or rollback | Full acquisition with a specific reason; no implicit Store migration |
| Interrupted generation write | Preserve previous CURRENT; remove only the unpublished derived generation |
| Shared query/build | No target Store/capture; retain full reviewed-knowledge audit |

### 5. Good / Base / Bad Cases

Good: a new note reassembles that note and its owner group, not unrelated executions;
an unselected observation's damaged raw file invalidates dependent groups. Base:
a legacy generation acquires full sources, and explicit build adds a bound capture.
Bad: record zero Python row expansions while running quick_check on every request,
or cache prior health because revision/mtime did not change.

### 6. Tests Required

Isolated real Store/CLI chain with SQL trace and public-read counters: cold/no-op/single
mutation; correction/retained/origin/withdrawal closure; artifact, Action, assessment,
Case and external knowledge/history changes; full/incremental DTO/health equivalence.
Inject owner-health ABA and assert acquisition, publisher and text/relation final
return fences reject it. Assert restored bytes retain semantic equality, private
content/fences never persist in capture, current and counterevidence remain separate,
typed watermarks/corrupt or old captures are explicit, and interrupted publication
preserves CURRENT. Current engineering evidence is the parent task's
`research/incremental-acquisition-verification.json`; no model, real migration or
release acceptance is implied. Use existing guards, not a new project test framework.

### 7. Wrong vs Correct

Wrong: persist mtime inside the semantic source fingerprint to catch ABA.
Correct: hash real bytes/health for meaning, compare separate per-call identity fences.
Wrong: treat reused FTS/vector rows as proof of incremental source acquisition.
Correct: measure actual row/group reads and SQL, excluding independent current reads.
Wrong: compare only Store revision at the final query boundary.
Correct: compare the closed binding, capture and fresh external-source fences together.


## Explicit cutover archive and restore recovery (2026-10-12)

### 1. Scope / Trigger

Explicit legacy import promotion and pre-primary restore; Store remains v17.
Ordinary reads still reject a fenced preview. No implicit migration, new fact
owner, automatic replay or knowledge admission is introduced.

### 2. Signatures

Existing `promote_target(...)`, `restore_legacy_metadata(...)`, `--promote` and
`--restore-legacy` remain. `migration_receipts.read_migration_receipt(path,
 target=..., store_id=...)` validates a completed import without active-history
admission. `read_legacy_archive(..., allow_pending=False)` remains active-only
by default; only explicit cutover opts into pending archive validation.

### 3. Contracts

- Bind target, Store, typed manifest, canonical unique paths, exact file set,
  size and digest in the shared receipt owner. The archive file set must equal
  the legacy-owner subset of the import manifest, not merely be a valid subset.
- Publish each immutable archive file with the existing descriptor-bound,
  no-overwrite, byte-verified primitive also used by PatternDB. Publish and
  directory-sync the complete archive receipt before unlinking any original.
- Without an archive receipt, resume only if all original manifest bytes match.
  Reuse verified partial archive files; never overwrite conflicting material.
  With a pending receipt, verify every archive byte and every remaining input
  before any further unlink or role commit; finish all remaining owner unlinks.
- First restore requires a readable preview DB, matching fence/import identity,
  and verified/restored original bytes. It then atomically publishes and syncs
  `legacy_restore_status="prepared"` in the existing migration receipt before
  deleting any database file. No new receipt file or database is introduced.
- A prepared restore may resume cleanup when its DB or fence is already absent;
  `store_id=None` is admitted by the receipt reader only for this prepared phase.
  Any existing DB must still prove preview. Prepared permits restore only, never
  promotion or active-history reads. Delete the prepared receipt last.
- Missing DB without prepared restore is ambiguous, even with a pending archive:
  reject before restoring originals or deleting WAL/SHM/fence. Primary always
  rejects legacy restore; post-commit recovery only finishes activation markers.
  Completed activation still re-enters without requiring cleaned-up archives.
- Pre-receipt restore preserves unreceipted partial archives for diagnosis.
  Completed archive restoration cleans only its manifest-bound archive directory;
  restored originals remain exact. No filesystem/power-loss transaction is claimed.

### 4. Validation & Error Matrix

| Input / interruption | Required result |
|---|---|
| Archive file or receipt publication fails | Originals and preview preserved; exact explicit resume or restore |
| Source bytes drift before receipt | Reject promotion and restore without cleanup |
| Pending archive missing a mapped item / bad locator / damaged bytes / symlink | Reject before role commit or further owner unlink |
| Original unlink interrupted | Verify all inputs, then finish remaining unlinks on promote |
| Prepared restore interrupted at DB, fence or receipt unlink | Same restore resumes to legacy; promotion remains blocked |
| Primary marker failure, new write, then missing DB | Refuse legacy restoration; preserve WAL/SHM and recovery metadata |
| Active completed cutover, archive cleaned up | Idempotent primary result; no fact mutation |

### 5. Good / Base / Bad Cases

Good: pending freeze resumes after checking the exact original mapping and bytes.
Base: a completed primary returns its existing identity without archive reads.
Bad: interpret pending receipt or missing DB as proof that primary never ran.

### 6. Tests Required

Use isolated synthetic roots and real CLI subprocesses. Assert source/Store
identity, logical rows and history-origin expansion; inject file/receipt/unlink
and post-commit failures; retain real WAL/SHM around a new primary write. Check
malformed metadata, drift, symlink components, prepared-cleanup continuation,
unchanged PatternDB archive bytes/permissions/retry, and no active-history
admission while prepared. Parent `research/cutover-recovery-verification.json`
records this engineering check; it is not schema-upgrade or release acceptance.

### 7. Wrong vs Correct

Wrong: return an existing pending receipt and immediately commit primary.
Correct: validate the complete binding and archive bytes, then finish freezing.
Wrong: absent DB plus pending archive authorizes deleting recovery sidecars.
Correct: only a durable restore prepared from a readable preview authorizes
cleanup continuation; otherwise preserve the current Store recovery inputs.


## SQLite backup publication and schema recovery (2026-10-12)

### 1. Scope / Trigger

`TargetStore` metadata snapshots and explicit schema upgrades. This does not
copy external evidence, migrate real targets automatically or change schema v17.

### 2. Signatures

`TargetStore.backup(destination: str | Path) -> Path` returns the supplied path
after successful publication. Ordinary canonical relative paths remain valid.
`upgrade_schema(backup_path)` and `upgrade_memory_schema(backup_path)` retain
their existing absolute, private-directory, outside-target backup requirements.

### 3. Contracts

- Reject any `..` component with `StoreError` before filesystem access. Do not
  silently resolve it: lexical normalization and symlink traversal can identify
  different parents. Pin directory components without following symlinks.
- SQLite writes only `snapshot.sqlite3` in a private temporary directory beside
  the destination, never the final pathname after releasing an `O_EXCL` guard.
  Close SQLite and fsync the snapshot descriptor before publication.
- Publish the closed 0600 snapshot by a no-overwrite hard link through the
  pinned parent descriptor, then fsync that directory. Temporary files are
  cleaned on failure; competing destination files and symlinks are untouched.
- A failure after publication retains the complete backup. Do not unlink it
  based on its pathname or claim that directory-sync failure proves durability.
  Existing destinations still reject retries; use a new backup path as required.
- Backups include committed WAL data even while another reader retains an older
  snapshot. Upgrades verify the backup identity/integrity before transactional
  DDL, preserve original facts, and CAS the source identity/revision/schema.
- Failed upgrade DDL/audit rolls back schema, facts, revision and audit while
  retaining the backup. An already-current upgrade creates no additional backup
  or audit event. Ordinary readers never perform schema upgrades.

### 4. Validation & Error Matrix

| Input / failure | Result |
|---|---|
| Existing or concurrently created final file/symlink | `FileExistsError`; competitor bytes/link unchanged |
| Symlink parent / `..` component | Directory error / `StoreError`; no backup published |
| SQLite snapshot failure | `StoreError` preserving cause; no final backup |
| `KeyboardInterrupt` during snapshot | Propagate interruption; clean temporary snapshot, retain competitor |
| Hard-link publication failure | Propagate error; no final backup; same unused path can be retried |
| Directory fsync fails after publication | Propagate error; retain complete backup; no durability claim |
| Upgrade audit fails after DDL | Roll back all transactional changes; retain verified backup |
| Retry after failed upgrade using its existing backup path | Refuse overwrite; new backup path required |
| Supported old schema / already current | Explicit upgrade preserving facts / unchanged identity and revision |

### 5. Good / Base / Bad Cases

Good: an old reader sees one Action while the backup contains both committed
Actions. Base: a new canonical path receives one complete 0600 snapshot. Bad:
`A/link -> B/child` with `A/link/../copy.sqlite3` must not publish in `A` while
returning a pathname that points into `B`.

### 6. Tests Required

Use isolated synthetic source/target roots. Cover file/symlink races, exact error
and interruption propagation, symlink-plus-`..`, WAL, failed publication retry
and post-publication sync failure. Build physical v8–v16 schemas rather than
relabeling the current schema or calling current APIs on an old layout. Close
every SQLite connection and checkpoint before replacing fixture database files.
Assert old rows, raw evidence, current empty handoff, current premise, Action and
assessment/delivery links survive; verify history-origin admission and rejection
of history as basis/claim support. Audit failures cover v8 table reconstruction,
v12 relationship rebinding and v16 external-source reconstruction. Retain the
existing `test_store_missing_corrupt_wrong_target_permissions_backup_and_legacy_refusal`.

### 7. Wrong vs Correct

Wrong: create and close a final-path descriptor, then let SQLite reopen the name.
Correct: build a private snapshot and publish closed bytes without overwriting.
Wrong: normalize only the directory handle while other operations use raw `..`.
Correct: reject ambiguous components once at the backup owner boundary.
Wrong: use `with sqlite3.connect(...)` as proof a fixture connection is closed.
Correct: explicitly close connections as well as committing/rolling back their
transactions before replacing a database pathname.
