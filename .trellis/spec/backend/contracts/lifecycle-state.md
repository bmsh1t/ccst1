# Lifecycle and State Contracts

> 身份、checkpoint、case、observation 和 queue 生命周期契约。

## Scenario: simple-efficient-refactor 结构契约（2026-09-11）

### 1. Scope / Trigger

修改 `tools/autopilot_state*.py`、`tools/autopilot_gate.py`、`tools/autopilot_loop_guard.py`、
`tools/claim_templates.py`、`tools/distill_target.py`、`tools/contracts.py` 或
`action_queue.ingest_checkpoint` 时读取。

### 2. Signatures

- `python3 tools/action_queue.py claim --target <t> --id <id> [--template <name>] [--from-evidence <ref>] --metadata-json '<obj>'`
- `python3 tools/action_queue.py list-templates [--json]`
- `python3 tools/evidence_ledger.py record --target <t> --from-probe <event_id> --result <r> [--notes <n>]`
- `python3 tools/distill_target.py prompt --target <t> --typology <pattern|target-vuln|failure|bypass> --json`
- `python3 tools/distill_target.py commit --target <t> --triple-json <file-or-json> [--slug-hint <s>] --json`
- `python3 tools/target_memory.py lead --target <t> --structured-json '{"hypothesis":...,"evidence_ref":...,"next":...,"stop_condition":...}'`
- `ingest_checkpoint(repo_root, target, *, checkpoint: dict)` — checkpoint 必填（不再懒加载）

### 3. Contracts

- **claim 模板合并优先级**：`final = {**template, **from_evidence_derived, **metadata_json}`；
  AI 显式值永远赢；四判断字段（hypothesis_id/expected_learning/kill_condition/
  decision_reason）永不进模板（`tests/test_claim_templates.py` 负断言）。
- **模块拆分与 re-export**：autopilot_gate/loop_guard/state_read 被 autopilot_state
  全量 re-export——外部 import 只从 `tools.autopilot_state` 走；closure/decision
  投影族留在 state（深耦合 30+ 状态构建函数，搬动会反向循环）。
- **依赖单向**：checkpoint → action_queue（模块加载期 aq 不得 import ck）；
  contracts.py 零 import（纯常量）。
- **/distill 两段式**：机器出题（拉 ledger/findings/case_state 原始证据）→
  AI 提三元组 → 机器 scrub（裸 IPv4/credential 形态拒绝写入）+ evidence_refs
  目标名下可溯源校验 → 草稿卡 `knowledge/candidates/<slug>.md`；mv 即 promote。

### 4. Validation & Error Matrix

- 未知模板名 → `ValueError("unknown claim template ...; available: ...")`
- --from-probe 未知 event_id → `ValueError("--from-probe event_id ... not found")`
- 三元组含裸 IPv4 → `ValueError("triple contains a bare IPv4 address...")`
- 三元组含 credential 形态文本 → `ValueError("triple contains credential-shaped text...")`
- evidence_ref 非目标名下/不存在 → `ValueError("not target-owned" / "does not exist")`
- structured-json 缺任一四字段 → `SystemExit("requires all of: ...")`
- `ingest_checkpoint(checkpoint=None)` → `ValueError("requires an explicit checkpoint dict")`

### 5. Good/Base/Bad Cases

- Good：`claim --template idor-cross-actor --from-evidence probe.json --metadata-json '{四判断字段+覆盖值}'` 一条命令完成激活
- Base：`record --from-probe <event_id> --result tested_clean`（机械字段全复制）
- Bad：模板里出现 hypothesis_id（内容门槛回潮，负断言测试会红）

### 6. Tests Required

- `tests/test_claim_templates.py`（9 项：预填/优先级/负断言/深度契约版本一致性）
- `tests/test_distill_target.py`（13 项：两段式/脱敏负测试/可溯源/slug 冲突）
- `tests/test_stage_one_ux.py`（9 项：from-probe/summary 一致性/结构化 leads）
- `tests/test_contracts.py`（4 项：契约同步/零 import 纪律）

### 7. Wrong vs Correct

#### Wrong
```python
# 模板里预填判断字段（把 AI 判断变成机械字段）
CLAIM_TEMPLATES["x"] = {"hypothesis_id": "auto", ...}
```
#### Correct
```python
# 模板只放类别稳定字段；判断字段必须每次由 AI 显式给出
CLAIM_TEMPLATES["x"] = {"family": "IDOR", "risk_tier": "medium", ...}
# 缺 hypothesis_id 时 Queue 的 FORMAT gate 照样拒绝
```

---

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

## Legacy State Migration Semantics

The one-shot migration orchestrator (`tools/migrate_legacy_state.py`) is
retired; the live repo holds no legacy state shapes. The owner-side migration
semantics it exercised remain in their owners:

- `finding_index.load_finding_index(..., migrate_legacy=True)` normalizes
  historical list payloads in memory; it never writes a second findings schema.
- An untyped `source_paths` entry is `needs_review`; no command flag is
  inferred. A typed `source_bindings` list may be promoted to bounded
  `source_refs`.
- An active Queue row with `activation_required=true` but incomplete depth
  metadata is `needs_review`: report the missing fields and a repair action,
  but never invent an AI hypothesis, Skill route, evidence reference, or
  decision reason.
- `target_paths.migrate_legacy_list_storage` moves list-key state only after
  the owner runtime names the same canonical list path; otherwise it reports
  and leaves the legacy directory untouched.

## Canonical Finding and Report Identity Contracts

### 1. Scope / Trigger

Use this contract whenever scanner rebuilds, coverage marks, worker joins,
validation runners, `/validate`, or report generation mutate target-level
`findings/<target_key>/findings.json` or create structured report drafts.

### 2. Signatures

- `load_finding_index(findings_dir: str | Path, *, migrate_legacy: bool = True) -> dict[str, Any]`
- `find_finding(findings_dir, finding_id, *, migrate_legacy: bool = True) -> dict[str, Any] | None`
- `upsert_finding(findings_dir, finding, *, target=None) -> dict[str, Any]`
- `upsert_findings(findings_dir, findings, *, target=None) -> dict[str, Any]`
- `update_finding_status(findings_dir, finding_id, **updates) -> dict | None`
- `write_finding_index(findings_dir, *, target=None, output=None) -> dict`
- `report_generator.process_findings_dir(findings_dir) -> tuple[int, list]`
- `report_generator.sync_report_action_queue(target_name, finding, report_file) -> dict`

### 3. Contracts

- Target-level `findings.json` is always an object with `schema_version`,
  `target`, `total`, `counts`, and `findings[]`. Worker scratch files under
  `evidence/<target_key>/workers/**/findings.json` remain private list payloads.
- `finding_index.py` owns target-level schema, normalization, counts, lifecycle
  preservation, atomic writes, and legacy-list migration. Coverage, worker
  join, runner, and `/validate` must call its mutation API instead of writing
  the file directly.
- Identity matches exact `id` first, then normalized `url|endpoint` plus
  `vuln_class|type` when an endpoint exists. Rows without endpoints remain
  distinct by ID; they must not collapse merely because their type matches.
- Rebuild, legacy migration, and generic upsert must verify existing finalized
  provenance before signing a new snapshot. Invalid/missing provenance is
  quarantined as `needs_owner_revalidation/not_generated`; the original claim
  remains in `claimed_validation_status` / `claimed_report_status` with evidence
  pointers, but cannot be consumed as finality.
- Lifecycle merge is monotonic: a candidate cannot downgrade trusted
  validated/rejected or generated/reported state, and `reported` cannot fall
  back to `generated`.
- Root claims should use `kind=finding_claim`, `schema_version=1`. Unknown kinds,
  invalid schemas, ordinary status JSON, and off-target endpoint/target values
  are not claims. `claim_sources[{claim_id,source_file,revision}]` is a stable
  source+content-revision union; scalar claim fields remain compatibility only.
- A matching runner may fill a missing canonical endpoint/type after target
  ownership validation and clear matching `incomplete_fields`. It must fail
  closed on a non-empty identity conflict and must not create a second finding.
- New validation artifacts are per finding:
  `<artifact-key>.validation-summary.json` and
  `<artifact-key>.submission-notes.md`. The row records the actual summary path
  and SHA-256 digest. `last-validate.json` is a pointer, never evidence.
- Structured report IDs are persistent target state. Allocation must inspect
  finding rows, `INDEX.json`, and existing Markdown filenames, then select the
  next free per-type numeric ID.
- Canonical finding taxonomy and historical report-template keys are separate
  contracts. `report_generator` owns the one-way normalization from canonical
  `type`/`category` to a supported `VULN_TEMPLATES` key; aliases such as
  `authentication_bypass -> auth_bypass` must be explicit there. Consumers must
  not rewrite the canonical finding type merely to select a template.
- Report Markdown is created with exclusive semantics. An existing file is
  reusable only when its Finding Reference names the same finding ID; another
  finding's file is never overwritten.
- Finding owns the durable report binding and Queue reconciliation witness:
  `report_status`, `report_id`, `report_file`, and `queue_sync`. `INDEX.json`
  remains a rebuildable projection and must not become a lifecycle owner.
- Resume may expose explicit external dependencies from a target-owned Finding as
  a bounded `structured_findings.chain_context` projection. It is inert context
  only: it must not change target Finding counts, endpoint eligibility, Scope,
  Queue, Coverage, or Closure, and it must retain target-side evidence refs.
  Resume/Autopilot projections always force `active=false` for these entries.
- A rerun must reconcile owner-provenance-valid `generated` findings before
  rebuilding `INDEX.json`. A unique active report action is resolved through
  Action Queue; a unique `reported` action is idempotent only when finding or
  report identity matches. Endpoint-only terminal matches are not sufficient.

### 4. Validation & Error Matrix

- Historical list payload -> normalize rows, preserve non-final lifecycle and
  evidence pointers, quarantine unverified finality, write the canonical object
  atomically, then return that object.
- Machine preflight over historical list payload -> read without migration;
  failed binding leaves every target-owned byte unchanged.
- Summary missing or digest mismatch -> shared provenance verification fails and
  finalized consumers downgrade the row to owner revalidation.
- Machine report path owned by another finding -> reject before the first write;
  same-finding rerun and byte-identical crash replay remain recoverable.
- Root claim source content changes -> new revision is reconciled into the same
  semantic finding; multiple sources remain a stable union after one pass.
- Duplicate ID or endpoint/class pair -> merge evidence fields and recompute
  counts; return `created=0` for that row.
- Same type with two different endpoint-less IDs -> retain two rows.
- Requested report ID owned by another finding or file -> allocate the next
  free numeric ID.
- Report file written before a prior status update crashed -> reuse only when
  its embedded finding ID matches, then finish the status update.
- Finding marked `generated` before Queue sync -> retry the Queue owner, persist
  `queue_sync` through `update_finding_status`, then rebuild the Index.
- Queue action already `reported` but Finding lacks `queue_sync` -> recognize
  the same finding/report identity as `unchanged`; do not mutate the Queue again.
- Multiple equal-rank Queue matches -> persist/return `ambiguous`; do not choose
  one automatically. Queue exception -> persist `error` so a later run retries.
- Canonical `authentication_bypass` finding -> select the `auth_bypass` report
  template and allocate an `auth_bypass_<N>.md` report ID; do not fall back to
  `misconfig`.

### 5. Good/Base/Bad Cases

- Good: coverage adds one candidate while an existing validated SQLi row and
  its report fields remain unchanged.
- Good: a second incremental SQLi report becomes `sqli_002`; `sqli_001.md`
  remains byte-for-byte unchanged.
- Good: two findings validated into one directory receive distinct summary and
  notes paths, and each canonical row verifies its own summary digest.
- Good: an incomplete root claim is reconciled once, then a matching runner
  fills its endpoint without changing the finding ID.
- Good: a validated canonical `authentication_bypass` finding generates an
  `auth_bypass_001.md` report while its canonical type remains unchanged.
- Good: interruption after report file, Finding update, Queue resolution, or
  before Index publish converges on one report/action after one rerun.
- Base: a legacy worker list is loaded once and rewritten as canonical object.
- Base: an unverified legacy `validated/generated` row becomes visible as
  `needs_owner_revalidation` until explicit `/validate` creates fresh provenance.
- Bad: a consumer reads an object as `[]`, appends its row, and discards every
  existing finding.
- Bad: each invocation starts report numbering at one and opens the path with
  mode `w`.
- Bad: `report_status=generated` causes the report generator to rebuild only the
  Index while leaving a matching Queue action active.

### 6. Tests Required

- `tests/test_finding_index.py` must cover list migration, duplicate lifecycle
  preservation, endpoint-less rows, incremental same-type reports, crash-file
  reuse/ownership, canonical-to-template aliases, and non-overwrite behavior.
- Coverage and parallel-worker tests must seed an existing canonical object and
  prove new rows do not erase it.
- Validation runner and `/validate` tests must assert the canonical object and
  counts after their write-back paths.
- Finality tests must cover direct edit -> rebuild/upsert quarantine, legacy
  migration quarantine, valid owner revalidation, and monotonic lifecycle merge.
- Root-claim tests must cover discriminator/schema, scheme-less target ownership,
  revision replay, multi-source idempotency, and incomplete runner completion.
- Validation tests must cover two findings in one artifact directory, summary
  content mutation, cross-finding report ownership, and strict legacy
  machine-decision zero-write.
- Report tests must inject interruption after report creation, Finding binding,
  Queue resolution, and before Index publish; retry must preserve one report ID,
  one Queue action, terminal `reported`, persisted `queue_sync`, and one Index row.
- Terminal Queue matching must reject endpoint-only matches from another finding.

### 7. Wrong vs Correct

#### Wrong

```python
rows = json.loads(path.read_text())
rows.append(finding)
path.write_text(json.dumps(rows))
```

Wrong:

```python
finding["type"] = "auth_bypass"  # 为报告模板改写 canonical taxonomy
```

Wrong:

```python
if finding["report_status"] == "generated":
    return existing_index_row  # 跳过仍未同步的 Queue owner
```

#### Correct

```python
from tools.finding_index import upsert_finding

upsert_finding(findings_dir, finding, target=target)
```

Correct:

```python
template_type = _report_vuln_type(finding)  # 仅报告消费者选择模板
```

Correct:

```python
queue_sync = sync_report_action_queue(target, finding, finding["report_file"])
update_finding_status(findings_dir, finding["id"], queue_sync=queue_sync)
```

## Runtime-v2 Checkpoint Witness Contracts

### 1. Scope / Trigger

Use this contract whenever checkpoint output, runtime-v2 session state, or the
`/autopilot` pressure validator changes.

### 2. Signatures

- `build_checkpoint(repo_root, *, target, ...) -> dict`
- `write_checkpoint_witness(repo_root, target, checkpoint) -> dict`
- `begin_round(repo_root, target, *, max_lanes) -> dict`
- `record_round_lane(repo_root, target, *, lane, max_lanes) -> dict`
- `prepare_round(repo_root, target, max_lanes) -> dict`
- `settle_round(repo_root, target, *, note="", refresh_coverage=True) -> dict`
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

`snapshot_digest` is computed from the current Queue, Coverage, Ledger, Finding,
Surface, Recon and enrichment projections; the `global_review` field itself is
excluded from digest material so recording it cannot invalidate its own attestation.
Every evidence reference must resolve to a non-empty file owned by the target.
`follow_up` must name an existing active Queue action. Missing, malformed, stale, or
unmapped reviews project `global_review_required`, `global_review_invalid`, or
`global_review_stale`; those are Checkpoint handoffs, not external permission gates.
Any owner write that changes the digest invalidates the prior review. No new state,
Queue, controller, or state machine is introduced.

### 3. Contracts

- Runtime-v2 `session.json` stores only non-derivable breadcrumbs. It must not
  regain v1 `context_pack`, selected-skill, card, surface, or queue snapshots.
- Every successful checkpoint atomically replaces a small witness containing
  `schema_version`, `kind=autopilot_checkpoint_witness`, `generated_at`,
  `target`, `target_key`, and `context_pack` recommendation fields.
- Witness context includes advisory `selected_skill`, `knowledge_cards`,
  `reference_hints`, and `required_checks`; it does not duplicate full surface,
  finding, evidence, or queue bodies.
- A successful checkpoint preserves the prior `global_review` witness while
  owner writes change its digest; Closure then reports it stale until the
  current snapshot is reviewed again.
- `round_progress` is the same witness's bounded execution budget. Reads and
  mutations use the checkpoint target lock; active rounds retain their original
  max and unique claimed lane IDs across CLI/context restarts.
- `settle_round()` holds that same target lock from its Closure preflight through
  checkpoint/coverage write-back, Queue sync, round closure, and final projection.
  The lock is same-thread reentrant so existing checkpoint owner functions remain
  the only mutation paths. A concurrent lane claim waits, then is rejected after
  the round becomes completed; it cannot enter between preflight and first write.
  If the post-write Surface projection remains stale or unavailable, checkpoint
  and Queue write-back may persist but round closure is deferred; the active round
  and all existing evidence remain recoverable.
- `checkpoint.py` mutations and `autopilot_state.py` Closure projection use the
  same `checkpoint_witness.validate_round_progress()` structural validator.
  The reader-only recovery flag may expose historical completed lanes with
  invalid evidence for repair, but it never relaxes schema, `1..MAX_LANES`,
  derived-count, lane-order, bounded-text, timestamp, or terminal-field checks.
- New explicit passive claims (`idle:*`, `monitor:*`, `verify:idle*`,
  `verify:no-change*`, or `idle-no-change`) are rejected before budget mutation;
  duplicate legacy passive lanes keep their started/terminal recovery semantics.
- The pressure validator reads the witness plus durable queue/ledger artifacts.
  It validates structural workflow evidence, not exploitability or value.

### 4. Validation & Error Matrix

- Runtime-v2 session plus complete witness -> context check passes.
- Session exists but witness is missing -> context check fails and loses the
  context-pack score; do not inspect deprecated v1 session fields.
- Witness has no recommended skill or no card/reference detail -> context check
  fails with the precise missing field.
- Atomic witness write fails -> checkpoint fails fast; do not claim a completed
  checkpoint without its review artifact.
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
- The explicit post-lane `--loop-check --projection-only` projection returns the
  existing `loop_guard` plus a bounded `control` object (`hard_gate`,
  `priority_frontier`, `next_action`, `fallback_action`, and `selection_mode`).
  The controller may use this as its refreshed frontier state; it must not issue
  a second ordinary state read for the same heartbeat unless the command fails or
  a later owner write requires a fresh snapshot. The projection is derived only
  and creates no owner state.

### 5. Good/Base/Bad Cases

- Good: `build_checkpoint()` chooses a Skill/card, writes the witness, and the
  real pressure validator awards the full context score.
- Base: an early checkpoint has a recon Skill and coverage card; that is still
  valid routing evidence.
- Good: settle sees no started lane, holds the witness lock across all owner calls,
  closes the round, and a waiting late claim observes the completed round.
- Bad: tests hand-inject v1 `context_pack` into `session.json` while production
  runtime-v2 writers never create that shape.
- Bad: settle checks `unfinished_lanes`, releases or never acquires the witness
  lock, then permits a concurrent `record_round_lane()` before checkpoint write.

### 6. Tests Required

- `tests/test_checkpoint.py` must assert witness path, kind, and context parity
  with the returned checkpoint.
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

### 7. Wrong vs Correct

#### Wrong

```python
session["context_pack"] = build_context_pack(...)
```

#### Correct

```python
checkpoint = build_checkpoint(repo, target=target)
# state/<target_key>/checkpoint_latest.json is the bounded runtime witness.
```

Wrong: duplicate `round_progress` field validation in Checkpoint and Closure readers.

Correct: both consumers call `validate_round_progress()`; only the read-only
historical-evidence repair path enables its explicit compatibility flag.

Wrong: treat the no-started-lane preflight as sufficient without holding the
checkpoint witness lock across subsequent writes.

Correct: `settle_round()` acquires the existing witness lock once and reuses the
same owner functions under its same-thread reentrant scope.

## Target Case State Contracts

### 1. Scope / Trigger

Use Target Case State when a target has reusable actors, sessions, owned
objects, private markers, active hypotheses, or validation backlog items. This
is runtime target memory, not knowledge-card content.

### 2. Signatures

- `python3 tools/target_case_state.py summary --target <target> [--json]`
- `python3 tools/target_case_state.py add-actor --target <target> --actor <id> --role <role>`
- `python3 tools/target_case_state.py add-session --target <target> --session <id> --actor <actor> --kind <kind> --header-name <name> --header-value <value>`
- `python3 tools/target_case_state.py add-object --target <target> --object <ref> --type <type> --owner-actor <actor> --endpoint <url> [--private-marker <marker>]`
- `python3 tools/target_case_state.py add-hypothesis --target <target> --vuln-class <class> [--id <hypothesis_id>] [--metadata-json <object>]`
- `python3 tools/target_case_state.py add-backlog --target <target> --runner idor-actor-pair --owner-actor <actor> --peer-actor <actor> --object-ref <ref>`
- `python3 tools/target_case_state.py add-backlog --target <target> ... [--hypothesis-id <hypothesis_id>]`
- `python3 tools/target_case_state.py next --target <target>`
- `python3 tools/target_case_state.py complete-backlog --target <target> --id <val_id> --result <status> --evidence-ref <path>`
- `python3 tools/action_queue.py add --target <target> ... [--metadata-json <object>]`
- `evidence_ledger.build_summary(..., vuln_classes: list[str] | None = None) -> dict`

### 3. Contracts

- Storage path is `state/<target_key>/case_state.json`; do not commit target
  case state.
- Actor/session/object/hypothesis/backlog mutations use one target-level
  `case_state_mutation_lock()` around load, mutation, and atomic replace; a
  concurrent writer must not silently lose an update.
- Public session rows contain only metadata and `private_ref`. Header values are
  stored as `0600` files below `.private/case-state/<target_key>/sessions/`, and
  `.private` directories are `0700`. `load_case_state()` fails on a missing,
  malformed, or off-path private reference.
- `next` must not be a checklist-only output. It must include hypothesis,
  chain context, why-now reasoning, exact/replay draft when ready, required
  evidence, missing evidence, downgrade rule, stop condition, chain extensions,
  and write-back instruction.
- Raw command may contain local session headers for operator copy/paste, but
  `redacted_command` must also be emitted for safe summaries.
- Missing actor/session/object/private marker should produce
  `next_action=enrich_case_state`, not a fake validation command. A missing
  private marker is advisory when owner session, peer session, and object
  endpoint are ready: surface it in `optional_evidence_gaps` and let
  `validation_runner.py` downgrade unless marker-backed or exact non-trivial
  owner-body-match evidence appears.
- Persisted backlog items naming an unsupported or retired runner remain
  readable but project `next_action=enrich_case_state` with an empty command;
  they must never execute through a guessed replacement runner.
- `tools/checkpoint.py` should ingest the active `top_next_action` from case
  state and surface it ahead of generic coverage-gap / actor-gap follow-ups.
  Ready backlog items should expose exact replay drafts; not-ready backlog items
  should expose missing evidence, downgrade rule, stop condition, chain
  extensions, and write-back shape.
- A backlog may link to one hypothesis through `hypothesis_id`. Completing a
  linked backlog writes `metadata.last_outcome` and bounded
  `metadata.recovery_next_action` on that hypothesis. A `blocked` outcome
  projects `recover_hypothesis` with an empty replay command; it must not
  silently rerun the failed runner. `tested_clean`/`dead_end` close the linked
  hypothesis, while `tested_finding` leaves it as a candidate for `/validate`.
- Hypothesis `vuln_class` is a non-empty compatibility string, not a closed
  taxonomy. `add-hypothesis --metadata-json` accepts a JSON object for free
  family/primitive/chain context and rejects credential-bearing keys or values
  before mutation, including secrets embedded under descriptive allowlisted
  fields. `target_case_state.project_hypothesis_metadata()` is the sole
  bounded projection owner for Case State summaries and Autopilot; it allowlists
  `family`, `primitive`, `boundary`, `impact`, `chain`, `chain_id`, `dimensions`,
  `confidence`, `provenance`, `evidence_refs`, `next_question`,
  `stop_condition`, and descriptive `token_location`, recursively removes
  sensitive keys/legacy credential-shaped values, and bounds nested values.
- Knowledge cards and `hypothesis_seeds` are advisory inputs, not family
  conclusions or Queue actions. Context Pack and Checkpoint may query the actor matrix only from
  explicit owner-backed canonical families. `build_summary(vuln_classes=None)`
  keeps the legacy `IDOR/Authz` default; explicit `vuln_classes=[]` means no actor
  matrix rows, gaps, or record commands.
- The canonical Coverage taxonomy is a one-way compatibility projection, not the
  AI hypothesis space. Unknown families and incomplete identity candidates remain
  executable/open; only an owner-backed Matrix terminal state or a complete
  validator-confirmed `identity_v2` can close canonical Coverage.
- `tested_clean` and `dead_end` must not close a backlog that matches a
  lifecycle-final canonical Finding. `complete_backlog()` rejects the write;
  summary exposes the same conflict when reading legacy state so Autopilot can
  reconcile the Finding owner instead of hiding it behind Case State finality.
- Generic deep actions may carry `hypothesis_id`, `tested_dimensions`,
  `expected_learning`, `kill_condition`, `next_question`, `attempts`,
  `last_outcome`, and `pivot_hints` in existing Action Queue `metadata`.
  `--metadata-json` accepts only a JSON object and fails before queue writes;
  this is a metadata extension, not a second state owner.
- Command and rule docs must describe this as case-state-first, not
  case-state-only. Empty, stale, or irrelevant case state must never block
  discovery, browser/JS/source enrichment, ranked-surface hunting, or AI
  chain pivots. New evidence should enrich or supersede case state instead of
  being forced through an old backlog.
- `tools/case_state_seed.py` is suggestion-only. It may read cached
  recon/browser/JS/source artifacts and emit `add-actor`, `add-object`, and
  `add-backlog` command drafts, but it must not auto-write case state or claim
  candidate/finding status.
- Case-state public sessions contain metadata and a private header reference.
  `load_case_state()` hydrates the full `headers` map in memory for validation;
  `header_name` / `header_value` remain compatibility fields only and must never
  be serialized into the public state file.

### 4. Validation & Error Matrix

- Adding a session for a missing actor -> fail-fast.
- A missing/invalid private session reference -> fail-fast; do not fall back to
  empty or anonymous headers for an existing actor session.
- Adding an object with a missing owner actor -> fail-fast.
- Non-object members or duplicate non-empty IDs in `hypotheses` or
  `validation_backlog` -> fail-fast with an explicit `ValueError`.
- `add-backlog --hypothesis-id` referencing an unknown hypothesis, or reusing
  an existing hypothesis/backlog ID -> fail-fast before mutation.
- Invalid/non-object `add-hypothesis --metadata-json`, or credential-bearing
  nested metadata -> fail-fast before mutation without echoing the secret value.
- Explicit empty actor-matrix families -> empty matrix projection; missing
  argument -> legacy default; unknown/free hypothesis family -> no invented
  `Authz`, `IDOR`, or `RCE` projection.
- IDOR backlog with owner/peer/object/session/private marker present -> ready
  runner command.
- Ready backlog command should include `--complete-case-state` when a concrete
  backlog id exists, so repeated autopilot loops do not re-run stale evidence.
- Missing peer session -> not ready; return missing evidence.
- Missing private marker with owner/peer/object ready -> ready replay plus
  `optional_evidence_gaps=["owner private marker"]`.
- Completing backlog moves it out of active `next` selection.
- Completing a linked backlog with `blocked` keeps a durable recovery pointer
  but returns `ready=false`, `next_action=recover_hypothesis`, and no replay
  command until the recovery step is recorded.
- Cached object-shaped endpoints with concrete IDs -> seed suggestions; route
  templates without concrete object IDs -> no object registration.
- Cached transport/session/cache identifiers such as Socket.IO `sid`, `EIO`,
  `transport`, timestamps, CSRF tokens, JWTs, or generic session tokens are not
  business objects and must not create `add-object` / IDOR backlog suggestions.

### 5. Good/Base/Bad Cases

- Good: `user_a` owns `order_123`, `user_b` has a peer session, object has a
  private marker, and `next` emits an `idor-actor-pair` command plus fallback
  chain extensions.
- Base: sessions exist but private marker is missing; keep as enrichment need,
  but do not block replay. The runner may return `candidate` or `tested_clean`;
  only marker-backed or exact non-trivial owner-body-match evidence can become
  `tested_finding`.
- Base: `/orders/123` in browser/recon/source artifacts creates a suggested
  `order_123` object and IDOR backlog draft, but the operator still supplies
  sessions and private markers.
- Base: `.private/user-a.json` contains Cookie, CSRF, tenant, and custom auth
  headers; `target_case_state.py add-session --auth-file` stores all of them in
  a private session artifact, and `validation_runner.py --from-case-state`
  replays the full set from the hydrated owner state.
- Bad: store target-specific sessions, object IDs, or private markers in
  `knowledge/`, `skills/`, or tracked docs.
- Bad: replay only the first Cookie/Bearer header from case state when the
  actor context also needs CSRF, tenant, org, or custom auth headers.
- Bad: seed tool auto-applies generic `user_a` / `user_b` or marks a backlog as
  validated just because an endpoint contains an ID.
- Bad: treat a blocked backlog's recovery text as an executable runner command,
  or create a second queue to store hypothesis history.

### 6. Tests Required

- `tests/test_target_case_state.py` must cover empty-state shape, actor/session
  validation, object registration, hypothesis/backlog insertion, `next`
  readiness, missing evidence, write-back, CLI JSON output, public-file secret
  absence/private permissions, and concurrent actor/session mutation.
- It must also cover hypothesis linkage, blocked recovery without replay,
  duplicate/corrupt hypothesis/backlog records, and recovery projection through
  `autopilot_state`/`checkpoint` into Action Queue metadata.
- Hypothesis metadata tests must cover CLI round-trip, free family/chain values,
  recursive key/value secret filtering, bounded projection, and descriptive
  fields such as `token_location` that are not credential values.
- The local long-loop witness must exercise a localhost compound surface across
  at least two bounded rounds, preserve queued work and started-lane recovery,
  and prove that three identical no-information closures become a bounded
  stagnation handoff rather than false completion. Runtime staging must also
  cover a real `claude -p` Bash `tool_use -> tool_result` exchange across two
  independent invocations; the fake backend is protocol evidence, not model
  quality evidence.
- Context Pack, Checkpoint, Evidence Ledger, and identity tests must cover empty
  actor-matrix input, owner-backed family reuse, unknown/incomplete candidates
  staying open, and complete RCE identity projection through the existing validator.
- `tests/test_action_queue.py` must cover `--metadata-json` round-trip,
  duplicate upsert idempotency, and invalid/non-object JSON zero-write behavior.
- Any future validation-runner integration via `--from-case-state` must assert
  fail-fast behavior for missing actors/sessions/objects.
- `tests/test_checkpoint.py` must cover both ready case-state backlog
  prioritization and enrichment-mode backlog surfacing.
- `tests/test_case_state_seed.py` must cover object extraction from paths/query
  params, source/JS artifacts, existing-state de-duplication, missing evidence
  labels, and CLI JSON output.

### 7. Wrong vs Correct

#### Wrong

Write Cookie/Bearer headers directly into the tracked/public case-state JSON, or
let concurrent callers perform independent load-then-save updates.

#### Correct

Persist target-specific metadata and backlog under `state/<target_key>/case_state.json`,
keep session headers in its private reference, and let Claude use `next` to
choose the highest-value chain step before deterministic validation replay.

For a blocked linked hypothesis, preserve the outcome and expose only a
structured recovery pointer:

```json
{
  "hypothesis_id": "hyp_001",
  "last_outcome": {"status": "blocked", "evidence_ref": "..."},
  "recovery_next_action": "capture the export route"
}
```

The existing Action Queue may carry the same metadata via `--metadata-json`; it
does not become a new lifecycle or evidence owner.

Wrong: infer `RCE`, `IDOR`, or `Authz` from a selected knowledge card or broad
keyword and use that inference to close or manufacture Coverage work.

Correct: persist the AI's free hypothesis in Case State/Queue, then project only
complete owner-backed evidence through the existing identity and Closure owners.

---

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

### Queue candidate projection idempotency

Runner candidate follow-ups and Checkpoint candidate projections may use different
human-readable evidence, question, and command text. The Action Queue must not
interpret that presentation difference as a second lane: active
`candidate-evidence-gap` rows are merged by their existing finding identity or,
when no finding ID exists, the existing endpoint/execution identity from
`_action_identities()`. A Runner rewrite refreshes the stored `dedupe_key`, and
identity-matched Checkpoint ingestion adopts the incoming key so later replays
are key-idempotent. Historical duplicate candidate rows are retained as
`n/a` records with `metadata.dedupe_retired=true`; they are not final owner
evidence and do not suppress the surviving active lane. This applies only to
active candidate-gap projections; it does not collapse distinct validation,
coverage, or final owner actions.

### 1. Scope / Trigger

Use these contracts whenever checkpoint, validation runner, report generator,
coverage matrix, and action queue interact. The goal is not to pass a lab; lab
or target execution is only a pressure test for whether discovery, validation,
reporting, and handoff state converge without repeated TODO loops.

### 2. Signatures

- `python3 tools/checkpoint.py --target <target> [--json]`
- `python3 tools/action_queue.py ingest-checkpoint --target <target>`
- `python3 tools/action_queue.py next --target <target>`
- `python3 tools/action_queue.py claim --target <target>`
- `python3 tools/action_queue.py add --target <target> ... [--metadata-json <object>]`
- `python3 tools/action_queue.py resolve --target <target> --id <AQ-id> --status <status> --evidence <text> [--notes <text>]`
- `python3 tools/report_generator.py <findings_dir>`
- `load_queue(repo_root, target) -> dict`
- `save_queue(repo_root, target, queue) -> Path`

### 3. Contracts

- `checkpoint.py` may expose broad coverage statistics, but it should only
  promote a coverage gap into `next_action_queue` when the gap has concrete
  semantic fit (`relevance_score > 0`) from path, parameter, browser, source, or
  finding evidence.
- Action queue reads return an empty schema only when the file is absent. Bad
  JSON, non-object payloads, wrong schema versions, and non-list `actions` fail
  fast with the queue path; checkpoint must surface that failure instead of
  silently rebuilding from an empty queue.
- Queue claim and writes hold the target queue lock across complete
  read-select-mutate-replace. Writes use a same-directory temporary file,
  `flush/fsync`, then atomic `Path.replace()`; replace failure preserves old bytes.
- Resolving `validated` or `reported` requires an existing repository-local
  artifact under a recognized evidence root (`evidence`, `findings`, `reports`,
  `recon`, or `.private`). An arbitrary source/documentation file such as
  `README.md` does not satisfy terminal evidence merely because it exists.
- Resolving a previously claimed (`running`) action as `tested` uses the same
  locatable-artifact rule. Unclaimed legacy queued rows remain compatible for
  recovery, but new runners claim before replay and cannot close execution
  without its artifact.
- `running` actions always resume before new queued/report/advisory work. Claiming
  queued work changes it to `running` once; re-claiming running work is idempotent
  and preserves attempts, notes, evidence, and the queued siblings.
- Generic high-impact cells such as `/rest/admin x RCE` with no execution sink,
  parameter, method, or body signal remain visible in coverage counts but must
  not become immediate ready actions.
- Actor-matrix gaps are not automatically executable. Anonymous baseline gaps
  may enter the queue without case state, but owner/peer/low-role/cross-tenant
  gaps require registered runtime actor/session/object context first. If that
  context is missing, checkpoint emits a recoverable case-state handoff for the
  affected role lane while unrelated discovery/replay remains available.
- The actor/session prerequisite is local to the affected owner/peer comparison
  lane. Closure exposes `actor_context_gap` with `blocking=true`,
  `reason=actor_context_required`, and `next_action=resume_case_state` when that
  context is missing or partial. The handoff must point to `add-actor` /
  `add-session`; it must never synthesize credentials or silently close the lane.
  Anonymous, public-exposure, source, browser, injection, workflow, and other
  independent lanes remain executable. The affected Matrix cells remain
  unknown/untested rather than becoming `tested_clean`.
- A persisted checkpoint enrichment lead whose `missing_evidence` is only
  actor/session/business-object context remains recoverable for an explicit
  later claim, but is advisory in the automatic Queue projection until that
  context exists. It must not become `durable_work_pending` merely by being
  written to `action_queue.json`.
- Ranked-surface Authz/IDOR/GraphQL/CSRF drafts must also respect the same
  runtime-context boundary. If actor/session/object context is missing, the
  replay draft should request exact browser baseline capture or case-state
  registration first, and the ledger skeleton should use a context-prerequisite
  signal rather than pretending owner/peer replay evidence exists.
- Red-line gating must be based on explicit side-effect risk (`red-line`,
  `state-changing`, `mutation`, `unsafe`, `delete`, destructive behavior), not
  merely on words such as `actor`, `role`, or `owner` in an authorization replay
  draft.
- `checkpoint.py` must filter actions already final in persistent
  `action_queue.json`; `recommended_executable_action` should be empty when all
  current suggestions have already been resolved.
- Re-ingesting checkpoint-generated actions may lower priority or clear stale
  `redline_required` flags because checkpoint is a current-state projection.
  Manual/non-checkpoint queue items should preserve conservative priority/risk
  merging.
- Legacy `ranked-surface` queue items are advisory unless their `command_hint`
  contains an exact replay command such as `python3 tools/validation_runner.py`.
  Older high-priority `ranked-surface` actions must not preempt reports or the
  current `surface-review` candidate set merely because they were created before
  the AI-first rename.
- If `decision` would be `continue`, `hunt`, `enrich`, or `checkpoint` but the
  filtered queue is empty, return `decision=handoff` instead of a contradictory
  "continue with no action" state.
- Checkpoint proposal windows must be wider than the final displayed
  recommendation count. Persistent action-queue final-state filtering happens
  after proposal generation; if secondary-sweep, coverage, or already-final
  ranked-surface items fill the early slots, checkpoint must still expose fresh
  ranked-surface candidates behind them instead of handing off while P1 surface
  remains.
- Checkpoint proposals are versioned structured entries
  (`{schema_version: 1, text, type, priority, command_hint, metadata}`).
  Producers that hold structured fields emit them directly; `text` stays
  human-readable prose for `target_write_back` and target-memory consumers.
  `_classify_next_action` / `_extract_action_metadata` are a dual-read channel
  for remaining plain-string producers (recon, enrichment hints, viewstate,
  secret, cross-evidence, high-risk lanes, secondary-sweep, unsafe-skipped,
  case-state seed, root-claim evidence gaps) and for legacy on-disk queue
  items via `validation_runner._action_matches_legacy_marker`; migrated
  families must not re-grow prose-only extraction paths.
- `report_generator.py` must mark `report_status=generated` in `findings.json`
  and best-effort close matching `report` queue items as `reported`.
- Rebuilding `findings.json` must preserve replay/validation-backed findings
  that were appended by `validation_runner.py` or `/validate` even when no
  scanner text line currently reproduces the same ID. Default unvalidated
  scanner-only orphans may disappear with their source artifact; validated,
  rejected, partial, reported, or `source_file=evidence/.../summary.json` rows
  are runtime state and must survive target-owned rebuilds.
- `report_generator.py` must derive report directories with
  `target_storage_key()`. URL-form targets such as `http://127.0.0.1:3002`
  write under `reports/127.0.0.1:3002/`, never `reports/http:/...` or
  ad-hoc sanitized variants.
- Report indexes are cumulative state for the target, not "reports generated in
  this invocation". Re-running `report_generator.py` for one new validated
  finding must keep previously generated structured reports in
  `INDEX.json`/`SUMMARY.md`.
- Context contradictions are advisory evidence only. `checkpoint.py` may show
  them, but must not enqueue a `context-review` action merely because a remembered
  dead end token-overlaps with fresh evidence; Claude decides whether it matters.
- Closure checks for Claude-facing outputs must go through
  `tools/closure_resolver.py`, not fresh local logic in `checkpoint.py`,
  `context_pack.py`, `surface.py`, or future consumers. The resolver is a
  state-dedup gate only: it may answer whether an exact endpoint × vuln_class,
  artifact review, or newer dead-end closure is final, but it must not rank
  surfaces, decide value, delete raw attack surface, or infer reportability.
  Unknown/generic vuln classes fail open; Authz and IDOR do not close each
  other globally. Placeholder object replay may additionally consult the
  concrete object's IDOR closure because that lane is explicitly an object
  replay, not a general Authz/IDOR family rule.
- `closure_resolver.py` also owns canonical vulnerability aliases used by
  coverage and identity consumers. `NoSQLi`, `PrototypePollution`,
  `OpenRedirect`, and `BusinessLogic` are append-only canonical families and do
  not inherit SQLi, XSS, or Authz disposition. SSTI, command injection,
  deserialization, LFI, RFI, and other same-family variants remain technique
  hints. Checkpoint consumes `VULN_CLASSES` directly so every family appears once.
- Closure identity is endpoint × vulnerability class × technique or an exact queue/finding
  action, never a bare endpoint path. A closed Authz/IDOR/SQLi/SSRF cell may
  suppress repetition of that exact lane, but raw `/surface` endpoint evidence
  remains visible for other classes and fresh browser/JS/source/workflow signals.
  Surface may attach `ledger_history` / `action_queue_history` as advisory
  context; it must not convert that history into a path-wide score cliff or
  exclusion.
- Already finalized findings (`validated`, `rejected`, or
  `report_status=generated`) must not be re-promoted as the same exact finding or
  report action. If the available item is only raw URL surface without that exact
  identity, keep it reviewable rather than treating the path as globally closed.
- Resolving an action-queue item as `dead-end` or `blocked` closes that current
  action only. It must not map the coverage cell to `tested_clean` or `n_a`;
  only explicit tested/finding/not-applicable evidence may change those states.
- Validation runner summaries are AI-review evidence, not final findings. A
  non-final runner candidate that is not owned by an active structured finding
  should become a checkpoint validation action phrased as "review raw evidence,
  then `/validate` or ledger downgrade"; checkpoint must not hand off while such
  evidence is the only open reportability decision.
- Runner candidate pools must suppress summaries already closed by final
  structured finding state (`rejected` or `report_status=generated`) or by a
  later non-runner evidence-ledger row (`tested_clean`, `tested_finding`,
  `dead_end`, `blocked_redline`, `not_applicable`). Runner-written ledger rows
  stay visible because they are the evidence needing AI review.
- `/validate` summaries must preserve the HTTP `method` used by the validated
  replay, and ledger sync must write that method instead of defaulting every
  validated endpoint to `GET`.
- Any ledger row explicitly marked state-changing requires an explicit
  `redline_checked` decision, regardless of whether it uses `POST`, `PATCH`, form,
  SOAP, or another method. Missing redline downgrades covering results to terminal
  `blocked_redline` while retaining `requested_result`; an explicitly
  non-state-changing preview is not downgraded merely because its method is
  `PUT`/`PATCH`/`DELETE`. Unknown method effect is an evidence-classification gap,
  not a red-line conclusion. Ledger appends are serialized per target so concurrent
  runner writes remain valid JSONL.
- Coverage-gap proposals must respect evidence-ledger closed cells. If the
  ledger already has `endpoint x vuln_class` as `tested_clean`,
  `tested_finding`, `dead_end`, or `not_applicable`, checkpoint should keep the
  broad coverage count but not propose that cell as the next executable action.
  Vulnerability-class normalization for this comparison must cover all matrix
  classes, not default unknown labels to `Authz`.

### 4. Validation & Error Matrix

- Queue file absent -> return the canonical empty queue.
- Queue JSON/shape/schema invalid -> raise a path-bearing `ValueError`; CLI and
  checkpoint exit `2` instead of treating the queue as empty.
- Atomic replace fails -> propagate the error, keep the old queue byte-for-byte,
  and remove the temporary file.
- Checkpoint suggestion matches an action queue final dedupe key -> omit it from
  `next_action_queue`.
- Checkpoint sees only zero-relevance coverage gaps -> keep coverage statistics,
  but do not enqueue coverage-gap actions.
- Checkpoint sees actor-matrix owner/peer gaps with empty case state -> enqueue
  at most anonymous baseline plus a low-priority enrichment lead, not fake
  owner/peer replay actions.
- Checkpoint ranks an IDOR/Authz surface but case state is empty -> keep the
  surface lead, but phrase it as browser baseline / case-state prerequisite,
  not as an executable two-actor replay.
- Surface review pool contains both browser-observed candidates and higher-score
  score-only candidates -> browser/source/scanner evidence appears first in the
  review pool; score-only candidates remain visible as tail fillers.
- Checkpoint re-ingest changes an action from red-line/high-priority to
  non-red-line/lower-priority -> queued checkpoint action updates to the new
  projection unless it is already final.
- Queue contains a report plus a legacy `ranked-surface` action whose
  `command_hint` is only prose -> report is selected first. Queue contains a
  legacy `ranked-surface` with an exact `validation_runner.py` command -> treat
  it as substantive validation work.
- First N ranked surfaces already final in `action_queue.json` -> checkpoint
  rolls forward to later P1/P2 ranked surfaces and keeps `decision=continue`.
- Report draft generated for a validated finding -> update `findings.json` and
  close matching report queue item.
- Queue/finding state missing during runner/report sync -> return or record
  `sync.status=skipped`; do not fail evidence generation.
- Rebuild `findings.json` with scanner artifacts after runner-created findings
  exist -> unchanged scanner rows keep validation/report fields; target-owned
  runner/validate-backed rows absent from scanner text are appended back; off-
  target rows are not promoted.
- URL target in structured index -> report output path uses the target storage
  key; path/query/fragment are ignored for directory naming.
- A checkpoint contradiction exists but no concrete executable item remains ->
  output the contradiction under context, but do not create a `context-review`
  queue item or change handoff/report decisions.
- A validated/rejected/generated finding reappears with the same finding/action
  identity -> suppress that duplicate action; a raw endpoint item on the same
  path remains available for other vulnerability classes or fresh evidence.
- A runner summary is still candidate-ready and not final in findings/ledger ->
  checkpoint emits a validation action for AI review instead of handoff.
- A runner summary has a later AI-review or `/validate` ledger closure ->
  omit it from the runner candidate pool.
- `/validate --method POST` confirms a finding -> validation-summary and
  evidence-ledger row both record `method=POST`.
- A coverage gap matches a closed ledger cell -> omit the coverage-gap action
  while leaving the matrix count visible.
- Coverage alias input such as NoSQLi, deserialization, or RFI -> normalize
  through the closure owner; high-risk output contains canonical keys plus
  technique hints, not duplicate alias dispositions.
- A coverage-gap queue item is resolved as `dead-end` or `blocked` -> leave the
  matrix cell `untested`; the final queue row prevents immediate exact-action
  repetition without falsifying coverage.
- The immediate checkpoint projection may attach `_projection_family` metadata
  and emit one representative for an existing route-template or a high-volume
  structural family. This is an execution bound only: exact Queue identities
  remain endpoint-specific, sibling Matrix cells stay `untested`, and Closure
  still reads the complete canonical matrix.
- `_projection_family.size` is the complete family count while `members` is a
  bounded preview (currently at most 12 endpoints). The preview is advisory,
  does not assert family equivalence, and must direct AI to the raw Coverage gap
  window when `size > len(members)` so a queue bound never becomes a judgment
  bound.
- Coverage Action Queue dedupe must strip both `Queue projection only:` and
  `Family projection:` advisory suffixes from the action/evidence text. Changing
  projection wording must update an existing legacy row rather than retire and
  replace it.

### 5. Good/Base/Bad Cases

- Good: an interrupted queue replacement leaves the prior durable handoff
  readable and no `.tmp` file behind.
- Base: no queue file exists yet, so the owner returns an empty schema and the
  first action can be added normally.
- Good: a runner validates a finding, writes raw evidence, updates
  `findings.json`, and closes the active validation queue item; the next
  checkpoint moves to report or another evidence-backed action.
- Good: a runner summary exists for `POST /profile/image/url`; `/validate`
  records `method=POST`, and subsequent checkpoint state uses that exact method
  for evidence audit.
- Good: `GET /rest/products/search x XSS` remains in broad matrix statistics,
  but a ledger-backed XSS finding suppresses the executable coverage-gap action.
- Good: a ranked surface returns only `{"version":"x.y.z"}`; runner records
  `tested_clean` and closes the ranked-surface queue item.
- Good: a lower-score browser-observed XHR appears before a higher-score
  score-only helper endpoint in `review_pool`; Claude sees the real workflow
  evidence first while the helper endpoint remains available as a tail lead.
- Good: `/api/orders × Authz` is tested clean, so surface shows that lane as
  history while preserving `/api/orders` for SQLi, workflow, object, and fresh
  browser/source review.
- Good: `findings.json` rebuild preserves a validated XSS row whose source is
  `evidence/<target>/validation/.../summary.json`, while dropping a stale
  unvalidated scanner-only row whose text artifact no longer exists.
- Good: generating a new XSS report for `http://127.0.0.1:3002` appends it to
  the existing `reports/127.0.0.1:3002/INDEX.json` instead of overwriting the
  index with only the latest report.
- Base: checkpoint still reports many broad high-value coverage gaps, but none
  have semantic relevance; the system hands off rather than inventing low-value
  RCE/SQLi/SSRF TODOs.
- Base: old `ranked-surface` queue rows without runner commands remain visible
  for review, but they do not outrank report or current `surface-review`.
- Bad: a resolved secondary-sweep artifact keeps reappearing as the recommended
  executable action every checkpoint.
- Bad: `autopilot_state.py` re-sorts `review_pool` by `-score`, causing a
  generic high-score path to hide browser/source evidence from the first
  candidate window.
- Bad: `finding_index.py` rebuilds from scanner text and silently deletes
  runner-created validated/candidate rows, causing checkpoint to forget report
  or validation state.
- Bad: `report_generator.py` writes a URL target under `reports/http:/...` or
  rewrites `INDEX.json` to contain only the newest report.
- Bad: a dead-end memory overlap creates the highest-priority queue item even
  though it is only advisory context.
- Bad: checkpoint prints runner candidates that were already rejected/generated
  or closed by later AI-review ledger rows.
- Bad: `/validate` confirms a POST-only issue but writes `GET` into the
  evidence ledger.
- Bad: a ledger-closed coverage cell keeps reappearing as the next coverage-gap
  action.
- Bad: one finalized finding or queue row removes its entire endpoint from raw
  surface review, hiding unrelated vulnerability classes or newer evidence.
- Bad: `dead-end` is written as `tested_clean`, or `blocked` is written as `n_a`,
  merely to reduce coverage noise.
- Bad: queue becomes empty but checkpoint still says `decision=continue`.
- Bad: malformed JSON is swallowed as an empty queue and checkpoint overwrites
  the only recoverable handoff.

### 6. Tests Required

- `tests/test_validation_runner.py` must assert runner sync for structured
  findings and non-finding ranked-surface actions.
- `tests/test_finding_index.py` must assert report generation closes matching
  report queue items.
- `tests/test_finding_index.py` must assert finding-index rebuilds preserve
  runner/validate-backed orphan rows, drop default scanner-only orphans, and
  report generation keeps cumulative target indexes under canonical
  `target_storage_key()` directories.
- `tests/test_checkpoint.py` must assert zero-relevance coverage gaps are not
  queued, semantically relevant gaps still are queued, ledger-closed coverage
  cells are skipped, final action-queue items are filtered, and empty filtered
  queues produce handoff-compatible state.
- `tests/test_checkpoint.py` must assert advisory contradictions are not
  executable queue items and finalized finding URLs are not re-promoted as
  surface-review actions.
- `tests/test_checkpoint.py` must assert non-final validation-runner candidates
  become AI-review validation actions.
- `tests/test_structured_findings.py` must assert validation-runner candidate
  pools filter final findings and later non-runner ledger closures while keeping
  runner-only evidence visible.
- `tests/test_validate_target_mode.py` must assert validation summaries and
  ledger sync preserve explicit HTTP methods.
- `tests/test_surface_tool.py` must assert evidence-rich review candidates
  precede score-only tail candidates in `review_pool`.
- `tests/test_autopilot_state_tool.py` must assert `surface_review_candidates`
  preserve review-pool order instead of sorting by score.
- `tests/test_action_queue.py` must assert legacy prose-only `ranked-surface`
  is advisory while exact runner-backed `ranked-surface` remains substantive.
- `tests/test_action_queue.py` must assert corrupt JSON, invalid object/actions/
  schema shapes, path-bearing CLI diagnostics, and atomic replace failure that
  preserves old bytes and removes temporary files.
- `tests/test_surface_tool.py` and `tests/test_autopilot_state_tool.py` must
  assert cell/finding closure does not hide raw endpoint surface.
- `tests/test_action_queue.py` must assert `dead-end` and `blocked` leave the
  corresponding coverage cell `untested`.

### 7. Wrong vs Correct

#### Wrong

Optimize a lab by adding target-specific answers, or let checkpoint keep pushing
generic coverage cells until a human manually suppresses them.

```python
try:
    return json.loads(path.read_text())
except (OSError, json.JSONDecodeError):
    return empty_queue()
```

#### Correct

Use the lab to expose project failures, then fix the generic state contract:
evidence-producing tools close queue items, reports close report actions, and
checkpoint only asks Claude to execute semantically grounded next steps.

```python
if not path.is_file():
    return empty_queue()
payload = json.loads(path.read_text())  # 损坏或非法 shape 向上抛出
save_with_same_directory_temp_fsync_and_replace(payload)
```

---

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
- Good：模型文字中的 confirmed finding 与 `findings.json`、ledger 和 raw artifacts 一一对应。
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
  Q1–Q7 basis、CVSS、impact、至少一个存在的 raw evidence ref 及受 bound findings dir 约束的
  report path/content。
- machine binding 必须通过 `migrate_legacy=False` 只读加载 canonical/legacy payload；target、
  ID、endpoint、class、evidence 和 report ownership 全部通过后，才允许迁移或首次写入。
- machine decision 的成功路径只能调用既有 `finding_index` owner。行内
  `owner_provenance` 与 `mutation-events.jsonl` event 必须匹配 owner、operation、timestamp、
  target、finding ID、evidence summary 与 stripped-row fingerprint。
- `validated`/`rejected` 或 `generated`/`reported` 未通过 shared verifier 时，runtime、resume、
  surface、runner 与 report consumer 必须将其视为 candidate/owner revalidation；不得报告、
  suppress surface 或关闭 runner candidate。
- rebuild、legacy migration、通用 upsert 不得给未验证 finality 重签名；它们统一降级为
  `needs_owner_revalidation` 并保留 `claimed_*`。合法 `/validate` 可以产生新的 validated event。
- validation summary/notes 路径必须由 `tools/validate.py` 按 finding/report identity 生成并回传；
  caller 不得拼固定名。canonical row 保存 summary path/digest，shared verifier 校验内容；
  `last-validate.json` 只是 latest pointer。
- machine report 首次使用 exclusive create；已有路径只有在同 finding owner 重跑，或 crash
  replay 内容完全相同时可恢复。被另一 finding 占用时必须在所有 validation write 前拒绝。
- `--max-lanes N` 仅在 `--deep` 下有效，`N` 为 1..32。bootstrap 的
  `invocation_batch={bounded,max_lanes,handoff}` 是唯一 command/agent 输入；达到 N 个命名
  substantive lane 后 checkpoint 自动同步 durable queue、说明 handoff 并结束本次 invocation。
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
- canonical coverage/queue JSON 损坏时 `--closure --json` 必须返回
  `closure.verdict=error` 且 exit `2`；不得把损坏状态当 empty/handoff/finish。
- round 结束必须按 checkpoint/write-back → coverage rebuild/find-gaps → closure 排序；lane budget
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
| 直接 JSON 写 validated/generated | 下次 owner mutation 隔离为 `needs_owner_revalidation`；state 显示 owner revalidation，不生成报告 |
| owner API 写 validated/generated | verifier 成功；report/runtime 可消费同一 event |
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
- Base：legacy finalized list 首次 owner 读取迁移为
  `needs_owner_revalidation`，随后合法 decision 重新建立可信 validated event。
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

- `tests/test_validate_target_mode.py`：non-TTY zero-write、合法 decision 的 target/finding binding
  与 owner provenance、坏 binding 的无副作用、legacy read-only preflight、per-finding artifact、
  summary digest mutation 和 report path ownership。
- `tests/test_finding_index.py`：event round-trip、fingerprint/operation/timestamp mismatch 和 legacy
  migration/finality quarantine、rebuild/upsert trust normalization；
  `tests/test_autopilot_run_contract.py`：direct JSON reject、owner API accept。
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

This contract applies when Evidence Ledger, ClosureResolver, Checkpoint,
Autopilot, or coverage projections create or consume terminal closure state.
It extends the legacy endpoint x vulnerability projection without changing
target storage keys, Surface raw URL identity, or Finding IDs.

### 2. Signatures

```python
build_closure_cell(endpoint, family, dimensions) -> IdentityBuildResult
record_entry(..., identity_v2=None, identity_dimensions=None, identity_candidate=None,
             identity_replaces_event_id="") -> dict
ClosureResolver.is_closure_closed(identity_v2) -> bool
ClosureResolver.closed_result(endpoint, family, *, identity_v2=None) -> str
```

### 3. Contracts

- Complete keys persist as nested `identity_v2` objects with
  `schema_version=2`, `kind=closure_cell`, an `EndpointKey`, canonical family,
  and only that family's required dimensions. Persisted readers require both
  outer and nested `kind`/`schema_version` markers; missing or legacy markers
  fail open instead of being upgraded implicitly.
- A validation runner may accept `--identity-v2-json` for a key created during
  test planning. It carries that object through its Ledger request unchanged;
  Ledger still verifies endpoint, family, and overlapping durable facts before
  allowing `identity_status=complete`.
- Ledger rows may also persist `identity_candidate`, `identity_status`,
  `identity_missing_fields`, `identity_conflicts`, and
  `identity_follow_up_action`. AI candidates are untrusted until deterministic
  policy, confidence, provenance, evidence-reference, and Ledger-fact agreement
  gates pass. Deterministically comparable endpoint, family, or method
  disagreement creates a durable follow-up action and cannot emit `identity_v2`;
  semantic actor/object/workflow disagreement is carried as an explicit
  candidate conflict rather than guessed from differently named raw fields.
- Current family policies are stored in `tools/identity_contract.py`; unknown
  families and incomplete candidates are fail-open and cannot create a v2
  terminal cell.
- `closed_cells_v2` is the only complete family-aware terminal projection.
  Legacy `closed_cells` may contain only rows without `identity_status`; legacy
  rows are readable for audit but cannot close a v2 key.
- Ledger is the durable fact source. Checkpoint and Autopilot may expose v2
  cells and follow-up actions but must not reconstruct keys from display text.
- Coverage gap projections preserve an explicit `identity_v2` already attached
  to an untested cell. They do not synthesize one from endpoint, parameter, or
  display fields; ClosureResolver remains the validation/comparison owner.
- Ledger summaries expose `identity_v2_shadow` with deterministic legacy-only
  and v2-only closure differences during rollout. Checkpoint and Autopilot
  expose the Ledger's `identity_v2_follow_up_actions` projection so conflicts
  remain actionable rather than only incrementing a diagnostic counter.
- Identity enrichment never mutates an existing key. A later complete identity
  is a new linked cell with the original event ID, evidence reference, and old
  key (when present) preserved under `identity_replacement`. Current projections
  omit the replaced event while the append-only Ledger retains both rows.

### 4. Validation & Error Matrix

| Input | Result |
|---|---|
| Complete policy dimensions | `identity_status=complete`; eligible for `closed_cells_v2` |
| Missing required dimension | `identity_status=incomplete`; recorded but not closeable |
| AI low confidence/conflict/missing provenance | `follow_up_required`; durable follow-up metadata |
| Unknown family | `family_policy` missing; fail-open |
| Legacy path-only terminal | legacy display only; no v2 closure |
| Malformed `identity_v2` | ignored by v2 resolver; no terminal decision |
| Ledger partial/unreadable | clear both closure projections and handoff |

### 5. Good/Base/Bad Cases

- Good: SQLi `GET /search` with parameter `q` and `term` produces two distinct
  closure keys.
- Base: a legacy endpoint terminal remains visible in `closed_cells` while a
  new v2 cell remains open until its complete identity is recorded.
- Bad: a path-only terminal, AI guess, or endpoint summary closes a method,
  actor, object, parameter, sink, or workflow-specific cell.

### 6. Tests Required

- `tests/test_identity_contract.py`: deterministic encoding, every family
  policy, missing/conflicting dimensions, and AI candidate gates.
- `tests/test_evidence_ledger.py`: v2 persistence, legacy separation,
  candidate follow-up, redline interaction, replay and event-id idempotency.
- `tests/test_closure_resolver.py`: v2 matching, matrix/path-only fail-open,
  SPA and query separation.
- `tests/test_autopilot_state_tool.py` and `tests/test_checkpoint.py`: v2
  projection visibility and pending identity follow-up behavior.

### 7. Wrong vs Correct

```text
Wrong: closed_cells endpoint=/api/search, vuln=SQLi -> close every parameter.
Correct: closed_cells_v2 compares EndpointKey + family + method + parameter.

Wrong: AI candidate says parameter=q -> immediately mark tested_clean.
Correct: persist candidate provenance/confidence, validate deterministic fields,
        then close only after terminal evidence references the complete key.

## Scenario: AI-activated hypothesis depth and bounded continuation

### 1. Scope / Trigger

Use when Checkpoint projects an evidence-backed substantive action that must be
activated by AI before a validation Runner may execute it. Surface review,
runtime wait, recovery, and reporting actions remain versionless.

### 2. Signatures

- `claim_next_action(repo_root, target, *, action_id="", metadata=None)`
- `python3 tools/action_queue.py claim --target TARGET --id ACTION_ID --metadata-json JSON`
- `resolve_action(repo_root, *, target, action_id, status, result="", notes="", metadata=None)`
- Checkpoint action metadata: `activation_required`, `knowledge_refs`,
  `evidence_ref`, `baseline_ref`, `endpoint`, `method`, `input_boundary`, and
  `max_hypothesis_actions_cap`. An action-owner route may already be present;
  otherwise AI supplies `skill_route` at claim.

### 3. Contracts

- AI claim metadata uses `depth_contract_version=1`, a canonical primary `skill_route`, `hypothesis_id`, open
  `family`/`technique`, `active_dimension`, `expected_learning`,
  `kill_condition`, `risk_tier`, `max_hypothesis_actions`, optional selected knowledge
  references, and a bounded decision reason.
- Queue route validation resolves `skill_id` through the shared `SKILL_CATALOG`,
  requires the catalog's exact repository `skill_path`, and requires non-empty
  `required_dimensions`. An `active_dimension` outside the selected route is
  accepted only with a bounded `dimension_override_reason`; the first AI route
  selection is not a Skill override.
- Queue computes `execution_key` from endpoint/method/family/technique plus
  actor/object/workflow/dimension. Same key and evidence cannot repeat; changed
  evidence requires `repeat_reason`.
- Claim cannot disable stored `activation_required` or supply Runner-owned
  `last_outcome`, `tested_dimensions`, or `runner_operation_id`. The first
  explicit Skill selection does not require an override reason; replacing an
  action-owner route requires `skill_override_reason`.
- Missing or empty `selected_knowledge_refs` means Claude did not need a Card
  for this action and is accepted as `[]`. Non-empty values remain deduplicated;
  values outside action-owned `knowledge_refs` require a bounded
  `knowledge_override_reason`.
- Runner observation writes `last_outcome`, replayable refs, operation ID,
  `tested_dimensions`, and a bounded observation while the action stays
  `running`. An explicitly declared `baseline_only` observation is retained as
  recoverable context and cannot satisfy a kill resolve.
- AI terminal resolve supplies exactly one continuation kind or
  `kill_condition_met=true`; continuation materialization is at most one child
  and preserves the `depth_contract_version=1` hypothesis/parent/evidence
  lineage. `rotation` creates no child.
- `capability_primitives` is optional, target-owned, and capped at three; it is
  evidence lineage, not a second graph or state owner.
- A finalized versioned action with a target-owned primitive and concrete
  continuation hint may project one versionless `capability-chain-review` from
  Checkpoint. Its identity is the existing Queue tuple
  `source + parent_action_id + sha256(normalized primitive)` using
  `source_id` plus `metadata.generation`; active/final identities suppress
  replay, and an immediate `chain` continuation suppresses the review.
- The review is advisory, outside the hypothesis action cap, and cannot outrank
  running, validation, candidate, or report work. An executable chain is added
  as one normal versioned Queue action before the review resolves; unsupported
  speculation creates no review. Closure remains unchanged.

### 4. Validation & Error Matrix

| Input | Result |
|---|---|
| Missing activation or claim-selected route/evidence/budget field | reject before claim mutation |
| Claim overrides activation or supplies Runner observation fields | reject; queue bytes unchanged |
| Claim first selects a valid Skill route | accept without `skill_override_reason` |
| Claim replaces an action-owner Skill route without override reason | reject before claim mutation |
| Missing or empty `selected_knowledge_refs` | accept and normalize to `[]` |
| Non-empty selected refs outside action recommendations without reason | reject before claim mutation |
| Non-empty selected refs outside recommendations with reason | accept and deduplicate |
| Missing/non-primary Skill, path mismatch, or empty route dimensions | reject before claim mutation |
| Active dimension outside selected route without override reason | reject before claim mutation |
| Active dimension outside selected route with bounded override reason | accept and preserve the reason |
| Same execution key and same evidence | reject duplicate |
| Runner sync before claim or with off-target/partial evidence | `blocked`, action remains queued/running |
| Terminal resolve without observed difference, tested dimension, and outcome refs | reject; bytes stay unchanged |
| Both continuation and kill, or neither | reject before status mutation |
| Hypothesis action cap reached | reject continuation; preserve current action |
| Primitive lacks target-owned evidence or concrete continuation hint | no chain review projection |
| Active/final matching primitive review or immediate chain child exists | suppress duplicate review |
| Versionless action/metadata absent | retain legacy claim/resolve behavior |

### 5. Good/Base/Bad Cases

- Good: Context Pack recommends Skill/card context; Checkpoint preserves the
  evidence/baseline boundary without prebinding the recommendation; AI selects
  the route at claim, Runner observes it, then AI resolves one evidence-backed sibling.
- Base: a lower-risk action can use a smaller AI-selected cap and remains visible
  in Coverage even when not selected for deep execution.
- Bad: a score-only surface or one negative response becomes `tested` without a
  replayable outcome, tested dimension, or kill/continuation decision.

### 6. Tests Required

- `tests/test_autopilot_hypothesis_replay.py` must cover multi-source activation,
  pre-claim Runner blocking, activation/Runner-field spoof rejection, route
  provenance, canonical Skill/path and dimension-override rejection,
  optional/non-empty knowledge selection, missing write-back, one-child continuation, kill, budget,
  target-owned refs, and Closure handoff/finish.
- `tests/test_action_queue.py` must retain legacy pivot/claim/metadata regressions.
- `tests/test_checkpoint.py` must assert evidence-convergence activation and
  bounded Coverage window metadata, one-at-a-time primitive review projection,
  fingerprint idempotency, and immediate-chain suppression.

### 7. Wrong vs Correct

```text
Wrong: Checkpoint selects a Skill and Runner closes a negative action directly.
Correct: Checkpoint proposes; AI activates at Queue claim; Runner records only
         deterministic observation; AI resolves one continuation or supported kill.
```
```

## Scenario: Keep evidence-specific knowledge recall advisory after family closure

### 1. Scope / Trigger

Use when Context Pack recalls a concrete knowledge card, including after the
related canonical family is `tested` or `not_applicable`.

### 2. Signatures

- Context input: `knowledge_card_recall[{file,id,status,rank,reason}]`
- Checkpoint/witness output: bounded `context_pack.knowledge_card_recall[]`
- Diagnostic output: `_project_knowledge_effect_trace(checkpoint, actions) -> dict`

### 3. Contracts

- Preserve the Context Pack's stable selected/deferred recall order and bounded
  reasons in Checkpoint and its runtime witness.
- `knowledge_card_recall`, `hypothesis_seeds`, and `alternative_angles` remain
  diagnostic/advisory context. Checkpoint preserves its bounded seed/recall
  projection; none of these suggestions may create an Action Queue row or an
  activation `hypothesis_seed` by presence alone.
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
| Seed/recall exists without an owner action | keep advisory projection; Queue unchanged |
| Several selected/deferred recalls | preserve stable bounded recall in checkpoint/witness |
| AI selects a recommended card on claim | effect trace links the selected action/result |
| Family disposition is terminal | disposition remains unchanged; recall stays visible |
| Historical `knowledge-signal-review` exists | restore and resolve through compatibility path |

### 5. Good/Base/Bad Cases

- Good: RCE is `tested`; a later SSTI recall remains visible in the checkpoint
  and effect trace without reopening RCE or creating work.
- Base: an owner-backed SQL action can carry recommended context while its
  actual card selection remains an AI claim decision.
- Bad: a seed or unselected card creates a Queue item, activation hypothesis,
  or new technique Matrix dimension.

### 6. Tests Required

- `tests/test_checkpoint.py` must run a real Context Pack -> Checkpoint -> Queue
  path proving seeds/recall remain visible while no action is fabricated, and
  must preserve recall after terminal family dispositions.
- Effect-trace tests must cover pending, selected, and terminal result stages.

### 7. Wrong vs Correct

```text
Wrong: unselected seed/card -> generated durable Queue review.
Correct: keep the suggestion in checkpoint/witness/effect trace; only an
AI-selected, owner-backed action enters the Queue.
```

## Scenario: Invocation-local Autopilot owner projections

### 1. Scope / Trigger

Use when one Autopilot invocation builds State, Context Pack, and Checkpoint
from the same target. Owner projections may be passed between those calls to
avoid duplicate reads and to keep the invocation internally consistent.

### 2. Contracts

- A projection is read-only, invocation-local, and bound to the canonical
  target that produced it. Reusing it for another target must fail closed.
- Optional snapshot parameters preserve existing direct callers: when omitted,
  the callee performs its historical load path.
- Queue snapshots are shallow-copied before selecting or replacing `actions`;
  selectors must not mutate the caller-owned snapshot.
- State/Context Pack may reuse runtime, finding, candidate, case, observation,
  and valid Surface projections from the same invocation. Bounded bootstrap
  keeps its reduced Surface semantics and must not trigger a full rebuild.
- Coverage, Ledger, complete Queue, and round progress are closure-owned. Any
  write to Queue, Coverage, Finding, Ledger, Case, or round state invalidates
  the affected projection; final Closure and post-write Checkpoint reads must
  load fresh data.
- Round guard recording acquires the checkpoint witness lock before the target
  Queue mutation lock, then computes State/Closure from that locked Queue
  snapshot. Other code that needs both locks must keep the same order.
- One Closure evaluation binds `action_queue_next` and its active count to the
  same invocation-local Queue snapshot; a preloaded State pointer is advisory
  and never overrides that snapshot.
- Closure may expose a non-persistent `snapshot_digest` and bounded component
  generations for diagnostics. If owner file metadata changes during the read,
  the round coordinator retries once; a second change returns
  `state_snapshot_stale` with `refresh_state` instead of a terminal verdict.
- The Closure digest must include every decision projection it consumes,
  including Case State, Recon budget/continuation, Finding follow-up, Browser,
  Source, Intel, JS, SQL, JSON, Observation, Surface candidates, and Queue;
  changing one of these inputs must produce a new digest.
- Raw artifact readers and explicit cursors remain authoritative; projections
  must not truncate evidence or become a second persistence owner.

### 3. Validation & Error Matrix

| Input | Result |
|---|---|
| Snapshot omitted | Preserve legacy loading and output |
| Snapshot target differs | Reject before consumption |
| Missing Case | Preserve `status=missing` behavior |
| Corrupt Case | Preserve the historical error path |
| Queue selection | Caller snapshot remains byte-equivalent |
| Bounded bootstrap | No full Surface context/ranking read |
| State/Queue/Case write before Closure | Re-read affected closure owner |

### 4. Tests Required

- Instrument owner loaders and prove reduced same-invocation load counts.
- Compare direct and snapshot paths for action, queue, case, findings,
  candidates, frontier, and Surface projections.
- Cover target mismatch, Queue immutability, missing/corrupt Case behavior,
  and bounded no-rebuild behavior.

### 5. Good/Base/Bad Cases

- Good: Checkpoint passes State's valid Surface and candidate projections while
  Closure reloads Queue and Ledger after writes.
- Base: a direct `build_autopilot_state(...)` call omits snapshots and follows
  the existing loaders.
- Bad: retaining a pre-write Queue or Coverage snapshot for final Closure, or
  silently accepting a projection produced for another target.

### 6. Wrong vs Correct

```python
# Wrong: cross-invocation/global cache or stale snapshot after a write.
cached_state = GLOBAL_STATE[target]

# Correct: pass an optional, target-bound projection within one invocation and
# reload closure-owned data after mutation.
state = build_autopilot_state(repo_root, target, queue_snapshot=queue)
```
