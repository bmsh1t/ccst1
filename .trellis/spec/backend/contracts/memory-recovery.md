# Memory recovery and recall projections

## 1. Scope / Trigger

Autopilot bootstrap, text retrieval, compact experience anchors and distillation
history navigation. TargetStore remains the durable owner; these changes create
no schema, automatic memory writes or execution authority.

## 2. Signatures

- `compact_autopilot_state(state)["target_memory"]` reuses
  `state.resume_summary.target_memory` plus its `source_binding`.
- Recovery entries retain their owner-provided `version`; `experience_window.context_command`
  expands counterevidence using that entry's ID/version. Its budget is independent
  of the recent-history limit.
- `query_text(..., generations=None)` retains FTS ranking and appends fresh
  lexical-only matches; optional generations come from the same acquisition.
- `relation_recall.traverse(..., max_seconds=1.0, max_bytes=200000, cursor=None)`
  preserves bounded traversal and rejects a response budget smaller than one path.
- `target_store.py operations --target TARGET [--repo-root ROOT]
  [--limit N --cursor CURSOR | --id OPERATION_ID]` reads metadata/history.
- `build_evidence_view(...)["windows"]["ledger"]` describes the observation
  preview and the full operation-history browsing entry.

## 3. Contracts

- Startup memory carries the existing five-entry history, separate current
  handoff, next intent, conditions/provenance, owner binding and expansion
  commands. No second read or active-pointer fallback. Lists have no single-target
  memory; lock/wait, Scope and recovery gates are unchanged.
- Slash Bootstrap skips the unconsumed twenty-entry `target_goal_memory` diagnostic
  read; default builders and full/bounded diagnostics retain it. The five-entry
  Resume acquisition and its final owner-binding check remain intact. Context Pack
  formats owner-provided memory paths and still reacquires memory before returning.
- Model-facing timing has one owner: Shared Memory Continuity in runtime-protocol.
  Its problem recall covers missing historical basis, repeated experiments,
  changed origin/actor/object/conditions and lost compact context. Existing complete
  material may be reused; no per-request query or automatic applicability judgment.
  Memory CLI/authoring details live in commands/target, capture in evidence-runners.
  Autopilot/Hunt/validator do not maintain narrower write schedules.
- Recovery carries the same correction/source-health fields with exact versions.
  Latest handoff/next intent remain advisory even when disputed or superseded;
  consumers review counterevidence without suppressing independent investigation.
  Preserving fields in a fresh process proves durable recovery, not model compact
  compliance; real host behavior is evaluated separately.
- Native command installation and discovery do not prove dynamic expansion.
  Host acceptance must distinguish pre-expanded script receipts from a later
  model tool replay. Do not inject expected target answers into acceptance prompts.
- Isolated Claude host checks load `--setting-sources user,project,local` from the
  synthetic session/project. Verify root `CLAUDE.md`, its adapter import and the
  invoked command/Bootstrap in the first main request; runtime-doctor/discovery
  success alone does not prove delivery. Missing entry rules fail admission.
  Compact auxiliary requests may omit those rules. The observer checks only the
  preregistered initial request, keeps a failed entry closed, and leaves authority
  validation to the existing gateway. It forwards bytes unchanged and stores only
  message shapes, hashes and markers, never credentials, raw prompts or thinking.
- FTS hits keep BM25 order; substring-only matches retain source order and join
  before semantic fusion, reranking or pagination. Deduplicate exact source refs.
  Channel and ranking digest reflect the actual sources, including missing-index
  semantic fusion. Query never rebuilds an index.
- Lexical supplement normalizes each non-FTS document once per query, preserving
  empty-query source order and punctuation-only empty results. Reused generations
  must still match each freshly acquired partition binding; unavailable/stale
  generations retain explicit health and use current lexical sources. Knowledge
  parse reuse never skips raw bytes, registry, publication receipt or final fences.
- `recall_rows` shares only validated direct dependency nodes keyed by exact
  `(experience_id, version)` within its SQL transaction. Each root collects its
  own complete external references, including origins, cycles and shared tails;
  every source edge retains its expected-hash check. Basis health propagates
  through reverse edges once per newly unhealthy node; origins stay diagnostic.
  Claim endpoints reuse the enclosing acquisition's health graph. Later reads
  acquire health and verify external bytes again.
- `memory_context` reuses the newest handoff in the ordered recent page, with an
  independent returned object. Only a missing handoff requires the separate query
  so older handoffs outside the window remain accessible.
- Experience paging reuses `total` as the initial remaining count only without a
  cursor. Later pages still count the filtered tail on the same read transaction;
  ordering, exact remainder and revision-bound cursor validation stay unchanged.
- Counterevidence acquisition reads each artifact status once per artifact ID,
  retaining every root reference and source-specific status/error metadata. This
  reuse lasts for one `_acquire` call only. Page rechecks, subsequent pages and
  composite-query `verify_context` reacquire status and bytes; Store revision alone
  never establishes external artifact health.
- Relation time budget includes graph preparation but permits one traversal state
  transition per page to ensure progress after setup exhausts the time budget.
  Edge/path/depth/byte limits remain enforced. If no path fits `max_bytes`, raise
  `ValueError` with the required minimum instead of repeating the same cursor;
  callers may increase budgets with the existing cursor.
- Experience anchors place owner review state, incomplete-context warning and
  exact ID expansion before bounded detail/statement previews. Conditions and
  correction/applicability/source metadata come from the existing DTO/formatter.
  The bounded owner anchors precede other evidence within the twelve-entry pack
  and six-entry Resume windows. Resume must not cut them again at 300 characters. An incomplete
  preview requires expansion before reliance, not a new inferred validity state.
- Operation pages use ID order and operation counts, with existing target/Store/
  revision-bound cursors. Pages explicitly do not check artifact bytes. ID expansion
  preserves observations and reports fresh `artifact_health`; invalid bytes remain
  inspectable, never valid evidence. Assembly checks the owner revision again.
- Ledger windows count observations, not operations. A source-truncated preview
  has unknown total/remainder. Its history command starts at operation page one;
  it is not the next chronological observation page. Current truth still owns
  closure/identity health; successful artifact hashing is not a technical verdict.

- Handoff examples include explicit `--next-intent`. Omission remains legal and means
  no next action; it never revives older intent. The text save receipt shows the trimmed
  value accepted by Store, or `(none)` for an empty intent.
  All experience/handoff text fields use role labels and private credential references,
  never secret values. Evidence links identify the actual supporting observation steps;
  one `:0` cannot stand for a batch. These are authoring duties in commands/target,
  not a claim that Store validates prose or automatically redacts credentials.
- Each knowledge snapshot acquires/parses once. The final byte fence includes registry,
  cards, publication receipts, reviews and blind-answer artifacts, including missing
  paths observed during reads. A changed/missing/appearing dependency rejects the
  mixed snapshot. Later calls recheck all bytes; parse reuse does not cache trust.
  Acquisition stats use `verification=all-source-byte-fence`, not fictional second parses.

## 4. Validation & Error Matrix

| Input | Required behavior |
| --- | --- |
| Review chain changes during another card read | Reject mixed knowledge snapshot |
| Missing next intent | Empty next actions, explicit save receipt |
| Older handoff beyond recent five | Bootstrap retains handoff and owner warning |
| Recovery entry to counterevidence | Exact retained ID/version opens its own context page |
| First host request lacks expected root/import rules | Fail entry verification; exclude sample from rule-effect comparison |
| Admitted host sends compact auxiliary request without rules | Forward unchanged through the same allowlisted gateway |
| Failed host entry later sends a matching request | Remain rejected; do not admit a retry as the original sample |
| Experience page without / with cursor | Reuse total / count the filtered tail; identical page output |
| Multiple context roots share an artifact | One status read per acquisition; retain all references |
| Artifact or Store changes during context assembly | Reject mixed result; never reuse across final recheck |
| List / initialized empty target | No foreign memory / real empty bound memory |
| Locked target with memory | Wait remains authoritative |
| Mixed English FTS and Chinese substring | Both accessible, no duplicates over pages |
| Source/ranking changes | Existing cursor binding rejects stale continuation |
| Long challenged experience | Warning and expansion survive Resume |
| More than 40 observations | Exact preview remainder or unknown plus usable history entry |
| Bad operation ID/cursor/missing Store | Existing CLI error, exit 2, no initialization |
| Changed artifact | History retained with invalid health, no owner mutation |
| Cached dependency reached through two differently bound edges | Verify both expected hashes; reject the corrupt edge |
| Setup exceeds relation time budget | Cursor advances or query completes; no unchanged zero-progress page |
| First relation path exceeds response bytes | Explicit error with required `max_bytes`; no looping cursor |

## 5. Good / Base / Bad

Good: consume bound handoff, expand older experience and apply the current version.
Base: empty memory stays empty and a read-only request performs no business write.
Bad: treat absent Markdown filenames as absent memory, use direct SQL to bypass
provenance, or claim the operation cursor follows the observation preview.

## 6. Required Checks

Use isolated production copies and synthetic Stores. Check mixed-language partial
hits, deduplication/pagination, stale cursor refusal, long correction anchors,
bootstrap binding/wait/list/empty behavior, and real operation CLI paging/expansion
with tampered bytes. Do not access personal runtime or real target data. Host
checks use the requested model, independent sessions, hidden oracle and actual
file/owner receipts; small samples establish behavior only, not statistical gains.
Probe rule loading without provider forwarding first. A local observer check covers
initial mismatch, compact auxiliary requests, failed-entry retries, request-only
mode, authority rejection, byte preservation and exclusion of hidden thinking.
Record real `compact_boundary` separately from owner-memory recovery. Check new
observations and structured handoff fields after continuation; CLI success or more
requests do not prove them. Preserve failed samples and harness versions; count the
last cumulative CLI cost once. Observer-induced errors limit stability conclusions.
Cost checks compare full return values and count repeated work using synthetic
chains/cycles/diamonds, mixed FTS/substring cases, generation drift, page-window
handoffs and controlled relation clocks. A smaller bounded output does not prove
bounded source reads or lower model cost.
For reuse changes, compare complete outputs and cursors on the same synthetic Store
and index generation. Count SQL, assembled rows, connections and actual artifact
hash bytes separately from output size. Include shared artifact sources, error
metadata, revocation, missing bytes and changes during/following acquisition.

## 7. Wrong → Correct

Healthy FTS replaces substring candidates → union before ranking/paging.
State has memory but bootstrap drops it → preserve the existing bound DTO.
Truncate away a warning → bound at the producer with an explicit expansion.
Forty observations without continuation → expose full execution-history navigation.
Global dependency visited set → per-root closure over same-transaction node reuse.
Time budget returns an unchanged cursor → one bounded transition or explicit budget error.
Runtime sync is clean so rules must be loaded → verify the first actual main request.
Every request must contain project rules → gate the initial request; allow compact auxiliaries.
