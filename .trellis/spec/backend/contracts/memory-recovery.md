# Memory recovery and recall projections

## 1. Scope / Trigger

Autopilot bootstrap, text retrieval, compact experience anchors and distillation
history navigation. TargetStore remains the durable owner; these changes create
no schema, automatic memory writes or execution authority.

## 2. Signatures

- `compact_autopilot_state(state)["target_memory"]` reuses
  `state.resume_summary.target_memory` plus its `source_binding`.
- `query_text(...)` retains FTS ranking and appends fresh lexical-only matches.
- `target_store.py operations --target TARGET [--repo-root ROOT]
  [--limit N --cursor CURSOR | --id OPERATION_ID]` reads metadata/history.
- `build_evidence_view(...)["windows"]["ledger"]` describes the observation
  preview and the full operation-history browsing entry.

## 3. Contracts

- Startup memory carries the existing five-entry history, separate current
  handoff, next intent, conditions/provenance, owner binding and expansion
  commands. No second read or active-pointer fallback. Lists have no single-target
  memory; lock/wait, Scope and recovery gates are unchanged.
- Native command installation and discovery do not prove dynamic expansion.
  Host acceptance must distinguish pre-expanded script receipts from a later
  model tool replay. Do not inject expected target answers into acceptance prompts.
- FTS hits keep BM25 order; substring-only matches retain source order and join
  before semantic fusion, reranking or pagination. Deduplicate exact source refs.
  Channel and ranking digest reflect the actual sources, including missing-index
  semantic fusion. Query never rebuilds an index.
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

## 4. Validation & Error Matrix

| Input | Required behavior |
| --- | --- |
| Older handoff beyond recent five | Bootstrap retains handoff and owner warning |
| List / initialized empty target | No foreign memory / real empty bound memory |
| Locked target with memory | Wait remains authoritative |
| Mixed English FTS and Chinese substring | Both accessible, no duplicates over pages |
| Source/ranking changes | Existing cursor binding rejects stale continuation |
| Long challenged experience | Warning and expansion survive Resume |
| More than 40 observations | Exact preview remainder or unknown plus usable history entry |
| Bad operation ID/cursor/missing Store | Existing CLI error, exit 2, no initialization |
| Changed artifact | History retained with invalid health, no owner mutation |

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

## 7. Wrong → Correct

Healthy FTS replaces substring candidates → union before ranking/paging.
State has memory but bootstrap drops it → preserve the existing bound DTO.
Truncate away a warning → bound at the producer with an explicit expansion.
Forty observations without continuation → expose full execution-history navigation.
