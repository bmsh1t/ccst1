---
description: Save target experience and journal audit without changing finding verdicts. Usage: /remember
---

# /remember

Save observations or reusable experience to an already initialized target Store.
Use `python3 tools/remember.py`; required fields are target, vuln-class, endpoint
and result. Pass `--repo-root ROOT` when using an isolated checkout.

```bash
python3 tools/remember.py --target TARGET --vuln-class idor \
  --endpoint /api/objects/ID --result partial \
  --notes 'Unverified ownership hypothesis' --json
```

`--notes`, `--technique` or `--operation-ref` cause an experience write. With none
of these, only the journal entry is appended. The result label is the operator's
account; it does not create or confirm a Finding, coverage, report or submission.

| Input | Store experience |
|---|---|
| Notes or technique without registered operation refs | Advisory `note`, explicitly unverified |
| `--result confirmed` with operation refs | Evidence-backed `primitive` |
| `--result rejected` with operation refs | `negative`; conditions and reopening criteria required |
| Other results with operation refs | `note` |

```bash
python3 tools/remember.py --target TARGET --vuln-class idor \
  --endpoint /api/objects/ID --result rejected --notes 'Peer read denied' \
  --conditions 'same tenant; JSON; release 1' \
  --reopen-when 'Identity, representation or deployment changes' \
  --operation-ref OPERATION_ID:0 --command-id negative-review-1 --json
```

`OPERATION_ID:0` refers to an existing execution's zero-based observation step
in this target Store. A raw file path is not an operation reference. Register
already executed evidence through the existing evidence workflow
(`python3 tools/validation_runner.py record-evidence --help`); do not repeat
requests merely to save memory. Without registered evidence, use an advisory note.

The journal remains an audit artifact. The command does not write `patterns.jsonl`
or update target-profile findings/tested endpoints, and does not automatically
promote knowledge across targets. An identical `--command-id` replay does not
duplicate a retained command-bound journal entry. If journal append fails after a
Store commit, text/JSON reports `partial` (exit 2) with the committed receipt and
`command_id`, including an automatically generated ID. Resolve the journal error,
then retry with the **original resolved inputs and the same `--command-id`**; this
only fills a missing journal row and does not save the experience twice. Saving
memory never requires repeating the network execution. With `--from-validate`,
keep the same summary bytes or pass its resolved fields explicitly.

`journal_saved` means a row was appended by this call; `journal_replayed` means
the same row already exists, and `journal_status` distinguishes `appended`,
`already_present` and `unconfirmed`. Journal-only changes such as severity or tags
under the same ID are explicit conflicts. Timestamps/session IDs preserve the
original row. Deduplication covers the live file and existing numbered backups;
explicit retention/purge can remove that binding. Legacy unbound rows are kept
unchanged, so a first replay that repairs an absent binding cannot prove whether
an old row belongs to it and includes a `journal_recovery_note`.

For validation prefill, retain the original `/validate` receipt's `summary_path`
and pass it explicitly:

```bash
python3 tools/remember.py --from-validate --target TARGET \
  --validate-json VALIDATION_SUMMARY_PATH --json
```

Verify that summary's target and Finding identity. The Finding projection has no
summary locator, and `--target` alone does not locate one. If the original receipt
was not retained, state the gap or pass the resolved fields explicitly; do not
guess a filename, use the global latest pointer or rerun validation to recover it.
Prefill provides fields, not operation evidence; current Store/INDEX owns verdicts
and report status.

Recover saved experience with `python3 tools/target_memory.py show TARGET` or
`python3 tools/experience_recall.py query --target TARGET --json`; use the returned
query cursor or `--source-ref experience:ID` to expand. Store history cursors use
`experience_recall.py history`, not `query`.

For structured advisory claims, use `target_memory.py note --claims-json` with
the existing `subject/predicate/object/conditions/timing/source_refs` fields.
Optional `condition_bindings` maps explicit role names to exact entity bindings
from `target_memory.py entity`; optional `validity` requires both timezone-aware
ISO8601 `from` and `until` (`from < until`). Omitted values remain unknown. Plain
text conditions are preserved, and claims never confirm Findings or authorize actions.

Query results include a separate `counterevidence` page. Follow its `next_command`
for more corrections/dependencies, or each item's `expand_command` for the exact
retained version. Do not feed its cursor to `query` or `history`. Use
`--context-limit` and `--context-max-bytes` independently of retrieval `--limit`.

Use `target_memory.py link` (or the save's `--links-json`) to attach explicit
`supersedes`, `refutes` or `depends_on` relationships. Corrections require a stated
`--conditions` scope and CAS `--expected-revision`. Only a scope identical to both
retained endpoint declarations changes the whole record's review state. Differing
conditions retain `applicability.effect=conditional`, not a global replacement;
unknown endpoint conditions are not wildcards. `retract-link` preserves the original
challenge scope and history. Version, history and current views expose applicability;
budgeted counterevidence still retains correction scope and withdrawal references.

To cite a reviewed method, obtain its exact binding with
`target_memory.py knowledge-source --target TARGET --id ID --json`. Add
`purpose: "basis"` or `purpose: "origin"` to that object and include it in the
save's `--sources-json` array. The publication receipt hash is its external
version; do not substitute a Store revision. Only basis may support a claim.
Later review withdrawal or content change remains visible without rewriting history.

For an imported historical record, use
`target_memory.py history-source --target TARGET --id ID --json`. Its four-field
binding accepts only `purpose: "origin"` in `--sources-json`; history cannot support
a claim. Add `--full` to read the original selected record, source metadata and
availability. Available bytes are still `verification: "unverified"`. Missing or
changed originals have explicit diagnostics, never a fallback to an imported note
or live legacy file. A PatternDB receipt without an archive requires explicit
`target_migration.py --backfill-pattern-source SOURCE --repo-root ROOT --target TARGET`
with the same pinned source bytes; do not rerun an execution or create replacement
notes to repair history. Counterevidence provides the same exact expansion command.

Target-memory save commands may explicitly request `--update-index text`,
`relations` or `all`; knowledge promotion uses the same option for shared indexes.
No option means no index update. `--index-encoder PATH` requires text/all and a
locally available model. An index failure returns exit 2 with the committed save
receipt and independent recovery commands: rebuild the index, not the saved fact.

Target text/relation updates reuse a generation-bound source capture and reacquire
only affected experience/owner groups. `acquisition` reports these reads separately
from reused index sources. Current facts and referenced external bytes are always
rechecked; shared knowledge still receives a full review audit. Missing legacy
captures explicitly select full acquisition. Query/status never create or repair
an index; use `experience_recall.py index-build --target TARGET --full-rebuild`
(or `relation-build`) when a derived generation is corrupt.
