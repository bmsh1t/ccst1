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
  --operation-ref OPERATION_ID:STEP --command-id negative-review-1 --json
```

`OPERATION_ID:STEP` refers to the actual zero-based observation step in an existing execution
in this target Store. A raw file path is not an operation reference. Register
already executed evidence through `docs/evidence-runners.md#在执行时捕获原件`; do not repeat
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

Apply `skills/runtime-protocol.md#shared-memory-continuity` for recall and write timing.
The common recovery, counterevidence, version/source/claim, correction and index contracts
live in `commands/target.md`. Journal recovery and validation prefill remain owned here.
