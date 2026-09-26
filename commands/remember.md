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
append another journal entry. If journal append fails after a Store commit, the
error identifies the committed experience; preserve it and inspect the audit gap.

For validation prefill, select the current target or an explicit summary:

```bash
python3 tools/remember.py --from-validate --target TARGET --json
python3 tools/remember.py --from-validate --validate-json VALIDATION_SUMMARY_PATH --json
```

Copy the canonical Finding's exact `validation_summary` path. Do not infer a
filename or import the repository-global last-validation pointer into another
target. Prefill provides fields, not operation evidence.

Recover saved experience with `python3 tools/target_memory.py show TARGET` or
`python3 tools/experience_recall.py --target TARGET --json`; use the returned
cursor or experience ID to expand beyond the summary window.
