# Cutover Readiness Review (2026-09-22)

## Scope

- Authorization: confirmed for this review and an isolated fixture cutover attempt.
- Fixture root: `/root/mig-sandbox-10`.
- Target: `127.0.0.1:3001`.
- No live target or external service was contacted. No production target was
  promoted.

## Step 1: Scope, Writers, Backup, Rollback

- Canonical target and storage key: `127.0.0.1:3001`.
- A `/proc/*/fd` scan found zero open handles under `/root/mig-sandbox-10`.
  The process argument scan also found no target-specific migration, runner, or
  writer process. Existing lock files are not evidence of an active writer.
- Backup owner, backup location, permissions, and verification command are not
  recorded for this fixture: `OWNER`, `BACKUP_LOCATION`, `BACKUP_VERIFY_CMD`.
  The cutover remains blocked until those values are supplied.
- Rollback boundary is the existing forward-only protocol: use
  `restore_legacy_metadata()` only while activation is `pending`; after a
  primary fact exists, repair/export Store truth rather than restoring stale
  JSON.

## Step 2: Read-Only Review

Command:

```bash
python3 tools/target_migration.py \
  --repo-root /root/mig-sandbox-10 \
  --target 127.0.0.1:3001 \
  --json
```

Result:

- `mode=readonly-preview`, `status=partial`.
- Source manifest: `d8f17dce2a06ed2a118ebb599564de040e2d2c3fdc921a8bce58a888f43d5ee9`
  over 1,288 files.
- Preview counts: 11 findings, 126 observations, 0 report artifacts, and 55
  legacy target-memory entries. The preview did not mutate source hashes.
- The existing isolated import report is also `partial`: 11 findings, 81
  observations, 81 raw artifact bindings, 11 exact links, and 112 quarantined
  records (67 queue, 45 ledger). It retains 1,144 unreferenced raw artifacts.
- Quarantined items include missing raw evidence references, references outside
  the isolated copy, missing evidence, unbindable identities, and terminal
  legacy queue states. They require item-level disposition; aggregate counts
  are not sufficient.
- The fixture already contains
  `state/127.0.0.1:3001/metadata.sqlite3`. Its `store` table has the legacy
  schema and no current `backend` column, so it is not a valid migration
  receipt or current primary store.

## Step 3: Freeze / Publish / Promote Gate

Not executed. The authorization is present, but the technical preconditions are
not met:

1. `import_target_staged()` rejects a source that already contains
   `metadata.sqlite3` (`tools/target_migration.py:745-759`); the current owner
   must first export or explicitly remove that stale store through the owner
   path.
2. The import report is `partial`; staged receipts therefore become
   `status=partial` (`tools/target_migration.py:772-780`).
3. `publish_preview()` rejects any receipt that is not complete and preview
   backed (`tools/target_migration.py:796-809`). Consequently no freeze,
   publish, or promote was attempted, and no legacy metadata was removed.

## Step 4: Legacy Compatibility

No legacy writer was retired. The fixture remains unchanged and any future
unmigrated target must keep its restricted legacy adapter until its own receipt
and post-activation checks pass.

## Step 5: Online Capability Comparison

Not run. It remains a separate budgeted activity and is not inferred from this
offline review.

## Required Next Action

Assign `OWNER`, `BACKUP_LOCATION`, and `BACKUP_VERIFY_CMD`; resolve each
quarantine item; export/remove the stale current-owner database through the
explicit migration path; then create a fresh isolated import and require a
`ready` receipt with the same manifest digest before retrying publish and
promote.

## Follow-up Execution (authorized fixture only)

- A target-scoped backup was created at
  `/tmp/ccst-cutover-backup-20260922-127.0.0.1_3001` from the 1,288-file
  manifest. Every copied file matched its source size and SHA-256. The old
  `metadata.sqlite3` and its `-shm`/`-wal` sidecars remain in the fixture; they
  were excluded from the legacy owner export, not deleted.
- The explicit export source is
  `/tmp/ccst-cutover-source-20260922-127.0.0.1_3001`; its export record points
  back to the backup and excludes the three current-store files. A staged
  import was then created at
  `/tmp/ccst-cutover-stage-20260922-127.0.0.1_3001`.
- Staged receipt: `backend=preview`, `status=partial`, manifest
  `877ed02a9a0ee7a67f943cfd9c866e8f328723077686ff1968841e7314c81498`, 11
  findings, 81 observations, 81 artifacts, and 117 quarantined records
  (ledger 45, queue 67, case-state 5). Reasons include missing raw
  references, evidence paths outside the isolated copy, missing evidence,
  terminal queue verdicts, malformed queue identity, and private case-material
  metadata mismatches.
- Publish was attempted against the staged root and rejected with
  `preview receipt is incomplete or does not match target`; the published
  destination was not created. No freeze or promote occurred, and the source
  metadata database still exists.

## Quarantine Disposition Ledger

The 117 staged quarantine rows were normalized into the machine-checkable
ledger `/tmp/ccst-cutover-dispositions-20260922.json`. It has 117 unique
stable IDs, preserves only bounded paths/reasons, and leaves every decision as
`PENDING` with operator `OWNER`. The ledger validates that all 45 ledger, 67
queue, and 5 case-state rows have an explicit allowed-decision set. It is not a
publishable receipt until every row has a recorded decision and evidence
reference.

Rows lacking an event/id/line source identity use their bounded report index as
the explicit duplicate discriminator; otherwise a duplicate source identity is
rejected rather than silently merged.

The migration API now accepts `--disposition-ledger` (or the equivalent
`disposition_ledger=` argument). It binds the ledger to target and manifest,
rejects unknown/duplicate IDs and placeholder operators/references before
creating a destination Store, and permits only fact-preserving decisions. A
synthetic fixture ledger was used to verify the complete staged path: 117 rows cleared,
the receipt became `complete`, and publish succeeded in an isolated `/tmp`
destination. Those synthetic decisions are not operator dispositions for the
fixture and were not promoted.

## Correction (2026-09-22, post-review)

An independent review of the disposition-ledger change found that several
statements above were stronger than the implementation, and that the ledger
itself under-covered the real target. The record above is left as written; this
section corrects it.

- **The ledger was generated against an incomplete source.** Its bound manifest
  `877ed02a…` (1,285 files) matches
  `/tmp/ccst-cutover-source-20260922-127.0.0.1_3001` exactly, and that export
  contains **zero** `reports/` entries. Copying the real
  `reports/127.0.0.1:3001/` (10 files) into the export makes the manifest equal
  the live repository manifest `860c7d0d…` (1,295 files); those 10 files are the
  only difference between the two. The 117-row ledger therefore covers 1,285 of
  the 1,295 files a real cutover would migrate, and its `decision_rule` ("every
  item requires an explicit operator decision") does not account for the 10
  preserved report artifacts that a real import reports.
- **Binding did not cover the decision table.** `source_manifest_sha256` is read
  from the payload itself and `ledger_sha256` only covers the items, so a
  decision table generated for one report could be re-bound to a different input
  by editing one field. This was reproduced: reusing the fixture's 117 IDs
  against the reports-complete input, with the manifest field rewritten, was
  accepted and produced a `complete` receipt.
- **"before creating a destination Store" was not accurate for item-level
  checks.** Target/manifest binding is validated before staging begins, but
  unknown/duplicate IDs, placeholder operators, and unsupported decisions are
  validated at the end of `import_target`, after the destination Store exists
  and the full import has run. A failure retains the staging root for diagnosis
  and never publishes it.
- **"report index as the explicit duplicate discriminator" made identity
  order-dependent.** 45 of the 117 rows carried no event/id/line, so their ID
  changed if the report was reordered — contradicting the "reordering does not
  change the identity" contract. All 117 IDs were reproducible only under that
  index rule.
- **Ledger governance metadata was decorative.** `status: "pending"`, `count`,
  `staged_root`, `source_report_status`, and `decision_rule` were written but
  never read or enforced by the tool.

Fixes applied in the same review cycle (see
`transactional-target-state.md` § Migration Quarantine Disposition Contract for
the resulting contract):

- Identity no longer includes report position; identical rows are told apart by
  occurrence count, so the identity set is order-independent. Verified on the
  real 117 rows: identity set and roster digest are unchanged under reversal and
  under a seeded shuffle, while changing a reported fact changes both.
- The ledger may declare `quarantine_roster_sha256` (a digest over the complete
  source identity set), which is now required to match the input. A rebind
  attempt is refused with `disposition ledger quarantine roster does not match
  migration input`; the rebind reproduction above now fails instead of
  publishing.
- `rebind_after_export_verification` is accepted (it is what the generated
  ledger advertises) but is **non-terminal**: it and `operator_review` are
  recorded as `recorded_decision` on a still-quarantined row and keep the report
  `partial`. Only `preserve_verdict` and `permanent_quarantine` can clear the
  publish gate.
- Governance metadata is enforced for payloads declaring the cutover ledger
  `kind`: a placeholder `status` and a `count` that disagrees with `items` are
  refused.
- Staged receipts now record preserved-but-unregistered report artifacts under
  `unregistered_artifacts` (count, paths, digests), so that fact survives the
  run instead of existing only in the in-memory report.
- `--disposition-ledger` without `--import-source` is now a CLI error rather
  than being silently ignored.

Consequences for the cutover: the fixture ledger is unusable against a real
target (it is bound to a reports-less manifest) and every quarantine item needs
a fresh, terminal decision. The ledger file itself must be archived with the
cutover audit; the receipt stores only its digest and roster digest, not the
per-row decisions.
