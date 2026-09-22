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
