# F11 tests and live reference chain

Research only, 2026-10-07. Read the task PRD and audit F11; no product edits, CLI executions against targets, tests, activation, installation or commits. The defect is observed active guidance drift, not demonstrated model miswrites.

## R17 precedent and smallest reuse

- `tests/test_recon_ranker_contract.py:18-22`: `COMMANDS` extracts actual fenced bash invocations from `agents/recon-ranker.md` with `re` and `shlex`; it does not assert prose keywords.
- `tests/test_recon_ranker_contract.py:25-39`: `_run(root, command, *extra)` substitutes `TARGET`, supplies an isolated `--repo-root`, runs the actual tool in a fresh Python process with a 20-second timeout. `_files(root)` snapshots source bytes, excluding SQLite sidecars; domain mutation is separately checked through `store.binding()`.
- `tests/test_recon_ranker_contract.py:42-105`: `test_documented_ranker_queries_read_current_state_and_preserve_sources` covers current/empty/missing/stale, poisons retired owner paths with `LEGACY_ONLY`, verifies current handoff/Findings/experience, real cursor expansion, missing Store not created, unchanged binding/source bytes. This is the real R17 pattern; not `test_cli_flag_contract.py`.
- `tests/test_cli_flag_contract.py:7-9,24-42,77-79`: intentionally checks accepted flag tokens only, not semantic combinations; its current owner list excludes target-memory. Expanding this into a source registry/keyword gate would not prove F11.
- Minimal existing file to extend for F11 negative write examples: `tests/test_target_memory_cli.py`. `_command` at `14-21` already supplies isolated root/JSON, actual subprocess and expected exit status; the real observation fixture is at `24-40` and successful negative command at `52-54`. No new framework or shared fixture module is required.
- For new documented examples, borrow R17's extraction approach locally. Read only the approved live source docs; parse real shell invocations, join `\\\n` continuations before `shlex.split`, and replace only explicit placeholders with fixture values. A small parametrized test input is not a runtime guidance registry. Do not synthesize omitted flags in the test: an incomplete documented invocation must fail.
- Existing negative rejection regression: `tests/test_target_memory_cli.py:107-131`, `test_memory_cli_explains_failed_negative_and_recovers_as_advisory_note`; incomplete dead-end exits 2 without revision/pointer changes, and explicit note recovery remains advisory. Malformed operation reference is already covered at `85-104`. `177-225` additionally demonstrates target ownership, zero-based step checks and idempotent operation-bound handoff writes.
- Avoid importing the ranker test's hard-coded `TARGET`/`COMMANDS` fixture wholesale or renaming its scope. It assumes exactly five read-only commands including Surface, whereas F11 combines Store reads and explicit memory writes.

## Observable assertions for the implementation plan

1. Execute corrected validator/retrospective Store query examples from their documentation against temporary current, empty and missing Stores. Current rows and selected stable Finding IDs must match; missing Store must fail without creation/history fallback; read-only queries preserve binding and raw bytes. Poison old JSON paths as R17 does, rather than merely banning their names in prose.
2. Execute each distinct documented negative-write example with a registered local operation receipt and observation step 0. Assert exit 0 and persisted `kind == "negative"`, exact `conditions`, `reopen_when`, and `{operation_id, step: 0}` evidence; recover through a separate `show` process and check the same entry/reference.
3. Drop each of conditions/reopening/operation ref from one valid example, or replace its operation ref with malformed/foreign/missing-step input. Assert structured exit 2, unchanged Store revision and no new experience. Existing malformed-ref coverage can remain; add only gaps attributable to examples.
4. With no registered evidence, execute the explicit documented `note` alternative (not silent conversion). Assert advisory `kind == "note"`, no evidence refs and no negative entry; no implicit observation registration.
5. If selected-Finding recovery needs fixture setup, existing `tests/test_finding_index.py:19-46` `_register_finding` seeds a local observation/assessment/delivery; `tests/test_validate_target_mode.py:15-56` `_seed_machine_preflight` is a heavier full validation fixture. Prefer the former only when actual bound status/artifacts are asserted; do not rerun validation for a guidance-only change.

Final focused invocation selected by the main agent for after approval/implementation (not run during planning):

```bash
python3 -m pytest -q tests/test_target_memory_cli.py
```

This covers the new F11 documented-command cases and existing memory CLI rejection/recovery cases. R17 is a reuse reference, not a changed test file, so rerunning it is not required. The invocation is expected to fit the approximate 60-second budget; duration has not been measured in this planning turn.

## Direct live consumers and edit boundary

- `commands/retrospect.md:12-19`: explicitly requires `rules/retrospective.md`. `127-134` says execute only when the user explicitly requests automatic writes, but still contains executable incomplete `target_memory.py dead-end "..."` at line 132. This direct sibling belongs in F11's write-example alignment.
- `commands/retrospect.md:66-77` already has correct Store expansion (`target_store.py findings`, `experience_recall.py`), ID/reference-bound report-local recovery, and warning that `last-validate.json` is not selected-Finding binding. Reuse this shape rather than redesigning the whole command.
- `rules/retrospective.md:20-25` table and `110-116` bash block are executable write examples, both missing negative required fields. `36-55` includes automatic refresh/read legacy guidance. Main agent should compare this exact span with the already narrower command collection at `commands/retrospect.md:41-60`; `coverage_matrix.py rebuild` is a write, not a read-only default. This is live-chain alignment, not a separate coverage-engine change.
- `rules/retrospective.md:61-97` is the output template; `dead-end:` there is a classification/display field, not an executable command. Do not require flags in output labels or erase the classification method.
- `commands/autopilot.md:282-293` explicitly consumes **classification criteria (not the write commands)** from retrospective, emits one **presentation-only** Memory recommendations section, and says recommendations never write state/alter routing/budgets/Queue/lifecycle/closure/next action. It is a direct live reference but already constrained correctly: inspection/reference only, not a reason to add automatic writes or expand the F11 edit set.
- `rules/README.md:26` routes session review/promotion to retrospective; it is navigation, not another executable example.
- Exact-path search found no live markdown caller directly naming `agents/validator.md` beyond the directory spec example. The role is natively discoverable: `agents/validator.md:2-11` declares `name: validator`; `README.md:341-353` identifies `agents/` as explicit specialist source of truth and lists validator. Runtime discovery/sync uses `tools/runtime_doctor.py:102-124` `_repo_files` (Markdown glob) and `326` `sync_runtime`; `install.sh:40` sets the installed agents directory. Do not claim a direct command-to-validator invocation that was not found.
- Validator exact drift locations: `agents/validator.md:38-41` old Finding/target-memory inputs; `56-67` legacy status/current recovery; `49-52,86-89` unconditional failed-premise -> dead-end recommendation. Keep its decisions and `skills/triage-validation/SKILL.md` ownership at `91-101`; a KILL is not itself registered negative evidence.
- Correct existing write exemplar: `commands/target.md:48-56` binds dead-end to conditions, reopening criterion and `OPERATION_ID:0`, explaining real receipt/zero-based observation and note alternative. `rules/coverage-gate.md:211` has a valid one-line equivalent.

## Focused specification locations

- `.trellis/spec/backend/index.md:20,24,27` routes Store/memory, runtime guidance and validation contracts respectively.
- `.trellis/spec/backend/contracts/runtime-autopilot.md:34-40,108-111` is the existing R17 current-owner/read-only rule and documented-command regression entry; it expressly does not infer model behavior.
- Primary F11 write/recovery contract: `.trellis/spec/backend/contracts/transactional-target-state.md:613-622` Memory Consumer scope; `670-690` CLI shape and read-only Store expansion; `710-724` incomplete negative rejection, explicit note alternative, no implicit observation, unchanged revision/pointer and existing test symbol; `731-734` non-empty conditions/reopening and operation refs.
- Validation boundary reference only: `.trellis/spec/backend/contracts/validation-evidence.md:207-231` existing validation/Store/recovery tests; no need to add a new general guidance registry/spec.

## Checked

Used fast-context twice to locate relevant files, then exact `rg`, `nl` and `sed` anchors. No pytest or state-mutating CLI was run. This file is the only research write.
