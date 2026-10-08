# Historical task inventory for stabilization acceptance

## Scope and evidence level

- Read-only inventory at HEAD `a31535d`, 2026-10-07. Inspected active `task.json`, October archive metadata, bounded Codex journal entries, work-commit patches/file lists, and candidate research. No tests, live targets, network, task activation/status updates, or archive operations performed.
- Counts: **36 active task directories** = **2 directly related historical candidates + 2 current/parent acceptance tasks + 32 unrelated/unproven tasks retained**. Active status labels: 29 `in_progress`, 7 `planning`. **180 archived task directories**, including **8 October task directories covering F03–F11** (F07/F08 share one task).
- Status, archive metadata and journal success statements are historical evidence, not present acceptance. Foundational PRD/design/implement documents were intentionally left for the main agent to read in full. Nothing here authorizes archiving.
- Both candidate implementation commits and all eight archived implementation commits below passed `git -c safe.directory="$PWD" merge-base --is-ancestor COMMIT HEAD`. Candidate patches were inspected, not merely their commit messages. `git log --all -- <candidate-task-paths>` returned no task-record history; product commits are the usable Git evidence.

## Main follow-up (2026-10-08)

The main agent has now read all six original F01/F02 planning documents in full. F01
`implement.md:29–36` records **37 passed** and work commit `4646762`; F02
`implement.md:33–39` records **34 passed** and work commit `14f0261`. The journal-only
search below did not establish these results; its absence is not absence of all
historical evidence. These are still historical task records, not a fresh run.
Both candidates require the planned current acceptance and explicit closeout approval.
Current test/owner verification is in `f01-f05-acceptance.md`; no test was run in this follow-up.

## 1. Directly related candidates requiring fresh acceptance (2)

### F01 candidate: `.trellis/tasks/archive/2026-10/10-02-auth-env-roundtrip-isolation`

- Metadata: `task.json:4-6` describes export/reload isolation and is still `in_progress`; `:14,18` have `completedAt: null`, `commit: null`.
- Actual work: **`46467628e69d7a6e0b9bae4a50f0f570133db39e`**, 2026-10-02; three files: `tools/auth_session.py`, new `tests/test_auth_session.py` (161 lines), `.trellis/spec/backend/quality-guidelines.md`.
- Inspected owner patch replaces all eight derived/raw auth environment inputs before applying the selected session overlay. Current owner is `tools/auth_session.py:394` (`AuthSession.export_to_env`). This ties the implementation to the task description but does not establish every original acceptance requirement.
- Regression source exists at `tests/test_auth_session.py:43` (`test_export_roundtrip_replaces_all_auth_inputs`, empty/polluted/malformed ambient environments; bound/origin-only/unbound/anonymous combinations), `:90` (default process environment cleanup), `:106` (real Bash helper consumes exported session), `:127` (existing env/file/CLI source precedence), `:154` (target mismatch still rejects before export).
- **Historical test-run result not established by this inventory.** No F01/task/commit journal hit was found in `.trellis/workspace/Codex/journal-1.md` or `index.md`. The journal jumps from the 2026-09-28 shared-phase session (`journal-1.md:538-570`) to F03 on 2026-10-03 (`:573`). Tests committed in Git are test-source evidence, not evidence that they passed.
- `research/auth-env-boundary.md:5-11` locates export/consumer boundaries; `:17` expressly says neighboring runner tests were read, not run; `:21` references an older temporary audit reproduction but is not a fresh acceptance result. F01 numbering is inferred from the parent's audit scope/task match, not written in the task title; main should confirm against its original audit material.
- **Main must read in full before judging archive eligibility:**
  - `.trellis/tasks/archive/2026-10/10-02-auth-env-roundtrip-isolation/prd.md`
  - `.trellis/tasks/archive/2026-10/10-02-auth-env-roundtrip-isolation/design.md`
  - `.trellis/tasks/archive/2026-10/10-02-auth-env-roundtrip-isolation/implement.md`
- Existing runnable check location for fresh acceptance: `tests/test_auth_session.py`; use the original requirements to decide whether related runner checks are material. No run is claimed here.

### F02 candidate: `.trellis/tasks/archive/2026-10/10-02-direct-phase-lock-inheritance`

- Metadata: `task.json:4-6` explicitly identifies F02/direct child lock lifetime and is still `in_progress`; `:14,18` have `completedAt: null`, `commit: null`.
- Actual work: **`14f02612f2b0e5dbeada93b532c7a03b91c2b8cd`**, 2026-10-02; four files: `tools/runtime_phase_exec.py`, `tests/test_runtime_phase_execution.py`, `tests/test_runtime_state.py`, `.trellis/spec/backend/contracts/runtime-autopilot.md`.
- Inspected owner patch enables the existing `include_fd=True` lock path and supplies `pass_fds=(lock_fd,)` to the live child. Current references: `tools/runtime_phase_exec.py:29,42`.
- Regression source exists at `tests/test_runtime_state.py:376` (`test_direct_phase_runner_marks_child_lock_ownership`, live FD inode identity); `tests/test_runtime_phase_execution.py:164` (both direct/hunt observe inherited lock); `:280` (`test_direct_wrapper_sigkill_keeps_child_lock_until_reaped`, recon and scan). The inspected test kills the wrapper, checks surviving-child ownership, duplicate-start exit 75/no sentinel/no state rewrite, reaps the child, and then checks reacquisition. This is stronger than merely terminating the lock owner but remains unexecuted in this inventory.
- **Historical test-run result not established by this inventory.** No F02/task/commit journal hit was found; same journal gap as F01. `research/lock-lifetime.md:3` says planning did not rerun reproduction or implementation tests.
- Important non-duplication: `research/lock-lifetime.md:23` explicitly distinguishes `.trellis/tasks/09-27-fix-scanner-lock-identity` as **September's F06 target identity issue**, not October F02 lock lifetime. `:16` says the archived shared-phase refactor deliberately preserved the former direct/hunt FD difference, so that archive is not evidence of the later F02 fix.
- **Main must read in full before judging archive eligibility:**
  - `.trellis/tasks/archive/2026-10/10-02-direct-phase-lock-inheritance/prd.md`
  - `.trellis/tasks/archive/2026-10/10-02-direct-phase-lock-inheritance/design.md`
  - `.trellis/tasks/archive/2026-10/10-02-direct-phase-lock-inheritance/implement.md`
- Existing runnable check locations for fresh acceptance: `tests/test_runtime_state.py`, `tests/test_runtime_phase_execution.py`; choose the original task's relevant subset. No run is claimed here.

## 2. Parent/current acceptance tasks (2)

| Path | Recorded state | Interpretation |
|---|---|---|
| `.trellis/tasks/archive/2026-10/10-04-stabilization-closeout` | `planning`; commit/completion unset | Parent of five now-archived F06–F11 task directories plus the current acceptance child; retain until actual parent requirements are checked. |
| `.trellis/tasks/archive/2026-10/10-04-stabilization-acceptance` | `planning`; commit/completion unset | Current planned acceptance/history closeout task; not previously completed. `journal-1.md:849` expressly leaves concentrated engineering acceptance and history review unstarted. |

No current-task pointer is claimed or changed by this inventory. Older unrelated parent tasks remain in section 4, not here.

## 3. F03–F11 already archived: do not create duplicate closeout work

All paths below are real archive directories, all have `status: completed` in their `task.json`, and all named implementation commits are ancestors of HEAD. Table references use `.trellis/workspace/Codex/journal-1.md`. Test counts are **journal claims at their stated historical checkpoints**, not fresh results.

| Audit item | Exact archive directory | Actual work commit / changed implementation | Journal and historical test evidence |
|---|---|---|---|
| F03 | `.trellis/tasks/archive/2026-10/10-02-partial-execution-claim-recovery` | `b460f050572a08742f3998f4668c7b432db47b93`; `tools/target_store.py` + Store/runner regressions/contracts | `:582-598`: archive statement, commit, pre-fix failing guard; 44 focused passes, timestamp assertion corrected, two affected runner cases passed again. |
| F04 | `.trellis/tasks/archive/2026-10/10-03-action-completion-auth-race` | `704009cb8f1a49b31e40824e04bc5c1904c4b19a`; `tools/target_store.py`, its tests and transactional contract | `:617-623`: commit-time artifact authorization, replay/invalidation/restoration coverage and archive statement. **No numeric test result in this journal session. `task.json.commit` is null.** |
| F05 | `.trellis/tasks/archive/2026-10/10-04-actor-coverage-evidence-authorization` | `70871aa`; `tools/current_truth.py`, `tools/evidence_ledger.py`, owner/projection tests and evidence contract | `:639-655`: 72 passed + 2 timestamp failures; corrected canonical timestamps then 3 supersession cases passed; journal states 74 unique cases passed across two runs, not one clean full rerun. |
| F06 | `.trellis/tasks/archive/2026-10/10-04-report-failure-propagation` | `b63ad6a98c17c14305612ed387028d91a0de5fd9`; `tools/hunt.py`, finding/hunt tests and evidence contract | `:675-691`: `python3 -m pytest -q tests/test_finding_index.py tests/test_hunt_initialization.py -k 'hunt_report or report_only or non_report'` → 27 passed. **`task.json.commit` is null.** |
| F07/F08 | `.trellis/tasks/archive/2026-10/10-04-report-attachment-closure` | `fd02dc84cf829d418192354f72088c19ba20ed0b`; `tools/report_generator.py`, `tools/target_store.py`, report command/tests/contracts | `:715-729`: 130 focused passes before two final fixes, then 13 focused passes including four new scenarios; no claim of a full post-fix rerun. Archive commit `c03eb26` is distinct from work commit. |
| F09 | `.trellis/tasks/archive/2026-10/10-04-runtime-receipt-shape` | `538975e1b5f2fe57f5bd332bff39a7e0abcb4395`; `tools/runtime_doctor.py`, doctor/bootstrap tests and runtime contract | `:753-766`: current-closeout focused selection 22 passed; older verified logs 89 passed; py_compile explicitly not a typecheck. |
| F10 | `.trellis/tasks/archive/2026-10/10-04-disclosure-cache-failure` | `6245fb06e59a6aeeef60b5ad138305eee58f46dc`; `tools/disclosure_search.py`, `mcp/hackerone-mcp/server.py`, provider tests/guidance/error contract | `:790-804`: 80 passed before final cache-status fix, then 30 `bad_cache or healthy_cache or failed_refresh` passes; explicitly **not** a complete 83-case rerun. |
| F11 | `.trellis/tasks/archive/2026-10/10-04-active-guidance-alignment` | `3c83280236b5a2b86b432bc8738973bf0a79d345`; validator/retrospective/retrospect guidance, `tests/test_target_memory_cli.py`, transactional contract | `:828-841`: real documented CLI examples and anti-empty-run assertions; `python3 -m pytest -q tests/test_target_memory_cli.py` → 18 passed. |

Archive metadata gaps for F04/F06 are historical bookkeeping discrepancies, not missing code: actual work commits were linked through the journal and their changed file lists inspected. Do not silently rewrite archived metadata within this planning inventory.

## 4. Unrelated/unproven historical tasks retained (32)

No requirement-level archive judgment was attempted for these. Even where metadata records an implementation commit (notably `09-28-closure-review-input-contract` and `09-28-stable-release-redundancy-cleanup`), original acceptance scope was not checked. The older September F06/F10/F11 labels belong to another audit and must not be conflated with October F01–F11.

| Exact active task directory | Recorded status | Title |
|---|---|---|
| `.trellis/tasks/09-11-queue-activation-absolute-facts-reset` | `in_progress` | Decouple queue activation seeding from AI-owned fields; add absolute wire facts; owner-derived reset |
| `.trellis/tasks/09-11-remove-out-of-bucket-gates` | `in_progress` | Remove out-of-bucket gates: card/dimension/needle/origin checks default to trust, declaration intent routing |
| `.trellis/tasks/09-11-runner-admission-and-review-basis` | `in_progress` | Runner admission facts + global review basis scoping |
| `.trellis/tasks/09-11-runner-expected-declaration` | `in_progress` | Category-agnostic expected-declaration reconciliation in validation runner |
| `.trellis/tasks/09-14-dumb-queue-interface` | `in_progress` | Retire judgment layers in action_queue claim — dumb queue interface |
| `.trellis/tasks/09-14-kb-outbound-review` | `in_progress` | kb outbound review — pull records + retire loop |
| `.trellis/tasks/09-15-memory-nesting-pollution` | `in_progress` | 记忆链路的跨轮嵌套污染治理 |
| `.trellis/tasks/09-18-ai-native-convergence` | `planning` | AI 原生能力与责任边界分批收敛 |
| `.trellis/tasks/09-18-cvss-contract` | `in_progress` | 移除 CVSS 必需链路 |
| `.trellis/tasks/09-18-experiment-readiness` | `in_progress` | 修复选定实验的机械就绪投影 |
| `.trellis/tasks/09-18-js-bounded-expansion` | `in_progress` | 开放有界 JS 材料补读 |
| `.trellis/tasks/09-18-skill-decision-boundaries` | `in_progress` | 恢复 Skills 的动态决策边界 |
| `.trellis/tasks/09-27-autopilot-lab-full-round` | `planning` | Autopilot 本地靶场完整轮次（juice-shop @ 127.0.0.1:3001） |
| `.trellis/tasks/09-27-fix-case-update-replay` | `in_progress` | F10：修复 Case A→B→A 更新失效 |
| `.trellis/tasks/09-27-fix-command-examples` | `in_progress` | F13：修正失效命令示例 |
| `.trellis/tasks/09-27-fix-intel-corruption-errors` | `in_progress` | F12：区分损坏 intel 与合法空结果 |
| `.trellis/tasks/09-27-fix-report-destinations` | `in_progress` | F11：补齐全部 eligible 报告目的地 |
| `.trellis/tasks/09-27-fix-scanner-lock-identity` | `in_progress` | F06：修复 direct scanner 锁身份不一致 |
| `.trellis/tasks/09-27-web2-priority-functional-fixes` | `in_progress` | Web2 优先功能修复（F10/F11/F12/F13/F06） |
| `.trellis/tasks/09-28-closure-review-input-contract` | `in_progress` | Closure 路径身份与全局复核输入契约 |
| `.trellis/tasks/09-28-execution-review-contracts` | `in_progress` | 修复 D17-D20 执行身份与 review 语义契约 |
| `.trellis/tasks/09-28-stable-release-redundancy-cleanup` | `in_progress` | 稳定版前低风险冗余清理 |
| `.trellis/tasks/09-29-ai-route-closure-boundary` | `in_progress` | 恢复 AI 路线选择与有界结束边界 |
| `.trellis/tasks/09-29-native-first-boundary-optimization` | `in_progress` | Native-first 优化：保留实时 Intel，收敛行为与报告边界 |
| `.trellis/tasks/09-29-native-reading-retirement` | `in_progress` | 原生 JS 与源码阅读，退役冗余准备链 |
| `.trellis/tasks/09-29-report-guidance-convergence` | `in_progress` | 统一报告资格与动态调查指导 |
| `.trellis/tasks/09-29-stable-kernel-skill-knowledge` | `in_progress` | 稳定内核与技能知识驱动架构收敛 |
| `.trellis/tasks/09-29-validation-closure-scope` | `in_progress` | 修复验证证据的闭合作用域 |
| `.trellis/tasks/09-30-bootstrap-capability-retirement` | `planning` | 启动能力矩阵退役 |
| `.trellis/tasks/09-30-memory-handoff-continuity` | `in_progress` | 记忆交接证据与当前意图收敛 |
| `.trellis/tasks/09-30-report-capability-cleanup` | `planning` | 第二批：收缩报告写作层与启动能力矩阵 |
| `.trellis/tasks/09-30-report-native-publication` | `planning` | 报告发布去模板 |

## Main-agent decisions still required

1. The six original F01/F02 planning documents have been read; match their acceptance criteria to the new run before deciding eligibility. An implementation commit and historical pass are not current acceptance.
2. Perform the approved fresh acceptance, recording command, exit/result, fixture boundaries and any uncovered requirements. Source tests and older journal counts cannot replace this.
3. Only then decide whether F01/F02 and eventually the current acceptance/parent tasks are eligible for archive. Preserve the 32 unrelated/unproven active tasks unless a separate requirement-based review establishes otherwise.
