# Validation Results

Date: 2026-08-14

## Baseline

- Branch: `main`
- Start HEAD: `c2aca248d121fb63fceb94cac1e004877447145c`
- End HEAD: `c2aca248d121fb63fceb94cac1e004877447145c`
- Index at start: clean
- User worktree at start: 20 tracked dirty paths and 7 untracked paths
- Production files changed by this audit: none
- End worktree: same 20 tracked dirty and 7 untracked user paths; index still clean

The detailed starting path inventory is in `baseline.md`. The audit used the current
worktree as the primary subject and `HEAD` as the attribution reference.

## Static Gates

| Command | Result | Attribution |
|---|---|---|
| `git diff --check` | PASS | Current worktree |
| `python3 tools/runtime_doctor.py --fail-on-drift` | Exit 1: only `commands/hunt.md` advisory drift; critical drift = 0 | `WORKTREE` advisory |
| `python3 tools/capability_governance.py --strict` | PASS; 15 trigger-collision advisories, no governance errors | Current worktree |
| `python3 tools/knowledge_audit.py --strict` | PASS; errors = 0, warnings = 0 | Current worktree |

The runtime-doctor exit is not a critical runtime failure. The strict knowledge gates
also demonstrate that trigger collisions are advisory routing overlap, not registry or
lifecycle corruption.

## Automated Tests

| Scope | Result | What it proves |
|---|---|---|
| State persistence and failure replay focused selection | 11 passed | Atomic Queue/Checkpoint/Target Memory writes and Ledger -> Finding -> Queue replay paths exercised |
| `tests/test_vuln_scanner_script.py` focused suite | 40 passed | Current scanner wiring and text contracts pass; it does not prove action-level POST safety |
| Reporting focused selection | 14 passed | Historical report IDs no longer overwrite prior reports |
| Knowledge/context focused selection | 146 passed | Stable ordering, selected/deferred budgets, recall reasons and collision regressions |
| `pytest -q` | **3374 passed** | Entire repository suite passes on the audited worktree |

Passing tests do not negate the findings below: the scanner guard test asserts removal of
the action classifier, while the AuthSession, Brain and target-profile negative paths have
no equivalent regression.

## Synthetic Reproductions

All reproductions used a temporary directory, placeholder targets and fake runners. No
external network request or real target action was made.

### Auth source target mismatch

`AuthSession.from_sources()` was given an environment session bound to `target-a.test`
and an auth file bound to `target-b.test`. The result remained bound to A but contained
both `Authorization` and B's `Cookie` header.

`target_case_state add-session --target target-a.test --auth-file <target-b-file>` then
returned 0 and persisted the B cookie under A's private session state.

### Missing auth file

`AuthSession.from_file(<nonexistent-path>)` returned an empty session. It did not raise,
so a direct CLI can continue anonymously after an explicitly requested credential source
is missing.

### Interrupted target-profile write

The JSON writer was replaced only in-process with a fixture that wrote `{` and raised
`OSError`. The existing profile was truncated, the loader returned `None`, and a normal
rebuild changed `hunt_sessions` from 9 to 1 while dropping the recorded endpoint history.

### Legacy Brain command boundary

A fake model response containing one fenced shell command was passed through
`Brain.exploit_finding()` with a fake command runner. `_sanitize_exploit_command()`
returned the command unchanged and the runner received it, proving the deterministic
model-text -> shell execution path without executing a real command.

## Safety and Environment

- No `.env`, `.private/`, target response body or real credential content was read.
- No browser, scanner, network, package installation or external target command was run.
- The audit did not alter, stage, reset or format any production or user-owned worktree file.
