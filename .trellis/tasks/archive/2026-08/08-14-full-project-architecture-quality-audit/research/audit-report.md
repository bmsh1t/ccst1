# Full Project Architecture and Quality Audit

Date: 2026-08-14

## Verified Findings

### F-01 - P0 / high / `WORKTREE`: default scanner performs persistent or state-changing POST actions

**Invariant and impact.** A default broad scan must not upload executable files, submit
authentication assertions or perform repeated OTP attempts without an action-level opt-in
and controls. The worktree scanner now treats every POST as safe, so an ordinary
`tools/hunt.py --scan-only` can cross that boundary. The upload lane writes PHP/JSP/ASPX
content to the target and never removes the remote object; the MFA lane sends 15 OTP
attempts; the SAML lane posts an unsigned admin assertion.

**Root cause and call path.** `scanner_probe_guard()` delegates only to
`SafeMethodPolicy.is_safe(method)`, whose shared method set includes POST. The worktree
deleted the label/action classifier that previously required `ALLOW_UNSAFE_HTTP_TESTS=1`
for upload, MFA/OTP and SAML actions. The default scanner skips XSS only, so these lanes
remain enabled unless the operator names them in `--scanner-skip`.

**Evidence.**

- `tools/vuln_scanner.sh:257-303` - POST is accepted solely by method.
- `tools/vuln_scanner.sh:787-838` - executable upload canary and remote probes, with only
  the local temporary file removed.
- `tools/vuln_scanner.sh:1623-1660` - repeated OTP and response-manipulation requests.
- `tools/vuln_scanner.sh:1718-1730` - unsigned SAML assertion with an admin NameID.
- `tests/test_vuln_scanner_script.py:75-90` - text-only test explicitly requires the old
  action classifier to be absent.
- `.trellis/spec/backend/quality-guidelines.md:42-50` and `rules/red-lines.md:127-159` -
  risk is action/side-effect based; executable upload and state-changing actions require
  controls rather than a method-only decision.

**Verification.** The worktree diff removes `post_action_requires_opt_in`; the HEAD copy
still classifies the three action families. The 40 scanner tests pass because they verify
the changed text, not safe behavior.

**Minimum remediation.** Restore the existing action-level opt-in check. Make upload
validation inert by default and, when explicitly enabled against a test-owned resource,
record cleanup and verify it. Keep generic read-only/preview POSTs allowed; do not turn the
project into a GET-only scanner or add a new policy framework.

### F-02 - P1 / high / `HEAD`: legacy Brain executes model-generated shell text

**Invariant and impact.** Untrusted scanner evidence and model output must not become an
unbounded local shell command. A prompt-influenced or simply incorrect model response can
execute arbitrary commands on the operator host and may auto-install software.

**Root cause and call path.** Candidate finding text is sent to the model; the first
fenced shell block is extracted; `_sanitize_exploit_command()` rejects only three narrow
strings; non-basic tools are auto-installed; the remaining text is executed with
`shell=True`. The explicit `brain.py --phase exploit|autopilot` CLI makes this reachable,
but it is not the current inline `/autopilot` default, which limits severity to P1.

**Evidence.**

- `brain.py:988-999` - sanitizer accepts every command except three special cases.
- `brain.py:1900-1917` - arbitrary fenced shell text is extracted.
- `brain.py:1938-1955` - scanner evidence enters the model prompt and permission prompts
  are explicitly suppressed.
- `brain.py:1973-1989` - extracted text is sanitized, optionally installs a tool, then runs.
- `brain.py:1805-1811` - command execution uses `shell=True`.
- `brain.py:2022-2068` and `brain.py:2300-2328` - automatic finding-to-execution flow and
  direct CLI entry.

**Verification.** A fake model and fake runner showed that a fenced `bash -c ...` command
passes the sanitizer unchanged and reaches `run_command()`.

**Minimum remediation.** Reuse the existing save-only scan-plan behavior at
`brain.py:2131-2141`: generate and persist a plan by default, but do not execute it.
Retain execution only behind an explicit per-command review/action gate. Do not add a
general command DSL or another agent runtime.

### F-03 - P1 / high / `HEAD`: auth material can be merged or imported across targets

**Invariant and impact.** Credentials bound to one target must not be persisted or replayed
for another target. The current merge and case-state import paths can place target B's
cookie into a session owned by target A.

**Root cause and call path.** `AuthSession.from_sources()` merges file headers before
checking whether its target conflicts with the environment session, and only copies the
file target when the current target is empty. Separately, `target_case_state add-session`
calls `.headers_dict()` without binding the imported session to its CLI target, then writes
those values to the target-owned private case state.

**Evidence.**

- `tools/auth_session.py:260-282` - unconditional header merge and target adoption only
  when the destination target is empty.
- `tools/auth_session.py:93-112` - the existing `bind_target()` would clear cross-target
  credentials, but the import path does not invoke it.
- `tools/target_case_state.py:1282-1299` - auth-file headers are extracted without target
  binding.
- `tools/target_case_state.py:376-432` - headers are accepted into the session mutation.
- `tools/target_case_state.py:225-259` - credentials are persisted in target-owned private
  state.

**Verification.** The synthetic reproduction kept an A-bound environment bearer while
merging B's cookie, and the case-state CLI returned 0 while storing B's cookie under A.

**Minimum remediation.** Fail fast on conflicting source targets in the shared merge
boundary, then bind case-state imports to `args.target` before extracting headers. Keep the
existing `AuthSession` owner; do not add per-caller header filters or a second auth schema.

### F-04 - P1 / high / `HEAD`: an explicitly missing auth file silently becomes anonymous

**Invariant and impact.** A named credential source that cannot be read is an input error,
not an empty session. Direct validation CLIs can otherwise run anonymously and record
false negatives or misleading state.

**Root cause and call path.** `AuthSession.from_file()` returns `AuthSession()` when the
path does not exist. `session_from_args()` passes explicit `--auth-file` values through
that loader, and multiple network-capable CLIs consume the result. Inline `/autopilot`
prevalidates its path, but direct tools do not share that protection.

**Evidence.**

- `tools/auth_session.py:204-211` - missing file returns an empty session.
- `tools/auth_session.py:431-461` - CLI argument adapter forwards the explicit path.
- `tools/hunt.py:2448`, `tools/validation_runner.py:3627`,
  `tools/json_inject_probe.py:1186` - representative direct consumers.
- `.trellis/spec/backend/error-handling.md:5-15` and
  `.trellis/spec/backend/contracts/runtime-autopilot.md:156-165` - explicit missing or
  unreadable auth input must stop before target I/O.

**Verification.** Loading a nonexistent temporary path returned an empty session without
raising. Existing auth tests cover valid files and source precedence but not this case.

**Minimum remediation.** Make the shared file loader raise a bounded parameter error for
missing/non-file/unreadable explicit paths and add one direct-CLI regression proving no
network call occurs. Do not duplicate existence checks across every consumer.

### F-05 - P2 / high / `HEAD`: target profile interruption and corruption can erase hunt history

**Invariant and impact.** A failed write must preserve the previous valid profile, and a
damaged canonical profile must not be treated as a missing file. An interrupted profile
write can truncate the JSON; the next hunt/remember operation then rebuilds and overwrites
it, losing scope snapshot, endpoint history and counters.

**Root cause and call path.** `save_target_profile()` writes directly with `open(..., "w")`.
`load_target_profile()` catches I/O, JSON and schema errors and returns `None`. Both
`hunt._update_target_profile()` and `remember.load_or_create_target_profile()` interpret
`None` as first use and save a replacement.

**Evidence.**

- `memory/target_profile.py:96-118` - damaged input is hidden and writes are non-atomic.
- `tools/hunt.py:907-947` - missing/invalid profile is rebuilt and saved.
- `tools/remember.py:158-170` and `tools/remember.py:210-255` - same rebuild path before
  remembering a finding.
- `tests/test_target_profile.py:13-49` - only filename and happy-path round trip coverage.

**Verification.** A synthetic interrupted writer left `{`; loading returned `None`; a
normal rebuild reduced the session count from 9 to 1 and dropped the saved endpoint.

**Minimum remediation.** Apply the repository's existing temp-file + flush + `fsync` +
replace pattern and propagate corruption as a path-bearing error. Keep `None` only for a
truly missing profile. Add interrupted-write, malformed JSON and repeated recovery tests;
do not auto-repair damaged JSON or introduce a writer abstraction.

## Advisories and Technical Debt

### Runtime drift

`runtime_doctor.py --fail-on-drift` reports only `commands/hunt.md` advisory drift;
critical drift is zero. Handle it as a separate runtime-template synchronization change,
not inside the state/auth/scanner fixes.

### Knowledge trigger collisions

There are 15 collision advisories and no governance errors. Strict governance and audit
pass, while focused regressions prove stable ordering, bounded selected/deferred results,
recall reasons, negative samples and no duplicate loading. Keep the generic triggers;
extend regression cases only when recall behavior changes.

### Multi-owner eventual consistency

Evidence Ledger, canonical Finding and Action Queue remain separate files without a
cross-file transaction. Current `operation_id` replay, invalid-provenance detection and
Ledger -> Finding -> Queue rebuild paths converge in focused tests. Retain this design and
add failure-point replay tests with future mutations; a database, event bus or mutation
coordinator has no demonstrated benefit here.

### Remaining direct writers

`request_guard.py:75-118` also hides malformed JSON and directly overwrites guard state.
Because this module is explicitly advisory telemetry rather than an execution guard, loss
of breaker/rate history is P2 debt, not a scope bypass finding. Fix it in the same atomic
write/corruption batch as target profile. Derived browser/recon summaries may keep local
writers where their data is reproducible.

### Coordinator size and coupling

`agent.py`, `tools/hunt.py`, `checkpoint.py`, `context_pack.py` and related coordinators
are large and coupled, but line count alone is not a defect. Do not perform a repository
split. When changing one of these paths, extract only independently testable pure
functions, schemas or I/O helpers needed by that change.

### Legacy dual entry

The inline Claude runtime and `agent.py` / `brain.py` / `tools/hunt.py --agent` retain two
session models. Documentation and compatibility tests clearly separate target-level pickup
from exact legacy trace resume, so the dual entry itself is not a finding. Keep it until
usage can be measured; fix F-02 at its execution boundary without deleting or moving the
legacy runtime.

### Dependency reproducibility

The worktree adds pinned `badsecrets==1.2.1`, and the new wrapper is offline and covered by
an integration test. Existing top-level dependencies (`anthropic`, `requests`, `PyYAML`)
remain unpinned and there is no lockfile, which is P3 release reproducibility debt rather
than a current runtime defect. Add a lock/constraints workflow only when producing a
reproducible release artifact.

## Test Gaps

1. Scanner safety tests assert source strings rather than execute an action matrix; deleting
   the action-level guard made the test pass by design.
2. Auth tests lack conflicting source targets, target-bound case import and missing-file
   no-I/O regressions.
3. Brain has no regression proving untrusted model output cannot reach a real shell or
   installer without review.
4. Target-profile tests cover only a successful round trip, not partial write, bad JSON,
   schema damage or repeated recovery.

The full suite passing with all four gaps is evidence that the tests are insufficient for
these invariants, not evidence that the findings are speculative.

## Recommended Batches

1. **Immediate scanner containment (F-01).** Restore the prior action-level opt-in and make
   executable upload inert/cleanable. Add one behavior test for default skip and explicit
   opt-in. Keep this separate from all persistence work.
2. **Auth trust boundary (F-03, F-04).** Validate target compatibility in the shared source
   merge, bind case imports, and fail fast for explicit missing files before network I/O.
3. **Legacy Brain execution (F-02).** Default to the existing save-only plan path; require
   explicit review for execution and remove implicit installation from that flow.
4. **Atomic legacy state (F-05 + request-guard debt).** Reuse existing atomic-write patterns,
   fail fast on damaged JSON, and add interruption/recovery regressions.
5. **Advisory maintenance.** Resolve `hunt.md` drift independently, retain collision
   regressions, and preserve the documented legacy entry boundary.

## Residual Risk and Excluded Leads

- Full tests use synthetic fixtures and cannot prove remote side effects are reversible;
  F-01 should be contained before any live scanner use.
- Shell wrappers and older standalone report/analysis utilities still contain local direct
  path construction, but no primary runtime call chain or remote-input write primitive was
  verified during this audit. Keep them as legacy modernization leads, not findings.
- Historical report-ID overwrite behavior is fixed and its focused tests pass; it is not a
  current finding.
- No evidence supports introducing a database, event bus, global writer abstraction or a
  whole-repository coordinator refactor.
