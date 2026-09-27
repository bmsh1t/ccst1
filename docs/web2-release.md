# Web2 release acceptance

This acceptance covers the Linux x86_64 / Python 3.13 Web2 workflow: installation,
Scope/authenticated HTTP execution, private evidence, Store registration,
explicit technical/delivery decisions, immutable reports and process recovery.
Claude Code 2.1.278 is the host version exercised with a local fake Messages API.
This verifies command loading and argument expansion, not online model quality.

Other OS/Python/Claude versions and all external scanner version combinations
are not certified by this run. Web3 and Skill expansion are outside this release
acceptance. A release-ready commit is not a published release.

## Installation and updates

Run from the repository, using Python 3.13 and an active venv:

```bash
python3.13 -m venv .venv
. .venv/bin/activate
python -m pip install --require-hashes -r requirements-ci.lock
python tools/check_requirements_lock.py
python -m pip check
bash install.sh
python tools/runtime_doctor.py --fail-on-drift
```

The CI lock includes test dependencies. The installer writes commands, agents
and Skills; tools and target data remain in this checkout. Re-run it after
updating the checkout. It never upgrades a target database implicitly.

Installation preserves disabled commands, user settings and unrelated Skill
roots. Each repo-owned Skill directory is mirrored when rsync is present;
custom files inside that directory can be removed. Without rsync, copying is
additive and old nested files can remain. The doctor reports those as `EXTRA`.
After reviewing the affected Skill roots, explicit cleanup is available:

```bash
python tools/runtime_doctor.py --kind skills --sync --prune
python tools/runtime_doctor.py --fail-on-drift
```

A whole Skill removed from the repository is no longer an owned root and needs
manual retirement. The full doctor can report intentional external commands as
extras; review them rather than applying a blanket command prune. Autopilot's
startup gate checks critical runtime assets separately from advisory drift.

## Evidence and recovery

Keep the target Store, saved Scope and external raw/report files together.
Database-only backups do not contain raw evidence. Use the Store's backup API
for a live WAL database; do not copy only `metadata.sqlite3` while writes run.
An older database requiring migration must use the explicit schema-upgrade or
historical-import operation with its backup, not an installer side effect.

After interruption, inspect the attempt and existing raw before retrying.
Retry registration or the uncommitted judgment with its existing identity;
do not resend a network action merely because registration failed. Checkpoint
and `/pickup` reacquire current evidence health. Damaged/revoked raw retains
history but cannot authorize a current closure or report. An old JSON profile
is not a fallback for a missing or damaged Store.

## Reproduce the acceptance

```bash
python -m pytest -q tests
bash tests/test_cicd_scanner.sh
bash tests/test_recon_denoising_integration.sh
python tools/check_requirements_lock.py
python tools/knowledge_audit.py --strict
git diff --check
```

`tests/test_install_script.py` exercises installation/upgrade and preservation;
`tests/test_validation_runner.py::test_loopback_http_through_report_and_process_restart`
uses real loopback HTTP and independent CLI processes. Existing native/browser,
Scope, report-integrity, retry, backup and multi-round recovery tests remain part
of the full suite. Decisions in these fixtures are explicit test inputs, not
model-generated findings.

`tests/test_claude_release_wiring.py` installs to a temporary user directory and
runs the real Claude binary with dummy credentials and a local fake API. It
allows the read-only Python bootstrap through Bash; the fake endpoint emits no
tool calls. No personal configuration or target state is loaded. If Claude is
absent, this test explicitly skips; release acceptance then needs a separate
successful run with Claude installed. A skip cannot establish host compatibility.

The release record must identify the tested commit, environment, commands,
exit codes and any failures/skips. Publish only after all core gates pass;
record optional-tool limitations separately. Do not infer broader support or
model-performance claims from a green local suite.
