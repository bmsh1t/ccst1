# /autopilot Phase 4 Contract Pressure Test

Date: 2026-07-01

## Scope

Local, low-risk pressure test for the `/autopilot` runtime loop. This run used
a synthetic target key, `phase4-autopilot-local.test`, and did not send live
network traffic. The goal was to validate structure, not to prove a finding.

## Objective

Verify that a pressure-test run can produce machine-checkable artifacts for the
four required runtime assertions:

1. context-pack route recorded with selected skill and cards/hints
2. at least one executable script/command action
3. raw evidence path recorded in Evidence Ledger
4. action queue resolved with high-risk stop condition

## Gaps found while testing

- `checkpoint.py` still emitted slash-command hints for recon/context-review
  queue items. These are clear in Claude CLI, but they are weaker than explicit
  script commands for machine validation. Recon and context-review hints now map
  to `python3 tools/...` commands.
- `action_queue.py add` could not set a custom stop condition from CLI. That
  made high-risk manual queue items hard to close under the Phase 4 contract.
  The `--stop-condition` argument now persists through `add_manual_action()`.

## Pressure-test commands

Artifacts were written under:

```text
/tmp/ccst-phase4-autopilot-run/
```

The run used project commands for the chain:

```bash
python3 tools/context_pack.py --repo-root /tmp/ccst-phase4-autopilot-run --target phase4-autopilot-local.test --focus "ssrf blacklist filter url parser bypass" --json
python3 tools/checkpoint.py --repo-root /tmp/ccst-phase4-autopilot-run --target phase4-autopilot-local.test --json
python3 tools/action_queue.py --repo-root /tmp/ccst-phase4-autopilot-run add --target phase4-autopilot-local.test --type ssrf-parser-boundary ...
python3 tools/action_queue.py --repo-root /tmp/ccst-phase4-autopilot-run resolve --target phase4-autopilot-local.test --id AQ-0001 --status tested ...
python3 tools/evidence_ledger.py record --repo-root /tmp/ccst-phase4-autopilot-run --target phase4-autopilot-local.test --endpoint "/fetch?url=https://example.invalid/callback" --vuln-class SSRF --result tested_clean ...
python3 tests/skill-validator/check_autopilot_run.py --repo-root /tmp/ccst-phase4-autopilot-run --target phase4-autopilot-local.test
```

## Machine-check result

```text
AUTOPILOT RUN CONTRACT
target: phase4-autopilot-local.test
target_key: phase4-autopilot-local.test
[PASS] context_pack
[PASS] executable_action
[PASS] evidence_path
[PASS] queue_resolution_and_stop
RESULT: PASS
```

Additional observed route detail:

- focused context pack selected `skills/web2-vuln-classes/SKILL.md`
- focused context pack produced `skills/security-arsenal/references/bypass-patterns.md` as an on-demand `reference_hints` entry
- checkpoint recommended command hint became:

```bash
python3 tools/context_pack.py --target "phase4-autopilot-local.test"
```

## Conclusion

Phase 4 now has a deterministic local acceptance path. The pressure test also
improved the runtime chain by converting two slash-command hints to explicit
project commands and allowing CLI-specified stop conditions for queued actions.

This is not a lab pass claim and not a new vulnerability technique. It is a
runtime-loop validation that strengthens the `/autopilot` evidence/action/queue
contract.
