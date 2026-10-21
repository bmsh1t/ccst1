---
description: Review target-owned source with native Read/Grep; optionally acquire a bounded repository and preserve selected source/workflow originals. Usage: /source-hunt TARGET --repo-path PATH [--source-file RELATIVE_PATH]
---

# /source-hunt

Read the source that answers the current question, then follow entry points, guards,
object/tenant bindings and sinks with native Read/Grep. Use
`skills/src-hunter/modules/whitebox-audit.md` when useful. Select secret or CI analysis
from the actual evidence; collection does not run either analysis or create findings.

## Optional acquisition and original capture

For a local checkout, native reading needs no preparation. Use this helper when you
need persistent original bytes or a bounded public clone:

```bash
python3 tools/source_hunt.py --target TARGET --repo-path PATH --source-file src/routes.py --source-file src/service.py
python3 tools/source_hunt.py --target TARGET --repo-url https://github.com/org/repo --source-file src/routes.py
```

Local input performs no remote acquisition. The existing clone-size boundary remains;
use `--allow-large-repo` only for a deliberately selected larger repository. Do not run
repository scripts, builds, hooks or workflows merely to read them.

## Retained artifacts

```text
findings/<target-key>/exposure/repo_source_meta.json
findings/<target-key>/exposure/repo_summary.md
findings/<target-key>/exposure/repo_source_files/<sha256>.txt
findings/<target-key>/exposure/repo_workflows.json
findings/<target-key>/exposure/repo_workflows/<sha256>.yaml
```

Use the canonical target key from `tools/target_paths.py`; acquisition writes these
paths for you. Meta explicitly records `execution_mode=source-capture`,
`secret_scan=not_run` and `ci_scan=not_run`. Historical `repo_secrets.json` and
`repo_ci_findings.json` remain readable and are neither overwritten nor counted as
this run's results.

`--source-file` is repeatable: at most 32 distinct repository-relative UTF-8 files,
1 MiB each. `source_capture` maps original paths to exact SHA-256, byte count and
private snapshot. Missing, non-UTF-8, oversized or unsafe/symlink paths are unavailable;
`deferred_paths` retains names beyond the bound. Any omission makes capture partial
(exit 2), preserving successful originals. Empty files are valid empty originals.

Workflow collection preserves at most 256 `.yml`/`.yaml` originals under
`.github/workflows`, 1 MiB each, without YAML parsing or pattern checks. Invalid YAML
is still retained as source bytes. The inventory records paths, hashes, sizes,
per-file status, `remaining_files` and deferred names. Unreadable, oversized or unsafe
files and deferred work make the inventory partial. `analysis_status=not_run` is
independent of collection status.

Snapshots preserve BOM and line endings, use private files (0600), reuse identical
bytes and refuse changed existing snapshots. `repo_commit` is the acquired Git HEAD
when available, otherwise unknown. It does not prove a clean working tree or matching
deployment; the snapshot hash identifies the bytes actually read. A complete capture
only describes these collected files, with no clean audit or exploitability claim.

## Native analysis and handoff

Read retained originals and cite original paths, line context, hash and revision.
For GitHub Actions, trace event input through conditions, permissions, checkout refs,
expressions and code execution. An event name or checkout alone proves no exploit.
Use a directly invoked upstream tool such as `sisakulint` or `gitleaks` only when it
answers the selected question; retain its raw output, command/version and exit status.

Connect a source lead to the target's deployed entry before runtime validation. Then
use existing evidence registration and assessment owners for the selected request.
Source capture or upstream output does not authorize execution, create an Action or
confirm a Finding.
