---
description: Scan a GitHub public repo or local repo path for leaked secrets, risky config files, GitHub Actions / CI patterns, and source-derived hunting leads. Usage: /source-hunt target.com --repo-url https://github.com/org/repo [--allow-large-repo]
---

# /source-hunt

Scan source repositories for exposure observations and source-backed review candidates.

## Run This (the only required step)

```bash
python3 tools/source_hunt.py --target target.com --repo-url https://github.com/org/repo
python3 tools/source_hunt.py --target target.com --repo-path /path/to/local/repo
python3 tools/source_hunt.py --target target.com --repo-url https://github.com/org/repo --allow-large-repo
```

Claude may directly Read/Grep the local repository or cached raw artifacts after this scan. No second source parser is required.

## What This Writes

```text
findings/<target>/exposure/repo_source_meta.json
findings/<target>/exposure/repo_secrets.json
findings/<target>/exposure/repo_ci_findings.json
findings/<target>/exposure/repo_summary.md
```

## Use When

- Public repo URL is visible in target footer, docs, package metadata, GitHub org, or disclosed reports.
- `/surface` shows source-backed, route/auth, CI/CD, secret, or framework-intel leads.
- You need source-backed route, auth, object, tenant, GraphQL, export, or dangerous-sink evidence.

Read exact paths directly, then choose any explicit validation or queue action.

## CI evidence and judgment boundary

The built-in GitHub Actions checks emit **review candidates**, not vulnerability verdicts or severity claims.
`pull_request_target` plus checkout alone does not prove that attacker-controlled code runs. Inspect the
trigger, job/step conditions, permissions, checkout ref and actual data flow in the saved workflow before
judging impact. Existing rule IDs and the `repo_ci_findings.json` list remain; CI `severity` and `confidence`
are `unknown`, and `metadata.status` is `candidate`. No Finding/assessment or Queue action is created.

Additional outputs:

```text
findings/<target>/exposure/repo_workflows.json
findings/<target>/exposure/repo_workflows/<sha256>.yaml
```

The inventory maps original repository paths to exact source-byte snapshots, SHA-256, size and per-file
status. `artifact` and candidate `metadata.workflow_artifact` paths are relative to this exposure directory.
Candidate line numbers locate their job context in those original bytes. Every bounded workflow is saved,
including workflows with no matching pattern and invalid YAML; snapshots survive temporary clone cleanup.
Identical bytes reuse a snapshot, and a changed existing snapshot is refused rather than overwritten.
Files are private (0600); these internal source materials are not redacted public reports.

`repo_source_meta.repo_commit` and the inventory's `repo_commit` record the acquired local Git HEAD when
available. They are version context, **not a claim that the working tree is clean**: the snapshot hash binds
what was actually read. A non-Git folder or unavailable Git revision stays explicitly unknown.

The scan reads at most 256 workflows and 1 MiB per file. `deferred_paths` retains unscanned workflow names
for deliberate follow-up; `remaining_files`, oversized/unreadable/invalid
entries and unsafe paths make the result `partial`; the CLI exits 2 while retaining available candidates and
raw material. Omitted files are not tested-clean. A complete inventory only means this bounded GitHub Actions
collection and these checks finished, not that the repository is free of CI vulnerabilities. Files outside
these bounds require deliberate follow-up from the source/version context, not automatic wider scanning.

Local paths do not trigger remote GitHub requests. Existing clone-size approval and secret scanning remain.
No remote `sisakulint` call replaces local inspection, and no missing optional tool becomes a clean result.


## Selected source evidence for whitebox questions

```bash
python3 tools/source_hunt.py --target TARGET --repo-path PATH --source-file src/routes.py --source-file src/service.py
```

`--source-file` selects repository-relative UTF-8 files explicitly (repeatable;
32 distinct files, 1 MiB each). The existing source/secret/CI scan still runs;
this is not an execution mode or a general parser. For already saved originals,
read them directly instead of recollecting. Local input performs no remote acquisition.

`repo_source_meta.json/source_capture` binds each original path to its exact
SHA256, byte count and private `repo_source_files/<sha256>.txt` snapshot. Read
that snapshot with native Read/Grep and cite its original path and line range.
The hash binds dirty/current bytes independently of Git HEAD; no Git means
revision unknown. Empty files are valid empty originals, not a clean audit.

Missing, non-UTF-8, oversized and unsafe/symlink paths are per-file unavailable;
deferred names are explicit. Any omission makes capture and the command partial
(exit 2), retaining successful originals. Existing changed snapshots fail rather
than overwrite evidence. A complete capture only covers selected files; it says
nothing about unrequested files, deployment correspondence or exploitability.

Use `skills/whitebox-audit/SKILL.md` for entry/guard/sink analysis and conditional
source-to-runtime handoff. Source suggestions never run code, create an Action,
confirm a Finding or bypass `triage-validation` and the assessment owner.
