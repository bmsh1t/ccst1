---
description: Scan a GitHub public repo or local repo path for leaked secrets, risky config files, GitHub Actions / CI patterns, and source-derived hunting leads. Usage: /source-hunt target.com --repo-url https://github.com/org/repo [--allow-large-repo]
---

# /source-hunt

Scan source repositories for high-signal exposure and source-backed hunting leads.

## Run This (the only required step)

```bash
python3 tools/source_hunt.py --target target.com --repo-url https://github.com/org/repo
python3 tools/source_hunt.py --target target.com --repo-path /path/to/local/repo
python3 tools/source_hunt.py --target target.com --repo-url https://github.com/org/repo --allow-large-repo
```

If a local repo path is available, also extract source intelligence:

```bash
python3 tools/source_intel.py --target target.com --repo-path /path/to/local/repo
```

If only recon/JS artifacts exist, source intelligence can still mine cached recon context:

```bash
python3 tools/source_intel.py --target target.com
```

## What This Writes

```text
findings/<target>/exposure/repo_source_meta.json
findings/<target>/exposure/repo_secrets.json
findings/<target>/exposure/repo_ci_findings.json
findings/<target>/exposure/repo_summary.md
findings/<target>/source_intel/summary.md
findings/<target>/source_intel/hypotheses.jsonl
```

## Use When

- Public repo URL is visible in target footer, docs, package metadata, GitHub org, or disclosed reports.
- `/surface` shows source-backed, route/auth, CI/CD, secret, or framework-intel leads.
- You need route handlers, auth decorators, object IDs, tenant/account boundaries, GraphQL operations, export/download/invite/admin actions, or dangerous sinks.

After source intel, rerun:

```bash
python3 tools/surface.py --target target.com
```
