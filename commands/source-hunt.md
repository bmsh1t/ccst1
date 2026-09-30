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
