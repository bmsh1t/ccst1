---
description: Hunt leaked credentials in a filesystem path, git history, JS bundles from a recon run, or an entire GitHub org. Wraps trufflehog, noseyparker, and gitleaks, with regex fallback. Usage: /secrets-hunt --filesystem <dir> | --git <repo> | --js-bundle <recon-dir> | --github-org <org>
---

# /secrets-hunt

Find leaked API keys, tokens, and credentials. Treat hits as evidence leads until provider/ownership/usability are minimally proven.

## Run This (the only required step)

```bash
bash tools/secrets_hunter.sh --filesystem /path/to/project
bash tools/secrets_hunter.sh --git https://github.com/target/repo
bash tools/secrets_hunter.sh --js-bundle recon/target.com
bash tools/secrets_hunter.sh --github-org acme-corp
```

## Scanners

The script uses whichever is installed:

| Scanner | Strength |
|---|---|
| `trufflehog` | Verifies live keys against issuer APIs where supported |
| `noseyparker` | Fast on large histories with low false positives |
| `gitleaks` | Solid default rule pack |
| regex fallback | Last-resort local signal when scanners are missing |

## Output

```text
findings/secrets/<timestamp>/trufflehog.jsonl
findings/secrets/<timestamp>/noseyparker.jsonl
findings/secrets/<timestamp>/gitleaks.json
findings/secrets/<timestamp>/regex_hits.txt
```

## Handling Hits

- Prefer verified hits and target-owned context.
- Keep proof minimal: show the key is valid for the exposed target/provider; do not pivot beyond what is needed for evidence.
- If the hit comes from recon API leak artifacts, preserve the exact source file and line.
- After meaningful hits, rerun `/surface target.com` or continue with `/validate` when the evidence is candidate-quality.
