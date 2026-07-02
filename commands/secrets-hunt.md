---
description: Hunt leaked credentials in a filesystem path, git history, JS bundles from a recon run, or an entire GitHub org. Wraps trufflehog, noseyparker, and gitleaks, with regex fallback. Usage: /secrets-hunt --filesystem <dir> | --git <repo> | --js-bundle <recon-dir> | --github-org <org>
---

# /secrets-hunt

Find leaked API keys, tokens, and credentials. Treat hits as evidence leads until provider/ownership/usability are minimally proven.

Secret exposure is not automatically a high-value finding and is not a red line.
Treat it as a vulnerability signal: value depends on whether the key is valid,
target-owned, scoped to useful permissions, and tied to concrete security
impact.

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
- Do not chase generic leakage risk. Prove the vulnerability impact with the
  smallest useful request, then move to Candidate / validation if the evidence
  is meaningful.
- If the hit comes from recon API leak artifacts, preserve the exact source file and line.
- After meaningful hits, rerun `/surface target.com` or continue with `/validate` when the evidence is candidate-quality.

## Secret Triage Lane

After scanner output exists, triage secret findings before treating them as a
high-value Candidate:

```bash
python3 tools/secret_triage.py --file findings/<target>/exposure/repo_secrets.json
```

Triage classifies:

- provider/type: AWS, GitHub, Stripe, Slack, private key, bearer token,
  OAuth client secret, generic API key, password/config
- exact source: file/artifact/line and masked preview
- ownership context: target-owned domain, repo/org, bundle provenance,
  environment, account/workspace clues
- verification safety: minimal read-only check, bounded manual/read-only check,
  or manual review
- candidate status: `context-needed`, `needs-safe-verification`, or
  `candidate-ready`

Promotion rule:

- `context-needed` → stay as Signal; identify provider/owner/source first.
- `needs-safe-verification` → run only the smallest safe identity/capability check,
  or record why verification is blocked.
- `candidate-ready` → move to `/validate` with source, ownership, validity,
  usable permissions, and impact path.

Examples of safe verification intent:

- GitHub token → identity/org/capability check, no repo writes.
- AWS key → identity check when paired credentials exist, no resource changes.
- Stripe key → account/key metadata only, no charge/refund/customer changes.
- Slack token → auth identity/capability check, no message/channel/member changes.
- Private key/password → map purpose and ownership; do not automatically log in
  to infrastructure without a bounded reason.
