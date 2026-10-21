---
description: Review exact secret-like source evidence; optionally invoke gitleaks, noseyparker or TruffleHog directly. Usage: /secrets-hunt TARGET --filesystem PATH | --git REPO | --js-bundle RECON_DIR
---

# /secrets-hunt

Read exact cached source and context first. Distinguish public identifiers,
example/test keys, expired values and possible credentials. Follow ownership,
issuer, reachable use and effective permissions before judging impact.

For a concrete bulk/history gap, select one installed upstream scanner and read
its local help. Gitleaks and noseyparker can inspect local files/history.
TruffleHog provider verification makes external requests and requires deliberate
selection within current authorization. GitHub organization input requires
explicitly selected in-scope repositories. Reuse cached JS without silently
re-fetching it as a second scanner workflow.

For a selected local SOURCE_DIR and new private target RUN_DIR:

```bash
gitleaks dir "$SOURCE_DIR" --report-format json --report-path "$RUN_DIR/gitleaks.json"
```

Use current upstream syntax; preserve raw values privately, source path/line,
revision/hash, command/version, logs and exit status. See
[Direct upstream execution](../docs/tool-index.md#direct-upstream-execution).
Gitleaks normally uses exit 1 for detections; interpret the selected version's
exit meanings and keep execution failure separate. An unavailable scanner remains
unavailable, without an automatic regex fallback or clean verdict.

A match or verified-key label is an unassessed lead. Collect minimum useful
permission/ownership evidence before an HTTP candidate and register actual
execution through existing owners. Public summaries cite private artifacts.
