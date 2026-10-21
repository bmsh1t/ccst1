---
description: Review a target-owned dangling DNS/service lead; optionally invoke dnsReaper or subjack directly. Usage: /takeover SUBDOMAINS_FILE | /takeover --recon RECON_DIR
---

# /takeover

Read the observed DNS chain, provider response and current claim conditions. Select
target-owned hosts whose binding warrants review. A dangling record, error page or
historical fingerprint alone does not prove an available claim.

Use native DNS/HTTP inspection or the installed upstream dnsReaper/subjack for the
selected input. Check that version's help; available scanners are alternatives,
without a required chain or copied fingerprint fallback.

After preparing a reviewed INPUT_FILE and private target RUN_DIR:

```bash
dnsreaper file --file "$INPUT_FILE" --out "$RUN_DIR/dnsreaper.json" --out-format json
```

Keep original DNS/HTTP bytes, provider source/date, input, command/version and exit
status. Use [Direct upstream execution](../docs/tool-index.md#direct-upstream-execution)
for Scope/output paths. Any control proof must fit current Scope and authorization.
Retain unknown status when claimability cannot be established; supported HTTP
candidates use existing evidence and assessment owners.
