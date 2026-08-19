---
description: Run a focused nuclei CVE sweep against a host or recon directory, optionally filtered by year. Runs log4j-scan in parallel when installed for legacy enterprise stacks. Usage: /scan-cves <host-or-file> [--year 2024] | /scan-cves --recon <recon-dir>
---

# /scan-cves

Targeted nuclei scan of the `cve/` template directory plus optional log4j-scan.

## Usage

```
/scan-cves https://target.com
/scan-cves --recon recon/target.com
/scan-cves --year 2024 recon/target.com/live/urls.txt
```

## Why a separate command

The normal recon/scanner pass does not run a product-wide CVE sweep. This command
is the explicit, focused path for **known CVEs**, which:

- Cuts the runtime by an order of magnitude (high/critical CVE templates only).
- Surfaces signals that pay even on dormant programs (CVE-2021-44228 still hits
  on legacy enterprise hosts).
- Lets you re-scan one or two URLs without rerunning the full pipeline.

The integrated scanner can opt into its bounded origin pass for compatibility with
`BBHUNT_ENABLE_NUCLEI_CVES=1`; prefer this command when the AI has selected a
reachable component, version, or advisory. SQLi and SSRF are handled by their
dedicated probes/OAST routes and do not use Nuclei by default.

Set `NUCLEI_NO_UPDATE=1` to skip the template update on each run when
iterating quickly.

## Output

`findings/cve/<timestamp>/`:
- `nuclei_cve.jsonl` — one finding per line (template ID, host, severity)
- `log4j.txt` — optional log4j-scan output when the scanner is installed

## After a hit

1. Confirm the version manually (don't trust the template — show the response).
2. Check current target context, existing disclosure status, and patch posture;
   many CVE hits are stale, already disclosed, or mid-remediation.
3. Provide a non-destructive PoC: a single request that proves the version is
   vulnerable, not a working exploit chain.
