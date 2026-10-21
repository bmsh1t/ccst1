---
description: Show installed external tools, version smoke, and install hints. Usage: /arsenal | /arsenal --versions | /arsenal <tool-name>
---

# /arsenal

Inspect the external tool inventory used by this plugin.

## Usage

```
/arsenal                       # full status table (installed vs missing)
/arsenal --versions            # read-only core tool version smoke
/arsenal nuclei                # show install hint for a single tool
```

## Registry

`tools/external_arsenal.sh` is the single inventory and install-hint registry;
this command renders its current entries and does not maintain a copied tool
list. The helper supports `--versions`, `--install-hint <tool>`, and
`--have <tool>` from that same registry.

## Direct upstream use

The inventory provides discovery and install hints; it does not prescribe a tool
chain or prove runtime readiness. Use the chosen tool directly with its installed
help/version and selected input. No wrapper import is required.

For a direct install hint, use `./tools/external_arsenal.sh --install-hint TOOL`;
`/arsenal TOOL` is the Claude-facing equivalent. Installation remains explicit.
Version smoke is diagnostic-only and does not run during Autopilot startup.

Exchange evidence can be read natively or investigated with an explicitly selected
upstream tool. `tools/eburst_lane.py` is an optional adapter for the external
EBurst `-C` interface check, not a startup dependency. Select `--target` and
`--host https://HOST[:PORT]` with `--timeout`/`--max-hosts` bounds. Omitting `--host`
uses bounded cached Exchange candidates; it does not make this a default action.
The adapter checks current Scope, retains per-run raw bytes/exit status under
`recon/<target-key>/exchange/eburst/runs/`, and leaves historical raw files intact.
The retained command uses HTTPS; an HTTP-only input or a parent Scope continuation
requires another executor. Upstream output is review material, not a vulnerability
or account-validity verdict. Credential execution uses the existing `/spray`
preflight and stop contracts.
