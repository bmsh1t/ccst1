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

## Sourcing the helper

Other scripts source `external_arsenal.sh` to gate optional code paths:

```bash
. "$(dirname "$0")/external_arsenal.sh"
if _have nuclei; then nuclei -l hosts.txt -severity high; fi
```

Use `_have <tool>` rather than `command -v` so the install-hint table stays the
single source of truth for what is and isn't wired in.

For a direct install hint, use `./tools/external_arsenal.sh --install-hint <tool>`;
`/arsenal <tool>` is the Claude-facing equivalent.

Version smoke is diagnostic-only and never runs during `/autopilot` bootstrap.
It executes only known read-only version flags and reports unsupported tools without guessing.

Exchange is evidence-triggered, not a startup check. When target-owned recon shows
OWA/EWS/Autodiscover/Exchange paths, use `python3 tools/eburst_lane.py --target
<target>` for a bounded interface check. Route any reviewed credential test through
the existing `/spray` preflight instead of invoking EBurst's legacy dictionary mode.
