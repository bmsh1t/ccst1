---
description: Prepare cached JS materials and run the js-reader agent to produce endpoint, auth, realtime/framework, sink, and AI-reviewable hunting hypotheses. Usage: /js-read target.com
---

# /js-read

Convert cached JavaScript from `/recon` into LLM-derived hunting leads.

## Run This (the only required step)

```bash
python3 tools/js_reader.py --target target.com
```

Then use the `js-reader` agent on:

```text
findings/target.com/js_intel/materials.json
```

The preparation step is local-only and does not call an LLM. The agent reads the prepared materials and selected cached JS files.

## What This Produces

```text
findings/<target>/js_intel/materials.json
findings/<target>/js_intel/materials_summary.md
findings/<target>/js_intel/hypotheses.json
```

Expected hypotheses include:

- endpoint candidates with method/path/auth hints
- auth model: token storage, role checks, OAuth/OIDC, CSRF/SameSite
- GraphQL operations and WebSocket/realtime signals
- framework/source-map hints such as Next/Nuxt/source maps
- URL-fetch, webhook, upload/import/parser leads
- AI-reviewable attack-surface leads for `/surface` and `/hunt`

## When To Use

- `recon/<target>/urls/js_files.txt` or `recon/<target>/js/endpoints.txt` exists
- `/surface` shows JS-heavy, SPA, GraphQL, WebSocket, OAuth, CSRF, or hidden API signals
- LinkFinder/grep produced strings but the workflow/auth model is unclear

After `/js-read`, rerun:

```bash
python3 tools/surface.py --target target.com
```
