---
description: Prepare cached JS materials and run the js-reader agent to produce endpoint, auth, realtime/framework, sink, and AI-reviewable hunting hypotheses. Usage: /js-read target.com
---

# /js-read

Convert cached JavaScript from `/recon` into LLM-derived hunting leads.

## Optional chunk recovery

Do not run Packer-InfoFinder merely because JS files or deep candidates exist.
When browser/source/local-JS evidence shows a webpack runtime, dynamic import,
chunk map, source map, unreadable minified entry, or a missing lazy chunk, run
one evidence-bound lane before preparing materials:

```bash
# 已定位 1-5 个入口 bundle：上游 -j 模式
python3 tools/deep_js_packer.py --target target.com --mode bundle \
  --signal webpack-runtime \
  --evidence-ref recon/target.com/js_dump/runtime.js \
  --url https://target.com/assets/runtime.js

# 高价值 SPA 的 JS inventory 不完整：上游 -u --finder 模式
python3 tools/deep_js_packer.py --target target.com --mode page \
  --signal dynamic-import \
  --evidence-ref recon/target.com/browser/network.jsonl \
  --url https://target.com/app
```

Use `--browser` in page mode only when runtime dynamic loading was observed and
static page parsing did not expose the script. The adapter runs anonymously,
keeps target scope, and writes recovered files under
`recon/<target>/js_dump/packer/`; a partial/unavailable result leaves the
existing `deep-js-review` action unresolved.
Source Map restoration additionally requires `shuji@0.8.0` on `PATH` (Node >=14.15);
the adapter reports its absence as `unavailable` and does not install it automatically.

## Run This (the only required step)

```bash
python3 tools/js_reader.py --target target.com
```

Then use the `js-reader` agent on:

```text
findings/target.com/js_intel/materials.json
```

`js-reader` is an Agent, not a Queue Skill. Do not place `agents/js-reader.md` or
`commands/js-read.md` in `skill_route`; when JS evidence creates a substantive
Queue action, select a real Skill path, normally `skills/web2-recon/SKILL.md`.

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
