---
description: Build an AI-first attack-surface review pack from cached recon, hunt memory, structured findings, browser/JS/source intel, and exposure signals. Usage: /surface target.com
---

# /surface

Build a cached attack-surface review pack. It does not contact or exploit the target, but it may
refresh local derived artifacts (`surface/`, the observation summary sidecar, and the bounded
projection). It never deletes raw recon or changes finding/observation lifecycle, and it does not
replace Claude's judgment.
Claude CLI 下这是 `/autopilot` 的默认证据整理入口：把 recon、目标记忆、知识线索和检查信号合并为 URL 顺序的 AI Review Pool 与 Workflow Leads，由 Claude 判断下一步。

## Run This (the only required step)

Replace `target.com` with the supplied target.

```bash
python3 tools/surface.py --target target.com
python3 tools/surface.py --target target.com --json
python3 tools/surface.py --target target.com --refresh
python3 tools/surface.py --repo-root /path/to/data --target target.com --json
```

If `recon/<target>/` is missing, run `/recon target.com` first. If the output says the recon cache is thin, refresh recon instead of manually reading every file.

## What This Reads

`tools/surface.py` merges:

For initialized Store targets, claims, actions, Case context and target experience
come from that Store. Retired Finding/Profile/memory files are not current inputs.
Uninitialized, legacy or damaged targets require explicit initialization/import/recovery.
The remaining file inputs are raw material, runtime breadcrumbs or rebuildable indexes.

- `memory/goals/active.json` target selection only; Store owns target memory
- `recon/<target>/` live hosts, URLs, params, API paths, JS endpoints, and exposure files
- Store Findings and raw scanner candidate artifacts
- `state/<target>/session.json` runtime breadcrumbs
- `hunt-memory/journal.jsonl` session audit; current tested endpoints and experience come from Store
- `findings/<target>/js_intel/` from `/js-read`
- `findings/<target>/source_intel/` from source intelligence
- `recon/<target>/browser/` browser-observed XHR/API surface
- `recon/<target>/dirs/ffuf_summary.json` compact FFUF observations; full results stay in `ffuf_results.jsonl.gz`
- `recon/<target>/dirs/ffuf_target_plan.json` current bounded FFUF target selection and pending count
- `recon/<target>/dirs/ffuf_target_state.json` target-owned completion ledger for cross-round rotation
- `state/<target>/observations-summary.json` when its schema/body/source binding is valid; an
  explicit surface refresh may synchronize the full inventory once before publishing a new summary

## What This Outputs

- AI Review Pool: up to 16 exact URLs in lexical URL order; Claude chooses work from evidence
- `review_window`: URL order, total, returned, remaining, and limit; retired `p1`/`p2`/`kill` arrays stay empty
- Target Memory: current goal, hypothesis, active leads, next actions, dead ends, and latest handoff
- workflow leads from exposure, JS, source, browser, and scanner signals
- unranked FFUF status/control/signature facts plus at most four neutral Review Pool samples
- compact next actions for `/hunt` or `/autopilot`
- completeness metadata for exact URL rows, target-owned rows, shape/variant counts, and bounded
  overflow; these counts are not coverage closure

## Completeness And Cache Contract

- Raw recon artifacts and `state/<target>/observations.json` remain the completeness layer.
- `recon/<target>/surface/index.jsonl` merges only byte-equivalent URL identities after the existing
  line trim and unions their provenance. Query values/order, duplicate keys, encoding, scheme/port,
  path case, and trailing-slash variants remain separate rows.
- Every unique target-owned index row participates in the bounded URL window. Source, category,
  memory, severity, and shape never assign seats or priority. Shape IDs only group and navigate variants.
- FFUF target batches use the same neutral URL order over pending targets; scope, budget, wordlist
  binding, and the completion ledger still govern eligibility and cross-round continuation.
- `state/<target>/surface-projection.json` is a small, manifest-bound cache. `/autopilot` consumes it
  only on an exact fingerprint hit. Missing/stale/invalid means `prepare_surface_context`, not clean,
  exhausted, reviewed, or absent attack surface.
- Recon completion attempts the same finalizer once. A finalizer failure is non-fatal to raw recon;
  rerun this command with `--refresh` to rebuild the derived index and projection.

Inspect or page the complete exact index without changing state:

```bash
python3 tools/surface_index.py status --target target.com
python3 tools/surface_index.py --repo-root /path/to/data page --target target.com --limit 50
python3 tools/surface_index.py page --target target.com --target-owned --limit 50
python3 tools/surface_index.py page --target target.com --shape-id <shape-id> --limit 50 --cursor <cursor>
```

The output includes a root-bound full-index command starting at the first page,
including external context. The review pool is not an index page: do not skip the
first 50 rows when expanding it. Continue from each returned `next_cursor` with
the same target and filters. A stale index requires an explicit refresh.

Coverage queries use the current Store and observed Recon sources, even when a
retired matrix exists. `find-gaps --limit N` and `needs-triage --limit N` report
total/returned/remaining and an executable full query (`needs-triage --all`).
Cells use endpoint/class identity order; triage uses endpoint order. Neither
route kind nor source count chooses a preferred test. Full queries are fresh reads.

目标记忆保留为可检查的上下文：

- active lead / next action / dead end 命中 URL 时附带来源，不改变顺序或排除候选。
- Claude 结合原条件和当前证据决定适用性；假设和历史负结果不授权当前闭合。

## How To Use The Review Pack

1. Read the AI Review Pool first; choose the next target as Claude, using business impact, browser/source evidence, object/session context, and current findings.
2. Use `review_window.remaining` and the full-index command to expand beyond the preview. URL order carries no business priority; overflow remains available for review.
3. For FFUF evidence, compare random-miss controls and heavy response signatures, then page the full artifact by status/signature when needed. A control match is a noise hypothesis, not an exclusion.
4. If a candidate includes JS/source/browser/exposure hints, run that enrichment when it changes the next proof.
5. If a candidate is auth-gated, preserve auth state and compare roles/objects rather than widening blindly.
6. Before checkpoint/finish, run `/check-coverage` and write back the chosen candidate, blocker, or dead end with `/target`.

Bounded FFUF evidence paging:

```bash
python3 tools/recon_adapter.py --recon-dir recon/<target_key> --read-ffuf --status 403 --offset 0 --limit 100
python3 tools/recon_adapter.py --recon-dir recon/<target_key> --read-ffuf --signature-id <id> --offset 0 --limit 100
```

## Important Signals

- API docs / Swagger / OpenAPI / Postman collections → inspect auth model and hidden endpoints.
- Verified secret hits → minimal usability proof only, then preserve evidence.
- Identity/cloud intel → fuel for SSO, invite/reset-flow, cloud ownership, and source pivots.
- Browser-observed XHR/API → first-class attack surface, often better than static URLs.
- JS/source hypotheses → use as review leads; confirm with exact requests.

## Typical Chain

```text
/recon target.com
/surface target.com
# optional: /js-read, /source-hunt, /intel, /cloud-recon, /secrets-hunt when the review pack shows a signal
/hunt target.com
```
