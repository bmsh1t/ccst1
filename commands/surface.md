---
description: Build an AI-first attack-surface review pack from cached recon, hunt memory, structured findings, browser/JS/source intel, and exposure signals. Usage: /surface target.com
---

# /surface

Build a cached attack-surface review pack. It does not contact or exploit the target, but it may
refresh local derived artifacts (`surface/`, the observation summary sidecar, and the bounded
projection). It never deletes raw recon or changes finding/observation lifecycle, and it does not
replace Claude's judgment.
Claude CLI 下这是 `/autopilot` 的默认证据整理入口：先用目标记忆校准方向，再把 recon、hunt-memory、知识线索和检查信号合并成 AI Review Pool / advisory score hints / Workflow Leads。

## Run This (the only required step)

Replace `target.com` with the supplied target.

```bash
python3 tools/surface.py --target target.com
python3 tools/surface.py --target target.com --json
python3 tools/surface.py --target target.com --refresh
```

If `recon/<target>/` is missing, run `/recon target.com` first. If the output says the recon cache is thin, refresh recon instead of manually reading every file.

## What This Reads

`tools/surface.py` merges:

- `memory/goals/active.json` and `memory/goals/targets/<target>.json` target memory
- `recon/<target>/` live hosts, URLs, params, API paths, JS endpoints, and exposure files
- `findings/<target>/findings.json` structured scanner candidates
- `state/<target>/session.json` runtime breadcrumbs
- `hunt-memory/` previous sessions, tested endpoints, and reusable patterns
- `findings/<target>/js_intel/` from `/js-read`
- `findings/<target>/source_intel/` from source intelligence
- `recon/<target>/browser/` browser-observed XHR/API surface
- `recon/<target>/dirs/ffuf_summary.json` compact FFUF observations; full results stay in `ffuf_results.jsonl.gz`
- `state/<target>/observations-summary.json` when its schema/body/source binding is valid; an
  explicit surface refresh may synchronize the full inventory once before publishing a new summary

## What This Outputs

- AI Review Pool: Claude must choose final priority from evidence, not from regex score alone
- Advisory score hints only, kept for compatibility with older tools
- Low-priority / reopenable hints; never exclusions
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
- Every unique target-owned index row is scored before bounded P1/P2/AI Review Pool frontiers are
  selected. Shape IDs group and navigate variants only; they never delete or pre-sample rows.
- `state/<target>/surface-projection.json` is a small, manifest-bound cache. `/autopilot` consumes it
  only on an exact fingerprint hit. Missing/stale/invalid means `prepare_surface_context`, not clean,
  exhausted, reviewed, or absent attack surface.
- Recon completion attempts the same finalizer once. A finalizer failure is non-fatal to raw recon;
  rerun this command with `--refresh` to rebuild the derived index and projection.

Inspect or page the complete exact index without changing state:

```bash
python3 tools/surface_index.py status --target target.com
python3 tools/surface_index.py page --target target.com --target-owned --limit 50
python3 tools/surface_index.py page --target target.com --shape-id <shape-id> --limit 50 --cursor <cursor>
```

目标记忆只做软偏置：

- active lead / next action 命中 URL 时，提高优先级并标注 `Source: target memory`
- dead end 命中 URL 时，降低优先级并标注 `Caution: matches remembered dead end`
- 不把记忆里的假设当作已验证结论；仍然需要 `/hunt` 和 `/validate` 证明

## How To Use The Review Pack

1. Read the AI Review Pool first; choose the next target as Claude, using business impact, browser/source evidence, object/session context, and current findings.
2. Treat every score as a hint, not a verdict. Do not discard lower-ranked or overflow surfaces solely because they are outside the bounded window or a regex score is low.
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
