---
description: Show ranked attack surface for a target based on cached recon output, hunt memory, structured findings, browser/JS/source intel, and exposure signals. Usage: /surface target.com
---

# /surface

Rank cached attack surface. This is a read/rank view; it does not exploit the target.
Claude CLI 下这是 `/autopilot` 的默认排序入口：先用目标记忆校准方向，再把 recon、hunt-memory、知识线索和检查信号合并成 P1/P2/Workflow Leads。

## Run This (the only required step)

Replace `target.com` with the supplied target.

```bash
python3 tools/surface.py --target target.com
python3 tools/surface.py --target target.com --json
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

## What This Outputs

- P1: start here
- P2: widen after P1
- Kill/low-value surface
- Target Memory: current goal, hypothesis, active leads, next actions, dead ends, and latest handoff
- workflow leads from exposure, JS, source, browser, and scanner signals
- compact next actions for `/hunt` or `/autopilot`

目标记忆只做软偏置：

- active lead / next action 命中 URL 时，提高优先级并标注 `Source: target memory`
- dead end 命中 URL 时，降低优先级并标注 `Caution: matches remembered dead end`
- 不把记忆里的假设当作已验证结论；仍然需要 `/hunt` 和 `/validate` 证明

## How To Use The Ranking

1. Start with the top P1 item unless a stronger validated/candidate finding is already pending.
2. If P1 includes JS/source/browser/exposure hints, run that enrichment before broad scanning.
3. If P1 is auth-gated, preserve auth state and compare roles/objects rather than widening blindly.
4. If all P1 items are dead, write the dead lane to target memory and move to P2; do not loop on the same endpoint.
5. Before checkpoint/finish, run `/check-coverage` and write back the next P1/P2 or dead end with `/target`.

## Important Signals

- API docs / Swagger / OpenAPI / Postman collections → inspect auth model and hidden endpoints.
- Verified secret hits → minimal usability proof only, then preserve evidence.
- Identity/cloud intel → fuel for SSO, invite/reset-flow, cloud ownership, and source pivots.
- Browser-observed XHR/API → first-class attack surface, often better than static URLs.
- JS/source hypotheses → use as ranked leads; confirm with exact requests.

## Typical Chain

```text
/recon target.com
/surface target.com
# optional: /js-read, /source-hunt, /intel, /cloud-recon, /secrets-hunt when the ranking shows a signal
/hunt target.com
```
