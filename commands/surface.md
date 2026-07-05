---
description: Build an AI-first attack-surface review pack from cached recon, hunt memory, structured findings, browser/JS/source intel, and exposure signals. Usage: /surface target.com
---

# /surface

Build a cached attack-surface review pack. This is a read-only evidence view; it does not exploit the target and does not replace Claude's judgment.
Claude CLI 下这是 `/autopilot` 的默认证据整理入口：先用目标记忆校准方向，再把 recon、hunt-memory、知识线索和检查信号合并成 AI Review Pool / Advisory P1/P2 / Workflow Leads。

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

- AI Review Pool: Claude must choose final priority from evidence, not from regex score alone
- Advisory P1/P2: score hints only, kept for compatibility with older tools
- Kill/low-value surface
- Target Memory: current goal, hypothesis, active leads, next actions, dead ends, and latest handoff
- workflow leads from exposure, JS, source, browser, and scanner signals
- compact next actions for `/hunt` or `/autopilot`

目标记忆只做软偏置：

- active lead / next action 命中 URL 时，提高优先级并标注 `Source: target memory`
- dead end 命中 URL 时，降低优先级并标注 `Caution: matches remembered dead end`
- 不把记忆里的假设当作已验证结论；仍然需要 `/hunt` 和 `/validate` 证明

## How To Use The Review Pack

1. Read the AI Review Pool first; choose the next target as Claude, using business impact, browser/source evidence, object/session context, and current findings.
2. Treat P1/P2 score as a hint, not a verdict. Do not discard lower-ranked surfaces solely because a regex score is low.
3. If a candidate includes JS/source/browser/exposure hints, run that enrichment when it changes the next proof.
4. If a candidate is auth-gated, preserve auth state and compare roles/objects rather than widening blindly.
5. Before checkpoint/finish, run `/check-coverage` and write back the chosen candidate, blocker, or dead end with `/target`.

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
