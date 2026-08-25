---
description: Probe a 401/403 access-limit endpoint with a bounded fallback or an evidence-linked AI plan. Scope, auth, method safety, raw evidence, and result semantics stay tool-owned.
---

# /bypass-403

Run the single access-limit executor. It is for path, directory, proxy-route, and
authorization-boundary evidence; WAF is only response context, not a prerequisite.

## Usage

```
/bypass-403 https://target.com/admin
/bypass-403 -l recon/target.com/live/status_403.txt
/bypass-403 https://target.com/admin --max-requests 96
/bypass-403 --plan plan.json --target target.com [--auth-file .private/auth.json] [--queue]
```

The positional URL/list path keeps the existing bounded fallback and optional
`byp4xx` compatibility. When `ALLOW_UNSAFE_HTTP_TESTS=1` and no explicit
`--max-requests` is supplied, `byp4xx` runs as an external compatibility pass
with a 60-second wall-clock timeout (`BYP4XX_TIMEOUT`); its output is unparsed
and therefore remains `needs_review`/`partial`. Supplying `--max-requests` forces
the counted built-in matrix. The `--plan` path accepts schema-versioned JSON generated
from target evidence; it validates target scope, AuthSession, request budget,
headers, and methods before sending anything. Method names remain advisory; only
probes explicitly marked `state_changing`, `destructive`, or
`action_requires_opt_in` require `ALLOW_UNSAFE_HTTP_TESTS=1`.

Fallback mode has a 64-request invocation budget by default; use
`--max-requests N` to narrow or raise it up to 512. A budget stop is written as
`partial` and the remaining list/variants must be resumed explicitly. Plan mode
also records the round, plan hash, executed probe IDs, and skipped probe IDs so a
second evidence-linked plan can continue without claiming full coverage.
The fallback uses its built-in WAF signatures so the request cap remains exact;
set `BYPASS_ALLOW_EXTERNAL_WAF=1` only when an additional uncounted `wafw00f`
advisory pass is intentional. Its result is context, never bypass proof.

## Result contract

`blocked` means the access-limit response remains; `edge_passed` means the edge
changed without protected-content proof; `candidate` requires protected marker or
permission-differential evidence; `needs_review` is ambiguous; `partial` records
transport, rate, or incomplete execution. A changed status or 200 alone is not a
bypass.

## Output

`findings/<target-key>/bypass/<timestamp>/`:
- `byp4xx.txt` — full upstream-tool output (with `byp4xx.meta.json` and
  `summary.json` marking the result for manual review), OR
- `bypass_hits.txt`, `bypass_edge_passed.txt`, `bypass_uncertain.txt`, and
  `bypass_blocked.txt` — line-oriented compatibility output
- `results.jsonl` and `summary.json` — plan result/state contract
- `raw/` — per-probe response headers and bodies for replay
- `action_queue.json` — optional existing Action Queue projection when `--queue` is set
