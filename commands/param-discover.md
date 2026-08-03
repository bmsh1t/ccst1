---
description: Discover hidden HTTP parameters on target-owned URLs using Arjun (or x8 fallback). Hidden params are useful leads for IDOR, SSRF, LFI, redirect, and authorization review.
---

# /param-discover

Find HTTP parameters the application accepts but doesn't link from any visible
endpoint. Useful when an endpoint looks unreachable or returns a generic
response — often a hidden `id`, `user`, `redirect`, `file`, or `debug` param
unlocks the real surface.

## Usage

```
/param-discover --target TARGET --url https://TARGET/v2/user
/param-discover --target TARGET --list recon/TARGET/live/urls.txt
```

## Tools

`tools/param_discovery.sh` delegates to the scoped Python owner. Anonymous runs
prefer `arjun` (richer JSON output) and fall back to `x8`; authenticated runs
require `x8` so the session stays in a private raw request file. Install hint:

```
pipx install arjun
# or
cargo install x8
```

## Why it pays

- Hidden `redirect=` / `next=` → open redirect, SSRF, OAuth code theft chain.
- Hidden `id=` / `user_id=` → IDOR.
- Hidden `file=` / `path=` / `template=` → LFI, SSTI, RFI.
- Hidden `debug=` / `admin=` → privilege escalation toggles.
- Hidden `callback=` / `jsonp=` → reflected XSS via JSONP.

After discovery, read `recon/TARGET/params/summary.json`, preserve the
parameter names as inert surface shapes, and route high-value shapes through
the matching validation runner.

## Output

`recon/TARGET/params/`:
- `summary.json` — scoped runs, rejected inputs, tool status, and queue sync
- `interesting_params.txt` — query and discovered GET parameter names
- `post_params.json` — POST form actions and parameter names
- `arjun_*` / `x8_*` — raw tool output for the bounded run
