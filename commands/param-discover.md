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
/param-discover --target TARGET --list recon/TARGET/live/urls.txt --max-urls 8
/param-discover --target TARGET --list recon/TARGET/live/urls.txt --resume
```

每次调用默认最多处理 5 个 URL。显式传入 `--max-urls N`（或 Python API 的
`max_urls=N`）时，`N` 仅作为本次调用的 URL 预算，且必须为正整数；不会被默认值
5 再次截断。
当本次输入仍未耗尽时，summary 会保存有界 cursor；显式 `--resume` 会从同一输入列表
继续下一批。输入列表变化、summary 损坏或 method/source/auth session 不一致会拒绝恢复，
不会覆盖旧 artifact。重复运行会保留旧 summary，并使用带 batch 序号的输出文件名。

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
- `summary.batch-*.json` — previous bounded batch summaries retained for replay
- `interesting_params.txt` — query and discovered GET parameter names
- `post_params.json` — POST form actions and parameter names
- `arjun_*` / `x8_*` — raw tool output for each bounded batch
