---
description: Run the local recon pipeline on a target — domain/IP/CIDR or primary-domain batch list, with httpx probing, URL/JS/API/config exposure discovery, API leak detection, identity/cloud intel, and CI/CD hints. Outputs to recon/<target>/; list input writes recon/<domain>/ per line plus a batch index.
---

# /recon

Run the production recon pipeline. Do not re-implement the methodology inline.

## Authorization Posture

Before recon, treat the supplied target, IP, CIDR, or primary-domain batch list
as this run's active target context. Do not pause to ask for
authorization, ownership proof, or public-program confirmation before routine
recon.

Pause only for ambiguous target identity, credentials that cannot be derived
through the controlled Credential Lane, a new target not present in the current input/context, or
explicit destructive side effects / irreversible mutations / high-pressure
actions. HTTP method alone is advisory, not a stop condition.

## Run This (the only required step)

Replace `target.com` / `targets.txt` with the supplied argument.

```bash
python3 tools/hunt.py --target target.com --recon-only             # domain: subdomain enum + live probe + URL collection
python3 tools/hunt.py --target target.com --recon-only --quick     # lower-cost recon path
python3 tools/hunt.py --target target.com --recon-only --deep      # full deep-JS path
python3 tools/hunt.py --target 192.0.2.10 --recon-only             # single IP: skip subdomain enum
python3 tools/hunt.py --target 10.0.0.0/24 --recon-only            # CIDR: probe supplied hosts
python3 tools/hunt.py --target targets.txt --recon-only            # primary-domain batch list
bash tools/recon_engine.sh target.com                              # direct full entrypoint (legacy-compatible)
```

`hunt.py --recon-only` 默认使用 normal profile；quick/normal 都完整保留 raw surface，只把逐 bundle
正则提取、secret grep 和递归 JS 链接分析交给 Surface/Action Queue。裸
`recon_engine.sh TARGET` 保持原 full 行为；Source Map 源文件恢复和动态 chunk 重建继续由
后续 `/js-read` 深度 lane 按证据选择。Shuji 只消费有效的 v3 Source Map；
通用 AST/去混淆不是 Recon 的固定自动步骤，需要时由 `web2-recon` DeepDive
在真实 JS/runtime 证据触发后使用当前可用的本地工具或 AI 分析。

For large primary-domain lists, keep the Claude session short and resumable:

```bash
BBHUNT_BATCH_SIZE=5 python3 tools/hunt.py --target targets.txt --recon-only
BBHUNT_BATCH_RESET=1 BBHUNT_BATCH_SIZE=5 python3 tools/hunt.py --target targets.txt --recon-only  # restart list from beginning
```

`unwaf` origin discovery is disabled by default because it is slow on large
batches. Enable only when origin-bypass discovery is worth the extra time:

```bash
BBHUNT_ENABLE_UNWAF=1 python3 tools/hunt.py --target target.com --recon-only
BBHUNT_ENABLE_UNWAF=1 BBHUNT_BATCH_SIZE=5 python3 tools/hunt.py --target targets.txt --recon-only
```

Success signal:

- Single target: `recon/<target>/live/urls.txt` or `recon/<target>/subdomains/all.txt` exists and has data.
- List target: each completed line has its own canonical `recon/<domain>/`;
  `recon/<list-stem>/` is the batch index and also contains grouped links
  `recon/<list-stem>/<domain> -> ../<domain>` for browsing by source list.

If these files are absent or empty, read the command output. Do not spend another turn restating the recon phases.

## AI-selected DNS expansion

DNS permutation/brute force is not a default Recon phase. After passive Recon,
AI may run the fixed lane only when it can state a target-specific reason such
as an observed environment/region/numbering dialect, a certificate/JS hostname
gap, or a materially thin inventory:

```bash
python3 tools/dns_expand.py --target target.com \
  --reason "observed dev/stage and numbered API host naming"

# Optional reviewed brute-force labels; never pass an unbounded corpus.
python3 tools/dns_expand.py --target target.com \
  --reason "source evidence names an unobserved environment family" \
  --wordlist /path/to/reviewed-dns-words.txt
```

The tool bounds seeds/candidates/rate/time, uses `alterx`/`dnsgen` plus
`puredns`, filters wildcard and off-target output, and merges only DNS-confirmed
hosts. On new hosts, run `python3 tools/surface.py --target target.com --refresh`.
Do not trigger from host count alone or treat zero resolved names as broad DNS
coverage.

## Target Semantics

- Readable file → primary/root-domain batch, one non-comment line per domain. No top-N pruning and no aggregate host mixing.
- Domain → passive subdomain enum, DNS resolution, live HTTP probing, URL/JS/API/config collection.
- Single IP / CIDR / host:port → skip subdomain enum and probe supplied hosts directly.
- `recon/<list-stem>/` is an index and AI handoff directory; never scan it as a single target. Use `/surface <domain>` or `/autopilot <domain> --normal` for active work.

## What The Pipeline Collects

The integrated `tools/recon_engine.sh` path may run, when available:

- subdomain sources: `subfinder`, `assetfinder`, `amass`, `crt.sh`, optional credential-gated `Chaos`, wayback-derived hosts, `puredns`；独立被动源并行、父流程按 target scope 统一合并
- live probing and fingerprinting: ProjectDiscovery `httpx`, WAF/origin hints, lightweight ports/services
- URL collection: `katana`, `gau`, `waymore`
- URL denoising: non-destructive `_filtered` URL views plus `urls/filter.log`; raw `urls/all.txt` is preserved
- Storage guard: large raw collector source files (`katana`/`gau`/`waymore`/`wayback`) are gzip-compressed after `all.txt` and `_filtered` files are built; set `BBHUNT_RECON_POST_COMPRESS=0` to keep source `.txt` files
- JS/API extraction: quick/normal 保留完整 JS inventory 并生成多类别有界 `js/deep_candidates.txt`，但不主动请求 bundle；full/deep 仅从 `js/request_targets.txt` 使用有界、限速、scope-filtered 的 xnLinkFinder，失败、不兼容 scope 或认证上下文回退逐 URL LinkFinder；所有 profile 都保留 raw backstop
- bounded directory/parameter fuzzing and config discovery with timeout guards
- exposure candidates: API docs, config files, cloud storage, S3 buckets, third-party hosted assets
- routing candidates: 从已有 origin/shared-IP/CNAME/certificate（若 artifact 已包含）、path/schema 事实及可选通用资产关系 observation 生成 Host/SNI、AI/LLM 与外部资产关系中性候选，不在 Recon 中主动验证
- API leak detection: `porch-pirate`, `postleaksNg`, Osmedeus `SwaggerSpy`, plus bounded `trufflehog` verified-secret pass
- identity/cloud intel: `emailfinder`, `LeakSearch`, `cloud_enum`
- CI/CD hints when repo/workflow artifacts are available

These are recon signals, not vulnerability conclusions. They feed `/surface`, `/hunt`, `/intel`, and `/autopilot`.

`ctf_mode` in `config.json` keeps the supplied target set as the active lab
target record. Recon-discovered subdomains, URLs, JS, params, and exposure
candidates under that target remain active assets for this run.

## Key Artifacts

```text
recon/<target>/
├── recon_manifest.jsonl
├── subdomains/all.txt
├── live/httpx_full.txt
├── live/urls.txt
├── live/discovery_hosts.txt
├── ports/
├── urls/all.txt
├── urls/all_filtered.txt
├── urls/with_params.txt
├── urls/with_params_filtered.txt
├── urls/with_params_analysis.txt
├── urls/js_files.txt
├── urls/js_files_filtered.txt
├── urls/js_files_analysis.txt
├── urls/api_endpoints.txt
├── urls/api_endpoints_filtered.txt
├── urls/filter.log
├── js/endpoints.txt
├── js/potential_secrets.txt
├── js/deep_candidates.txt
├── dirs/
├── params/
└── exposure/
    ├── api_doc_candidates.txt
    ├── api_leak_candidates.txt
    ├── api_leak_trufflehog_verified.jsonl
    ├── cloud_storage_candidates.txt
    ├── s3_bucket_candidates.txt
    ├── external_service_hosts.txt
    ├── host_pivot_candidates.jsonl
    ├── ai_asset_candidates.jsonl
    ├── asset_relation_observations.jsonl  # optional normalized input
    ├── asset_relation_candidates.jsonl    # derived projection
    ├── identity_intel/
    ├── cloud/
    └── api_leaks/
```

### Optional generic asset-relation intake

External tools or AI may normalize public asset facts into JSONL and reuse the
existing Recon → Surface → Checkpoint → Action Queue path:

```bash
python3 tools/recon_candidates.py \
  --repo-root . \
  --target TARGET \
  --asset-input INPUT.jsonl
```

Required fields are `schema_version`, `kind`, `asset_type`, `value`, `relation`,
and `source`; `related`, `signals`, `source_ref`, `confidence`, and UTC
`observed_at` are optional:

```json
{"schema_version":1,"kind":"asset-relation-observation","asset_type":"domain","value":"ASSET","relation":"certificate-san","related":["TARGET"],"source":"certificate-transparency","source_ref":"SOURCE_REF","confidence":"high","observed_at":"2026-01-01T00:00:00Z"}
```

Supported sources are intentionally generic: corporate registries/LEI,
RDAP/WHOIS, certificate transparency, passive DNS, ASN/BGP, TLS/HTTP
fingerprints, and public supplier records. The importer does not call these
services. Invalid rows are summarized in the CLI result; raw input remains the
caller’s evidence. The derived view defaults to the 5,000 strongest
confidence/provenance candidates (`--asset-limit` may lower it); the raw JSONL
remains complete. Relationship candidates are context only and never expand
target scope automatically.

For list input:

```text
recon/<list-stem>/
├── batch_targets.txt
├── batch_manifest.jsonl
├── batch_summary.md
├── ai_handoff.md
├── surface_ranking.txt
├── high_value_targets.json
├── completed_targets.txt
├── failed_targets.txt
├── grouped_targets.tsv
└── <domain> -> ../<domain>
```

## What To Do Next

1. Single target → run `/surface target.com` to build an AI-first cached attack-surface review pack.
2. List target → read `recon/<list-stem>/batch_summary.md`, `ai_handoff.md`, `surface_ranking.txt`, and `high_value_targets.json`; use `recon/<list-stem>/<domain>` only as a grouped browsing link, then run `/surface <domain>` or `/autopilot <domain> --normal`.
3. Read `recon/<target>/recon_manifest.jsonl` when a phase looks empty; distinguish skipped/partial phases from true low-signal results.
4. If exposure files are non-empty, review them as high-value pivots before broad scanning.
5. If the target looks app-like, SPA/authenticated, object/workflow-heavy, GraphQL, WebSocket, or business-critical, capture/import browser/source/JS evidence before scanner quick.
6. If no live hosts, APIs, params, JS, or exposure candidates appear, preserve the low-signal recon state and move on unless new scope/browser/source evidence appears.

## References

- Full recon playbook: `skills/web2-recon/SKILL.md`
- Direct engine: `tools/recon_engine.sh`
- Orchestrator entrypoint: `tools/hunt.py --recon-only`
