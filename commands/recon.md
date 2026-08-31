---
description: Run the local recon pipeline on a target — domain/IP/CIDR or primary-domain batch list, with httpx probing, URL/JS/API/config exposure discovery, API leak detection, identity/cloud intel, and CI/CD hints. Outputs to recon/<target>/; list input writes recon/<domain>/ per line plus a batch index.
---

# /recon

Run the production recon pipeline. Do not re-implement the methodology inline.

The supplied target, IP, CIDR, or primary-domain batch list is already the active
target context. Start directly with **Run This**.

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

Amass passive enumeration is disabled by default because it can dominate recon
runtime. Enable it explicitly for a run when the extra subdomain source is worth
the cost:

```bash
BBHUNT_ENABLE_AMASS=1 python3 tools/hunt.py --target target.com --recon-only
BBHUNT_ENABLE_AMASS=1 bash tools/recon_engine.sh target.com
```

`hunt.py --recon-only` 默认使用 normal profile；quick/normal 都保留 raw 证据归档；Coverage/scanner
`--deep` 使用 3600 秒默认 Recon 软预算（normal/full 为 1800 秒）；通过
`BBHUNT_RECON_SOFT_BUDGET_SECONDS` 可按环境覆盖。软预算只是覆盖遥测阈值：超过后仍继续
后续阶段，且不会把完整运行误报为 partial；父进程超时、工具中断或非零失败才以 partial
状态交接。所有已产生的原始产物都会保留，后续 `/surface` 或下一轮 Autopilot 可继续消费
未完成面。
仍把 Active surface 交给执行消费者，Surface index 同时提供 raw-only 的可重建证据投影；只把逐 bundle
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

## Focused FFUF Discovery

The integrated engine's **baseline FFUF** run is an automatic, bounded breadth
sensor. **Focused fuzz** is an **optional AI-selected discovery action**. It
requires a same-target naming dialect, route, parameter, schema, browser request,
or source reference that supports one concrete template and a bounded,
deduplicated wordlist. An empty baseline does not trigger focused fuzz, and a
route response alone is not a vulnerability candidate.

Each focused run is isolated and resumable. Before execution, record
`seed_refs`, `transformation`, `rationale`, `evidence_grade`, authentication
context, expected learning, and a stop condition. Do not mechanically merge a
generic wordlist or reuse a run across different templates or identities.

When a target dialect was actually used, keep these run-local evidence files:

```text
recon/<target_key>/focused_fuzz/<run_id>/
├── naming_profile.json
├── candidates.jsonl
├── wordlist.txt
└── dirs/
    ├── ffuf_results.jsonl.gz
    └── ffuf_summary.json
```

`naming_profile.json` records only observed dimensions:

```json
{
  "schema_version": 1,
  "surface": "path",
  "template": "https://HOST/api/FUZZ",
  "method": "<observed-method>",
  "auth_context": "<anonymous-or-session-label>",
  "seed_refs": ["<artifact-ref>"],
  "syntax": {"separators": ["<observed>"], "case_style": ["<observed>"], "slots": ["<observed-slot>"]},
  "hypotheses": [{"transformation": "<rule>", "seed_refs": ["<ref>"], "evidence_grade": "<grade>", "rationale": "<why-test>"}],
  "stop_condition": "<condition>"
}
```

`auth_context` contains only an anonymous/session label or reference; never put
tokens or cookie values in the profile. `candidates.jsonl` is a candidate input
projection and does not contain finding or validation state. Raw FFUF output and
the adapter summary remain the complete observation source.

For a path template, use an isolated run and the existing adapter:

```bash
RUN_DIR='recon/<target_key>/focused_fuzz/<run_id>'
mkdir -p "$RUN_DIR/dirs"
set -o pipefail
if ffuf -u 'https://target.com/api/v2/FUZZ' \
  -w "$RUN_DIR/wordlist.txt" \
  -H 'Authorization: Bearer <token>' -b 'session=<cookie>' \
  -mc all -ac -t 5 -timeout 10 -s -json 2> "$RUN_DIR/ffuf.log" \
  | gzip -c > "$RUN_DIR/dirs/ffuf_results.jsonl.gz"; then
  RUN_COUNTS=(--attempted 1 --succeeded 1)
else
  RUN_COUNTS=(--attempted 1 --failed 1)
fi
python3 tools/recon_adapter.py --recon-dir "$RUN_DIR" \
  --summarize-ffuf "${RUN_COUNTS[@]}"
```

The supported template can place `FUZZ` in a path, query, body, or header. Keep
one changed boundary per run and use an observed prefix rather than a generic
management dictionary:

```bash
ffuf -u 'https://target.com/FUZZ' -w "$RUN_DIR/wordlist.txt" -mc all -ac -t 3
ffuf -u 'https://target.com/api/v2/items?view=FUZZ' -w "$RUN_DIR/wordlist.txt" -mc all -ac -t 3
ffuf -u 'https://target.com/api/v2/items' -X POST -H 'Content-Type: application/json' \
  -d '{"action":"FUZZ"}' -w "$RUN_DIR/wordlist.txt" -mc all -ac -t 3
ffuf -u 'https://target.com/api/v2/items' -H 'X-API-Version: FUZZ' \
  -w "$RUN_DIR/wordlist.txt" -mc all -ac -t 3
```

For a captured request, remove unrelated values and keep one explicit `FUZZ`
slot:

```bash
ffuf -request "$RUN_DIR/request.txt" -request-proto https \
  -w "$RUN_DIR/wordlist.txt" -mc all -ac -t 3 -timeout 10 -s -json \
  2> "$RUN_DIR/ffuf.log" | gzip -c > "$RUN_DIR/dirs/ffuf_results.jsonl.gz"
```

Retain `-ac`; add `-fc 404` or `-fs <control-size>` only when a control supports
it. Read observations through the existing bounded adapter rather than copying
the result set:

```bash
python3 tools/recon_adapter.py --recon-dir "$RUN_DIR" \
  --read-ffuf --offset 0 --limit 100
```

Compare status, length, words, lines, content type, response signature,
control match, and redirect against ordinary 404/405, SPA/soft-404, login,
gateway, framework-error, and WAF controls. A difference is a Signal only;
replay with the same method and authentication before creating a Lead.

Write the interpretation through the existing target-memory owner and keep the
run out of `urls/all.txt`, Surface, Queue, Coverage, and Finding state:

```bash
python3 tools/target_memory.py lead \
  "Focused fuzz evidence: $RUN_DIR/dirs/ffuf_summary.json; why: <signal>; next: <verification>; stop: <condition>" \
  --target target.com
python3 tools/target_memory.py dead-end \
  "Focused fuzz scope: <template + evidence>; artifact: $RUN_DIR/dirs/ffuf_results.jsonl.gz; result: <why no useful signal>" \
  --target target.com
```

No useful difference records the bounded scope so a resumed session does not
repeat it. A stable difference may justify one next round, but there is no
automatic expansion or global round limit. The same contract applies to pattern
based directory discovery and missing-parameter signals; those remain Leads
until the selected vulnerability Skill and evidence owner validate them.

## Target Semantics

- Readable file → primary/root-domain batch, one non-comment line per domain. No top-N pruning and no aggregate host mixing.
- Domain → passive subdomain enum, DNS resolution, live HTTP probing, URL/JS/API/config collection.
- Single IP / CIDR / host:port → skip subdomain enum and probe supplied hosts directly.
- `recon/<list-stem>/` is an index and AI handoff directory; never scan it as a single target. Use `/surface <domain>` or `/autopilot <domain> --normal` for active work.

## What The Pipeline Collects

The integrated `tools/recon_engine.sh` path may run, when available:

- subdomain sources: `subfinder`, `assetfinder`, opt-in `amass`, `crt.sh`, optional credential-gated `Chaos`, wayback-derived hosts, `puredns`；独立被动源并行、父流程按 target scope 统一合并
- live probing and fingerprinting: ProjectDiscovery `httpx`, bounded `wafw00f` sampling with durable `live/waf_context.json` context, optional origin hints, lightweight ports/services
- URL collection: `katana`, `gau`, `waymore`
- URL denoising: raw collector output is staged, then atomically published as the filtered Active `urls/all.txt`; distinct object/parameter instances are retained by default, and `*_filtered.txt` remains a compatibility projection
- Storage guard: raw URL union is kept under `urls/raw/` until Closure, then gzip-compressed with collector sources; bounded `filter.log` samples and `filter_summary.json` retain the counts/hash without duplicating the corpus
- JS/API extraction: quick/normal 保留完整 JS inventory 并生成多类别有界 `js/deep_candidates.txt`，但不主动请求 bundle；full/deep 仅从 `js/request_targets.txt` 使用有界、限速、scope-filtered 的 xnLinkFinder，失败、不兼容 scope 或认证上下文回退逐 URL LinkFinder；所有 profile 都保留 raw backstop
- bounded directory/parameter fuzzing and config discovery with timeout guards
- exposure candidates: API docs, config files, cloud storage, S3 buckets, third-party hosted assets
- routing candidates: 从已有 origin/shared-IP/CNAME/certificate（若 artifact 已包含）、path/schema 事实及可选通用资产关系 observation 生成 Host/SNI、AI/LLM 与外部资产关系中性候选；候选生成后仅对高置信且当前 Scope 内的 Host pivot 做一次有界只读响应差异观察，AI 资产仍由后续专项路线验证
- API leak detection: `porch-pirate`, `postleaksNg`, Osmedeus `SwaggerSpy`, plus bounded `trufflehog` verified-secret pass
- identity/cloud intel: `emailfinder`, `LeakSearch`, `cloud_enum`
- CI/CD hints when repo/workflow artifacts are available

These are recon signals, not vulnerability conclusions. They feed `/surface`, `/hunt`, `/intel`, and `/autopilot`.

The built-in Host pivot check is deliberately narrow and read-only. It runs once
per candidate identity, records compact status/header/body-hash observations in
`exposure/host_collision_observations.jsonl`, and skips candidates already
observed on a resumed run. A response difference is still a candidate; it does
not change Scope, create a Queue action, or close Coverage.

After the target's Closure is complete, inspect raw-archive cleanup before applying it:

```bash
python3 tools/recon_artifact_gc.py --repo-root . --target target.com
python3 tools/recon_artifact_gc.py --repo-root . --target target.com --apply
```

The cleanup command is fail-closed on incomplete/corrupt Closure state and never removes
Active URL views or finding/ledger artifacts.

Recon-discovered subdomains, URLs, JS, params, and exposure candidates under the
supplied target remain active assets for this run.

## Key Artifacts

```text
recon/<target>/
├── recon_manifest.jsonl
├── subdomains/all.txt
├── live/httpx_full.txt
├── live/urls.txt
├── live/discovery_hosts.txt
├── ports/
├── urls/all.txt                         # Active, filtered, replay-safe view
├── urls/raw/all.txt[.gz]                # Closure-before raw evidence archive
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
├── urls/filter_summary.json
├── browser/request_shapes.json           # value-free method/body/GraphQL request shapes
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
    ├── host_collision_observations.jsonl
    ├── host_collision_summary.json
    ├── ai_asset_candidates.jsonl
    ├── host_ranking.jsonl              # all-host soft priority view; raw inputs remain authoritative
    ├── asset_relation_observations.jsonl  # optional normalized input
    ├── asset_relation_candidates.jsonl    # derived projection
    ├── asset_relation_summary.json        # Scope/partial projection
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
`observed_at` are optional. Corporate recursion may also supply `entity_ref`,
`parent_ref`, `ownership_pct` (0-100), and `depth` (0-4):

```json
{"schema_version":1,"kind":"asset-relation-observation","asset_type":"domain","value":"ASSET","relation":"certificate-san","related":["TARGET"],"source":"certificate-transparency","source_ref":"SOURCE_REF","confidence":"high","observed_at":"2026-01-01T00:00:00Z","entity_ref":"SOURCE_ENTITY_REF","parent_ref":"PARENT_ENTITY_REF","ownership_pct":75,"depth":1}
```

Supported sources are intentionally generic: corporate registries/LEI,
RDAP/WHOIS, certificate transparency, passive DNS, ASN/BGP, TLS/HTTP
fingerprints, and public supplier records. The importer does not call these
services. Invalid rows are summarized in the CLI result; raw input remains the
caller’s evidence. The derived view defaults to the 5,000 strongest
confidence/provenance candidates (`--asset-limit` may lower it); the raw JSONL
remains complete. Relationship candidates are context only and never expand
target scope automatically.

Run relationship expansion only for concrete organization, brand, certificate,
ASN/origin, registrant, supplier, or existing relationship evidence, or explicit
operator intent. Quick mode requires explicit intent; normal performs one bounded
pass at depth 1; deep may recurse to depth 3; full may recurse to depth 4. Recurse
only through majority/control relationships, deduplicate by `entity_ref` (or the
normalized source/entity identity), where `ownership_pct > 50` or explicit control
is present, and stop after two consecutive levels add no domains or the lane
budget is exhausted. Candidate limits never truncate raw observations.

Prefer structured public sources. Chrome DevTools MCP may read a public dynamic
registry/company page or its Network responses in a browser context that carries no
target-application credentials; this remains a public-only path without
target-application credentials. Write only selected normalized facts with locatable
`source_ref`; do not send the result through `tools/browser_mcp_import.py` or add
these pages to Browser Surface.

The derived candidate rows receive one tool-owned `scope_status`: `in_scope`,
`scope-review`, `external-chain-context`, `excluded`, or `unknown`. Explicit
exclusions win, and relationship evidence never grants `in_scope`. High-confidence
target-linked `scope-review` rows enter the existing Action Queue; active requests
remain prohibited until the explicit target set is updated. Raw observations and
external candidates remain available regardless of Scope disposition.

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
