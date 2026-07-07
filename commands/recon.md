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
python3 tools/hunt.py --target 192.0.2.10 --recon-only             # single IP: skip subdomain enum
python3 tools/hunt.py --target 10.0.0.0/24 --recon-only            # CIDR: probe supplied hosts
python3 tools/hunt.py --target targets.txt --recon-only            # primary-domain batch list
bash tools/recon_engine.sh target.com                              # direct shell entrypoint
```

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

## Target Semantics

- Readable file → primary/root-domain batch, one non-comment line per domain. No top-N pruning and no aggregate host mixing.
- Domain → passive subdomain enum, DNS resolution, live HTTP probing, URL/JS/API/config collection.
- Single IP / CIDR / host:port → skip subdomain enum and probe supplied hosts directly.
- `recon/<list-stem>/` is an index and AI handoff directory; never scan it as a single target. Use `/surface <domain>` or `/autopilot <domain> --normal` for active work.

## What The Pipeline Collects

The integrated `tools/recon_engine.sh` path may run, when available:

- subdomain sources: `subfinder`, `assetfinder`, `amass`, `crt.sh`, wayback-derived hosts, `puredns`
- live probing and fingerprinting: ProjectDiscovery `httpx`, WAF/origin hints, lightweight ports/services
- URL collection: `katana`, `gau`, `waymore`
- URL denoising: non-destructive `_filtered` URL views plus `urls/filter.log`; raw `urls/all.txt` is preserved
- Storage guard: large raw collector source files (`katana`/`gau`/`waymore`/`wayback`) are gzip-compressed after `all.txt` and `_filtered` files are built; set `BBHUNT_RECON_POST_COMPRESS=0` to keep source `.txt` files
- JS/API extraction: JS file list, JS endpoints, potential JS secrets, API/GraphQL-like paths, parameterized URLs; JS/parameter analysis uses filtered-first ordering with raw backstop
- bounded directory/parameter fuzzing and config discovery with timeout guards
- exposure candidates: API docs, config files, cloud storage, S3 buckets, third-party hosted assets
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
├── dirs/
├── params/
└── exposure/
    ├── api_doc_candidates.txt
    ├── api_leak_candidates.txt
    ├── api_leak_trufflehog_verified.jsonl
    ├── cloud_storage_candidates.txt
    ├── s3_bucket_candidates.txt
    ├── external_service_hosts.txt
    ├── identity_intel/
    ├── cloud/
    └── api_leaks/
```

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
