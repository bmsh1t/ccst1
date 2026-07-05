# Tool Index — Claude CLI Quick Reference

> **Purpose**: When `/autopilot` `/hunt` `/recon` is running, Claude consults this table to discover which `tools/*` script fits the current evidence shape. The "When to use" column answers *"why would Claude choose this now?"*
>
> **Convention**: Tools marked **⚠️ underused** exist in the repo but are rarely referenced in slash commands or agent prompts — surface them deliberately when their trigger fires.
>
> **Path convention**: All paths are relative to repo root.

## 1. Recon (target → live attack surface)

| Tool | When to use | One-line function |
|---|---|---|
| `tools/recon_engine.sh` | New target / stale recon / primary-domain batch | Expanded pipeline: batch→subdomain→probe→ports→urls→js→fuzz→config→API-leak→identity/cloud→params→cicd |
| `tools/cf_solver.py` ⚠️ manual-only | Operator-approved Cloudflare challenge clearance | Optional 2Captcha+Playwright helper; writes cf_clearance headers for recon reuse |
| `tools/recon_adapter.py` | Reading recon output programmatically | Unified reader for `recon/<target>/` artifacts |
| `tools/cloud_recon.sh` | Target brand likely owns buckets | S3/Azure/GCP discovery + CloudFlare origin reveal |
| `tools/cve_hunter.py` | After httpx tech detection | Match detected stack against public CVE DBs |
| `tools/cve_scan.sh` | Pre-engagement nuclei sweep | Fast nuclei pass scoped to known CVE templates |
| `tools/intel_engine.py` | Need CVE+disclosure intel pre-attack | `/intel` backend — fetches advisories and disclosed reports |
| `tools/learn.py` | Tech stack research | Compat backend used by `/intel`; gathers attack-class context |
| `tools/scope_checker.py` | Verifying target classification | Deterministic host/URL classifier against active target set |
| `tools/target_paths.py` | Computing per-target storage keys | Normalize target string for `recon/`/`findings/` directories |
| `tools/target_selector.py` | Pulling H1 public program info | Query HackerOne directory API for public programs |

Primary-domain list input (`targets.txt`) is handled by `tools/recon_engine.sh` as a batch dispatcher: each line writes its own `recon/<domain>/`; `recon/<list-stem>/` is only the manifest/summary index.

### `/recon` artifact map — read these before broad hunting

When `/recon` finishes, Claude should treat the files below as high-signal
handoff artifacts. They are not separate automation gates; they are quick reads
that help choose the next `/surface`, `/hunt`, `/intel`, `/cloud-recon`, or
manual review lane.

| Signal/tool | Primary artifact(s) | What Claude should do next |
|---|---|---|
| `waymore` historical URLs | `recon/<target>/urls/waymore.txt` | Merge mentally with `urls/all.txt`; prioritize old API/admin/export paths that no longer appear in current crawl |
| API doc grep (`swagger/openapi/redoc/postman/graphql`) | `recon/<target>/exposure/api_doc_candidates.txt` | Read first; API docs often reveal auth model, hidden operations, object IDs, and GraphQL/OIDC surface |
| API leak consolidation | `recon/<target>/exposure/api_leak_candidates.txt` | Review before scanner breadth; imported Postman/OpenAPI candidates can drive exact endpoint probes |
| `porch-pirate` Postman search | `recon/<target>/exposure/api_leaks/postman_leaks.txt` | Look for workspace/collection URLs, environment names, tokens, and non-production API hosts |
| `postleaksNg` | `recon/<target>/exposure/api_leaks/postleaks_urls.txt`, `postleaksNg.log`, `postleaksNg/` | Extract collection/spec URLs; feed interesting files into `/secrets-hunt --filesystem recon/<target>/exposure/api_leaks/` when non-empty |
| Osmedeus `SwaggerSpy` | `recon/<target>/exposure/api_leaks/swagger_leaks.txt` | Treat as API-spec discovery candidates; validate liveness and auth boundary before broad fuzzing |
| Verified secret pass | `recon/<target>/exposure/api_leak_trufflehog_verified.jsonl` | Minimal attribution/usability check; do not auto-login or credential-stuff |
| `emailfinder` | `recon/<target>/exposure/identity_intel/emails.txt` | Seed tenant, reset-flow, invite, SSO, and username-format hypotheses |
| `LeakSearch` | `recon/<target>/exposure/identity_intel/leaksearch.txt`, `summary.md` | Attribute hits to the target; use as identity/intel leads, not automatic login attempts |
| `cloud_enum` | `recon/<target>/exposure/cloud/cloud_enum.txt`, `cloud_enum.log` | Treat as candidate cloud ownership evidence; pivot to `/cloud-recon` or minimal ownership checks |
| Batch ranking | `recon/<list-stem>/surface_ranking.txt`, `ai_handoff.md`, `high_value_targets.json` | Pick completed domains with concrete signals; never hunt `recon/<list-stem>/` as a target |

Runtime readers also surface these counters through `tools/runtime_state.py` and
`tools/autopilot_state.py`, so `/autopilot` and `/surface` can notice exposure,
identity, and cloud signals without re-enumerating everything.

## 2. Discovery (expand surface)

| Tool | When to use | One-line function |
|---|---|---|
| `tools/param_discovery.sh` | Live URLs exist, parameters thin | Active hidden parameter mining (arjun + x8) |
| `tools/takeover_scanner.sh` | subdomains/all.txt populated | dnsReaper + subjack subdomain takeover scan |
| `tools/secrets_hunter.sh` | After JS/source collection | trufflehog/noseyparker/gitleaks — verified secret discovery |
| `tools/cicd_scanner.sh` | GitHub org name detected | sisakulint remote scan of `.github/workflows/*.yml` |
| `tools/source_hunt.py` | Public repo URL known | `/source-hunt` backend — git history secrets + CI risks |
| `tools/source_intel.py` | Source/JS bundle cached | Extract route handlers, ID schemas, auth decorators |
| `tools/repo_source.py` | Need to clone target's public repo | Size-bounded GitHub repo acquisition |
| `tools/repo_ci_scan.py` | Cloned repo present | YAML-based CI workflow danger pattern check |
| `tools/repo_secret_scan.py` | Cloned repo present | Filesystem high-signal secret regex sweep |
| `tools/repo_source_artifacts.py` | After source_hunt run | Persist source-hunt artifacts in findings/ |
| `tools/external_arsenal.sh` | Bootstrapping a fresh box | Detect installed bug-bounty tools + install hints |

## 3. Vuln & Bug-class testers

| Tool | When to use | One-line function |
|---|---|---|
| `tools/vuln_scanner.sh` | Recon done, want broad active coverage | Multi-lane scanner; unsafe methods become manual-review unless `ALLOW_UNSAFE_HTTP_TESTS=1` |
| `tools/bypass_403.sh` | 403/401 on interesting endpoint | byp4xx + 20 built-in header/method/encoding bypass tricks |
| `tools/sender_semantics.py` | Byte-exact/proxy/cache/smuggling work needs sender choice | `--list` / `--require ...`; sender capability matrix + raw HTTP/1 sender for low-level request semantics |
| `tools/smuggling_executor.py` | Smuggling/cache candidate execution plan | `--summary` / `--variant 0.CL`; sender + evidence classes |
| `tools/role_diff.py` | Multiple session files available | **Multi-role endpoint diff — IDOR gold standard** (R2 new) |
| `tools/h1_idor_scanner.py` ⚠️ underused | Two user accounts captured | Cross-user IDOR scanner — direct ID swap |
| `tools/h1_mutation_idor.py` ⚠️ manual-only | Explicit operator opt-in | GraphQL mutation battery; never auto-route from Claude prompts |
| `tools/h1_oauth_tester.py` ⚠️ H1-specific | HackerOne / H1-compatible OAuth flow | H1 auth/OAuth tester and pattern reference; not a generic target tool |
| `tools/h1_race.py` ⚠️ manual-only | Explicit operator opt-in | Race-condition burst tester; never auto-route from Claude prompts |
| `tools/zendesk_idor_test.py` ⚠️ underused | Target on Zendesk platform | Zendesk-specific IDOR/BAC probes |
| `tools/zero_day_fuzzer.py` ⚠️ underused | Standard scans plateaued | LLM-guided fuzz on remaining unexplored surface |
| `tools/hai_payload_builder.py` ⚠️ underused | Need payload library / LLM-shaped injection | VAPT payload library + LLM prompt-injection generator |
| `tools/hai_probe.py` ⚠️ underused | Target appears to expose AI Copilot | Probe + fingerprint HackerOne-style AI Copilot endpoints |
| `tools/sneaky_bits.py` ⚠️ underused | Need invisible/Unicode bypass payloads | U+2062 / U+2064 encoder for filter bypass |
| `tools/h1_run.sh` ⚠️ underused | Multi-tool ladder run | HackerOne 20-day-hunt master ladder |
| `tools/token_scanner.py` | Smart contract / token audit | Token red-flag scanner — meme coin rug vectors |

## 4. Browser / JS / Source intelligence

| Tool | When to use | One-line function |
|---|---|---|
| `tools/browser_evidence.py` | MCP unavailable or scriptable fallback needed | Capture minimal browser-state evidence via fallback browser automation |
| `tools/browser_surface.py` | Browser evidence dumped | Extract XHR/API/GraphQL surface from browser evidence |
| `tools/hai_browser_recon.js` | Need browser-side recon snippet | Playwright recon helper script (JS) |
| `tools/js_reader.py` | JS bundles cached | Prepare js-reader agent materials from cached JS |
| `tools/surface.py` | Cached recon ready for review | Build AI-first attack-surface review pack with hunt-memory context; P1/P2 are compatibility score hints |
| `tools/surface_js_intel.py` | After js-reader has run | Feed js-reader hypotheses into `surface.py` |
| `tools/surface_source_intel.py` | After source_intel has run | Feed source-intel hypotheses into `surface.py` |
| `tools/mindmap.py` | Choosing vuln class for a stack | Mermaid mind map + tech→vuln-class priority |
| `tools/finding_index.py` | Listing/querying structured findings | Structured finding index store + query API |
| `tools/structured_findings.py` | Reading single finding | Helpers to rank/load structured findings |

## 5. Auth & credentials

| Tool | When to use | One-line function |
|---|---|---|
| `tools/auth_session.py` | Carrying auth across recon/scan/replay | Auth-session helpers; produces `BBHUNT_*` headers |
| `tools/_auth_helper.sh` | Shell scripts sourcing auth env | Reads `BBHUNT_AUTH_HEADERS` into `BB_AUTH_ARGS=(-H ...)` |
| `tools/credential_store.py` | Loading `.env` secrets without leaking | Bounded credential loader |
| `tools/wordlist_engine.sh` | Manual credential-prep wordlist needed | cewler + hashcat rules into `recon/<target>/wordlists/` |
| `tools/osint_employees.sh` | Identity surface / username candidates needed | theHarvester + username-anarchy into `recon/<target>/osint/` |
| `tools/breach_checker.py` | Rank prepared password candidates | HIBP k-anonymity counts; sends SHA-1 prefixes only |
| `tools/spray_orchestrator.sh` ⚠️ controlled | Credential lane selected after prep | typed-hostname + lockout pre-flight; audit JSONL; stop-on-hit |

## 6. OAST / async (Blind vulnerabilities)

| Tool | When to use | One-line function |
|---|---|---|
| `tools/oast_listen.py` | Blind SSRF/XXE/RCE/SQLi suspected | **interactsh wrapper** — start/poll/stop callback listener (R4 new) |

## 7. Hunt orchestration & state

| Tool | When to use | One-line function |
|---|---|---|
| `tools/hunt.py` | Master hunt entrypoint (CLI) | Orchestrator — wraps recon/scan/agent/report flows |
| `tools/autopilot_state.py` | Reading current autopilot state | Combine resume + surface context into one state view |
| `tools/action_queue.py` | Actionable evidence exists or checkpoint has next actions | Persistent action queue: ingest, choose next, resolve, summarize |
| `tools/target_case_state.py` | Multi-actor/object validation needs durable target state | Actor/session/object registry, multi-header auth session import, validation backlog next action |
| `tools/case_state_seed.py` | Browser/recon/JS/source artifacts reveal object IDs but case state is empty | Suggest add-actor/add-object/add-backlog commands; no auto-write |
| `tools/coverage_matrix.py` | Checking high-value untested cells | Endpoint × vuln-class matrix; emits auto-hints and lets Claude mark endpoint kind |
| `tools/resume.py` | Continuing previous target work | `/pickup` backend — summarize prior session+untested endpoints |
| `tools/remember.py` | Logging finding to hunt memory | `/remember` backend — write to journal/pattern DB |
| `tools/validate.py` | Pre-report validation gate | 7-Question Gate + 4 gates — runs `/validate` |
| `tools/report_generator.py` | Drafting submission report | `/report` backend — H1/BC/Intigriti/Immunefi templates |
| `tools/request_guard.py` | Logging request telemetry | Advisory audit/replay record + breaker telemetry |
| `tools/memory_gc.py` | Hunt-memory JSONL too big | Inspect/rotate audit/journal/pattern JSONL files |
| `tools/legacy_bridge.py` | Internal compatibility | Bridges legacy top-level imports |
| `tools/runtime_config.py` | Reading repo-local config | Loader for `config.json` (incl. ctf_mode resolution) |
| `tools/runtime_doctor.py` | Checking repo↔runtime drift | `/sync-check` backend — compare commands/agents/skills |
| `tools/runtime_exec.py` | Subprocess execution | Shared shell-command runner with timeout/quoting |
| `tools/runtime_state.py` | Probing on-disk pipeline artifacts | Read autopilot/runtime state files |
| `tools/reset_target.sh` | Want clean re-run for one target | Wipe `recon/`/`findings/`/state for a single target |

---

## Quick-pick by symptom

| Claude observes | First-pick tool |
|---|---|
| Concrete signal plus unresolved next verification question | smallest safe lookup/replay/diff/enrichment/probe, then checkpoint state |
| Need to remember user_a/user_b sessions, owned objects, private markers, or IDOR backlog | `target_case_state.py summary/next` |
| `/orders/123`, `/invoices/42`, `/addresses/7`, `account_id`, `tenantId` appears in cached artifacts | `case_state_seed.py --target <target> --json`, then review suggested commands |
| Concrete CMS/plugin/theme/library version observed | `/intel`, `tools/intel_engine.py`, `tools/cve_hunter.py`, `/scan-cves` |
| 401/403 on interesting endpoint | `bypass_403.sh` |
| Multiple session files in `.private/` | `role_diff.py` |
| Two account creds + numeric IDs | `role_diff.py`, then `h1_idor_scanner.py` |
| GraphQL endpoint discovered | manual introspection / role diff; `h1_mutation_idor.py` only with explicit operator opt-in |
| OAuth `/authorize` `/callback` discovered | manual OAuth/OIDC flow review; `h1_oauth_tester.py` only for HackerOne/H1-compatible flows |
| Payment / coupon / wallet / cart / checkout endpoint | high-value logic lane; avoid only real money movement or irreversible state changes unless explicitly intended |
| Quota / OTP / payment / cart race signal | manual review; `h1_race.py` only for controlled race probes |
| Blind SSRF / RCE / XXE candidate | `oast_listen.py start` |
| Standard scans plateaued | `zero_day_fuzzer.py` |
| Unicode / filter bypass needed | `sneaky_bits.py` |
| Public repo URL in target footer | `source_hunt.py` |
| Brand keyword for buckets | `cloud_recon.sh` |
| Batch recon manifest exists | read `recon/<list-stem>/batch_manifest.jsonl`, then run `/surface` or `/hunt` on completed domains |
| Identity/cloud intel from recon has hits | review `exposure/identity_intel/summary.md` and `exposure/cloud/cloud_enum.txt`, then pivot to `/intel` or `/cloud-recon` |
| `subdomains/all.txt` ready | `takeover_scanner.sh` |
| Live URLs but no params | `param_discovery.sh` |
| JS bundles cached | `js_reader.py` (then `js-reader` agent) |
| Recon done, want broad active | `vuln_scanner.sh` |
| Tech stack identified, need CVEs | `cve_hunter.py` |
| Dashboard / SPA target | `browser_evidence.py` → `browser_surface.py` |
| Switching back to old target | `resume.py` |
| Want to remember a pattern | `remember.py` |
| Login surface + need credential prep | `/wordlist-gen`, `/osint-employees`, `/breach-check` |
| Credential breakthrough lane selected | `/spray` / `spray_orchestrator.sh` after prep + dry-run |

---

## Underused inventory (worth knowing they exist)

These tools exist in the repo but are rarely cited in slash-command or sub-agent prompts. Surface them when the trigger fits — they are battle-tested and ready:

- `h1_idor_scanner.py` — Direct IDOR swap when 2 users captured
- `h1_mutation_idor.py` — Manual-only GraphQL mutation auth battery
- `h1_oauth_tester.py` — HackerOne-specific OAuth/OIDC pattern tester
- `h1_race.py` — Manual-only concurrent race-condition burst tester
- `zendesk_idor_test.py` — Zendesk platform specifics
- `zero_day_fuzzer.py` — LLM-guided fuzz post-plateau
- `hai_payload_builder.py` — Payload library + LLM injection generator
- `hai_probe.py` — AI Copilot endpoint fingerprint
- `sneaky_bits.py` — Invisible/Unicode payload encoder
- `h1_run.sh` — Multi-tool master ladder
- `mindmap.py` — Tech → vuln-class priority (consult before lane choice)
- `wordlist_engine.sh` / `osint_employees.sh` / `breach_checker.py` — manual credential-prep chain; useful when identity surface matters

---

## Maintenance

When adding a new `tools/*` script:

1. Add a row to the appropriate category
2. If it covers a previously untooled attack class, add a "Quick-pick by symptom" entry
3. Keep description ≤ 80 characters
4. Don't list test fixtures, `__init__.py`, internal helpers

When deprecating a tool: keep the row but prefix label with `(deprecated)`.

---

## Related References

- `rules/hunting.md` — canonical state model + lane semantics
- `commands/autopilot.md` — autonomous loop execution contract
- `docs/v4.4.2-autopilot-capability-gaps.md` — historical capability-gap notes
- `docs/PRODUCT.md` — product-level overview
