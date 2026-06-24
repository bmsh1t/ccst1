# Changelog

## v4.4.1 — JSON-Inject Probe Dispatcher Wiring + Heuristic Alignment (May 2026)

### Added
- `tools/hunt.py::run_json_inject_probe`: wrapper around `tools.json_inject_probe` that auto-discovers `recon/<target>/browser/xhr_endpoints.txt` and `findings/<target>/js_intel/hypotheses.json`, honors explicit overrides, and writes POCs under `findings/<target>/poc/json_inject/`.
- `agent.py`: 4-hook ToolDispatcher integration for `run_json_inject_probe` — `_OPTIONAL_TOOL_FUNCS` mapping, `_FINISH_FLOOR_PROGRESS_TOOLS` membership (counts as a substantive hunt step), `_ALL_TOOL_SPECS` JSON schema (4 optional args: `endpoints_file`, `js_intel`, `max_requests`, `add_default_seeds`), and dispatch branch with type coercion. System-prompt rule 15 now routes the LLM to this probe whenever POST JSON endpoints are discovered.
- `tools/vision_auto.py`: `spa_app_signal` primary class (`≥5 JS files` + known SPA framework fingerprint) — covers SPA root paths like Juice Shop "/" that bootstrap login modals via JS, where `login_signal` and `password_signal` both miss. Added Angular CLI `ng build` bundle fingerprints (`main-es*`, `runtime-es*`, `vendor-es*`, `polyfills-es*`, `styles-es*`, including `-es2015` variants).

### Changed
- `tools/chain_hints.py`: removed the `_QUALIFYING_SEVERITY` gate. Many high-leverage chains start at info-level signals (S3 listable, GraphQL introspection enabled, JWT alg=none, subdomain takeover candidate). The regex patterns themselves are specific enough to discriminate noise — info + no pattern match still returns empty. Docstring updated to reflect the soft-bias model.

### Tests
- `tests/test_json_inject_dispatcher.py` (17 cases, NEW) — TOOL_NAMES / TOOLS registration, well-formed JSON schema, description content (POST/JSON/sqli/ssti hints to LLM), `_OPTIONAL_TOOL_FUNCS` mapping, `_FINISH_FLOOR_PROGRESS_TOOLS` membership, `_finish_floor_progress_count` recognition, dispatcher default-arg invocation, custom-arg forwarding, int coercion, wrapper auto-discovery of `xhr_endpoints.txt`, auto-discovery of `hypotheses.json`, explicit-override precedence, and `tools/json_inject_probe.py` module sanity (clean import, all 8 payload classes present).
- `tests/test_chain_hints.py`: `TestSeverityGate` → `TestSeverityHandling`. 3 tests rewritten to assert info-level still fires when the pattern matches; info + no pattern still returns empty.
- `tests/test_vision_auto.py`: 2 new tests for `spa_app_root` triggering without a `/login` path, and the framework-fingerprint requirement.
- Full suite: **1462 / 1462 pass in ~11 s**.

### Demo (mock-vuln target)
- 4-endpoint mock server (SQLi auth-bypass, SQLi error, SSTI, open redirect) confirmed end-to-end probe → dispatcher → observation summary path. Each hit produces a `curl` reproducer + evidence string suitable for `/validate` and `/report`.

### Notes
- Architecturally a camp-2 (AI-precision) move rather than a camp-1 (brute scanner wrapper) one: the probe runs only on endpoints the LLM judges relevant, instead of fanning out across the full surface like nuclei DAST. Speed-per-test stays tight; AI judgment continues to gate which endpoints get touched.

## v4.4.0 — Phase 5 Wire-up + Chain Hint Expansion (May 2026)

### Added
- `tools/chain_hints.py`: pure regex → "[CHAIN HINT HH:MM] …" mapper. 15 patterns covering IDOR, auth bypass, stored XSS, SSRF callback, open redirect, S3 listing, GraphQL introspection, LLM prompt injection, LFI, subdomain takeover, JWT weak, file upload bypass, webhook/callback, SQLi (any flavour), DOM/reflected XSS / prototype pollution.
- `tools/output_cap.py`: UTF-8-safe 50KB output cap with truncation marker for autopilot observations.
- `tools/vision_auto.py`: multi-signal SPA / login / dashboard heuristic for auto-firing playwright vision capture; explicit kill rules for static assets.
- `LoopDetector` semantic loop wiring: `endpoint_family('/api/users/1')` → `/api/users/{id}`, response-hash normalisation (timestamps, UUIDs, hex, request IDs), 3× family + same-hash rule plus 5× pure-hash rule, rotation-hint emitter, wired into `ReActAgent` loop.
- `HuntMemory.bootstrap_context` and `bootstrap_state` now persist across `save()` / `load()` instead of being lost on reload.
- `HuntMemory.add_finding` injects chain hints into `working_memory` for Medium+ findings, with 8 KB tail-preserve cap and exception isolation (broken `chain_hints` cannot break `add_finding`).
- `tools/validate.py`: `--result confirmed | rejected | partial | informational | unknown` mapping to `pattern_calibration.jsonl` outcomes (`helped`, `false_positive`, `no_signal`, `None`), with `record_validation_calibration(summary, session_id, path)` helper.

### Tests
- `tests/test_chain_hints.py` (33 cases) — severity gate, all 15 pattern bodies, robustness (no match / empty / non-dict / multiple matches / format indices / `vuln_class` & `tool` fallbacks), `HuntMemory` integration (working_memory append, info severity no-op, exception isolation, 8 KB cap, save/load persistence).
- `tests/test_loop_detector_semantic.py` (30 cases) — endpoint family templating, response normalisation, dual-rule detection, window trimming, rotation hint, reset, legacy coexistence.
- `tests/test_output_cap.py` — UTF-8 safe truncation + marker.
- `tests/test_bootstrap_serialize.py` — bootstrap_context round-trip.
- `tests/test_vision_auto.py` — multi-signal heuristic.
- Full suite: **1426 / 1426 pass in ~12 s**.

### Capability Demo (real target)
- ginandjuice.shop two pending findings (DOM XSS via prototype pollution on `/blog`, boolean blind SQLi on `/catalog`) now produce chain hints for the LLM (XSS → ATO via postMessage / localStorage / admin pivot; SQLi → UNION extraction + LOAD_DATA INFILE + information_schema enumeration), are written into the local `reports/ginandjuice.shop/` directory with CVSS 4.0 scores, and are recorded in `findings.json` with `status=reported`, `validation=7Q-PASS`.

### Notes
- Phase 5 closes the audit-identified wire-up gap: Phase 4 primitives existed but were not invoked in the live agent loop. Each channel now has a verified end-to-end path from source → working_memory or audit artefact.

## v4.3.0 — Auth Sessions + Recon Arsenal (May 2026)

### Added
- `docs/auth-sessions.md` and `docs/auth.example.json`: end-to-end guidance for auth-aware hunting, env vars, file formats, and downstream shell-tool propagation.
- `skills/security-arsenal/METHODOLOGY_CHEATSHEET.md`: quick per-vulnerability methodology table distilled from upstream hunting references.
- `skills/security-arsenal/REFERENCES.md` and `wordlists/REFERENCES.md`: source references for methodology and larger wordlist/payload collections.

### Changed
- `tools/auth_session.py`, `tools/_auth_helper.sh`, `tools/hunt.py`, `tools/recon_engine.sh`, `tools/vuln_scanner.sh`, and `scripts/full_hunt.sh`: auth context can now be defined once (`--cookie`, `--bearer`, env vars, or `--auth-file`) and propagated consistently into Python fetches plus shell tools such as `httpx`, `katana`, `ffuf`, `nuclei`, `dalfox`, and `curl`.
- README: added the v4.3 auth / recon-toolkit notes and linked the dedicated auth-session docs.

### Notes
- The local fork keeps its target-driven execution semantics; upstream auth-session and recon-toolkit assets were absorbed without restoring authorization-first gates.

## v4.2.6 — Runtime Doctor + Autopilot Quick Wiring (May 2026)

### Added
- `tools/runtime_doctor.py`: compares repo `commands/`, `agents/`, and `skills/` with the Claude CLI installed runtime under `~/.claude/`, reports `OK` / `DIFF` / `MISSING` / `EXTRA`, and can sync or prune the managed runtime files back into place.
- `/sync-check`: Claude Code entrypoint for runtime drift inspection and sync guidance.

### Changed
- `agent.py` + `tools/hunt.py`: wired `--quick` through the autonomous agent path so `/autopilot <target> --quick` now reaches the agent runtime, tool dispatcher defaults, and quick recon/scanner behavior end-to-end.
- `README.md`, `CLAUDE.md`, and `docs/OVERVIEW.md`: aligned current version, command/agent counts, and runtime sync guidance with the actual project state.

### Why
- Prevents “repo looks fixed but Claude CLI still loads old commands/agents” drift.
- Makes `/autopilot --quick` behave the way the command docs already promised.

## v4.2.5 — Agent Model Fallback (May 2026)

### Changed
- `agents/*.md`: replaced hard Claude versioned `model:` pins with explicit `model: inherit`. Each agent now follows the current Claude Code session model while keeping its preferred model class in the description (`report-writer` prefers Opus-class quality, `recon-agent` / `recon-ranker` prefer Haiku-class speed, and the remaining analysis agents prefer Sonnet-class balance).
- `README.md`: updated the agent model table to document preferred class → current session fallback behavior instead of hard-coded versioned model IDs.

### Why
- Prevents project-level subagents from failing when an upstream Claude model ID is retired.

## v4.2.4 — Writer-Owned Memory Rotation (May 2026)

### Changed
- `memory/hunt_journal.py` `HuntJournal.append()`: now calls `rotate_if_needed` before each append, matching `AuditLog.log()` and `PatternDB.save()`.
- `/memory-gc` documentation: rotation correctness is writer-owned and no longer depends on a Claude Code `Stop` hook.

### Tests
- Added journal auto-rotation coverage in `tests/test_hunt_journal.py`.

---

## v4.2.3 — Auto-rotation Stop Hook (May 2026)

### Added
- **`.claude/settings.json`** with a `Stop` hook that runs `python3 -m tools.memory_gc --rotate` (quietly, non-blocking via `async: true`) whenever a Claude Code session ends. Long-running hunts that never trigger an inline write-time rotation now still get GC'd at session end. Hook is a no-op if `tools/memory_gc.py` is missing or the working dir isn't the repo root, so it is safe to ship in the project file.

---

## v4.2.2 — Restore ReconAdapter (May 2026)

### Fixed
- **`tools/recon_adapter.py`** was missing the `ReconAdapter` class that `tests/test_recon_adapter.py` imports — the test file had been silently uncollectable since the rename in 0db9640. Added the class with read accessors for the subdir-nested layout that `recon_engine.sh` writes (`subdomains/all.txt`, `live/urls.txt`, `urls/with_params.txt`, `js/potential_secrets.txt`, etc.), graphql extraction, fallback path resolution, summary counts, and a `normalize()` method that creates the derived files brain.py expects (`priority/`, `api_specs/`, `urls/graphql.txt`, `subdomains/resolved.txt`).

### Tests
- 31 previously-uncollectable tests in `tests/test_recon_adapter.py` now run and pass. Suite total: **215 passing** (was 184).

---

## v4.2.1 — PatternDB Perf Fix (May 2026)

### Fixed
- **`PatternDB.save()` was O(n²)** — every save re-read the entire JSONL file to dedup. At 10k entries this pegged CPU for 5+ minutes per insert pass. Replaced with an in-memory dedup index of `(target, vuln_class, technique)` tuples, populated lazily on first save and updated per write. 10k saves now complete in ~2 seconds instead of 5+ minutes.

### Added
- `tests/test_pattern_db.py::TestPatternPerformance`: 4 new tests covering the perf bound, dedup correctness at 10k entries, lazy-load via reopen, and corrupted-line resilience.

### Resolved
- **TODO-8 (final item)** — `PatternDB.save()` performance test at 10,000 entries.

---

## v4.2.0 — Memory Rotation (Apr 2026)

### Added
- `memory/rotation.py`: size-based JSONL rotator under `fcntl.LOCK_EX`. Default cap 10 MB, keep 3 backups.
- `tools/memory_gc.py` + `/memory-gc` slash command: scan, rotate, or purge backups across the hunt-memory tree.
- `tests/test_rotation.py`: 22 tests covering rotation primitives, auto-rotation in `AuditLog`/`PatternDB`, multi-process concurrent writes (with and without rotation), and disk-full OSError propagation.

### Changed
- `memory/audit_log.py` `AuditLog.log()`: calls `rotate_if_needed` before each append.
- `memory/pattern_db.py` `PatternDB.save()`: calls `rotate_if_needed` before each append.
- `memory/__init__.py`: exports rotation helpers.

### Resolved
- **TODO-7** — memory GC / rotation policy.
- **TODO-8** (partial) — concurrent-write stress test + disk-full OSError propagation test.

---

## v4.1.0 — Patch: Bug Fixes + Assets (Apr 2026)

### Fixed
- **TODO-4 resolved**: `hunt.py` BASE_DIR path resolution — `hunt.py` was relocated to `tools/` so `TOOLS_DIR`/`BASE_DIR`/`RECON_DIR`/`FINDINGS_DIR` now resolve correctly. All 5 open TODOs are now closed.

### Added
- `logo-banner.svg` and `logo-icon.svg` — SVG vector assets for banner and icon variants

---

## v4.0.0 — Meme Coin Security Module (Apr 2026)

### Added — New Skill Domain
- `skills/meme-coin-audit/SKILL.md`: **Meme coin rug pull detection + 8 token bug classes**
  - Mint authority / freeze authority checks
  - Bonding curve exploit patterns
  - LP lock verification
  - Honeypot detection
  - Token metadata tampering
  - Solana-specific audit path (SPL token checks)
  - Pre-dive kill signals for obvious rugs

### Added — Tool
- `tools/token_scanner.py`: automated token red flag scanner supporting EVM + Solana
  - EVM: ABI analysis, ownership checks, hidden mint functions, transfer tax detection
  - Solana: SPL token account authority checks, metadata validation

### Changed
- `CLAUDE.md`: Skills count 8 → 9, added `meme-coin-audit` to skill table; Commands 13 → 14, added `/token-scan`
- `README.md`: Updated skill domain count

---

## v3.1.1 — CI/CD GitHub Actions Security Expansion (Mar 2026)

### Changed — Existing Skill Enhancement
- `SKILL.md` CI/CD Pipeline section: **5 checklist items → 6 categories, 30+ checks, PoC templates, hunting workflow, and GHSA reference table**
  - **Category 1: Code Injection & Expression Safety** — expression injection, envvar/envpath/output clobbering, argument injection, SSRF via workflow, taint source catalog, fix patterns (env var extraction, heredoc delimiters, end-of-options markers)
  - **Category 2: Pipeline Poisoning & Untrusted Checkout** — untrusted checkout on `pull_request_target`/`workflow_run`, TOCTOU with label-gated approvals, reusable workflow taint, cache poisoning, artifact poisoning, artipacked credential leakage
  - **Category 3: Supply Chain & Dependency Security** — unpinned actions (tag → SHA), impostor commits from fork network, ref confusion, known vulnerable actions, archived actions, unpinned container images
  - **Category 4: Credential & Secret Protection** — secret exfiltration, secrets in artifacts, unmasked `fromJson()` bypass, excessive `secrets: inherit`, hardcoded credentials
  - **Category 5: Triggers & Access Control** — dangerous triggers without/with partial mitigation, label-based approval bypass, bot condition spoofing, excessive GITHUB_TOKEN permissions, self-hosted runners in public repos, OIDC token theft
  - **Category 6: AI Agent Security** — unrestricted AI triggers, excessive tool grants to AI agents, prompt injection via workflow context
  - **Hunting workflow** — 6-step recon→scan→triage→verify→PoC→prove pipeline
  - **Expression injection PoC template** — ready-to-use `gh issue create` payload
  - **10 real-world GHSAs** — proven Critical/High advisories with affected actions
  - **A→B signal chains** — 7 CI/CD-specific escalation paths
  - **Tooling**: integrated [sisakulint](https://sisaku-security.github.io/lint/) — 52 rules, taint propagation, 81.6% GHSA coverage
  - **Deep-dive guide**: Decision tree for verifying sisakulint findings based on 36 real-world paid reports (Bazel $13K, Flank $7.5K, PyTorch $5.5K, GitHub $20K, DEF CON $250K+)

### Added — Tool Integration
- `tools/cicd_scanner.sh`: standalone sisakulint wrapper — org/repo scanning, recursive reusable workflow analysis, parsed summary output with per-rule breakdown
- `install_tools.sh`: sisakulint binary auto-download with OS/arch detection (v0.2.11, linux/darwin, amd64/arm64/armv6), cicd_scanner install now optional (`--with-cicd-scanner`)
- `tools/recon_engine.sh` Phase 8: auto-detects GitHub orgs from recon data (httpx, JS endpoints, URLs), invokes `cicd_scanner.sh` per org
- `tools/hunt.py`: surfaces CI/CD findings between recon and vuln scan stages via `check_cicd_results()`
- `tests/test_cicd_scanner.sh`: shell tests for cicd_scanner (syntax check + CLI behavior)

## v3.1.0 — Hunting Methodology Skill (Mar 2026)

### Added — New Skill Domain
- `skills/bb-methodology/SKILL.md`: **Hunting mindset + 5-phase non-linear workflow** — the "HOW to think" layer that was missing from the toolkit
  - **Part 1: Mindset** — Define/Select/Execute discipline, 4 thinking domains (critical, multi-perspective, tactical, strategic), developer psychology reverse-engineering, Amateur vs Pro 7-phase comparison, Feature-based vs Vuln-based route selection, anti-patterns
  - **Part 2: Workflow** — 5-phase non-linear flow (Recon → Map → Find → Prove → Report) with decision trees per phase, input-type → vuln-class routing, Error vs Blind detection cascade, escalation decision trees per vuln class
  - **Part 3: Navigation & Timing** — "I'm stuck because..." quick reference table, 20-minute rotation clock, tool routing by phase with rationale, session start/end checklists

### Changed
- `CLAUDE.md`: Skills count 7 → 8, added `bb-methodology` to skill table
- `README.md`: Updated skill domain count to 8
- `SKILL.md`: Added cross-reference to `bb-methodology` after CRITICAL RULES section

## v3.1.0 — CVSS 4.0 + TODO Fixes (Mar 2026)

### Changed — CVSS 3.1 → 4.0
- `tools/validate.py`: Full CVSS 4.0 interactive scorer. Replaces 8-metric CVSS 3.1 with 11-metric CVSS 4.0. New metrics: AT (Attack Requirements), VC/VI/VA (Vulnerable System), SC/SI/SA (Subsequent System, incl. Safety). Scope metric removed. UI now has three values (None / Passive / Active). Score verified via FIRST.org calculator link in output.
- `agents/report-writer.md`: Updated CVSS section to 4.0. New metric descriptions, updated common-pattern examples, verification link.

### Fixed — TODOs resolved
- `agents/autopilot.md` already implemented TODO-2 (safe HTTP methods) and TODO-3 (circuit breaker) — marked resolved in TODOS.md
- `tools/hunt.py` BASE_DIR path resolution was already correct (TODO-4 was based on wrong assumption about file location) — marked resolved
- `tools/recon_adapter.py` created (TODO-5): auto-detects nested vs flat recon format, returns unified `ReconData`. `normalize_to_nested()` migrates legacy flat output. CLI: `python3 tools/recon_adapter.py example.com --migrate`

---

## v2.1.0 — 20 Vuln Classes + Payload Expansion (Mar 2026)

### Config
- Recon commands now read the Chaos API key from the `$CHAOS_API_KEY` environment variable for cleaner setup across different environments.

### Added — New Vuln Classes
- `web2-vuln-classes`: **MFA/2FA Bypass** (class 19) — 7 bypass patterns: rate limit, OTP reuse, response manipulation, workflow skip, race, backup codes, device trust escalation
- `web2-vuln-classes`: **SAML/SSO Attacks** (class 20) — XML signature wrapping (XSW), comment injection, signature stripping, XXE in assertion, NameID manipulation + SAMLRaider workflow

### Added — security-arsenal Payloads
- **NoSQL injection**: MongoDB `$ne`/`$gt`/`$regex`/`$where` operators, URL-encoded GET parameter injection
- **Command injection**: Basic probes, blind OOB (curl/nslookup), space/keyword bypass techniques, Windows payloads, filename injection context
- **SSTI detection**: Universal probe for all 6 engines (Jinja2, Twig, Freemarker, ERB, Spring, EJS) + RCE payloads for each
- **HTTP smuggling payloads**: CL.TE, TE.CL, TE.TE obfuscation variants, H2.CL
- **WebSocket testing**: IDOR/auth bypass messages, CSWSH PoC, Origin validation test, injection via messages
- **MFA bypass payloads**: OTP brute force (ffuf), race async script, response manipulation, device trust cookie test
- **SAML attack payloads**: XSW XML templates, comment injection, signature stripping workflow, XXE payload, SAMLRaider CLI

### Added — web2-recon Skill
- **Setup section**: `$CHAOS_API_KEY` export instructions, subfinder config.yaml with 5 API sources, nuclei-templates update command
- **crt.sh** passive subdomain source (no API key needed) added as Step 0
- **Port scanning**: naabu command for non-standard ports (8080/8443/3000/9200/6379/etc.)
- **Secret scanning**: trufflehog + SecretFinder JS bundle scan, grep patterns
- **GitHub dorking**: `gh search code` commands, GitDorker integration for org-wide secret search

### Added — report-writing Skill
- **Intigriti template**: Full format with platform-specific notes (video PoC preference, safe harbor stance)
- **CVSS 4.0 quick reference**: Key differences from CVSS 3.1, score examples for common findings, calculator link

### Added — rules/hunting.md
- **Rule 18**: Mobile = different attack surface (APK decompile workflow, key targets)
- **Rule 19**: CI/CD is attack surface (GitHub Actions expression injection, dangerous workflow patterns)
- **Rule 20**: SAML/SSO = highest auth bug density (test checklist)

### Updated
- README: CHAOS_API_KEY setup section with free key instructions and optional subfinder API keys
- README: Updated vuln class count from 18 → 20, updated skill descriptions
- `web2-vuln-classes` description updated to reflect 20 classes and new additions

---

## v2.0.0 — ECC-Style Plugin Architecture (Mar 2026)

Major restructure into a full Claude Code plugin with multi-component architecture.

### Added
- `skills/` directory with 7 focused skill domains (split from monolithic SKILL.md)
  - `skills/bug-bounty/` — master workflow (unchanged from v1)
  - `skills/web2-recon/` — recon pipeline, subdomain enum, 5-minute rule
  - `skills/web2-vuln-classes/` — 18 bug classes with bypass tables
  - `skills/security-arsenal/` — payloads, bypass tables, never-submit list
  - `skills/web3-audit/` — 10 smart contract bug classes, Foundry template
  - `skills/report-writing/` — H1/Bugcrowd/Intigriti/Immunefi templates
  - `skills/triage-validation/` — 7-Question Gate, 4 gates, always-rejected list
- `commands/` directory with 8 slash commands
  - `/recon` — full recon pipeline
  - `/hunt` — start hunting a target
  - `/validate` — 4-gate finding validation
  - `/report` — submission-ready report generator
  - `/chain` — A→B→C exploit chain builder
  - `/scope` — asset scope verification
  - `/triage` — quick 7-Question Gate
  - `/web3-audit` — smart contract audit
- `agents/` directory with 5 specialized agents
  - `recon-agent` — runs recon pipeline, uses claude-haiku-4-5 for speed
  - `report-writer` — generates reports, uses claude-opus-4-6 for quality
  - `validator` — validates findings, uses claude-sonnet-4-6
  - `web3-auditor` — audits contracts, uses claude-sonnet-4-6
  - `chain-builder` — builds exploit chains, uses claude-sonnet-4-6
- `hooks/hooks.json` — session start/stop hooks with hunt reminders
- `rules/hunting.md` — 17 critical hunting rules (always active)
- `rules/reporting.md` — 12 report quality rules (always active)
- `CLAUDE.md` — plugin overview and quick-start guide
- `install.sh` — one-command skill installation

### Content Added to Skills
- SSRF IP bypass table: 11 techniques (decimal, octal, hex, IPv6, redirect chain, DNS rebinding)
- Open redirect bypass table: 11 techniques for OAuth chaining
- File upload bypass table: 10 techniques + magic bytes reference
- Agentic AI ASI01-ASI10 table: OWASP 2026 agentic AI security framework
- Pre-dive kill signals for web3: TVL formula, audit check, line-count heuristic
- Conditionally valid with chain table: 12 entries
- Report escalation language for payout downgrade defense

---

## v1.0.0 — Initial Release (Early 2026)

- Monolithic SKILL.md (1,200+ lines) covering full web2+web3 workflow
- Python tools: `hunt.py`, `learn.py`, `validate.py`, `report_generator.py`, `mindmap.py`
- Vulnerability scanners: `h1_idor_scanner.py`, `h1_mutation_idor.py`, `h1_oauth_tester.py`, `h1_race.py`
- AI/LLM testing: `hai_probe.py`, `hai_payload_builder.py`, `hai_browser_recon.js`
- Shell tools: `recon_engine.sh`, `vuln_scanner.sh`
- Utilities: `sneaky_bits.py`, `target_selector.py`, `zero_day_fuzzer.py`, `cve_hunter.py`
- Web3 skill chain: 10 files in `web3/` directory
- Wordlists: 5 wordlists in `wordlists/` directory
- Docs: `docs/payloads.md`, `docs/advanced-techniques.md`, `docs/smart-contract-audit.md`
