<p align="center">
  <img src="logo.png" alt="Claude Bug Bounty Logo" width="320"/>
</p>

<div align="center">

<img src="https://img.shields.io/badge/v4.4.1-JSON--Inject_Probe_Wired-blueviolet?style=for-the-badge" alt="v4.4.1">

# Claude Bug Bounty

### The AI-Powered Agent Harness for Professional Bug Bounty Hunting

*Your AI copilot that sees live traffic, remembers past hunts, and hunts autonomously.*
<br>
*The community made a meme coin to support the project CA: J6VzBAGnyyNEyzyHhauwg3ofRctFxnTLzQCcjUdGpump*
<sub>by <a href="https://shuvonsec.me">shuvonsec</a></sub>

<br>

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=flat-square)](LICENSE)
[![Python 3.8+](https://img.shields.io/badge/Python-3.8+-3776AB.svg?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![Tests](https://img.shields.io/badge/Tests-1979_passing-brightgreen.svg?style=flat-square)](tests/)
[![Claude Code](https://img.shields.io/badge/Claude_Code-Plugin-D97706.svg?style=flat-square&logo=anthropic&logoColor=white)](https://claude.ai/claude-code)

<br>

<a href="#-quick-start">Quick Start</a>&nbsp;&nbsp;|&nbsp;&nbsp;<a href="#-how-it-works">How It Works</a>&nbsp;&nbsp;|&nbsp;&nbsp;<a href="#-commands">Commands</a>&nbsp;&nbsp;|&nbsp;&nbsp;<a href="#-whats-new">What's New</a>&nbsp;&nbsp;|&nbsp;&nbsp;<a href="#-installation">Install</a>

<br>

```
  Core 4 workflow  ·  Power commands  ·  Claude CLI agents  ·  Skill routing
  20 web2 vuln classes  ·  10 web3 bug classes
  Burp MCP  ·  Caido MCP  ·  JSHook MCP  ·  HackerOne MCP  ·  Autonomous Mode
```

</div>

<br>

---

<br>

## The Problem

Most penetration-testing toolkits give you a bag of scripts. You still have to:
- Figure out **what** to test and **in what order**
- Waste hours on **false positives** that get rejected
- Write **reports from scratch** every time
- **Forget** what worked on previous targets
- **Context-switch** between 15 different terminal windows

<br>

## The Solution

Claude Bug Bounty is an **agent harness** — not just scripts. It reasons about what to test, validates findings before you waste time writing them up, remembers what worked across targets, and generates reports that actually get paid.

<br>

<div align="center">

| Before | After |
|:---|:---|
| Run scripts manually, hope for the best | AI orchestrates 25+ tools in the right order |
| Write reports from scratch (45 min each) | Report-writer agent generates submission-ready reports in 60s |
| Forget what worked last month | Persistent memory — patterns from target A inform target B |
| Can't see live traffic from Claude | Burp/Caido MCP integration — Claude reads your proxy history |
| Hunt one endpoint at a time | `/autopilot` runs full hunt loops with safety checkpoints |

</div>

<br>

---

<br>

## Quick Start

> **Prerequisite:** install Claude Code and use a Claude Pro/Max plan or an Anthropic API key with billing enabled; a free web-only Claude account does not provide Claude Code model usage.

**Step 1 — Install**

```bash
git clone https://github.com/shuvonsec/claude-bug-bounty.git
cd claude-bug-bounty
chmod +x install.sh && ./install.sh
# optional: create repo-local runtime config
cp config.example.json config.json
# localhost/private IP/CIDR/list targets remain valid inputs;
# request guard records advisory audit/replay metadata.
```

**Step 2 — Hunt**

```bash
claude                          # Start Claude Code from this repo root

/recon target.com               # Discover attack surface
/surface target.com             # Rank cached recon + memory before active testing
/hunt target.com                # Test for vulnerabilities
/js-read target.com             # LLM-read cached JS bundles when present
/source-hunt target.com --repo-path /path/to/repo
/validate                       # Check finding before writing
/report                         # Generate submission-ready report
/sync-check                     # Check repo/runtime drift after pulls or weird CLI behavior
```

> Legacy CVE/report entrypoints remain available as compatibility paths, but prefer `/intel` and `/report` as the primary workflows.

> **AI-first hunt loop:** load target context, rank surface, enrich app-like targets with chrome-devtools MCP / playwright MCP / browser XHR / source_intel / js-reader, attack exact business workflows, preserve leads/signals, then validate only report-ready candidates.

**Step 3 — Go Autonomous**

```bash
/autopilot target.com --normal  # Full autonomous hunt loop
/intel target.com               # Fetch CVE + disclosure intel
/pickup target.com              # Pick up where you left off
```

**Authenticated / stateful targets**

When a target needs a logged-in cookie, bearer token, or repeatable custom
headers, keep the auth context in one place and pass it through the local hunt
CLI. The auth session propagates into Python-side fetches and the shell recon /
scanner pipeline (`httpx`, `katana`, `ffuf`, `nuclei`, `dalfox`, `curl`) when
those tools support headers. See `docs/auth-sessions.md` for the full auth flow
and reusable file formats.

```bash
mkdir -p .private
cat > .private/auth.json <<'EOF'
{
  "cookie": "session=REDACTED",
  "headers": ["X-CSRF-Token: REDACTED"]
}
EOF

python3 tools/hunt.py --target target.com --auth-file .private/auth.json
python3 tools/hunt.py --target target.com --agent --quick --auth-file .private/auth.json
```

Environment-variable mode also works:

```bash
export BBHUNT_COOKIE='session=REDACTED'
export BBHUNT_BEARER='REDACTED'
python3 tools/hunt.py --target target.com --agent --auth-from-env
```

Inside Claude Code, say the auth source explicitly in the turn, for example:

```text
/hunt target.com, use auth file .private/auth.json and focus account/export workflows
/autopilot target.com --normal, use BBHUNT_COOKIE from env and prioritize API/object ownership paths
```

**How to continue work:**

| Goal | Recommended path |
|---|---|
| See where the last run stopped for this target | `/pickup target.com` |
| Continue this target with a clean agent run state | `/hunt target.com` or `/autopilot target.com --normal` |
| Resume the exact previous agent working memory / trace | `python3 tools/hunt.py --target target.com --agent --resume latest` |

Autonomous agent runs start a fresh local session by default under
`targets/<storage-key>/sessions/<session_id>/`. For domains and single IPs the
storage key matches the target; CIDR targets replace `/` with `_`, and host-list
targets use the list filename stem. `/pickup` only reads target-level
history and structured findings. It does not automatically reuse an old
`agent_session.json`. Use these commands only when you explicitly want to
continue the previous agent's local state:

```bash
python3 tools/hunt.py --target target.com --agent --resume latest
python3 tools/hunt.py --target target.com --agent --resume <session_id>
```

Fresh target hygiene: new targets keep only the scanner's built-in XSS lane
skip; use `--scanner-full` when the current run must include XSS. Temporary
instructions such as “skip/ignore this module”, focus lanes, or excluded bug
classes apply only to the current target and the current Claude Code turn where
they were explicitly stated. They are not persisted through `/pickup`, README
examples, old agent traces, or a newly opened Claude Code CLI. Do not
add skips because of previous target context.

<br>

> **Or run tools directly** — no Claude needed:
> ```bash
> python3 tools/hunt.py --target target.com
> python3 tools/hunt.py --target target.com --scan-only --scanner-full
> python3 tools/hunt.py --target target.com --auth-file .private/auth.json
> python3 tools/hunt.py --target target.com --agent --auth-file .private/auth.json --quick
> # Optional, per-invocation exclusion only when explicitly requested now:
> python3 tools/hunt.py --target target.com --scan-only --scanner-skip module1,module2
> ./tools/recon_engine.sh target.com
> python3 tools/source_hunt.py --target target.com --repo-path /path/to/repo
> python3 tools/intel_engine.py --target target.com --tech nextjs
> python3 tools/runtime_doctor.py --kind commands,agents
> ```

> **Repo-local note:** launch Claude Code inside this repository. The slash commands reference local `tools/`, `memory/`, and optional `config.json`.
>
> **Local/CTF note:** localhost/private IP/CIDR/list targets stay valid inputs. Helper guards keep the supplied target set active and write advisory audit/replay state instead of pausing for external bounty metadata such as policy text, allowed-method notes, or `scope_snapshot.json`.
>
> **Claude Code CLI tool priority:** for web access, logged-in state,
> SPA/XHR/GraphQL behavior, browser storage, and page interaction testing,
> prefer chrome-devtools MCP for live browser/network evidence and playwright MCP
> for automated interaction/snapshots. Use `tools/browser_evidence.py` /
> `playwright-cli` only when MCP is unavailable or a scriptable fallback is
> needed. Bulk recon still uses the `httpx` / `katana` / `gau` /
> `waybackurls` pipeline. Fall back to `curl` / `urllib` / local helpers only
> for lightweight API replay after the request is exact. Burp/Caido history
> remains auxiliary context.

<br>

---

<br>

## How It Works

Claude Code CLI uses a local, layered workflow:

| Layer | Responsibility |
|:---|:---|
| **Agent** | Executes bounded roles such as recon, ranking, validation, reporting, chaining, Web3, token review, and autopilot loops |
| **Skill** | Supplies reusable methodology; broad skills coordinate, narrower skills own recon, vuln classes, validation, reporting, arsenal, Web3, and token tactics |
| **Memory** | Persists target-level state, tested surfaces, findings, audit trails, and reusable patterns without forcing old agent sessions into new runs |

The default manual lane is the Core 4: **`/recon` -> `/hunt` -> `/validate` -> `/report`**. Power commands such as `/autopilot`, `/surface`, `/pickup`, `/intel`, `/source-hunt`, `/chain`, `/web3-audit`, `/token-scan`, and `/memory-gc` extend that lane when you need autonomy, source intelligence, chaining, Web3/token review, or memory maintenance.

```
                         YOU
                          |
                    ┌─────▼─────┐
                    │   Claude   │ ◄── Burp/Caido MCP (sees your traffic)
                    │   Code     │ ◄── HackerOne MCP (program intel)
                    └─────┬─────┘
                          |
          ┌───────────────┼───────────────┐
          |               |               |
    ┌─────▼─────┐  ┌──────▼──────┐  ┌────▼────┐
    │   Recon    │  │    Hunt     │  │ Report  │
    │   Agent    │  │   Engine    │  │ Writer  │
    └─────┬─────┘  └──────┬──────┘  └────┬────┘
          |               |               |
    subfinder        target match     H1/Bugcrowd
    httpx            vuln test        Intigriti
    katana           validate         Immunefi
    nuclei           chain A→B→C      CVSS 4.0
          |               |               |
    ┌─────▼───────────────▼───────────────▼─────┐
    │              Hunt Memory                   │
    │  journal · patterns · audit · rate limit   │
    └───────────────────────────────────────────-─┘
```

Each stage feeds the next. Claude orchestrates everything, or you run any stage independently.

<br>

---

<br>

## Commands

Default lane: **`/recon target.com` -> `/hunt target.com` -> `/validate` -> `/report`**.
Use this Core 4 when you want a clear Claude Code CLI loop from attack-surface discovery to report gating.

### Core 4 Workflow

| Command | What It Does |
|:---|:---|
| `/recon target.com` | Full recon — subdomains, live hosts, URLs, nuclei scan |
| `/hunt target.com` | Active testing — tech detect, test highest-ROI bugs |
| `/validate` | 7-Question Gate + 4 gates — PASS / KILL / DOWNGRADE / CHAIN REQUIRED |
| `/report` | Submission-ready report for H1/Bugcrowd/Intigriti/Immunefi |

### Power Commands

| Command | What It Does |
|:---|:---|
| `/scope <asset>` | Summarize the active target set before testing |
| `/triage` | Quick 2-minute go/no-go before deep validation |
| `/js-read target.com` | LLM-read cached JS bundles and write JS attack-surface hypotheses |
| `/source-hunt target.com` | Source repo scan — secrets, risky configs, GitHub Actions / CI issues |
| `/chain` | Find B and C from bug A — systematic exploit chaining |
| `/web3-audit <contract>` | 10-class smart contract checklist + Foundry PoC |
| `/token-scan <token>` | Meme/token risk review and rug-pull checklist |
| `/autopilot target.com` | Full autonomous hunt loop with safety checkpoints |
| `/surface target.com` | AI Review Pool with advisory evidence from recon + memory |
| `/pickup target.com` | Continue previous hunt — shows what's untested |
| `/remember` | Save finding or pattern to persistent memory |
| `/intel target.com` | CVEs + disclosures cross-referenced with your hunt history |
| `/sync-check` | Check whether repo commands/agents/skills match the installed Claude runtime |
| `/memory-gc` | Report or rotate oversized hunt-memory JSONL files |

<br>

---

<br>

### Recon Toolkit (v4.3)

Thin wrappers over external tools. Each one is gated on tool presence — missing
tools are skipped, not fatal.

| Command | What It Does |
|:---|:---|
| `/secrets-hunt --js-bundle <dir>` | Hunt leaked credentials in source, JS bundles, or GitHub orgs |
| `/takeover --recon <dir>` | Subdomain takeover candidates from a recon run |
| `/cloud-recon --keyword <name>` | Public S3 / Azure / GCP buckets + CloudFlare-bypassed origin IP hints |
| `/param-discover <url>` | Hidden HTTP parameters via Arjun / x8 |
| `/bypass-403 <url>` | Header, method, and encoding tricks against a 403/401 |
| `/scan-cves <host>` | Focused nuclei CVE sweep + optional log4j-scan |
| `/arsenal [tool]` | Lists installed external tools or prints install hints |

<br>

---

<br>

## AI Agents

Specialized agents, each tuned for its role:

| Agent | What It Does | Model |
|:---|:---|:---|
| **autopilot** | Autonomous hunt loop with advisory guard telemetry | Prefer Sonnet -> current session fallback |
| **recon-agent** | Subdomain enum, live hosts, URL crawl, nuclei | Prefer Haiku *(fast)* → current session fallback |
| **recon-ranker** | AI review and prioritization of recon + memory evidence | Prefer Haiku *(fast)* -> current session fallback |
| **js-reader** | Reads cached JS materials into ranked attack-surface hypotheses | Prefer Sonnet -> current session fallback |
| **report-writer** | Professional reports, impact-first, human tone | Prefer Opus *(quality)* → current session fallback |
| **validator** | 7-Question Gate + 4-gate finding validation | Prefer Sonnet → current session fallback |
| **chain-builder** | Systematic A-B-C exploit chaining | Prefer Sonnet → current session fallback |
| **disclosed-researcher** | Disclosed-report pattern research and hypothesis seeds | Prefer Sonnet -> current session fallback |
| **credential-hunter** | Credential-prep stages; prepares controlled spray decisions | Prefer Sonnet -> current session fallback |
| **web3-auditor** | 10-class contract audit + Foundry PoC stubs | Prefer Sonnet -> current session fallback |
| **token-auditor** | Meme/token contract and launch-risk review | Prefer Sonnet -> current session fallback |

Agent frontmatter now uses `model: inherit` instead of hard versioned model
IDs. Claude Code follows the current session model, while the table above
documents the preferred model class for each role.

<br>

---

<br>

## What's New

> **The "brain in a jar" is now a bionic hacker.**

### v4.4.1 — JSON-Inject Probe Dispatcher Wiring (May 2026)

- **`run_json_inject_probe` is now AI-callable.** 4-hook ToolDispatcher
  integration — registered tool spec, `_OPTIONAL_TOOL_FUNCS` mapping,
  `_FINISH_FLOOR_PROGRESS_TOOLS` membership, and dispatch branch with type
  coercion. The LLM can fire surgical POST-JSON probes (SQLi auth-bypass,
  SQLi error, SQLi time, SSTI, cmd-injection, open redirect, path
  traversal, XSS) directly on endpoints it judges relevant, instead of
  fanning out across the full surface like a brute scanner.
- **Auto-discovery.** Wrapper picks up
  `recon/<target>/browser/xhr_endpoints.txt` and
  `findings/<target>/js_intel/hypotheses.json` automatically; explicit
  caller overrides win.
- **Chain hints lose the severity gate.** Many high-leverage chains start
  at info-level (S3 listable, GraphQL introspection, JWT alg=none). Regex
  specificity, not severity, discriminates noise — info + no pattern
  match still returns empty.
- **Vision auto adds `spa_app_signal`.** SPA root paths like Juice Shop
  "/" that bootstrap login modals via JS now trigger, with Angular CLI
  `ng build` bundle fingerprints (`main-es2015`, `runtime-es`,
  `polyfills-es*`, …) recognised.
- **Tests.** 17 new dispatcher contract tests; full suite **1462 / 1462
  pass in ~11 s**.

### v4.4.0 — Phase 5 Wire-up + Chain Hints (May 2026)

- **Auto chain-hint injection.** Every Medium+ finding is matched against 15
  exploit-chain patterns (IDOR, auth bypass, stored XSS, SSRF, open redirect,
  S3 listing, GraphQL introspection, prompt injection, LFI, subdomain
  takeover, JWT, file upload, webhook/callback, SQLi, DOM XSS / prototype
  pollution). A matching hint lands in `working_memory` automatically, so the
  LLM is reminded of the next attack class without re-reading the table.
- **Semantic loop detector.** `LoopDetector` collapses
  `/api/users/1`, `/api/users/9999` → `/api/users/{id}` and hashes responses
  with timestamps / UUIDs / hex / request IDs scrubbed. Three same-family
  same-hash requests, or five same-hash anywhere, fire a rotation hint so
  the agent stops spinning on dead lanes.
- **Vision auto-trigger.** Multi-signal SPA / login / dashboard heuristic
  decides when to fire playwright screenshots, with explicit kills for
  static assets.
- **Output cap & bootstrap persistence.** 50KB UTF-8 safe truncation on
  tool observations; `bootstrap_context` and `bootstrap_state` now survive
  `save()` / `load()` instead of being lost on session reload.
- **Validation calibration.** `tools/validate.py --result` maps confirmed /
  rejected / partial / informational outcomes into
  `pattern_calibration.jsonl`, feeding the deprioritisation logic for
  patterns that consistently false-positive.
- **Test suite 1426 / 1426 in ~12 s.** Phase 5 added 30 loop-detector tests
  + 33 chain-hint tests + output-cap, bootstrap, vision-auto, validate-mapping
  coverage.

### v4.3.0 — Auth Sessions + Recon Arsenal (May 2026)

- **Auth-aware hunting.** Set a session once (`--cookie`, `--bearer`, env vars,
  or `.private/target.json`) and every downstream tool that takes auth —
  `httpx`, `katana`, `ffuf`, `nuclei`, `dalfox`, plus the SQLi/SSTI/upload PoC
  probes — carries it. Most paying bugs (IDOR, BOLA, mass assignment, SSRF
  behind a login) only exist after login; the default pipeline used to miss
  them. See [`docs/auth-sessions.md`](docs/auth-sessions.md).
- **7 new commands.** `/secrets-hunt`, `/takeover`,
  `/cloud-recon`, `/param-discover`, `/bypass-403`, `/scan-cves`, and
  `/arsenal`.
- **External tool registry.** `tools/external_arsenal.sh` is the single source
  of truth for optional external-tool install hints and `_have <tool>` checks.
- **Recon pipeline.** `recon_engine.sh` can add an optional nuclei phase when
  the tool is present.
- **Methodology cheatsheet.** `skills/security-arsenal/METHODOLOGY_CHEATSHEET.md`
  distills quick-check tables from HowToHunt, HolyTips, AllAboutBugBounty, and
  KingOfBugBountyTips.

<details>
<summary><b>Autonomous Hunt Loop</b> — <code>/autopilot</code></summary>
<br>

7-step loop that runs continuously: **scope - recon - rank - hunt - validate - report - checkpoint**

Three checkpoint modes:
- `--paranoid` — still auto-selects the next branch; checkpoints after meaningful findings or strong partial signals
- `--normal` — batches findings, checkpoints every few minutes
- `--yolo` — minimal stops (still requires approval for report submissions)

Built-in telemetry: circuit breaker state, per-host pacing hints, and every request logged to `audit.jsonl`.

Those helper controls stay in **advisory audit/replay** behavior for the supplied target set: requests are still logged, and helper state is recorded for reproducibility.

</details>

<details>
<summary><b>Persistent Hunt Memory</b> — remember everything</summary>
<br>

- **Journal** — append-only JSONL log of every hunt action (concurrent-safe writes)
- **Pattern DB** — what technique worked on which tech stack, sorted by payout
- **Target profiles** — tested/untested endpoints, tech stack, findings
- **Cross-target learning** — patterns from target A suggested when hunting target B

</details>

<details>
<summary><b>MCP Integrations</b> — Burp + Caido + HackerOne</summary>
<br>

**Burp Suite MCP** — Claude can read your proxy history, replay requests through Burp, use Collaborator payloads. Your AI copilot now sees the same traffic you do.

**Caido MCP** — Claude can read Caido proxy history, replay requests, and use captured traffic as testing context.

For Claude Code CLI browser-state work, prefer chrome-devtools MCP for live browser/network evidence and playwright MCP for automated interaction/snapshots. Use `tools/browser_evidence.py` / `playwright-cli` only as an unavailable-MCP or scriptable fallback; Burp/Caido remain auxiliary proxy-history and replay sources, while bulk recon stays on the recon pipeline.

**HackerOne MCP** — Public API integration:
- `search_disclosed_reports` — search Hacktivity by keyword or program
- `get_program_stats` — bounty ranges, response times, resolved counts
- `get_program_policy` — optional policy context such as scope, exclusions, and notes

</details>

<details>
<summary><b>On-Demand Intel</b> — <code>/intel</code></summary>
<br>

Wraps `learn.py` + HackerOne MCP + hunt memory:
- Flags **untested CVEs** matching the target's tech stack
- Shows **new endpoints** not in your tested list
- Surfaces **cross-target patterns** from your own hunt history
- Prioritizes: CRITICAL untested > HIGH untested > already tested

</details>

<details>
<summary><b>Deterministic Target Matching</b></summary>
<br>

`scope_checker.py` uses anchored suffix matching — code check, not LLM judgment:
- `*.target.com` matches `api.target.com` but NOT `evil-target.com`
- Excluded domains always win over wildcards
- Exact IPs and CIDR ranges match when explicitly configured
- Optional filtering stays available for bookkeeping or custom workflows

</details>

<br>

---

<br>

## Vulnerability Coverage

<details>
<summary><b>20 Web2 Bug Classes</b> — click to expand</summary>
<br>

| Class | Key Techniques | Typical Payout |
|:---|:---|:---|
| **IDOR** | Object-level, field-level, GraphQL node(), UUID enum, method swap | $500 - $5K |
| **Auth Bypass** | Missing middleware, client-side checks, BFLA | $1K - $10K |
| **XSS** | Reflected, stored, DOM, postMessage, CSP bypass, mXSS | $500 - $5K |
| **SSRF** | Redirect chain, DNS rebinding, cloud metadata, 11 IP bypasses | $1K - $15K |
| **Business Logic** | Workflow bypass, negative quantity, price manipulation | $500 - $10K |
| **Race Conditions** | TOCTOU, coupon reuse, limit overrun, double spend | $500 - $5K |
| **SQLi** | Error-based, blind, time-based, ORM bypass, WAF bypass | $1K - $15K |
| **OAuth/OIDC** | Missing PKCE, state bypass, 11 redirect_uri bypasses | $500 - $5K |
| **File Upload** | Extension bypass, MIME confusion, polyglots, 10 bypasses | $500 - $5K |
| **GraphQL** | Introspection, node() IDOR, batching bypass, mutation auth | $1K - $10K |
| **LLM/AI** | Prompt injection, chatbot IDOR, ASI01-ASI10 framework | $500 - $10K |
| **API Misconfig** | Mass assignment, JWT attacks, prototype pollution, CORS | $500 - $5K |
| **ATO** | Password reset poisoning, token leaks, 9 takeover paths | $1K - $20K |
| **SSTI** | Jinja2, Twig, Freemarker, ERB, Thymeleaf -> RCE | $2K - $10K |
| **Subdomain Takeover** | GitHub Pages, S3, Heroku, Netlify, Azure | $200 - $5K |
| **Cloud/Infra** | S3 listing, EC2 metadata, Firebase, K8s, Docker API | $500 - $20K |
| **HTTP Smuggling** | CL.TE, TE.CL, TE.TE, H2.CL request tunneling | $5K - $30K |
| **Cache Poisoning** | Unkeyed headers, parameter cloaking, web cache deception | $1K - $10K |
| **MFA Bypass** | No rate limit, OTP reuse, response manipulation, race | $1K - $10K |
| **SAML/SSO** | XSW, comment injection, signature stripping, XXE | $2K - $20K |

</details>

<details>
<summary><b>10 Web3 Bug Classes</b> — click to expand</summary>
<br>

| Class | Frequency | Typical Payout |
|:---|:---|:---|
| **Accounting Desync** | 28% of Criticals | $50K - $2M |
| **Access Control** | 19% of Criticals | $50K - $2M |
| **Incomplete Code Path** | 17% of Criticals | $50K - $2M |
| **Off-By-One** | 22% of Highs | $10K - $100K |
| **Oracle Manipulation** | 12% of reports | $100K - $2M |
| **ERC4626 Attacks** | Moderate | $50K - $500K |
| **Reentrancy** | Classic | $10K - $500K |
| **Flash Loan** | Moderate | $100K - $2M |
| **Signature Replay** | Moderate | $10K - $200K |
| **Proxy/Upgrade** | Moderate | $50K - $2M |

</details>

<br>

---

<br>

## Tools & Architecture

<details>
<summary><b>Core Pipeline</b> — <code>tools/</code></summary>
<br>

| Tool | What It Does |
|:---|:---|
| `hunt.py` | Master orchestrator — chains recon, scan, report |
| `recon_engine.sh` | Subdomain enum + DNS + live hosts + URL crawl |
| `cf_solver.py` | Optional manual Cloudflare challenge clearance helper; not auto-run |
| `learn.py` | CVE + disclosure intel from NVD, GitHub Advisory, HackerOne |
| `intel_engine.py` | Memory-aware intel wrapper (learn.py + HackerOne MCP + memory) |
| `validate.py` | 4-gate validation — target context, impact, dedup, CVSS |
| `report_generator.py` | H1/Bugcrowd/Intigriti report output |
| `scope_checker.py` | Deterministic target matching with anchored suffix matching |
| `cicd_scanner.sh` | GitHub Actions SAST — wraps [sisakulint](https://github.com/sisaku-security/sisakulint) remote scan (52 rules, 81.6% GHSA coverage) |
| `mindmap.py` | Prioritized attack mindmap generator |

</details>

<details>
<summary><b>Vulnerability Scanners</b> — <code>tools/</code></summary>
<br>

| Tool | Target |
|:---|:---|
| `h1_idor_scanner.py` | Object-level and field-level IDOR |
| `h1_mutation_idor.py` | GraphQL mutation IDOR |
| `h1_oauth_tester.py` | OAuth misconfigs (PKCE, state, redirect_uri) |
| `h1_race.py` | Race conditions (TOCTOU, limit overrun) |
| `zero_day_fuzzer.py` | Logic bugs, edge cases, access control |
| `cve_hunter.py` | Tech fingerprinting + known CVE matching |
| `vuln_scanner.sh` | Active candidate scanner: upload canaries, SQLi timing, dalfox/SSTI, MFA/SAML, nuclei |
| `hai_probe.py` | AI chatbot IDOR, prompt injection |
| `hai_payload_builder.py` | Prompt injection payload generator |

</details>

<details>
<summary><b>MCP Integrations</b> — <code>mcp/</code></summary>
<br>

| Server | Tools Provided |
|:---|:---|
| **Burp Suite** (`burp-mcp-client/`) | Read proxy history, replay requests, Collaborator payloads |
| **Caido** (`caido-mcp-client/`) | Read proxy history, replay requests, traffic/search context |
| **FofaMap MCP (FOFA + Shodan)** (`fofamap-client/`) | Optional external FOFA and Shodan asset-search tools through one MCP server |
| **JSHook MCP** (`jshook-client/`) | Optional runtime JavaScript hook evidence for SPA/client-side behavior |
| **HackerOne** (`hackerone-mcp/`) | `search_disclosed_reports`, `get_program_stats`, `get_program_policy` |

FofaMap MCP (FOFA + Shodan) and JSHook MCP are optional external Claude MCP
capabilities. They do **not** automatically integrate with `/recon`, `/surface`,
`/autopilot`, or `agent.py`. See `mcp/fofamap-client/README.md` and
`mcp/jshook-client/README.md` for setup.

</details>

<details>
<summary><b>Hunt Memory System</b> — <code>memory/</code></summary>
<br>

| Module | What It Does |
|:---|:---|
| `hunt_journal.py` | Append-only JSONL hunt log (concurrent-safe via `fcntl.flock`) |
| `pattern_db.py` | Cross-target pattern DB — matches by vuln class + tech stack |
| `audit_log.py` | Every outbound request logged + advisory per-host pacing/breaker telemetry |
| `schemas.py` | Schema validation for all entry types (versioned) |

</details>

<details>
<summary><b>Full Directory Structure</b> — click to expand</summary>
<br>

```
claude-bug-bounty/
├── skills/                     Skill domains and runtime protocol
├── commands/                   Command docs for all `/` slash commands
├── agents/                     Specialized Claude CLI agents
├── tools/                      Python/shell tool implementations
├── memory/                     Persistent hunt memory system
├── mcp/                        MCP server integrations
│   ├── burp-mcp-client/        Burp Suite proxy
│   ├── caido-mcp-client/       Caido proxy
│   ├── fofamap-client/         External FofaMap MCP (FOFA + Shodan)
│   ├── jshook-client/          External JSHook MCP runtime JS hooks
│   └── hackerone-mcp/          HackerOne public API
├── tests/                      Regression tests
├── rules/                      Always-active hunting + reporting rules
├── hooks/                      Session start/stop hooks
├── docs/                       Payload arsenal + technique guides
├── web3/                       Smart contract skill chain
├── scripts/                    Maintained wrappers; campaign scripts are archived
├── archive/                    Historical campaign scripts and root clutter manifests
└── wordlists/                  5 wordlists
```

</details>

<br>

---

<br>

## Installation

### Prerequisites

```bash
# macOS
brew install go python3 node jq

# Linux (Debian/Ubuntu)
sudo apt install golang python3 nodejs jq
```

### Install

```bash
git clone https://github.com/shuvonsec/claude-bug-bounty.git
cd claude-bug-bounty
chmod +x install.sh && ./install.sh     # Install skills + commands into ~/.claude/
bash install_tools.sh                    # Install recon/scan tools + sisakulint
```

### API Keys

<details>
<summary><b>Chaos API</b> (required for recon)</summary>
<br>

1. Sign up at [chaos.projectdiscovery.io](https://chaos.projectdiscovery.io)
2. Export your key:

```bash
export CHAOS_API_KEY="your-key-here"
echo 'export CHAOS_API_KEY="your-key-here"' >> ~/.zshrc
```

</details>

<details>
<summary><b>Optional API keys</b> (better subdomain coverage)</summary>
<br>

Configure in `~/.config/subfinder/config.yaml`:
- [VirusTotal](https://www.virustotal.com) — free
- [SecurityTrails](https://securitytrails.com) — free tier
- [Censys](https://censys.io) — free tier
- [Shodan](https://shodan.io) — paid

</details>

<br>

---

<br>

## The Golden Rules

These are always active. Non-negotiable.

```
 1. USE TARGET SET DIRECTLY treat the supplied target set as the execution scope
 2. NO THEORETICAL BUGS    "Can attacker do this RIGHT NOW?" — if no, stop
 3. KILL WEAK FAST         Gate 0 is 30 seconds, saves hours
 4. KEEP NOTES ADVISORY    target notes guide pacing/replay, not execution bans
 5. 5-MINUTE RULE          nothing after 5 min = move on
 6. RECON ONLY AUTO        manual testing finds unique bugs
 7. IMPACT-FIRST           "worst thing if auth broken?" drives target selection
 8. SIBLING RULE           9 endpoints have auth? check the 10th
 9. A→B SIGNAL             confirming A means B exists nearby — hunt it
10. VALIDATE FIRST         7-Question Gate (15 min) before report (30 min)
```

<br>

---

<br>

## The Trilogy

| Repo | Purpose |
|:---|:---|
| **[claude-bug-bounty](https://github.com/shuvonsec/claude-bug-bounty)** | Full hunting pipeline — recon to report |
| **[web3-bug-bounty-hunting-ai-skills](https://github.com/shuvonsec/web3-bug-bounty-hunting-ai-skills)** | Smart contract security — 10 bug classes, Foundry PoCs |
| **[public-skills-builder](https://github.com/shuvonsec/public-skills-builder)** | Ingest 500+ writeups into Claude skill files |

<br>

---

<br>

## Contributing

PRs welcome. Best contributions:

- New vulnerability scanners or detection modules
- Payload additions to `skills/security-arsenal/SKILL.md`
- New agent definitions for specific platforms
- Real-world methodology improvements (with evidence from paid reports)
- Platform support (YesWeHack, Synack, HackenProof)

```bash
git checkout -b feature/your-contribution
git commit -m "Add: short description"
git push origin feature/your-contribution
```

<br>

---

<br>

<div align="center">

### Connect

[GitHub](https://github.com/shuvonsec) &nbsp;&nbsp;|&nbsp;&nbsp; [Twitter](https://x.com/shuvonsec) &nbsp;&nbsp;|&nbsp;&nbsp; [LinkedIn](https://linkedin.com/in/shuvonsec) &nbsp;&nbsp;|&nbsp;&nbsp; [Email](mailto:shuvonsec@gmail.com)

<br>

---

Use the current task's supplied target set as the active execution context.<br>
Keep evidence reproducible and review report output before sharing.

---

<br>

MIT License

**Built by bug hunters, for bug hunters.**

If this helped you find a bug, leave a star.

</div>
