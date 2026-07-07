# External Reference Library

## Local on-demand references

These files are part of this skill and should be loaded only when the active
evidence needs them. They keep detailed tables out of broad coordinator skills.

| Local file | Use it for |
|---|---|
| `references/bypass-patterns.md` | SSRF URL/IP parser bypasses, open redirect parser tricks, upload validation bypasses, magic bytes, SQLi/WAF normalization shapes |
| `references/sink-and-grep-patterns.md` | DOM sources/sinks and language-specific grep patterns for source or bundle review |
| `references/recon-tool-usage.md` | Recon pipeline, ffuf, Semgrep, cloud/storage discovery, API endpoint discovery, target metadata retrieval command shapes |
| `references/payload-families.md` | SSTI, command injection, XXE, and request-smuggling probe families with evidence gates and stop conditions |

---

When the in-tool methodology runs short, these upstream collections are the
ones to mirror or grep next. They are pulled from the project owner's
GitHub stars list — high-signal repos curated by working bounty hunters.

## Project Web deep-delta references

The current project is the canonical source for Web2 methodology and payload
basics. When current evidence needs deeper detail, load the distilled project
assets below instead of raw external notes or local absolute paths.

| Project path | Use it for |
|---|---|
| `rules/playbook-router.md` | Evidence-shaped router from Web signal → project card/playbook/tool |
| `knowledge/cards/auth-sso-token-edge-cases.md` | JWT/JWE/JWKS, OAuth/OIDC/SAML, account-linking, MFA/step-up token boundaries |
| `knowledge/cards/sqli-hidden-surfaces.md` | Hidden SQLi inputs, second-order SQLi, auth-token connector fields |
| `knowledge/cards/ssrf-url-fetch.md` | URL fetch entry validation and parser/fetcher discrepancy questions |
| `knowledge/cards/ssrf-internal-impact.md` | Low-impact SSRF internal reachability and impact proof |
| `knowledge/cards/render-pipeline-ssrf.md` | PDF/image/HTML/render/export pipeline SSRF and file-read pivots |
| `knowledge/cards/upload-parser.md` | Upload/import/archive/parser differentials and processing chains |
| `knowledge/cards/upload-to-execution.md` | Upload-to-execution as controlled impact proof |
| `knowledge/cards/controlled-rce-impact.md` | RCE/command/SSTI/deser impact proof, red-line and cleanup model |
| `knowledge/cards/node-prototype-pollution.md` | Node/prototype source → property → gadget → sink chains |
| `knowledge/cards/web-llm-tool-chains.md` | Web LLM/RAG/agent tool-use boundary testing |

Raw external CTF categories, writeups, flag paths, DoS/ReDoS, broad payload
dictionaries, and local absolute reference paths are excluded from the default
Claude CLI attention chain. External material is first audited and distilled
into the project assets above.

## Methodology / playbooks

| Repo | Use it for |
|---|---|
| `KathanP19/HowToHunt` | Per-vuln-class methodology checklists (IDOR, race, SSRF, OAuth, GraphQL, business logic) |
| `HolyBugx/HolyTips` | Notes + writeups + per-class checklists |
| `daffainfo/AllAboutBugBounty` | Big bypass + payload reference, organised by class |
| `KingOfBugbounty/KingOfBugBountyTips` | One-line recon recipes from named hunters |
| `dwisiswant0/awesome-oneliner-bugbounty` | Bash/awk one-liners for rapid recon and triage |
| `nahamsec/Resources-for-Beginner-Bug-Bounty-Hunters` | Broad starter library |
| `OWASP/wstg` | OWASP Web Security Testing Guide — definitive coverage matrix |
| `0xRadi/OWASP-Web-Checklist` | Compressed WSTG checklist for tracking coverage during a hunt |
| `aufzayed/HowToHunt`, `sehno/Bug-bounty` | Additional case studies |

## Disclosed reports & writeups

| Repo | Use it for |
|---|---|
| `devanshbatham/Awesome-Bugbounty-Writeups` | Categorised writeups by vuln class |
| `ngalongc/bug-bounty-reference` | Same idea, older but exhaustive |
| `B3nac/Android-Reports-and-Resources` | Big list of Android H1 disclosures |
| `arkadiyt/bounty-targets-data` | Hourly dump of public target metadata (H1/Bugcrowd/Intigriti/YWH/Immunefi) |

## Tool catalogues

| Repo | Use it for |
|---|---|
| `vavkamil/awesome-bugbounty-tools` | Curated tool list, broader than this plugin |
| `hahwul/WebHackersWeapons` | Same, with maturity tags |
| `edoardottt/awesome-hacker-search-engines` | Shodan/Censys/etc. alternatives |
| `qazbnm456/awesome-web-security` | Long-form learning resources |
| `arainho/awesome-api-security` | API-specific tools and references |
| `4ndersonLin/awesome-cloud-security` | Cloud-specific tools and references |
| `wong2/awesome-mcp-servers` | MCP server registry — additional servers to wire in |
| `awesome-android-root/awesome-android-root` | Android tooling |

## Dorking / OSINT

| Repo | Use it for |
|---|---|
| `cipher387/Dorks-collections-list` | Master index of dork collections |
| `sushiwushi/bug-bounty-dorks` | Dorks for sites with disclosure programs |
| `techgaun/github-dorks` | Find leaked secrets via GitHub search |
| `obheda12/GitDorker` | Automated GitHub dork scraper |
| `streaak/keyhacks` | How to **verify** every leaked key class (this is the hard part) |

## Subdomain takeover

| Repo | Use it for |
|---|---|
| `EdOverflow/can-i-take-over-xyz` | Authoritative fingerprint + claim-instructions list |
| `punk-security/dnsReaper` | Best-in-class scanner (already wrapped in `tools/takeover_scanner.sh`) |
| `vincentcox/bypass-firewalls-by-DNS-history` | DNS-history origin-IP lookup |
| `m0rtem/CloudFail` | CloudFlare-specific origin discovery |
| `spyboy-productions/CloakQuest3r` | CloudFlare/Sucuri origin IP exposure |

## API key verification

When you find a leaked secret you must prove it works. `streaak/keyhacks` shows
the right curl-one-liner per provider (AWS / Stripe / Slack / Twilio / ...).

## AI / agentic-security skills (cross-pollination)

| Repo | Idea worth borrowing |
|---|---|
| `mukul975/Anthropic-Cybersecurity-Skills` | 754 cybersecurity skills mapped to MITRE ATT&CK / NIST CSF |
| `SnailSploit/Claude-Red` | Curated offensive-security skills for the Claude skills system |
| `0xSteph/pentest-ai-agents` | Specialised Claude Code agents for offsec research |
| `BehiSecc/bugSkills` | Tooling to convert disclosed reports into reusable skills |
| `pikpikcu/airecon` | Self-hosted LLM + tool-router pattern for autonomous recon |
| `Armur-Ai/Pentest-Swarm-AI` | Swarm-of-agents pattern for full-pipeline pentest |
| `BugTraceAI/reconftw-mcp` | reconftw exposed as an MCP server |
| `naebo/mcp-external-recon-server` | External-recon MCP server |
| `ente0/mcpstrike` | Pentest tool MCP server + Ollama autonomous client |
