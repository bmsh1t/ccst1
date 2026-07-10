# Frequently Asked Questions

This FAQ is written for local Claude Code CLI usage. It focuses on command
entry points, Local / CTF / Lab target semantics, MCP proxy traffic, the memory
system, and common troubleshooting.

---

## Getting Started

### How do I use this project?

Start Claude Code from the project root:

```bash
cd /path/to/claude-bug-bounty
claude
```

Common primary flows:

```text
/recon target.com
/surface target.com
/hunt target.com
/validate
/report
```

To resume work on an older target:

```text
/pickup target.com
```

### Do I need to start from the project root?

Yes, that is recommended. The slash commands reference local `tools/`,
`memory/`, `commands/`, and optional `config.json`. If you launch Claude Code
from another directory, tool paths, output locations, or local config
resolution may drift from what the project expects.

### What is the difference between `/recon`, `/hunt`, and `/surface`?

- `/recon`: refreshes target recon caches and writes output to
  `recon/<target>/`.
- `/surface`: reads existing recon plus hunt memory and presents an AI Review
  Pool with advisory evidence hints; Claude chooses the priority and next lane.
  It does not actively exploit.
- `/hunt`: starts the active testing flow and chooses directions based on
  cached data, memory, and the current target context.

### Why are `/validate` and `/report` separate?

`/validate` is meant to eliminate weak findings, false positives, and claims
without demonstrated impact first. `/report` should draft output only from
validated evidence. This helps avoid turning a suspicious signal into a formal
report too early.

### In Claude Code CLI, how should I choose between browser tools, recon tools, and API replay?

The default priority is:

- For web navigation, authenticated browser state, SPA/XHR/GraphQL behavior,
  browser storage (`cookies`, `localStorage`, `sessionStorage`), and page
  interaction testing: prefer the installed `playwright-cli` skill.
- For bulk recon: keep using the `/recon` pipeline behind `httpx`, `katana`,
  `gau`, `waybackurls`, and similar tools. Do not use `playwright-cli` as the
  main bulk recon engine.
- For lightweight API replay: once a request is already narrowed down to a
  precise HTTP exchange that does not depend on browser state, use `curl`,
  `urllib`, or a local helper.
- Burp/Caido: use them as supporting sources for proxy history, replay, and
  traffic comparison. Missing Burp/Caido should not block browser-state
  validation.

This priority order also applies to Local / CTF / Lab targets. It only affects
how evidence is collected; it does not weaken the sandbox semantics of a
supplied target.

---

## Local / CTF / Lab Targets

### How are these targets handled now?

The project no longer depends on a separate mode toggle for this. As long as
the current command explicitly provides a target, execution treats that target
as the active target set:

- `localhost`, private IPs, IP/CIDR ranges, and host lists are valid inputs.
- External bounty scope text, public program policy, allowed-method notes, and
  `scope_snapshot.json` are optional context only.
- Helper state such as method risk, breaker state, cooldown, and rate-limit
  hints is still recorded for review.
- Request and audit state is still preserved for replay and post-run analysis.

### Are `/validate` and `/report` restrictions?

No. They are not execution restrictions. `/validate` and `/report` are only for
write-up quality and should not block ongoing recon or vulnerability hunting.
You should still record:

- The entry point and full request.
- The response or state transition.
- Reproduction steps.
- Impact notes.
- Preconditions and environment notes when relevant.

---

## Claude Code CLI Workflow

### When should I use `/autopilot`?

Use it when the target scope is already understood, baseline recon exists, and
you want systematic attack-surface coverage. For unfamiliar targets, start
with:

```text
/autopilot target.com --paranoid
```

For more familiar targets, you can use:

```text
/autopilot target.com --normal
```

Reports are still not submitted automatically; human approval is still
required.

### Can one Claude Code session test multiple targets?

Yes, but it is not recommended. Claude Code keeps conversational context, and
mixing multiple targets in one long session can cause payloads, assumptions,
and historical findings to bleed together. The safer pattern is one session per
target. If you must switch, run:

```text
/pickup new-target.com
```

### Will a new target inherit the previous target's skip/ignore settings?

It should not. The current project contract is:

- A new target only keeps the scanner's built-in XSS lane skip by default. If a
  run truly needs the XSS lane included, use `--scanner-full` explicitly.
- Skip/ignore directives, focus lanes, and excluded bug classes only apply when
  explicitly declared for the current target in the current Claude Code turn.
- `/pickup` reads target-level history and structured findings only. It does
  not turn temporary exclusions from a previous target into default policy.
- Temporary skips, external bounty exclusions, or competitiveness heuristics
  from the last target must not add extra skips to the current target.

### What if the session context gets too large?

Use Claude Code's built-in `/compact` command to compress conversation context.
Local recon, findings, reports, and hunt memory live on disk and do not depend
on the full chat transcript being preserved.

---

## MCP and Proxy Traffic

### Do I need Burp or Caido installed?

No. Without MCP, authenticated browser state, SPA/XHR/GraphQL flows, browser
storage, and page interaction testing should still go through the installed
`playwright-cli` skill first. Only lightweight stateless API replay should fall
back to `curl`, local scripts, or manually pasted requests and responses.

Once Burp or Caido MCP is configured, Claude Code can read proxy history,
replay requests, and use captured traffic as validation context.

### How do I configure Caido MCP?

See `mcp/caido-mcp-client/README.md`.

A common setup is:

```bash
export CAIDO_URL="http://127.0.0.1:8080"
export CAIDO_PAT="your-personal-access-token"
```

You can also use OAuth login:

```bash
CAIDO_URL=http://localhost:8080 caido-mcp-server login
```

### Will MCP responses leak credentials?

The Caido MCP server redacts `Authorization`, `Cookie`, `Set-Cookie`, and
common API key headers. Even so, for sensitive targets you should still inspect
proxy history manually first and avoid bringing unnecessary credentials,
personal data, or third-party data into model context.

---

## Local Memory and Output

### Where is hunt memory stored?

By default, it lives in the project or Claude Code local project context under
`hunt-memory/`. It is used to track:

- Tested endpoints.
- Request audit history.
- Target profiles.
- Validated findings.
- Reusable testing patterns.

### Where do recon, findings, and reports go?

Common directories:

```text
recon/<target>/
findings/<target>/
reports/<target>/
hunt-memory/
```

### How do I resume a previous target?

Use:

```text
/pickup target.com
```

It reads historical testing records, untested surface, and reusable patterns so
you can continue from the last state.

---

## Troubleshooting

### What if `/recon` produces no output or says tools are missing?

Install the tool dependencies first:

```bash
bash install_tools.sh
```

Then confirm that `subfinder`, `httpx`, `katana`, `nuclei`, and related tools
are available in `PATH`.

### What if `/surface` says there is no recon data?

Run:

```text
/recon target.com
```

`/surface` primarily reads cached data. It does not replace the recon flow.

### What if `/intel` says there is no tech stack?

Run `/recon` first so the tool can extract technologies from files such as
`recon/<target>/live/httpx_full.txt`. You can also provide the tech stack
explicitly, for example:

```bash
python3 tools/intel_engine.py --target target.com --tech nextjs,graphql
```

### What if Caido MCP shows no proxy history?

Browse the target through Caido first, confirm that request history appears in
Caido, then return to Claude Code and use `/hunt` or `/validate`.

### When should I run `/memory-gc`?

If JSONL files under `hunt-memory/` become large, or read/write performance
degrades after long automated runs, you can run:

```text
/memory-gc
```

If you want rotation:

```text
/memory-gc --rotate
```

---

## Reports and Evidence

### Will `/report` submit anything automatically?

No. `/report` only generates an editable draft. It does not submit anything to
any platform or system automatically.

### What is the difference between a CTF write-up and a real bug bounty report?

A CTF / Lab write-up can focus on the solution path, test inputs, key state
changes, and flag recovery process. A real authorized testing report should be
stricter about scope, business impact, affected users, remediation guidance,
and safe reproduction wording.

In either case, do not present unvalidated clues as confirmed vulnerabilities.
