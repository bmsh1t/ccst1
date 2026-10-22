---
description: Select an evidence-backed smart-contract review path for EVM or Solana targets. Uses the existing Web3 Skill and deterministic tools without a fixed class order or payload catalog. Usage: /web3-audit <contract-or-repo>
---

# /web3-audit

Review a supplied contract or repository using the complete
[Web3 method](../skills/src-hunter/modules/web3-audit.md). It owns invariant
branches, preflight, evidence and stop/reopen rules; this command owns entry
and artifact handoff.

## Usage

```text
/web3-audit CONTRACT_OR_REPO
```

Provide source/deployment identity, chain/network, revision, actors and the
permitted simulation or transaction boundary. Select the current question from
that evidence and preserve original analysis artifacts.

## Handoff

Pure contract/program evidence remains analysis material; non-HTTP Store lifecycle
integration is deferred. Do not fabricate an HTTP URL for a contract identity.
Use /validate only for an actual target-owned HTTP(S) Finding. Report-writing
methods remain available for an analysis document without Store registration.

## Output

```text
TARGET: [contract/repository identity]
HYPOTHESIS: [one boundary and expected learning]
EVIDENCE: [artifact refs, observed delta, and source locations]
STATUS: [CONFIRMED / NEXT_ACTION / STOP]
ACTION: [one bounded next action; /validate only for an actual HTTP Finding]
```
