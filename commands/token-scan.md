---
description: Select an evidence-backed token review path for EVM or Solana targets. Uses native source and chain-state analysis without a static risk verdict. Usage: /token-scan <contract_path_or_dir> [--chain solana]
---

# /token-scan

Review a supplied token/program using the complete
[Token method](../skills/src-hunter/modules/meme-coin-audit.md). It owns the
authority, accounting, liquidity and transfer branches, evidence and stop rules;
this command supplies source/chain context.

## Usage

```text
/token-scan CONTRACT_OR_DIRECTORY [--chain solana]
```

Provide chain/network, contract/program identity, source or bytecode revision when
available, authority and actor context, plus the permitted simulation boundary.
Keep unavailable source/revision information explicit. Preserve original source,
transaction and analysis artifacts.

## Handoff

Pure contract/program evidence remains analysis material; non-HTTP Store lifecycle
integration is deferred. Do not fabricate a URL for a token/program identity.
Use /validate only for an actual target-owned HTTP(S) Finding; the parent owns publication.

## Output

```text
TARGET: [contract/program identity]
CHAIN: [EVM / Solana]
HYPOTHESIS: [one boundary and expected learning]
EVIDENCE: [artifact refs and observed delta]
STATUS: [CONFIRMED / NEXT_ACTION / STOP]
ACTION: [one bounded next action; /validate only for an actual HTTP Finding]
```
