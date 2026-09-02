---
description: Select an evidence-backed token review path for EVM or Solana targets. Uses token_scanner.py as an optional signal source and does not impose a fixed class order or risk verdict. Usage: /token-scan <contract_path_or_dir> [--chain solana]
---

# /token-scan

Review a token or program by selecting the most informative trust, authority,
accounting, liquidity, or transfer question from the supplied code and chain
context. `skills/meme-coin-audit/SKILL.md` owns the direct-only decision
contract; this command owns entry and optional scanner handoff.

## Usage

```text
/token-scan CONTRACT_OR_DIRECTORY [--chain solana]
```

Run `tools/token_scanner.py` only when its bounded static signal can answer a
current question. Scanner output is a lead with file/line provenance, not a
finding or a clean verdict.

## Decision Tree

Choose the branch with the highest expected information gain and lowest
reversible cost. Branches are alternatives, not a required sequence:

| Signal | Question to answer |
|---|---|
| Mint, supply, or balance authority | Can an unintended actor create or alter supply outside the intended invariant? |
| Transfer, blacklist, freeze, or hook behavior | Can a controller selectively prevent or redirect transfers? |
| Fee, tax, router, or receiver controls | Can mutable economics produce an unbounded or actor-specific outcome? |
| LP, pool, migration, or emergency withdrawal path | Can liquidity or reserves be moved by an unintended authority? |
| Bonding curve or graduation state | Can mutable parameters or transitions change value without the intended checks? |
| EVM proxy or Solana upgrade/authority state | Can implementation or mint/freeze/upgrade control change after deployment? |
| Renounce, delegate, or secondary admin signal | Does the public ownership state match the effective control path? |
| Rebase, swap, or transfer-order behavior | Can a bounded transaction change price, balances, or user outcomes unexpectedly? |

The list is non-exhaustive. Select another branch when target evidence supports
it, or stop when the invariant is preserved and no new evidence question remains.

## Evidence and Handoff

- Preserve chain, contract/program identity, source/version, authority context,
  and raw scanner or analysis artifacts.
- Use a test account/resource and the least-impact read-back needed to decide the
  hypothesis. Do not infer a rug vector from a name, age, liquidity amount, or
  regex match alone.
- Record one boundary, baseline, changed condition, observed delta, impact, and
  stop/reopen condition. Route a confirmed candidate through the existing
  validation/report lifecycle.

## Output

```text
TARGET: [contract/program identity]
CHAIN: [EVM / Solana]
HYPOTHESIS: [one boundary and expected learning]
EVIDENCE: [artifact refs and observed delta]
STATUS: [CONFIRMED / NEXT_ACTION / STOP]
ACTION: [one bounded next action or /validate]
```
