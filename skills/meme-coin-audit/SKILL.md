---
name: meme-coin-audit
description: Decision skill for explicitly scoped token, liquidity-pool, and Solana program reviews. Chooses authority, transfer, liquidity, and integration branches without embedding probe syntax.
---

# Token and Meme-Coin Decision Skill

Separate token identity, authority state, market/liquidity state, and holder
impact. Select the next branch from observed chain data and the allowed
simulation boundary; concrete command and probe knowledge remains on demand.

## Direct Execution Contract

- Entry: Invoke only for an explicitly scoped token or program. Require chain
  and network, mint/contract identity, source or bytecode revision when
  available, and a read-only, simulation, or transaction boundary.
- Evidence: Before promotion, retain address and revision, authority/role
  evidence, verified source or decoded instruction, clean transfer or read-only
  baseline, smallest controlled variant, and impact read-back. Scanner or
  branding signals are leads only.
- Stop: Stop when token/network identity, authority data, or reproducible impact
  is unavailable; when the result is only a centralization note; or when a live
  trade or irreversible action would be required. Hand bounded candidates to
  `triage-validation`.

## Decision Tree

- Identity or chain state is unknown -> resolve the mint/contract, deployment,
  program revision, and current authority set before interpreting code.
- EVM token -> inspect mint, transfer restrictions, fee controls, ownership,
  upgrade, and liquidity-consumer branches according to observed interfaces.
- Solana or Token-2022 program -> inspect mint/freeze/update/close authority,
  extensions, hooks, delegates, and instruction privilege boundaries.
- DEX, bonding curve, bridge, or aggregator integration is present -> follow the
  asset flow, slippage/price source, migration, callback, and settlement edge.
- A holder, caller, or pool can be denied, drained, diluted, or redirected in a
  repeatable bounded simulation -> hand the canonical state delta to validation;
  otherwise keep the result as a lead or informational risk.

## ROI Priorities

1. Retained mint/freeze/admin authority and upgrade or migration paths.
2. Transfer restrictions, fee changes, hidden supply, and holder-specific rules.
3. LP custody, bonding-curve settlement, oracle/price, callback, and slippage
   edges that can change recoverable value.
4. Token-2022 extensions and cross-program integrations with a concrete actor or
  asset boundary.
5. Branding, social, concentration, or generic centralization signals only as
   context, never as a confirmed finding.

## Phase Checkpoints

- Identity checkpoint: bind address, chain, deployment/revision, authority set,
  and permitted value boundary.
- Baseline checkpoint: capture a clean read or test-owned transfer/simulation,
  including actor, amount, pool, and resulting state.
- Pivot checkpoint: after a bounded branch yields no authority, asset, or holder
  differential, switch to the next ROI branch or stop.
- Handoff checkpoint: preserve the exact state delta, actor/asset scope, replay
  context, and cleanup status.

## Evidence Gate and Handoff

The minimum proof is `identified token/program -> authority or source evidence ->
controlled baseline -> bounded variant -> holder/pool/permission state change ->
repeatable read-back`. A scanner hit, retained authority name, low liquidity, or
failed sell alone does not pass. Route complete evidence to
`triage-validation`.

## Red Lines

Use read-only calls, simulations, test-owned wallets, and reversible fixtures.
Do not trade live funds, drain or freeze unrelated holders, publish irreversible
authority changes, or retain private keys. The model selects the branch and
existing deterministic tooling records the evidence.
