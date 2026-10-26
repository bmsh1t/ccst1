# Token and Meme-Coin Decision Module

内部完整方法，按当前问题读取；不是独立原生 Skill，不自动启动执行或委派。
返回 [src-hunter 调查主干](../SKILL.md)；恢复/写回仍归 `skills/runtime-protocol.md`。

适用：Use only when a token, liquidity pool, or Solana program is explicitly in scope. Separates token identity, authority state, market/liquidity state, and holder impact to choose the next branch within the allowed simulation boundary; command and probe knowledge remains on demand, and a centralization note alone stops before promotion.

Separate token identity, authority state, market/liquidity state, and holder
impact. Select the next branch from source interfaces, recorded fixture state or observed chain data and the allowed
simulation boundary; concrete command and probe knowledge remains on demand.

## Direct Execution Contract

For real delegation, use the input/output and acceptance boundary in
`skills/src-hunter/SKILL.md#real-delegation-and-execution-handoff`. Return
contrary evidence and unknowns as well as results; propose global pivots to the
main session. Same-session reading requires no handoff form. Expert self-report
does not resolve Action or confirm Finding.

- Entry: Invoke only for an explicitly scoped token or program. Source review binds
  revision, simulated roles/state and the permitted local analysis/simulation boundary.
  Deployed-behavior claims additionally require chain/network, mint/contract,
  implementation and current authority/state evidence.
- Evidence: Before promotion, retain revision/local-fixture identity (and deployment when claimed), authority/role
  evidence, verified source or decoded instruction, clean transfer or read-only
  baseline, smallest controlled variant, and impact read-back. Scanner or
  branding signals are leads only.
- Stop: Stop the affected claim when revision or reproducible impact is unavailable;
  missing deployment/authority state blocks deployed-behavior claims, not source analysis.
  Stop when the result is only a centralization note or when a live
  trade or irreversible action would be required. Hand bounded candidates to
  `triage-validation`.

## Decision Tree

Branches are alternatives, not a required sequence. Choose the highest expected
information gain and lowest reversible cost; follow another evidence-supported
branch or stop when the invariant is preserved and no new question remains.

- Source revision is unknown -> resolve it before interpreting code. Record local
  roles/state assumptions for simulation; resolve mint/contract, deployment and current
  authority separately before making claims about a live token.
- EVM token -> inspect mint, transfer restrictions, fee controls, ownership,
  upgrade, and liquidity-consumer branches according to observed interfaces.
- Solana or Token-2022 program -> inspect mint/freeze/update/close authority,
  extensions, hooks, delegates, and instruction privilege boundaries.
- DEX, bonding curve, bridge, or aggregator integration is present -> follow the
  asset flow, slippage/price source, migration, callback, and settlement edge.
- A holder, caller, or pool can be denied, drained, diluted, or redirected in a
  repeatable bounded simulation -> hand the canonical state delta to validation;
  otherwise keep the result as a lead or informational risk.

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

Include transaction ordering, slippage, or actor-specific outcome when they affect
the selected boundary. Read the selected implementation, callers and guards with
native Read/Grep; select an upstream chain CLI/RPC only when current deployment
state is needed.

## Local Attention Clues

These are alternatives within the current question, not a required ordering or
a reason to exhaust every branch. Global priorities belong to the main session.

1. Retained mint/freeze/admin authority and upgrade or migration paths.
2. Transfer restrictions, fee changes, hidden supply, and holder-specific rules.
3. LP custody, bonding-curve settlement, oracle/price, callback, and slippage
   edges that can change recoverable value.
4. Token-2022 extensions and cross-program integrations with a concrete actor or
  asset boundary.
5. Branding, social, concentration, or generic centralization signals only as
   context, never as a confirmed finding.

## Phase Checkpoints

- Identity checkpoint: bind revision/local fixture, actor/authority assumptions and
  permitted value boundary; add address, chain and current deployment/state when claimed.
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
failed sell alone does not pass. A token age, liquidity amount, ownership label
or source name cannot determine impact. Keep uncertainty and source/version
references visible. Record `revision/fixture (plus chain/contract for deployed claims) -> invariant or trust boundary
-> baseline -> one changed condition -> observed state/value/authority delta
-> impact -> stop/reopen condition` and preserve original source, transaction and
analysis artifacts. `triage-validation` provides assessment methods.
A local fixture or fork proves only its recorded revision, configuration and state;
production exploitability requires matching deployment and state evidence.
Non-HTTP token/program evidence remains analysis material pending Store lifecycle
integration. Do not substitute a fictional HTTP identity for a program.
Use `/validate` only for an actual target-owned HTTP(S) Finding; the parent owns publication.

## Red Lines

Use read-only calls, simulations, test-owned wallets, and reversible fixtures.
Do not trade live funds, drain or freeze unrelated holders, publish irreversible
authority changes, or retain private keys. The model selects the branch and
existing deterministic tooling records the evidence.
Use the least-impact read-back that proves the claim; do not invoke state-changing
or value-moving actions merely to complete a checklist.
