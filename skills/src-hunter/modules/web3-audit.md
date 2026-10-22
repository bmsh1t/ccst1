# Web3 Audit Decision Module

内部完整方法，按当前问题读取；不是独立原生 Skill，不自动启动执行或委派。
返回 [src-hunter 调查主干](../SKILL.md)；恢复/写回仍归 `skills/runtime-protocol.md`。

适用：Use only when a Solidity, Rust, wallet, or smart-contract target is explicitly in scope. Treats source, bytecode, chain state, and value movement as separate evidence planes and chooses the invariant, authority, oracle, signature, or upgrade branch from the contract's actual interfaces; execution detail stays on demand, and static patterns or TVL are leads, never findings.

Treat source, bytecode, chain state, and value movement as separate evidence
planes. Choose the next branch from the contract's actual interfaces and
invariants rather than following a fixed bug checklist.

## Direct Execution Contract

For real delegation, use the input/output and acceptance boundary in
`skills/src-hunter/SKILL.md#real-delegation-and-execution-handoff`. Return
contrary evidence and unknowns as well as results; propose global pivots to the
main session. Same-session reading requires no handoff form. Expert self-report
does not resolve Action or confirm Finding.

- Entry: Invoke only for an explicitly scoped contract or program. Require
  chain/network, deployment identity, source or bytecode revision, and the
  permitted read-only, fork, simulation, or transaction boundary.
  Establish deployment/upgrade control, relevant actors and protocol value at
  risk. These facts affect ROI and evidence depth; they are not universal skip thresholds.
- Evidence: Before promotion, retain source/bytecode and revision hash, affected
  function and caller privilege, invariant or state delta, baseline simulation,
  and a reproducible local-fork or on-chain read-back. Static patterns and TVL
  are leads only.
- Stop: Stop on source, revision, chain, scope, or reproducibility mismatch; on
  a hard economic kill; or when impact cannot be bounded. Hand reproducible
  candidates to `triage-validation`; never move live value outside scope.

## Decision Tree

The classes are unordered and non-exhaustive. Select the invariant or trust
boundary that answers the current question; inspect siblings, callers and
downstream consumers when current evidence points there. Choose the branch with
the clearest expected learning and lowest reversible cost.

- Source or bytecode identity is missing -> resolve the deployment/revision
  first; do not mix verified source with another implementation.
- Bridge or cross-chain dependency -> follow source independence, bounds,
  message/actor binding and the downstream value or authority decision.
- A candidate changes caller authority, protected state, or recoverable value in
  a reproducible boundary -> hand it to validation; otherwise keep the signal
  as an invariant gap or informational note.

### Accounting Desync
Compare balance, share, debt, reward, and supply invariants across all relevant
state transitions and early/partial paths. Map create/update/withdraw/claim and
settlement behavior, then test the smallest controlled state differential.

### Access Control
Compare role, modifier, initializer, proxy, and sibling-function boundaries for
the actor that can actually reach the call. Follow authority transitions to the
highest-value state or asset boundary.

### Incomplete Code Path
Compare paired lifecycle operations and refunds, including failure, partial,
cancel, and retry states. Every create/deposit path needs its intended
reverse/refund behavior.

### Off-By-One
Exercise equality, empty, first, last, deadline, epoch, and rounding boundaries
only where the code or state model makes them relevant. Include index/loop
boundaries and the final element.

### Oracle / Price Manipulation
Trace freshness, confidence, source, window, decimal, and fallback assumptions
to the value or authorization decision they influence. Follow oracle, reserve,
TWAP and price-feed inputs through their downstream consumers.
Verify source independence and bounds before considering manipulation impact.

### ERC4626 Vaults
Check conversion, donation, transfer, preview, and first-depositor invariants
against the implementation's actual asset/share model.

### Reentrancy
Trace external calls, callbacks, and state ordering across the reachable call
graph; prove a controlled state or value delta before claiming impact. Include
token-transfer and sibling-function callback paths.

### Flash Loan
Determine whether a same-transaction price or liquidity assumption can change a
protected outcome, and require a bounded state/value differential.

### Signature Replay
Trace nonce, domain, chain, contract, expiry, and message binding across sign and
consume paths. Include permits and cross-chain messages, checking actor binding
and replay scope.

### Proxy / Upgrade
Trace implementation ownership, initialization, delegatecall, storage layout,
upgrade authorization, and version transition behavior.

## Local Attention Clues

These are alternatives within the current question, not a required ordering or
a reason to exhaust every branch. Global priorities belong to the main session.

1. Upgrade/initialization and admin paths controlling high-value deployments.
2. Accounting and authorization invariants on deposits, withdrawals, claims,
   settlements, and token transfers.
3. Oracle, bridge, callback, and signature-domain edges that can change value.
4. Cross-function and sibling-path inconsistencies with a clear state delta.
5. Style, centralization or static lint evidence when it changes the current invariant question.

## Phase Checkpoints

- Identity checkpoint: bind chain, deployment, implementation, revision, and
  value boundary before reading behavior.
- Invariant checkpoint: name the expected invariant, actor, state variables, and
  read-back that would falsify it.
- Pivot checkpoint: after a bounded branch yields no state or authority delta,
  switch to the next independent invariant or stop; do not broaden live actions.
  Stop when the invariant is disproven, evidence is insufficient, or the claim
  is proven; preserve the next action and concrete reopen condition.
- Handoff checkpoint: preserve the minimal reproduction, gas/value context,
  cleanup status, and unresolved proof question.

## Evidence Gate and Handoff

The minimum proof is `identified revision -> controlled caller/state -> concrete
invariant or authority differential -> bounded value/permission impact ->
repeatable read-back`. TVL, a privileged function name, a regex hit, or a failed
transaction alone does not pass or determine severity. Choose existing local
analysis, chain tooling or a Foundry PoC only when the selected hypothesis needs it.
Record `target/version -> invariant or boundary -> baseline -> one changed condition
-> observed state/value/authorization delta -> impact -> stop/reopen condition`.
Use the existing source/fork/subprocess
boundary. `triage-validation` provides assessment methods; non-HTTP contract
evidence is not yet integrated with the Store validation/report lifecycle.
Preserve analysis artifacts without substituting a fictional HTTP identity.
Use `/validate` only for an actual target-owned HTTP(S) Finding. Report-writing
methods remain available for analysis documents without claiming Store registration.

## Red Lines

Prefer read-only calls, simulations, test-owned accounts, and local forks. Do
not transfer live funds, alter production governance, publish a transaction, or
retain credentials outside the declared boundary. The model chooses the
hypothesis; deterministic tooling records the evidence.
