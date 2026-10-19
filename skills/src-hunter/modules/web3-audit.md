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
- Evidence: Before promotion, retain source/bytecode and revision hash, affected
  function and caller privilege, invariant or state delta, baseline simulation,
  and a reproducible local-fork or on-chain read-back. Static patterns and TVL
  are leads only.
- Stop: Stop on source, revision, chain, scope, or reproducibility mismatch; on
  a hard economic kill; or when impact cannot be bounded. Hand reproducible
  candidates to `triage-validation`; never move live value outside scope.

## Decision Tree

- Source or bytecode identity is missing -> resolve the deployment/revision
  first; do not mix verified source with another implementation.
- Privileged roles, upgrade paths, or initialization are present -> compare all
  sibling entry points and authority transitions, then follow the highest-value
  state or asset boundary.
- Accounting, vault, token, or settlement state is present -> map the invariant
  across every create/update/withdraw/claim path and test the smallest controlled
  state differential.
- External price, oracle, bridge, callback, or flash-liquidity dependency is
  present -> verify freshness, source independence, bounds, and the downstream
  value decision before considering manipulation impact.
- Signed messages, permits, or cross-chain messages are present -> compare
  domain, nonce, chain, contract, actor, and replay scope.
- A candidate changes caller authority, protected state, or recoverable value in
  a reproducible boundary -> hand it to validation; otherwise keep the signal
  as an invariant gap or informational note.

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
- Handoff checkpoint: preserve the minimal reproduction, gas/value context,
  cleanup status, and unresolved proof question.

## Evidence Gate and Handoff

The minimum proof is `identified revision -> controlled caller/state -> concrete
invariant or authority differential -> bounded value/permission impact ->
repeatable read-back`. TVL, a privileged function name, a regex hit, or a failed
transaction alone does not pass. Use the existing source/fork/subprocess
boundary. `triage-validation` provides assessment methods; non-HTTP contract
evidence is not yet integrated with the Store validation/report lifecycle.
Preserve analysis artifacts without substituting a fictional HTTP identity.

## Red Lines

Prefer read-only calls, simulations, test-owned accounts, and local forks. Do
not transfer live funds, alter production governance, publish a transaction, or
retain credentials outside the declared boundary. The model chooses the
hypothesis; deterministic tooling records the evidence.
