---
description: Select an evidence-backed smart-contract review path for EVM or Solana targets. Uses the existing Web3 Skill and deterministic tools without a fixed class order or payload catalog. Usage: /web3-audit <contract-or-repo>
---

# /web3-audit

Review a supplied contract or repository by selecting the highest-value
evidence question for the observed protocol, trust boundary, and deployment
context.

## Usage

```text
/web3-audit CONTRACT_OR_REPO
```

`skills/web3-audit/SKILL.md` owns the direct-only decision contract. This command
owns entry and artifact handoff; it does not duplicate its phase gates or create
a second audit state.

## Decision Tree

Select one or more branches from current code, deployment, and protocol evidence.
The list is unordered and non-exhaustive:

| Signal | Question to answer |
|---|---|
| Balance, share, debt, or reward accounting | Do all state transitions preserve the same invariant? |
| Role, modifier, initializer, or proxy boundary | Can an unintended actor reach a protected function or implementation? |
| Paired lifecycle functions | Does every create/deposit path have a complete reverse/refund path? |
| Deadline, epoch, index, or loop boundary | Does equality, empty state, or final element produce an unintended result? |
| Oracle, reserve, TWAP, or price feed | Can stale, low-confidence, or manipulable data change value or authorization? |
| ERC4626 conversion/transfer | Are share/asset conversions and first-depositor boundaries consistent? |
| External call or token transfer | Is the state transition safe across reentrancy and callback boundaries? |
| Signature, nonce, domain, or replay evidence | Is authorization bound to the intended chain, contract, and message instance? |
| Upgrade or delegatecall evidence | Is implementation ownership and storage compatibility enforced? |

Choose the branch with the clearest expected learning and lowest reversible cost.
Do not skip a high-value branch solely because another class is earlier in a
table, and do not infer a finding from a pattern match alone.

## Evidence and Handoff

- Preserve source/deployment identity, version, actor, and raw analysis artifacts.
- Use existing local analysis, chain tooling, or Foundry only when the selected
  hypothesis needs it; choose the concrete test from the observed code.
- Stop when the invariant is disproven, evidence is insufficient, or the claim
  is proven. Record the next action/reopen condition through canonical owners.
- Send confirmed candidates through `/validate` and the report-only
  `skills/report-writing/SKILL.md`; do not treat a static scanner score as a
  validated finding.

## Output

```text
TARGET: [contract/repository identity]
HYPOTHESIS: [one boundary and expected learning]
EVIDENCE: [artifact refs, observed delta, and source locations]
STATUS: [CONFIRMED / NEXT_ACTION / STOP]
ACTION: [one bounded next action or /validate]
```
