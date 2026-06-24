# Execution Boundaries and Operating Notes

This document explains the intended usage scope of the local toolkit, the
meaning of Local / CTF / Lab targets, the boundaries of automation, and the
principles for evidence and report output.

This project is a Claude Code CLI assistant for vulnerability research,
internal security review, lab workflows, and CTF-style environments. It helps
organize recon, validation, reporting, and post-run review, but it does not
replace the operator's judgment about target facts or the truth of a finding.

---

## 1. Intended Use Cases

This project is suitable for:

- Authorized bug bounty or security testing targets.
- Internal security review inside an organization.
- Local labs, CTFs, sandboxed environments, and training targets.
- Source code, APIs, containers, services, and asset lists that the user owns
  or is permitted to test.

Tool output should not be treated as proof that a vulnerability is real. Any
finding still needs reproduction, impact confirmation, and supporting evidence.

---

## 2. Targets and Context

By default, this project treats the **target set explicitly supplied by the
current command** as the active execution context.

- `scope`, `request guard`, `audit`, and `validate` may enrich context, but do
  not act as execution bans.
- External policy text, accepted-impact lists, and `scope_snapshot.json` are
  optional context sources only.
- Target profiles, historical records, breaker state, cooldown, rate-limit
  hints, and unsafe-method signals are advisory and review-oriented; they no
  longer block execution.

---

## 3. Local / CTF / Lab Targets

This project no longer depends on a separate mode toggle to activate local,
CTF, or lab semantics. If a command explicitly supplies a target, that target
becomes the active execution context. For local, CTF, experimental, or other
sandbox-style targets:

- Requests are not blocked by external policy allowlists.
- `localhost`, private IPs, IP/CIDR targets, and host lists are not rejected
  automatically.
- Request helper logic stays advisory-only and does not participate in
  execution-side blocking.
- External policy text, allowed-method descriptions, and `scope_snapshot.json`
  are not required.
- Request and audit records are still kept for replay, review, and write-up
  workflows.

`/validate` and `/report` are write-up quality helpers, not execution
prerequisites.

---

## 4. Automation Boundaries

Automation reduces repetitive work, but it should still operate within these
boundaries:

- Reports are never auto-submitted. `/report` only produces an editable draft.
- High-impact actions should still receive human confirmation first, such as
  deletion, transfers, permission changes, bulk writes, or access to real user
  data.
- Rate-limit signals, breaker state, cooldown hints, and unsafe-method warnings
  should still be recorded and interpreted against live behavior, but they no
  longer auto-block the flow.
- Proxy history, request samples, logs, and report drafts may contain sensitive
  information and should be handled according to target authorization and local
  data-protection requirements.

---

## 5. Evidence and Reporting Principles

A valid report or write-up should include at least:

- The target and affected entry point.
- Complete reproduction steps.
- The key request, response, or state change.
- Impact and any necessary preconditions.
- False-positive elimination notes.
- A suggested fix or mitigation direction.

In CTF / Lab scenarios, a write-up may describe the solution path and flag
recovery process. In real authorized testing, reporting should use a stricter
vulnerability-report style and avoid overstating impact or omitting important
constraints.

---

## 6. Local Data and Output

Common local output directories:

```text
recon/<target>/
findings/<target>/
reports/<target>/
hunt-memory/
```

Avoid committing unsanitized requests, responses, reports, tokens, cookies,
personal data, or third-party data to public repositories. Review `.gitignore`,
report attachments, and command output before sharing.

---

## 7. Maintenance Principles

Local enhancements should follow these rules:

- Do not remove stable capabilities just to mirror upstream structure.
- Do not introduce unnecessary dependencies.
- Prefer small, reversible, and verifiable changes.
- Keep documentation aligned with actual Claude Code CLI behavior.
- For Local / CTF / Lab targets, keep execution-side helper logic advisory-only
  while preserving audit records.
