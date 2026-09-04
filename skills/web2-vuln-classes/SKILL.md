---
name: web2-vuln-classes
description: Web/API vulnerability-class routing guide for autonomous assessment. Use when the focus or target memory names a concrete class such as IDOR, access control, JWT/OAuth/SAML, GraphQL, SQLi/NoSQL, SSRF, upload, SSTI, deserialization/ViewState/machineKey, XXE, path traversal, request smuggling, cache poisoning/deception, race, browser boundary, WebSocket, LLM tool flow, or controlled RCE. Provides evidence-driven route selection, project-card recall, evidence gates, stop conditions, and write-back boundaries.
---

# WEB2 VULN CLASSES — Routing Layer

This Skill is the decision layer after Claude selects a concrete Web/API bug-class
lane. General technique knowledge and exact test-input syntax come from the model;
this file keeps project-specific routing, evidence gates, and lifecycle boundaries.

## Runtime Contract

1. Read target memory first: current surface, hypothesis, active leads, and dead ends.
2. Pick one evidence-backed lane; do not run a generic class checklist.
3. Establish a baseline before changing one boundary at a time.
4. Use the model's least invasive test input for the observed parser, identity,
   state, cache, browser, or transport boundary; use one changed axis at a time.
5. Save target-bound raw evidence for every Candidate and queue executable actions.
6. Use `triage-validation` before reporting; a framework name, status code, or
   parser error alone remains a Lead/Signal.
7. Write the result to the existing owner and leave a concrete next action or stop reason.

## Four-Layer Memory Hooks

Use `tools/context_pack.py` and the `knowledge` registry to select only cards
matching the observed boundary; do not maintain a second card map here.

Cards provide patterns, counterexamples, and evidence prompts. They do not own
the target state or force an execution sequence.

## Boundary-First Pattern Router

Use the distilled project decision shape, not a fixed technique route:
`boundary -> baseline -> hidden surface -> bug family -> primitive -> connector -> impact`.
Keep this as an AI reasoning aid; do not import flag hunting, admin-bot assumptions,
DoS/ReDoS, persistent shell, or broad payload spraying into real targets.

At each pivot record `Evidence`, `Primitive`, `Connector`, `Impact hypothesis`,
`Next action`, and `Stop condition`. Use explicit `Primitive:` and `Connector:`
entries. The model may skip, combine, or invent a
branch when the observed evidence justifies it.

### Pattern Map

| Signal | Route |
|---|---|
| Object ID, tenant/org/user/account/invoice/order IDs | IDOR / object authorization |
| Token, callback, redirect, JWK/JKU/KID, SAMLResponse | JWT/OAuth/SAML/SSO |
| Query, sort, filter, report, export, header/cookie/path input | SQLi/NoSQL hidden surface |
| URL fetch, webhook, import, preview, callback | SSRF URL fetch; internal impact only after server-side proof |
| Upload, import, convert, preview, SVG/Office/XML | Upload parser; safe verification and read-back before storage, access, and execution proof |
| Template syntax, command output, shell primitive | SSTI/command/controlled RCE |
| ASP.NET `__VIEWSTATE` / ViewState / machineKey | Insecure deserialization / ViewState integrity |
| CL/TE, host header, proxy trust, cache key, unkeyed header | Proxy/cache/smuggling |
| Origin, postMessage, DOM, CORS, clickjacking | Browser boundary |
| WS handshake/frame/subscription | WebSocket / realtime API |
| Source/config/secret/file read signal | Info disclosure / path traversal / management exposure |

## Focused Route Notes

### Object-Level Auth Matrix

Compare the same target-bound action across two owned identities, object IDs,
methods, fields, and workflow states. A stable 403/404 or no server-side delta is
a stop condition; introspection or a UI difference is not an authorization proof.

### Access-Control Boundary Matrix

Use raw replay for URL, method, path/header rewrite, and other observed access
boundaries. The method diff -> path/header rewrite -> raw replay branch is optional
evidence-driven routing, not a fixed dictionary. Use Playwright request/raw replay
when browser fetch cannot preserve the observed request.

### Missing Parameter Signal Lane

Use target material, schemas, source, and parser errors to build a target-specific wordlist.
Test one low-impact parameter at a time; Do not bulk-enumerate real users,
PII, passwords, addresses, or tokens. Preserve the raw differential and route to
`knowledge/cards/missing-parameter-discovery.md`.

### Management Exposure Lane

Use target naming and observed routes for read-only fingerprinting and an auth
boundary check. Do not import keys into cloud panels or take resource control;
record minimal config evidence and a validation plan.

### SQLi Lane Flow

示例输入面按证据选择，不是固定顺序; not a fixed checklist. When ordinary
parameters are quiet, check observed hidden surfaces such as headers, path segments,
or second-order inputs; establish a baseline and require a boolean/length or
time/OOB differential. A DNS-only SSRF signal needs a second signal proving a
server-side fetch before impact routing. Change one boundary at a time and stop on
unstable or WAF-only output; the model chooses syntax from the observed query shape.

### Hidden Auth Switch Lane

Start with an owned/test account baseline across the visible flow and any observed
provider, channel, or role selector. Do not silently fall into password brute force.
If credential testing is selected, route to `skills/credential-attack/` or a
controlled `/spray` run with lockout, rate limits, and stop conditions.

## Chain Shapes

Treat these as connector examples, not an allowlist:

| Primitive | Connector | Validated impact |
|---|---|---|
| Open redirect | OAuth callback / token leakage | Account or code boundary proof |
| SSRF callback | Internal service / metadata credential | Raw data or control-plane impact |
| Upload parser | Stored file / converter | Parser or controlled execution proof |
| GraphQL introspection | Node/global ID / mutation auth | Object or field authorization proof |
| XSS | Session action / admin browser | Sensitive action or data proof |
| Request smuggling | Cache, capture, or auth boundary | Victim-facing request/response proof |
| Info disclosure | Source/config/route/secret | Follow-on boundary proof |
| Race primitive | Quota/payment/OTP/state transition | Controlled state-delta proof |

## Evidence and Write-Back

Before escalation, require a raw baseline, a controllable input, a reproducible
differential, and the smallest demonstrated impact. A `server-side fetch`,
`field-level auth matrix`, `introspection alone is informational`,
`storage/access/execution`, `baseline/type classification`, or `state machine/bounded
parallel replay` phrase is a prompt for evidence, not a finding by itself. Use the
current user/test resource for race checks. Record the selected route, action, evidence references, coverage,
dead ends, remaining unknowns, next action, and owner write-back using the shared
`SKILL RESULT` contract.

## Global Stop Conditions

Stop or downgrade to Lead when there is no raw baseline, no controllable input, no
owned/test identity where required, no repeatable response/state delta, or only a
framework/status/parser signal without a target-bound connector.
