# Integration Contracts

> 可选外部工具、凭据/OAST 和动态 token adapter 契约。

## Scenario: 凭据与 OAST continuation 的 durable queue 契约

### 1. Scope / Trigger

- 修改 `tools/spray_contract.py`、HTTP form/OAuth/Trevor 适配器或
  `tools/oast_listen.py` 的运行结果、认证请求、回调轮询和停止语义时适用。
- 目标是让无人值守 `/autopilot` 能从 Action Queue 恢复 credential/OAST 工作，同时不
  把密码、client secret、token 或 callback 原文写入公共状态。

### 2. Signatures

```python
finish_run(context, status=..., stop_reason=..., counters=..., exit_code=...)
python3 tools/oast_listen.py start|poll|stop --target <target>
```

### 3. Contracts

- `finish_run()` 先写 `spray_summary`，再在 `action_queue_sync` 写入 `status`、`queue_status`、
  `action_id`、队列路径；同步失败必须写 `warnings`，不能静默丢失 continuation。
- Spray disposition 为：有效凭据 `candidate`；ambiguous/rate-limited/guarded/locked/unknown
  为活动 `signal`；完整 invalid run 为终态 `tested`；中断、工具或网络未完成为 `lead`。
- 已有 `candidate` 不得被后续不完整/clean run 降级；队列更新按 target+mode 幂等，metadata
  只允许 summary path、run id、mode、分类计数和 stop reason。
- CSRF helper URL 和 OAuth 重定向必须通过 `target_paths.url_belongs_to_target()`；跨 Scope
  在网络请求或凭据转发前分类为 guarded/scope error。
- OAST `start` 创建当前监听代次的活动 `oast-callback`；`poll` 无回调保持活动，有回调
  转为 `candidate` 并记录 callback artifact/count；`stop` 无回调转为 `dead-end`，已有
  callback 不得关闭 candidate。最终认领仍由人工处理。

### 4. Validation & Error Matrix

| 条件 | 结果 |
|---|---|
| CSRF URL outside target | `ValueError`，不发起请求 |
| OAuth 307/308 redirect outside target | `guarded` + `scope_redirect`，不转发 body |
| malformed action queue during finish | summary 保留，`action_queue_sync.status=error` + warning |
| valid credential/token | queue `candidate`，只引用私有 evidence/summary |
| OAST poll callback | queue `candidate`，保存 callback artifact/count |
| OAST stop without callback | queue `dead-end`，不声明 takeover/漏洞 |

### 5. Good / Base / Bad Cases

- Good：同一 target 的 spray summary 可重复 finish，队列只有一个 mode continuation，candidate
  保持活动并可被 `/autopilot` 选中。
- Base：OAST 轮询无回调返回成功并保持活动；webhook poll 成功返回 CLI `0`。
- Bad：把密码/token 写入 attempts、summary、queue metadata，跟随跨域 307/308，或把
  OAST callback 直接升级为 validated finding。

### 6. Tests Required

- `tests/test_spray_contract.py`：summary/queue 投影、幂等、candidate 不降级、同步失败 warning。
- `tests/test_spray_http_form.py`：跨 Scope CSRF 拒绝。
- `tests/test_spray_oauth.py`：跨 Scope redirect 拒绝和 guarded 分类。
- `tests/test_oast_listen.py`：start/poll candidate、stop dead-end、队列路径隔离和 webhook
  callback artifact。

### 7. Wrong vs Correct

#### Wrong

```text
Markdown hint -> next invocation guesses whether spray/OAST ran
```

#### Correct

```text
summary/callback artifact -> existing Action Queue -> bounded Autopilot projection
```

## Optional External Solver Contracts

### 1. Scope / Trigger

External challenge solvers, paid APIs, CAPTCHA helpers, and browser-based
clearance helpers may exist as manual tools, but must not be auto-run by
`/autopilot`, `/recon`, or scanner breadth without explicit operator intent.

### 2. Signatures

- `python3 tools/cf_solver.py --target <url> [--tier 1|2] [--dry-run]`
- `python3 tools/cf_solver.py --target <url> --export-env`
- `python3 tools/cf_solver.py --target <url> --check [--auto-resolve]`

### 3. Contracts

- API keys live in local `config.json` or environment variables such as
  `TWOCAPTCHA_API_KEY`; tracked files only contain placeholders.
- `--export-env` emits `BBHUNT_AUTH_HEADERS`, not a cookie-only variable,
  because Cloudflare clearance cookies are user-agent bound.
- Stored solver output stays under `recon/<target_key>/` as runtime evidence.
- The tool may suggest manual cookie use when a challenge tier is unsupported.

### 4. Validation & Error Matrix

- Missing API key for solve -> exit `5`.
- Missing solver dependency -> exit `4`.
- Insufficient/invalid solver balance -> exit `3`.
- Unsupported JS-only challenge -> exit `2`.
- Stored-cookie check with no cookie -> exit `6`.
- Stored-cookie check expired -> exit `1` unless `--auto-resolve` is supplied.

### 5. Good/Base/Bad Cases

- Good: operator runs `--dry-run`, then `--export-env`, then supplies the emitted
  `BBHUNT_AUTH_HEADERS` to recon/scanner commands.
- Base: `--check` reports no stored cookie and exits without loading paid solver
  dependencies or reading API keys.
- Bad: `/autopilot` spends solver balance automatically during routine recon.

### 6. Tests Required

- Static/local tests must cover no-cookie `--check` behavior without network.
- Export tests must assert cookie and paired `User-Agent` are emitted together.
- Docs/config tests must assert the tool is documented as manual/optional.

### 7. Wrong vs Correct

#### Wrong

Auto-trigger a paid solver from recon whenever Cloudflare text appears.

#### Correct

Surface the solver as a manual helper in `docs/tool-index.md`; require operator
choice before any solve, and keep the resulting headers in runtime artifacts.

## Scenario: TREVORspray CLI 适配契约

### 1. Scope / Trigger

修改 `tools/spray_orchestrator.sh`、`tools/_spray_trevor.py` 或升级
TREVORspray 时，必须核对项目的轮次语义与上游每请求 CLI 语义。

### 2. Signatures

```text
o365 -> trevorspray --module msol
okta -> trevorspray --module okta
users/passwords -> --users FILE --passwords FILE
```

### 3. Contracts

- `SPRAY_DELAY`/`SPRAY_JITTER` 是每账号轮次间隔；适配器按非空用户名数均摊为
  TREVORspray 的每请求秒数。
- TREVORspray 始终带 `--no-loot`；未设置 `SPRAY_CONTINUE_ON_HIT=true` 时同时带
  `--exit-on-success`。
- 用户名文件为空时在启动外部进程前失败。

### 4. Validation & Error Matrix

| 条件 | 结果 |
|---|---|
| `o365` | module=`msol` |
| `okta` | module=`okta` |
| 2 个用户、delay=1800、jitter=60 | 每请求 delay=900、jitter=30 |
| 空用户名文件 | `ValueError`，不启动进程 |

### 5. Good / Base / Bad Cases

- Good：当前 TREVORspray CLI 接受生成的全部参数，轮次时长与 preflight 估算一致。
- Base：单个已知用户名保持完整 delay/jitter。
- Bad：使用旧 `--passlist`、把秒除以固定 60，或 Okta 沿用默认 `msol`。

### 6. Tests Required

- `tests/test_spray_trevor.py` 固定两个 module、当前参数名、按用户数换算、停止和
  no-loot 行为，并覆盖空用户名文件。
- 升级 TREVORspray 后执行一次只读 `--help` 参数 smoke。

### 7. Wrong vs Correct

#### Wrong

```text
--passlist FILE --delay $((seconds / 60))
```

#### Correct

```text
--module MODULE --passwords FILE --delay (round_seconds / nonempty_users)
```

---

## Scenario: Evidence-gated Exchange EBurst lane

### 1. Scope / Trigger

Use only when target-owned Recon contains Exchange/OWA/EWS/Autodiscover evidence. It is an optional
interface-availability lane, never baseline Recon or an automatic credential spray.

### 2. Signatures

```bash
python3 tools/eburst_lane.py --target TARGET [--host TARGET_OWNED_URL] [--timeout 120]
```

External resolution checks `EBURST_HOME`, `BBHUNT_TOOLS_DIR`/`OSMEDEUS_TOOLS_DIR`, then
`$HOME/Tools/EBurst`; `EBurst.py` requires a Python 2 interpreter (`EBURST_PYTHON`, `python2`, or
`python2.7`).

### 3. Contracts

- `detect_exchange_hosts()` reads only bounded live technology/URL artifacts and applies
  `url_belongs_to_target()` before a host can enter the command.
- The lane invokes EBurst with argv `INTERPRETER EBurst.py -C -d HOST`, `shell=False`, one host at a
  time, at most 5 hosts, and a 1..900 second per-host timeout. Auth environment variables are removed.
- Results publish `recon/<target-key>/exchange/eburst/summary.json` and 0600 raw output files. Missing
  EBurst/Python 2 is `unavailable`; timeout/non-zero is `partial`/`failed`, never tested-clean.
- EBurst's legacy user/password mode is not routed by Autopilot; reviewed credential testing uses the
  existing `/spray` preflight and action queue contracts.

### 4. Validation & Error Matrix

| Condition | Result |
|---|---|
| No Exchange evidence | `not_applicable`, no network execution |
| Missing script or Python 2 | `unavailable`, exit 1 |
| Off-target/invalid explicit host | structured error, exit 2, no execution |
| Host timeout/non-zero | raw evidence retained, `timeout`/`failed`, non-zero lane result |
| All selected hosts succeed | `ok`; interface reachability only, not an auth finding |

### 5. Good / Base / Bad Cases

- Good: target-owned `/owa` evidence selects one host and stores a bounded `-C` result.
- Base: Exchange signal exists but runtime is absent; record `unavailable` and continue other lanes.
- Bad: feed `urls/all.txt` without evidence filtering, pass third-party hosts, or invoke EBurst's dictionary mode.

### 6. Tests Required

- `tests/test_eburst_lane.py`: resolver/runtime, Exchange detection, target scope, argv, timeout, raw evidence,
  summary status, and artifact path.
- `tests/test_external_arsenal.py`: shared-tools discovery must not install or execute the external tool.
- `tests/test_capability_profile.py`: `exchange.eburst` remains bounded and advisory.

### 7. Wrong vs Correct

#### Wrong

```text
all URL corpus -> EBurst dictionary mode -> third-party hosts / unbounded credentials
```

#### Correct

```text
Exchange evidence -> target-owned bounded hosts -> EBurst -C with timeout -> scoped raw/summary artifact
```

---

## Scenario: Workflow dynamic-token extraction

### 1. Scope / Trigger

Use only for a recorded same-target workflow step that declares a short-lived token source and an
explicit request destination. This extends the existing workflow runner, not `AuthSession` ownership.

### 2. Signatures

`steps[].token` accepts `url`, optional `method`, exactly one of `regex`, `response_header`, `cookie`,
or `json_path`, plus either destination `header` or a body `placeholder` (default `{TOKEN}`).

### 3. Contracts

- Token refresh uses `request_once()` and `AuthSession.headers_for_url()` immediately before the step.
- Source and redirect URLs remain in canonical target scope; values stay in private sequence evidence.
- `regex` needs a capture group; `json_path` supports only 1-8 dotted key/numeric-index segments;
  extracted values are non-empty scalar strings bounded to 8192 characters.
- Header injection rejects CR/LF. A body destination must contain its declared placeholder.
- Normalize negative `step_index` before identity derivation. New runs derive `run_id` from the evidence
  path/stat snapshot plus `perturb` and normalized step index; summary/private artifact paths use this
  `run_id`. Queue `source_id` derives from evidence ref plus `run_id`, and `metadata.generation=run_id`.

### 4. Validation & Error Matrix

| Condition | Result |
|---|---|
| Zero or multiple extraction sources | `ValueError` before token-source network I/O |
| Off-target source/redirect | scoped `ValueError`, no cross-target token transfer |
| Missing regex group/header/cookie/JSON path | lane error, sequence remains partial |
| Object/list/bool/empty/oversize token | lane error, no replay with that value |
| Header token contains CR/LF or body placeholder is absent | lane error before workflow request |
| Same evidence snapshot and transition rerun | reuse artifact identity and Queue action |
| Same evidence snapshot, different perturb or normalized step | distinct artifacts and Queue action |

### 5. Good / Base / Bad Cases

- Good: same-target refresh JSON `$.data.csrf` is inserted into `X-CSRF-Token` for one replay step.
- Base: token is absent or stale; preserve private evidence and leave the sequence partial.
- Bad: try every extractor, forward a token off-target, or silently run a step without using the token.

### 6. Tests Required

`tests/test_workflow_sequence.py` covers legacy body regex, response Header, `Set-Cookie`, bounded JSON
path, ambiguous extractors, missing destinations, target scope, request counts, private write-back, and
transition identity isolation/idempotency.

### 7. Wrong vs Correct

```text
Wrong: refresh response -> guess token source -> replay even when extraction/injection failed
Correct: one declared source -> bounded extraction -> explicit same-target destination -> private evidence
Wrong: evidence snapshot alone -> one artifact/Queue identity for every perturbation
Correct: evidence snapshot + perturb + normalized step -> deterministic transition identity
```

---
