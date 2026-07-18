---
description: Controlled password spray runner with hard operational guards — typed-hostname confirmation, lockout warning, audit log. Modes: http-form (custom login page), oauth (password grant), o365 + okta (via TREVORspray). Default delay 30min/round + 60s jitter. Usage /spray <url> --mode <mode> --users <file> --passes <file>
---

# /spray

Controlled credential spray against an authentication endpoint. `/autopilot`
may select this lane when credential access is a reasonable breakthrough path,
but the guardrails here still apply: concrete target, dry-run/pre-flight,
rate/lockout review, audit log, and stop-on-hit discipline.

## Modes

| Mode | Use case | Engine |
|---|---|---|
| `http-form` | Custom login page (POST username/password) | Built-in Python + urllib |
| `oauth` | OAuth password grant (`grant_type=password`) | Built-in Python + urllib |
| `o365` | Microsoft 365 / Azure AD | `trevorspray` |
| `okta` | Okta SSO | `trevorspray` |

## Usage

```
# HTTP form (simplest)
/spray https://target.com/login --mode http-form \
    --users users.txt --passes ranked.txt

# HTTP form with CSRF token extraction
/spray https://target.com/login --mode http-form \
    --users users.txt --passes ranked.txt \
    --post-data "user={USER}&pass={PASS}&_token={CSRF}" \
    --csrf-extract 'name="_token" value="([^"]+)"' \
    --success-regex "Welcome" \
    --fail-regex "Invalid credentials"

# OAuth password grant
/spray https://target.com/oauth/token --mode oauth \
    --users users.txt --passes ranked.txt \
    --oauth-client-id mobile-app \
    --oauth-scope "openid profile"

# Microsoft 365 (TREVORspray)
/spray https://login.microsoftonline.com --mode o365 \
    --users users.txt --passes ranked.txt

# Dry-run (pre-flight only, no real attempts)
/spray https://target.com/login --mode http-form \
    --users users.txt --passes ranked.txt --dry-run
```

## Hard guards (cannot be bypassed)

1. **Typed-hostname confirmation** — Pre-flight prints the target hostname and requires you to type it back. Prevents spraying the wrong target.
2. **Lockout warning** — Calculates per-user failed-attempt count from your `--passes` size and warns if it exceeds typical lockout thresholds.
3. **Audit log** — Built-in HTTP/OAuth handlers append every request attempt；O365/Okta append every TREVOR emitted event to `recon/<host>/spray/attempts-<timestamp>.jsonl`. **Passwords are never logged in plaintext** — only a SHA-256 prefix when the emitted line can be associated with a passlist value；token/session/Authorization values in TREVOR raw output are also redacted.
4. **Spray order** — `pass[i] × all_users` per round (NOT brute-per-user). Each account sees at most 1 failed attempt per round.

## Spray order example (3 users × 3 passwords)

```
Round 1:  Password1!  → alice, bob, charlie    [delay]
Round 2:  Welcome2025 → alice, bob, charlie    [delay]
Round 3:  Summer2024  → alice, bob, charlie
```

If `--continue-on-hit` is NOT set, spray stops at the first valid credentials.

## Rate limiting

| Flag | Default | Effect |
|---|---|---|
| `--delay <sec>` | 1800 (30 min) | Sleep between rounds |
| `--jitter <sec>` | 60 | Random ±jitter added to each delay |
| `--aggressive` | off | Sets delay=60, jitter=10 (fast spray — use only when you intentionally accept the lockout/rate-limit risk) |

For Microsoft 365 / Azure AD smart lockout: defaults are designed to stay well under the 10-min sliding window threshold. **Do not use `--aggressive` against O365** unless you've cleared it with the program.

## Success detection (http-form mode)

The script checks these in order:
1. `--success-regex` matches response body → success
2. `--fail-regex` set + body does NOT match → success
3. HTTP redirect (3xx) to a path that is NOT the login page → success (heuristic)
4. None of the above → not success

If you get false positives, supply `--fail-regex` (e.g. `--fail-regex "Invalid|incorrect|wrong password"`) to anchor detection.

## Success detection (oauth mode)

HTTP 200 response with `"access_token"` field in JSON body → success.
HTTP 4xx (typically 400 invalid_grant / 401) → fail.

## Result classification (o365 / okta)

TREVOR 输出先转换为结构化 emitted-event JSONL，再按身份提供方分类。它的粒度取决于
TREVOR 实际输出，不宣称每个网络请求都有一条事件。

- Azure AD：优先解析 `AADSTS` code。`50034`=invalid user，`50126`=invalid
  password/user exists，`50053`=locked，`53003`=valid password + Conditional
  Access，`50076/50079`=valid password + MFA，`50158`=external auth，`530003`=device
  required，`65001`=consent required，`700016/90002`=app/tenant configuration。
- Okta：识别 `E0000004`、`E0000119`/`LOCKED_OUT`、`MFA_REQUIRED`、
  `PASSWORD_EXPIRED`、`SUCCESS + sessionToken`、`E0000047`/HTTP 429。
- 只有响应 JSON 的顶层 `access_token` key 才标记 token issued；claims 或原始文本包含
  `access_token` 不算成功。
- 未识别输出保留为 `unknown`，供后续人工/AI 复核。

## Pre-flight output (what you see before any HTTP)

```
=============================================
  SPRAY PRE-FLIGHT — target.com
=============================================
  Target URL:        https://target.com/login
  Mode:              http-form
  Users file:        users.txt (50 entries)
  Passes file:       ranked.txt (10 entries)
  Total attempts:    500
  Rounds:            10
  Delay/round:       1800s + 60s jitter
  Est. duration:     ~5h
=============================================

[!] OPERATIONAL RISK REMINDER
[!] This sends live authentication attempts and can trigger lockouts/rate limits...
Type the target hostname (target.com) to confirm: _

[!] LOCKOUT WARNING
[!] Per-user failed attempts (this run):  10
[!] Estimated accounts likely to be locked: ~80% of 50 = 40
Type 'yes' to proceed (anything else aborts): _
```

## Skipping confirmations

`--i-understand` skips both prompts. Use it only after a clean dry-run and when
the active run has already selected the controlled credential lane, confirmed
the exact target host, and intentionally accepts the lockout/rate-limit risk.
The flag is a deliberate friction point.

## Audit log format

Built-in HTTP/OAuth 每次请求一行：

```json
{"ts":"2026-05-27T22:00:01Z","round":1,"user":"alice","pwd_sha256_prefix":"a3f2b8e1c0d4","status_code":401,"looks_like_success":false,"duration_ms":320}
{"ts":"2026-05-27T22:00:02Z","round":1,"user":"bob","pwd_sha256_prefix":"a3f2b8e1c0d4","status_code":302,"redirect_to":"/dashboard","looks_like_success":true,"duration_ms":410}
```

O365/Okta 每条 TREVOR emitted event 一行：

```json
{"schema_version":1,"ts":"2026-07-18T12:00:00Z","mode":"o365","tool":"trevorspray","event":"attempt_result","user":"alice@example.test","classification":"valid_password_mfa","credential_valid":true,"token_issued":false,"aadsts_code":"50076","pwd_sha256_prefix":"a3f2b8e1c0d4","raw":"..."}
```

## Pipeline position

```
/wordlist-gen <target>        -> ranked.txt
/breach-check ranked.txt      -> ranked-ranked.txt (HIBP-validated)
/osint-employees <target>     -> usernames.txt
/spray <login> --users usernames.txt --passes ranked-ranked.txt
```

## Dependencies

- Built-in modes (http-form, oauth): pure Python 3.9+ stdlib
- TREVOR modes (o365, okta): `trevorspray` from `./install_tools.sh --with-credential-attack`
- typed-hostname confirmation and lockout estimation are built into `tools/spray_orchestrator.sh`

## Underlying tool

`tools/spray_orchestrator.sh <url> --mode ... --users ... --passes ...`
