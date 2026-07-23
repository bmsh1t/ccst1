---
name: credential-attack
description: AI-first credential preparation and controlled Spray methodology covering target word candidates, HIBP enrichment, known/inferred usernames, HTTP request specs, OAuth/O365/Okta execution, preflight binding, stop conditions, evidence, and resume.
---

# Credential Attack Pipeline

## AI/工具边界

```text
AI /autopilot
  → 判断是否进入 Credential Lane、入口价值、模式、用户名可信度、shortlist 和是否 live
确定性工具
  → 输入校验、编码、节奏、请求、停止、脱敏、证据和恢复
```

发现登录页、组件名或 SSO 品牌都不自动触发 Spray。live 前需要：具体 endpoint、reviewed users、AI shortlist、可判定信号、锁定/限速计划、dry-run preflight 和停止条件。

## 准备链

```text
cewler clean ─┐
Hashcat rules ├→ candidate-pool.txt → HIBP buckets → AI spray-shortlist.txt
brand pydictor┘                                      │
known users ─────────────────────────────────────────┤
unknown users → OSINT → confirmed/inferred split ───┘
```

### Candidate pool

```bash
tools/wordlist_engine.sh target.com --mode balanced --filter strict
```

- cewler 原词、Hashcat 批量变异和品牌 pydictor 分层输出。
- pydictor 只扩展品牌/少量证据 seed，不扩展整个网站词集。
- `$PATH` 和 `$HOME/Tools` 均可发现；不自动安装。
- `candidate-pool.txt`/`ranked.txt` 只供审阅，不直接 live。

### HIBP

```bash
tools/breach_checker.py recon/target.com/wordlists/candidate-pool.txt \
  --limit 10000 --with-counts
```

`1..1000=sweet`、`0=zero`、`>1000=common`、API error=`unknown`。HIBP 只做 k-anonymity enrichment；zero 品牌词仍可能高价值，unknown 不得丢失。

### Usernames

已知用户名直接进入审阅，跳过 OSINT。未知时才运行：

```bash
tools/osint_employees.sh target.com
```

Decision package 必须分开 `confirmed` 与 `inferred`，不能把 permutations 当真实账号。

### AI shortlist

生成 `spray-shortlist.txt` 和无明文 metadata JSONL。每行 metadata 使用
`schema_version/pwd_sha256_prefix/source/hibp_count/hibp_bucket/reason`，顺序必须与密码文件
一致。两个文件均为 `0600`；入口会拒绝候选池 alias、缺失 metadata 和 digest 漂移。
根据候选来源、HIBP、用户名数量、锁定证据和预期时长逐项选择；不设置替代 AI 的统一硬上限。

## 四种执行模式

| mode | 选择条件 | 成功证据 |
|---|---|---|
| http-form | 自有 form/JSON/GraphQL 登录 | 显式 body/redirect/session cookie |
| oauth | 已观察到 password grant | HTTP 200 + 非空顶层 `access_token` |
| o365 | Microsoft identity 协议证据 | AADSTS/token 分类 |
| okta | Okta identity 协议证据 | errorCode/status/sessionToken 分类 |

普通 OIDC authorization-code 登录不等于 ROPC。TREVOR 使用 `msol/okta` module、`--no-loot`、默认 `--exit-on-success`，并把 HOME 隔离到本次 `.private` run。

## Dry-run 与 live

```bash
# dry-run：验证完整 mode contract，认证请求数必须为 0
tools/spray_orchestrator.sh URL --mode MODE --users users.txt \
  --passes spray-shortlist.txt [--request-spec request.json] --dry-run

# unattended live：显式绑定 preflight
tools/spray_orchestrator.sh URL --mode MODE --users users.txt \
  --passes spray-shortlist.txt [--request-spec request.json] \
  --preflight preflight.json --i-understand
```

preflight 绑定 URL、mode、users/passwords、request config、delay/jitter 和 stop-on-hit；24 小时过期，输入漂移 fail-fast。`--i-understand` 只跳过交互，不跳过契约。

TLS 默认验证证书。仅在已确认的自签名环境显式增加 `--insecure`；该选择进入 preflight
binding，不能在 live 前静默改变。

## HTTP request spec

- form/JSON 由标准库结构化编码，避免 `&`、`+`、引号破坏请求。
- 每个用户一个 CookieJar；CSRF GET 与 POST 共享 session，默认每次尝试刷新。
- 至少一个明确 success/failure signal。
- failure regex 消失只是 `ambiguous_candidate`，立即停止等待复核。
- guard status/body 必须显式配置；默认识别 429，不凭宽泛关键词猜测 WAF/lockout。

详见 `commands/spray.md`。

## 顺序和停止

- 固定 `password → all users`；账号每轮最多一次尝试。
- `--delay/--jitter` 是账号轮次间隔；TREVOR adapter 按用户名数换算每请求间隔。
- 默认首个 valid 停止。
- 首个 rate-limit、guard、ambiguous 停止；连续三次 network error 停止。
- 不输出伪精确锁定百分比；只报告用户数、轮数、节奏和已知/未知阈值。

## 证据与恢复

普通 run 目录保存 `run.json`、统一 `attempts.jsonl`、原子 `summary.json`；密码只保留 SHA-256 prefix。响应、token、cookie 和 TREVOR history 只保存到 0600/0700 `.private/spray/<target>/<run-id>/`。

```bash
tools/spray_orchestrator.sh URL ... --resume recon/<target>/spray/<run-id> --i-understand
```

built-in 按 user + password hash 跳过已记录 attempt；TREVOR 在 private 目录生成与 binding
一致的去重输入并复用同一隔离 HOME。输入 digest 不一致、损坏 JSONL、run ID 不匹配或并发
resume 均 fail-fast。只有无 summary、`interrupted` 或 `error` run 可恢复；其他 summary 是终止状态。
SIGINT、guard stop 和非零退出必须写 summary，不能解释成 clean/no findings。

## 结果 handoff

有效凭据本身不自动生成 finding。将 valid/ambiguous/guarded summary 和 evidence ref 写入既有 target memory/action queue；再用现有认证后 `/hunt`/`/validate` 流程证明访问边界和影响。
