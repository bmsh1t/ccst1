---
name: credential-attack
description: AI-first credential preparation and controlled Spray methodology covering target word candidates, HIBP enrichment, known/inferred usernames, HTTP request specs, OAuth/O365/Okta execution, preflight binding, stop conditions, evidence, and resume.
---

# Credential Attack Pipeline

## AI/工具边界

```text
AI /autopilot
  → 真实 login form 触发 baseline review；判断入口价值、模式、用户名可信度、shortlist 和是否 live
确定性工具
  → 输入校验、编码、节奏、请求、停止、脱敏、证据和恢复
```

观察到 real `login form`（包括 admin/back-office）时，创建或考虑一个有界的 Credential
Review，默认评估少量 default/common weak-password candidates；这只是准备/排队动作，不是
live Spray。用户已提供稳定测试账号且未明确要求验证弱口令/默认凭据风险时，可跳过大规模弱口令
字典测试；高价值后台、已识别产品指纹、明显默认凭据场景或匿名态已出现弱口令信号时，仍可在
预算内保留少量默认凭据检查和高价值组合验证。候选值由 AI 基于目标证据有限选择，Skill 不维护
静态密码列表。
live 前仍需要：具体 endpoint、reviewed users、AI shortlist、可判定信号、锁定/限速计划、
dry-run preflight 和停止条件。

## Evidence-Selected Preparation

Baseline Review 不是固定流水线；除默认/常见候选的少量评估外，模型只在当前证据显示凭据路径
具有足够信息增益时选择一个或多个来源：

- target-owned brand/route/source observations;
- operator-supplied or previously confirmed usernames;
- optional breach/OSINT enrichment when it answers a concrete account hypothesis;
- a bounded transformation of target-derived seeds when the observed login flow supports it.

保留 `confirmed` 与 `inferred` 的来源差异，不能把 permutations 当真实账号。HIBP 等外部
enrichment 只改变候选优先级，不建立账号存在性或 finding。候选文件、digest、权限和
去重约束由 `commands/spray.md` 及其工具契约拥有；本 Skill 不复制命令、参数或 provider
阈值。

模型输出 shortlist 时记录每个候选的来源、选择理由、风险和预期学习，并让现有入口执行
输入校验、脱敏和 preflight binding。不设置替代模型判断的统一硬上限。

## 四种执行模式

| mode | 选择条件 | 成功证据 |
|---|---|---|
| http-form | 自有 form/JSON/GraphQL 登录 | 显式 body/redirect/session cookie |
| oauth | 已观察到 password grant | HTTP 200 + 非空顶层 `access_token` |
| o365 | Microsoft identity 协议证据 | AADSTS/token 分类 |
| okta | Okta identity 协议证据 | errorCode/status/sessionToken 分类 |

普通 OIDC authorization-code 登录不等于 ROPC。具体 provider/module、隔离目录和成功信号
由 `commands/spray.md` 的执行契约决定；本 Skill 只根据已观察到的协议选择模式。

## Dry-run 与 live

所有 dry-run/live、preflight、TLS、限速、去重和授权确认都走 `commands/spray.md`。进入
live 前必须完成 dry-run preflight 和停止条件；`--i-understand` 不能绕过契约。

## HTTP request spec

- form/JSON 由标准库结构化编码，避免 `&`、`+`、引号破坏请求。
- 每个用户一个 CookieJar；CSRF GET 与 POST 共享 session，默认每次尝试刷新。
- 至少一个明确 success/failure signal。
- failure regex 消失只是 `ambiguous_candidate`，立即停止等待复核。
- guard status/body 必须显式配置；默认识别 429，不凭宽泛关键词猜测 WAF/lockout。

详见 `commands/spray.md`。

## 选择和停止

本 Skill 不规定用户/密码排列或探测顺序。现有执行契约负责账号轮次、间隔、guard、
ambiguous、network error 和恢复语义；默认首个 valid 停止，首个 rate-limit/guard/ambiguous
停止。模型只根据目标证据决定是否继续、切换模式或结束 lane，并记录预期学习和 kill
condition，不输出伪精确锁定概率。

## 证据与恢复

证据格式、私有目录、digest、attempt 去重、原子 summary、resume 和中断状态均由
`commands/spray.md` 及现有工具拥有。本 Skill 只要求把 valid/ambiguous/guarded 结果和
artifact ref 写回既有 owner，不能把“无命中”解释成 clean/no findings。

## 结果 handoff

有效凭据本身不自动生成 finding。将 valid/ambiguous/guarded summary 和 evidence ref 写入既有 target memory/action queue；再用现有认证后 `/hunt`/`/validate` 流程证明访问边界和影响。
