---
id: information-disclosure-source-config
type: technique-card
related_skills:
  - web2-vuln-classes
  - triage-validation
trigger_tags:
  - information-disclosure
  - source-map
  - debug
  - backup
risk: low
maturity: draft
load_priority: medium
deep_refs: []
---

# 信息泄露 / Source / Config

## Quick Recall

- 信息泄露本身不是终点；价值取决于能否链到认证、权限、路由、密钥、依赖/CVE 或业务数据风险。
- 高信号：debug/stack trace、source map、备份文件、目录列表、配置片段、版本/组件、robots/security.txt、错误页。
- 版本泄露要提取完整组件版本，例如框架名 + major/minor/patch；不要把 `Apache Struts 2 2.3.31` 截断成主版本。
- 只提取最小必要证据，不保存真实凭证、客户数据或大体积源码。

## 能力定位

本卡给 `web2-vuln-classes` 和 `triage-validation` 提供信息泄露的影响建模和补漏清单。

## 触发信号

- `.map`、`.bak`、`~`、`.old`、`.git`、目录索引、debug endpoint、trace/error 页面。
- 响应里出现路径、类名、版本、环境名、配置键名、internal host、API route。
- JS/source 暴露 hidden route、token claim、feature flag 或管理接口。

## 思路分支

- Route discovery：源码/source map -> hidden API -> authz/IDOR。
- Config clue：配置键名/issuer/JWKS/internal host -> token/SSO/SSRF 假设。
- Dependency clue：版本/组件 -> CVE/known issue lane。
- Data exposure：非公开文件/记录 -> 最小证明和 triage。

## 技巧家族 / Payload 家族

- 命名规律：source map、backup suffix、manifest、static asset map、error path。
- 只读探测：GET/HEAD、目录 index、版本 endpoint、debug status。
- 影响链：泄露 route -> 浏览器/API replay；泄露 secret clue -> 最小验证计划。

## 补充 Checklist

- 是否区分公开文档、低敏版本信息和真实敏感泄露？
- 是否能链到下一步验证，而不是只报告“看到了信息”？
- 是否避免保存完整密钥、PII、客户记录或大源码？

## 最小验证

- 记录 URL、状态、内容类型、最小片段和为何非公开。
- 对版本/组件泄露，记录完整版本字符串和触发参数，用于后续 CVE/known software lane。
- 提取一个可验证 next action，例如 hidden route、依赖版本、配置键名或权限边界。
- Candidate 前必须说明业务影响或可利用链。

## 常见误判 / 死路

- robots.txt、security.txt、公开版本号通常不是漏洞。
- source map 只有公开前端源码时价值有限，除非包含 hidden API/secret/业务逻辑。

## 关联 Skills

- `web2-vuln-classes`
- `triage-validation`

## 晋升到 Skill / Queue 的条件

- 有非公开证据和可验证影响链时写入 action queue，类型 `information-disclosure-source-config`。
