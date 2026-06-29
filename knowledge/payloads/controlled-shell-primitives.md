---
id: controlled-shell-primitives
type: payload-pack
related_cards:
  - knowledge/cards/controlled-rce-impact.md
  - knowledge/cards/upload-to-execution.md
related_skills:
  - web2-vuln-classes
  - triage-validation
trigger_tags:
  - webshell
  - reverse-shell
  - controlled-exploit
risk: high
maturity: draft
load_priority: low
---

# 受控 Shell Primitive 约束

## Quick Recall

- webshell / reverse shell 是高风险影响证明能力，不是默认验证动作。
- 只有在当前轮明确授权、目标范围明确、测试资源可清理、红线检查通过时使用。
- 默认目标是证明 execution context 和业务影响，不是维持访问。
- 不持久化、不横向移动、不隐藏、不规避检测、不扩大到真实数据。

## 使用前条件

- 已有明确 RCE primitive 或上传执行链。
- 用户当前轮明确允许 shell primitive，且目标是授权测试或实验环境。
- 有清理计划：上传路径、临时文件、回连监听、日志记录和删除方式。
- 有更低风险 probe 无法充分证明影响的理由。

## 推荐证明方式

- 优先一次性命令输出或 OAST callback。
- 如果必须交互，限制为短时会话、单目标、最小命令集合。
- 只证明身份、路径、边界和必要业务影响。
- 会话结束后立即清理测试文件、监听器和临时资源。

## 禁止默认化

- 不把 webshell 上传作为上传漏洞的默认验证。
- 不把 reverse shell 作为命令注入或 SSTI 的默认验证。
- 不做持久化、提权、横向移动、凭证抓取、批量文件读取。
- 不把 CTF “拿 flag”流程照搬到真实目标。

## 记录要求

- 为什么低风险 probe 不足。
- shell primitive 的授权边界。
- 执行的最小命令集合。
- 清理动作和结果。
