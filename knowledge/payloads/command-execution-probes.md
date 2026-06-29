---
id: command-execution-probes
type: payload-pack
related_cards:
  - knowledge/cards/controlled-rce-impact.md
related_skills:
  - web2-vuln-classes
trigger_tags:
  - command-injection
  - rce
  - low-risk-probe
risk: medium
maturity: draft
load_priority: low
---

# 命令执行低风险 Probe 家族

## Quick Recall

- 本附录只在已有明确命令执行 sink 或 RCE primitive 时读取。
- 目标是证明执行身份和边界，不是扩大利用。
- 默认不写文件、不读敏感文件、不 dump 全量环境变量、不启动 shell。
- blind 场景优先一次性 OAST token，记录来源和时间。

## Probe 家族

- 身份 proof：当前执行用户、权限组、进程身份。
- 位置 proof：工作目录、应用路径、容器/主机名。
- 平台 proof：操作系统类型、运行时类型、容器特征。
- Token proof：返回一次性随机 token，证明输入到执行输出的闭环。
- OAST proof：发起一次 DNS/HTTP callback，证明 blind execution 或 server-side action。

## 不默认执行

- reverse shell、webshell、持久化 agent、计划任务、启动项。
- 写入真实业务目录、修改配置、删除文件、执行包管理器或下载外部二进制。
- 读取全量环境变量、云凭证、数据库配置、用户文件或业务数据。
- 横向移动、内网扫描、暴力枚举进程/文件系统。

## 证据要求

- 原始请求、单变量 payload、响应或 OAST 记录。
- 执行身份和边界的最小证据。
- 控制请求，排除缓存、WAF、前端执行或日志回显误判。
- 如果使用了测试文件或回连，记录清理结果。
