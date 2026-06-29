---
id: controlled-rce-impact
type: workflow-card
related_skills:
  - web2-vuln-classes
  - triage-validation
trigger_tags:
  - rce
  - command-injection
  - ssti
  - deserialization
  - upload-execution
  - impact-proof
risk: high
maturity: draft
load_priority: medium
deep_refs:
  - knowledge/payloads/command-execution-probes.md
  - knowledge/payloads/controlled-shell-primitives.md
  - knowledge/playbooks/controlled-rce-validation.md
  - /root/tool/ccst/ctf-skills/ctf-web/server-side.md
  - /root/tool/ccst/ctf-skills/ctf-web/server-side-2.md
  - /root/tool/ccst/ctf-skills/ctf-web/server-side-deser.md
  - /root/tool/ccst/ctf-skills/ctf-web/server-side-exec.md
  - /root/tool/ccst/ctf-skills/ctf-web/server-side-exec-2.md
  - /root/tool/ccst/ctf-skills/ctf-web/node-and-prototype.md
---

# 受控 RCE / 命令执行影响证明

## Quick Recall

- RCE、命令注入、SSTI、反序列化、上传执行不是禁用能力；它们属于高风险受控影响证明。
- 目标不是“拿 flag”，而是证明真实安全影响：执行身份、运行边界、应用上下文、可达内部服务、配置/密钥风险或业务数据风险。
- 默认先证明 primitive：无破坏命令、单次请求、可复现差异、最小输出。
- 不默认执行 reverse shell、webshell、持久化、文件写入、横向移动、批量读取、真实数据导出或服务扰动。
- 需要 shell primitive 时，必须有明确当前轮授权、测试资源、清理计划和红线检查。
- 不默认 dump 全量环境变量、配置文件、密钥、数据库、用户数据或云凭证。
- 深挖时读取 `deep_refs` 中的 `ctf-web` 深度参考，提取执行 primitive、
  解析器差异、gadget 思路和链式证明，不照搬拿 flag / 持久 shell / 批量读取流程。
- 有明确 endpoint/input/command primitive 时，写入 action queue，类型可标记为 `controlled-rce-impact`。

## 能力定位

本卡用于把 CTF 中的 RCE / shell / post-exploit 技巧转译为授权渗透里的
Controlled Exploitation / Impact Proof。它给 `web2-vuln-classes` 和
`triage-validation` 补充高风险利用后的最小证明模型，不替代红线和验证 gate。

## 触发信号

- 输入可能进入 shell、process argv、模板引擎、脚本 runner、CI hook、代码解释器、反序列化 sink 或上传执行路径。
- SSTI、命令注入、反序列化、文件上传、解析器链、SSRF-to-RCE、CVE 命中等已产生可复现 primitive。
- 响应、OAST、日志或错误信息显示命令被执行、模板被求值、类/函数被调用、进程启动或文件系统被访问。
- 需要把 “能执行代码” 转化为可报告影响，而不是停在技术可能性。

## 思路分支

- Primitive proof：证明输入能影响命令/代码执行路径。
- Identity proof：证明执行用户、容器/主机边界、工作目录或运行时身份。
- App-context proof：证明能触达应用进程上下文，例如只读读取测试文件、非敏感配置键名、框架路径或版本信息。
- Internal-reachability proof：证明能以服务端身份访问内部服务，但只做低频、状态级、banner/health 级证据。
- Business-impact proof：把执行能力链到业务影响，例如可读应用配置、可触达数据库网络、可执行后台任务、可影响高权限工作流。
- Cleanup proof：如果创建了测试资源，记录路径、时间、清理命令和清理结果。

## 技巧家族 / Payload 家族

- 命令执行 probe：身份、工作目录、系统类型、短 token 回显、OAST callback。
- 模板执行 probe：算术表达式、变量访问、只读对象路径、最小命令 primitive。
- 反序列化 probe：URLDNS / HTTP callback / 类型错误差异，先证明反序列化触发，再考虑命令 gadget。
- 上传执行 probe：临时 marker、只读回显、测试目录内一次性执行，不默认持久 webshell。
- Shell primitive：webshell / reverse shell 只作为受控深度附录，默认不执行。

## 补充 Checklist

- 是否已经有 baseline 和单变量执行差异？
- 是否确认执行发生在目标服务端，而不是前端、WAF、代理或测试机？
- 是否能证明执行身份和边界，而不读取敏感数据？
- 是否有低风险方式证明业务影响，而不是扩大到真实数据？
- 是否需要写入文件？如果需要，是否是测试目录、可清理、当前轮明确授权？
- 是否已记录 red-line review、请求、响应、时间戳、OAST token、清理计划？

## 最小验证

- 先用无副作用 probe 证明执行 primitive，例如短 token 回显、身份/目录/系统类型级别证据。
- 对 blind RCE，使用一次性 OAST token，记录来源 IP、时间和参数，不做扫描式回连。
- 如果需要文件写入，只写测试资源和可清理临时路径；验证后立即清理并记录。
- 对内部访问能力，只证明单个明确内部目标的状态级可达性，不做大范围端口扫描。
- Candidate 前必须有可 replay 请求、执行证据、影响解释和红线/清理说明。

## 常见误判 / 死路

- 模板算术成立不等于 RCE；可能只是表达式求值。
- OAST callback 不等于命令执行；可能是 SSRF、预取、扫描器或解析器外连。
- 500/超时不等于执行成功；必须有控制请求和稳定差异。
- 读取 `/etc/passwd`、环境变量或配置文件可能跨越敏感数据边界；没有必要时不作为默认验证。
- shell 连接失败不代表 primitive 不存在；先回到无副作用 probe 和日志/OAST 证据。

## 关联 Skills

- `web2-vuln-classes`
- `triage-validation`
- `bb-methodology`

## 晋升到 Skill / Queue 的条件

- 只有 sink 迹象时，作为 Lead 交给当前 Skill 做低风险 primitive proof。
- 有明确 endpoint/input/probe/result 时，写入 `tools/action_queue.py`，类型 `controlled-rce-impact`。
- 需要 webshell、reverse shell、文件写入、内部服务访问或 RCE 后取证时，先做红线检查并按 `knowledge/playbooks/controlled-rce-validation.md` 执行。
- 需要验证报告时，转 `triage-validation`，必须包含执行边界、影响证明和清理说明。

## 可晋升经验

- 某类框架、模板、解析器或上传链反复能从 primitive 升级到受控影响证明。
- 某类 probe 在目标技术栈里稳定证明执行而不触碰敏感数据。
- 某类误判反复出现，应沉淀到 `dead-ends` 或本卡的误判区。
