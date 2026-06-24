# 智能漏洞赏金工作台 — 产品说明

## 产品定位

智能漏洞赏金工作台是一套面向**授权安全测试、漏洞赏金、企业自查、靶场与 CTF 场景**的本地化安全测试辅助系统。

它把 Claude Code 扩展为一个可执行的安全测试工作台：既能调度本地侦察、扫描、源码分析、报告生成等工具，也能通过记忆系统沉淀目标画像、历史测试记录和成功漏洞模式，帮助研究员更系统地完成从目标梳理到报告交付的完整流程。

一句话概括：

> 这是一个会做侦察、会排攻击面优先级、会辅助验证、会生成报告、还能跨会话记住目标状态的本地安全测试工作台。

---

## 核心价值

### 1. 从“工具集合”升级为“测试工作流”

传统安全测试经常需要在多个终端、扫描器、笔记、报告模板之间切换。本项目把这些步骤收口为一组清晰的工作流：

```text
目标确认 → 侦察 → 攻击面排序 → 漏洞测试 → 发现验证 → 报告生成 → 记忆沉淀
```

研究员既可以手动执行每一步，也可以使用自治模式让 agent 按阶段推进。

### 2. 降低无效发现和重复测试

项目内置 triage / validate 流程，用于在写报告前判断发现是否具备真实影响，减少：

- 理论漏洞
- 无实际影响的扫描噪声
- 已知重复问题
- 不满足提交条件的低价值发现

同时，hunt memory 会记录已测试端点、历史发现、技术栈和成功模式，避免每次重新开始。

### 3. 支持 Web2、源码、CI/CD、Web3 与 Token 场景

产品能力覆盖多个安全测试方向：

- Web 资产侦察与漏洞测试
- 域名 / IP / CIDR / 资产列表输入
- API / GraphQL / 参数与鉴权边界测试
- 浏览器态页面交互、XHR/API/GraphQL 请求回灌与攻击面排序
- 前端 bundle / 本地源码中的路由、对象 ID、租户边界和业务动作假设提取
- 源码密钥与配置泄露检查
- GitHub Actions / CI/CD 风险识别
- 代理流量辅助分析
- 智能合约审计方法论
- Meme coin / Token rug pull 风险扫描
- LLM / Agentic AI 功能安全测试方法论

---

## 产品核心能力

### 1. 侦察与攻击面发现

能力包括：

- 域名 / IP / CIDR / 域名列表目标识别
- 子域名枚举
- HTTP 存活探测
- 技术栈识别
- 端口扫描
- 历史 URL 收集
- JS 端点提取
- JS 潜在密钥识别
- 目录 fuzz
- 配置文件暴露检测
- 参数发现
- GitHub 组织识别与 CI/CD workflow 扫描
- 主动爬取超时控制，避免单个目标拖住整轮流程

### 2. 漏洞扫描与候选发现

覆盖方向包括：

- XSS
- 子域接管
- CORS / headers / misconfiguration
- 敏感文件暴露
- SSRF
- CVE
- Open Redirect
- IDOR 候选
- 未授权 API 访问
- HTTP 方法篡改
- Upload canary / 可执行上传验证
- SQLi timing / linear-scaling 验证
- SSTI math canary
- MFA / SAML / SSO 主动探测与人工复核候选
- `summary.txt` / `summary.json` 双格式扫描摘要，方便 Claude Code CLI、验证和报告流程读取

### 3. 源码暴露与 CI/CD 风险扫描

能力包括：

- 扫描本地 repo 或 GitHub public repo
- 大仓库阈值保护
- 内置高信号 secret 规则
- 可选调用 `gitleaks`
- 检测 `.env`、service account、config 文件
- 检测 GitHub Actions 风险：
  - `pull_request_target` checkout
  - self-hosted runner + 不可信触发
  - 用户输入直接进入 `run`
  - 第三方 action 未固定 SHA

### 3.1 浏览器态攻击面与源码情报假设

很多高价值 Web 漏洞并不是单靠 URL 字典或 `curl` 就能发现，尤其是 IDOR、越权、审批流、导出下载、邀请成员、订单/发票/报表等业务逻辑问题。本项目现在把这类“需要点页面、读前端、看真实请求”的过程纳入主工作流。

当前 Claude Code CLI 的核心工作流已调整为 AI-first：

```text
LOAD -> RANK -> ENRICH -> ATTACK -> CHAIN -> RECORD -> VALIDATE CANDIDATES -> REPORT
```

也就是先读取目标历史、recon、surface、findings，再用浏览器态、源码情报和 JS 阅读能力补全业务上下文，随后围绕真实业务动作做精确验证。这样可以避免工具只停留在“扫一遍”的层面，让 AI 更像高级渗透测试工程师一样主动阅读、点击、关联、复现和串联证据。

能力包括：

- 在 Claude Code CLI 中优先使用已安装的 `playwright-cli` 访问页面、复用登录态、点击功能点并采集浏览器证据
- 从浏览器真实请求中提取 XHR / API / GraphQL 端点和参数，回灌到 `recon/<target>/browser/`
- 攻击面排序会识别浏览器态发现的高价值接口，并给 GraphQL、导出、下载、管理、订单、用户、更新、删除、邀请等端点加权
- 从本地源码、前端 JS bundle 和 recon 产物中提取路由、GraphQL operation、对象 ID、租户/账号/角色边界和业务动作关键词
- 生成 IDOR、auth-bypass、business-logic 等假设，写入 `findings/<target>/source_intel/`
- `/js-read` 会把 cached JS bundle 交给 `js-reader` agent 阅读，生成端点候选、认证模型、sink 热点、GraphQL operation 和排序后的攻击面假设，写入 `findings/<target>/js_intel/`
- `/surface` 会读取 `js_intel` 假设并把 LLM 读出来的高价值 JS 接口纳入排序
- Agent 在遇到 SPA、登录态、dashboard、portal、XHR/GraphQL、账号相关页面时，会优先走浏览器态与源码情报 lane，再把关键请求收敛为可复现证据

### 4. 自治挖掘 / Agent 工作流

本地有一个 ReAct 风格 agent：

- 支持 Ollama 本地模型
- 可选 LangGraph 后端
- 默认每次自治运行创建新的本地 agent session，避免复用旧 `agent_session.json` 造成状态串扰
- 支持显式 session 续跑：`--resume latest` 或 `--resume <session_id>`
- `/pickup` 只读取目标级历史、structured findings 和下一步建议，不会隐式复用旧 agent session
- 本地 session 产物隔离在 `targets/<target>/sessions/<session_id>/`，便于复盘、trace 和人工介入
- 有 working memory
- 有 findings log
- 有 observation buffer
- 可以调用本地工具完成：
  - recon
  - vuln scan
  - JS 分析
  - secret hunt
  - source hunt
  - browser probe
  - source intelligence
  - JS reader
  - 参数发现
  - API fuzz
  - CORS check
  - CVE intel
  - report generation

自治模式有三种：

```text
paranoid / normal / yolo
```

### 4.1 Agent Session 与续接语义

本项目区分两类“续接”：

| 类型 | 作用 | 产品行为 |
|---|---|---|
| 目标级续接 | 查看目标历史、未测端点、历史发现、structured finding 状态 | 使用 `/pickup target.com`，不会污染下一次自治运行 |
| Agent 精确续跑 | 继续上一轮 ReAct agent 的 working memory、finding log、observation buffer 和 trace | 使用 `--resume latest` 或 `--resume <session_id>` 显式开启 |

默认的 `/autopilot target.com` 或 agent 运行会创建新的本地 session：

```text
targets/<target>/sessions/<session_id>/
├── recon/
├── agent_session.json
├── agent_trace.jsonl
└── agent_bump.txt
```

这样设计的目的是让 Claude Code 中的新一轮测试拥有干净的本地执行状态，避免旧 payload、旧假设或旧 findings 在 agent memory 中被误当成当前事实。历史经验仍会通过 `hunt-memory/`、`findings/`、`reports/` 和 `/pickup` 提供给研究员主动判断。

同时，临时操作偏好不会跨目标继承：某一轮里声明的 focus lane、跳过模块、excluded bug class 或“忽略某类漏洞”只对当前目标和当前命令生效。新目标默认只保留 scanner 内置的 XSS lane 跳过；当前运行需要包含 XSS 时显式使用 scanner full。本地 / CTF / Lab 目标也不会因为上一目标的临时排除项、外部项目策略或竞争度启发式额外增加跳过项。

### 5. 请求守卫与本地 / CTF 目标

普通模式下提供：

- scope / excluded domain / excluded vuln class 提示
- `yolo` 模式下 unsafe method 提示
- 每 host 速率控制提示
- circuit breaker 提示
- audit log

对于本地、CTF、Lab 或其它明确给定的目标，默认采用以下语义：

- 所有请求辅助逻辑继续保持 advisory-only
- 不要求外部 policy 文本、allowed methods 或 `scope_snapshot.json`
- audit 仍保留

这个模式适合在靶场、CTF、本地实验环境或授权沙箱目标中使用。

### 6. Hunt Memory

能力包括：

- `journal.jsonl`：挖掘日志
- `patterns.jsonl`：跨目标成功模式
- `audit.jsonl`：请求审计
- `targets/<target>.json`：目标画像
- 自动 JSONL 轮转
- `/pickup` 续接历史挖掘
- `/pickup` 展示 structured findings 的验证/报告续接建议
- `/surface` 根据 recon、scanner findings、local intel 和 memory 排序攻击面
- `/remember` 保存发现和成功打法
- `/memory-gc` 管理日志大小

这是产品亮点之一：它让系统不是一次性扫描器，而是能跨会话积累测试上下文和成功经验。

### 7. 验证与报告生成

能力包括：

- 快速 triage
- 交付前验证门禁
- agent 读取 findings 后给出下一步 `validate.py --finding-id` 提示
- CVSS 4.0 计算
- HackerOne / Bugcrowd / Intigriti / Immunefi 风格报告模板
- 从扫描结果批量生成报告草稿
- 生成 `validation-summary.json`
- 在验证摘要中保留 scanner finding id、source file 和 finding summary
- 从结构化 finding 生成报告时写入 Finding Reference 证据引用块
- 验证和报告生成后回写 `findings.json` 中的 `validation_status` / `report_status`
- agent findings 摘要展示每个候选的验证/报告状态
- agent 生成报告后展示 report index，标明 report id、finding id 和报告文件
- `/surface` 会降低已生成报告 finding 的优先级，避免重复追踪已完成候选
- 与 `/remember --from-validate` 衔接

这一层用于把“扫描候选”推进为“可复现、可解释、可交付”的漏洞报告。

### 8. 情报能力

数据来源包括：

- GitHub Advisory
- NVD CVE
- HackerOne 公开披露
- 本地 hunt memory
- recon 提取出的 tech stack

输出会把 CVE / disclosure 和本地已测记录结合，区分已测与未测方向，辅助研究员优先选择更值得验证的目标。

后续会进一步演进为本地知识检索能力，把历史报告、验证摘要、目标画像、公开披露摘要和技术栈笔记沉淀为可检索知识上下文。

### 9. Web3 / Token 安全

能力包括：

- Solidity 审计方法论
- Foundry PoC 思路
- Meme coin / Token rug pull 检测
- EVM + Solana 支持
- Hidden mint
- Honeypot
- Fee manipulation
- LP drain / LP lock bypass
- Fake renounce
- Authority retention
- Sandwich / MEV amplification
- Bonding curve 风险

---

## 后续规划能力

以下能力已经纳入产品规划，当前定位为后续演进方向，不代表已经完整实现。

### 1. 域名资产监控

目标是把一次性侦察升级为持续资产观察能力。

规划能力包括：

- 周期性生成资产快照
- 记录新增 / 消失的子域名和 live host
- 识别 HTTP 状态码、title、技术栈变化
- 发现新增端口、API、JS、参数入口
- 将资产变化转化为可测试候选面

产品价值：

- 适合长期测试目标
- 帮助研究员优先关注新暴露资产
- 减少重复跑完整侦察带来的噪声
- 为后续 rerank 提供“近期新增”信号

### 2. 向量化知识库

目标是把历史测试经验、报告、验证摘要和安全知识沉淀为本地可检索上下文。

规划能力包括：

- 检索历史相似目标
- 检索相似漏洞模式
- 关联技术栈与历史打法
- 为情报分析、续接测试、自治挖掘提供上下文
- 支持关键词检索与后续 embedding 检索逐步演进

产品原则：

- 知识库只作为辅助上下文
- 不能把历史经验直接当作当前目标事实
- 当前目标证据始终优先于记忆和知识库召回

### 3. 候选目标 Rerank

目标是对侦察、扫描、情报、记忆和资产监控产生的大量候选入口做统一优先级排序。

当前已实现的第一阶段能力：

- `/surface` 读取 `findings/<target>/findings.json`
- scanner finding URL 会进入候选集合
- 根据 severity、confidence、漏洞类型做确定性加权
- `/surface` 读取本地 `recon/<target>/intel.json` / `intel.md`
- 根据 disclosed report / CVE / advisory 的漏洞关键词做确定性加权
- P1 / P2 输出展示可解释评分明细，例如 `Score: 17 = attack +2, scanner +15`

后续规划评分信号包括：

- 是否 live、是否在 scope 内
- 是否为 API / GraphQL / auth / admin / billing / export / upload 等高价值入口
- 是否包含 ID、token、redirect、file、callback 等敏感参数
- 是否来自新增资产
- 是否命中历史相似成功模式
- 是否有多来源证据支撑
- request guard / breaker / cooldown 状态

产品价值：

- 减少扫描噪声
- 帮助研究员快速找到最值得验证的入口
- 为自治挖掘提供更稳定的下一步决策依据
- 与未来知识库、资产监控形成闭环

---

## 功能全景

```text
┌──────────────────────────────────────────────────────────────┐
│                        Claude Code                           │
│   /recon /hunt /surface /js-read /validate /report /autopilot│
└──────────────────────────────┬───────────────────────────────┘
                               │
             ┌─────────────────┼─────────────────┐
             │                 │                 │
             ▼                 ▼                 ▼
      Slash Commands      AI Agents          Skills 知识域
        17 个命令          9 个角色             9 个技能
             │                 │                 │
             └─────────────────┼─────────────────┘
                               ▼
                         本地执行层
        recon / scan / source-hunt / intel / token-scan / report
                               │
                               ▼
                         Hunt Memory
             journal / patterns / audit / target profiles
                               │
             ┌─────────────────┴─────────────────┐
             ▼                                   ▼
        reports/ findings/                 MCP 集成
        报告与证据输出                     Burp / Caido / HackerOne
```

---

## 典型使用场景

### 场景一：单目标漏洞赏金测试

适用于拿到一个明确目标后，从侦察开始系统推进。

```text
/scope target.com
/recon target.com
/surface target.com
/hunt target.com
/validate
/report
/remember
```

产出：

- `recon/<target>/`：侦察数据
- `findings/<target>/`：候选发现
- `reports/<target>/`：报告草稿
- `hunt-memory/`：历史状态与模式沉淀

### 场景二：续接历史目标

适用于隔天或多轮测试后继续同一目标。

```text
/pickup target.com
/surface target.com
/hunt target.com
```

系统会尝试展示：

- 上次测试时间
- 已测试端点
- 未测试端点
- 历史发现
- 相关技术栈
- 跨目标成功模式建议

### 场景三：自治挖掘

适用于希望 agent 按固定节奏推进测试流程。

```text
/autopilot target.com --normal
```

默认会创建新的本地 agent session。这样同一个目标可以多轮测试，但每轮自治 agent 的 working memory 和 trace 都保持独立。

自治流程会围绕以下阶段执行：

```text
scope → recon → rank → hunt → validate → report → checkpoint
```

支持三种 checkpoint 模式：

| 模式 | 特点 |
|---|---|
| `--paranoid` | 更频繁停下来确认，适合新目标 |
| `--normal` | 按批次汇总结果，适合常规测试 |
| `--yolo` | 更少中断，适合熟悉目标；报告提交仍需人工确认 |

如果需要继续某一轮自治 agent 的精确上下文，应先查看 `/pickup target.com` 判断是否值得续跑，再显式指定：

```bash
python3 tools/hunt.py --target target.com --agent --resume latest
python3 tools/hunt.py --target target.com --agent --resume <session_id>
```

### 场景四：源码与 CI/CD 暴露检查

适用于检查本地代码仓库或公开源码中的高信号风险。

```text
/source-hunt target.com --repo-path /path/to/local/repo
```

主要检查：

- 私钥、访问令牌、云服务 key
- `.env`、配置文件、service account 文件
- GitHub Actions 不安全触发
- self-hosted runner 风险
- 第三方 action 未固定 commit SHA
- 用户输入进入 workflow shell 的风险

### 场景五：浏览器态业务逻辑与 IDOR 挖掘

适用于登录态页面、SPA、管理后台、用户中心、订单/发票/报表、审批/邀请/导出下载等需要真实页面交互的目标。

```text
1. /recon target.com
2. /hunt target.com, prioritize browser-state IDOR and business logic
3. 使用 playwright-cli 打开登录态页面并点击关键功能
4. 读取 recon/<target>/browser/ 中的 XHR/API/GraphQL 与参数
5. /surface target.com
6. 对高分接口做账号 A/B、对象 ID、角色/租户边界和业务流验证
```

如果有本地源码或前端 bundle，也可以补充源码情报：

```text
1. /source-hunt target.com --repo-path /path/to/repo
2. 运行 source intelligence lane
3. 查看 findings/<target>/source_intel/summary.md
4. 将假设回到浏览器态或精确 HTTP 请求中验证
```

### 场景六：智能合约与 Token 风险扫描

智能合约审计：

```text
/web3-audit ./contracts/Vault.sol
```

Token / Meme coin 风险扫描：

```text
/token-scan contracts/Token.sol
/token-scan programs/token/ --chain solana --recursive
```

覆盖方向包括：

- Hidden mint
- Honeypot
- Fee manipulation
- LP drain / LP lock bypass
- Fake renounce
- Solana authority retention
- Transfer hook / permanent delegate 风险
- Bonding curve 与 MEV 放大问题

---

## 主要模块说明

### 1. Slash Commands

`commands/` 目录提供 17 个 Claude Code slash 命令。

| 命令 | 功能 |
|---|---|
| `/scope` | 测试前确认资产范围 |
| `/recon` | 执行侦察流水线 |
| `/surface` | 根据侦察结果、scanner、intel 和记忆系统排序攻击面 |
| `/hunt` | 进入主动测试流程 |
| `/js-read` | 阅读 cached JS bundle，生成 JS 攻击面假设 |
| `/triage` | 快速判断发现是否值得继续 |
| `/validate` | 完整验证发现，计算 CVSS 4.0，生成验证摘要 |
| `/report` | 生成可编辑的漏洞报告草稿 |
| `/remember` | 将发现、端点、技术栈和成功模式写入记忆 |
| `/pickup` | 续接历史目标 |
| `/autopilot` | 运行自治测试循环 |
| `/intel` | 拉取 CVE、披露报告和本地记忆情报 |
| `/source-hunt` | 扫描源码泄露和 CI/CD 风险 |
| `/chain` | 辅助构造 A→B→C 漏洞链 |
| `/web3-audit` | 智能合约审计辅助 |
| `/token-scan` | Token / Meme coin 风险扫描 |
| `/memory-gc` | 管理 hunt-memory JSONL 日志大小 |

### 2. AI Agents

`agents/` 目录定义了 9 个角色化 agent。

| Agent | 角色 |
|---|---|
| `recon-agent` | 子域枚举、存活探测、URL 收集、nuclei 侦察 |
| `recon-ranker` | 攻击面优先级排序 |
| `validator` | 发现验证与弱发现淘汰 |
| `report-writer` | 漏洞报告撰写 |
| `chain-builder` | 漏洞链构造 |
| `js-reader` | 阅读前端 JS bundle，输出端点、认证模型、sink 和业务逻辑假设 |
| `autopilot` | 自治测试循环 |
| `web3-auditor` | 智能合约审计 |
| `token-auditor` | Token / Meme coin 风险审计 |

### 3. Skills 知识域

`skills/` 目录提供 9 个安全测试知识域。

| Skill | 说明 |
|---|---|
| `bb-methodology` | 漏洞赏金方法论、会话纪律、路线选择 |
| `bug-bounty` | Web2 / Web3 主测试工作流 |
| `web2-recon` | Web 资产侦察方法 |
| `web2-vuln-classes` | Web2 漏洞类型、绕过方式与检测思路 |
| `security-arsenal` | Payload、绕过表、常见误报与拒收清单 |
| `triage-validation` | 发现验证、报告前门禁、N/A 防御 |
| `report-writing` | 多平台报告模板与影响优先写法 |
| `web3-audit` | 智能合约审计方法 |
| `meme-coin-audit` | Token / Meme coin rug pull 风险分析 |

### 4. 本地工具层

`tools/` 是实际执行工具的集中目录，包含 Python、Shell 和 JavaScript 工具。

核心工具包括：

| 工具 | 功能 |
|---|---|
| `tools/hunt.py` | 主调度器 |
| `tools/recon_engine.sh` | 侦察流水线 |
| `tools/vuln_scanner.sh` | 主动漏洞候选扫描，含 upload / SQLi / SSTI / MFA / SAML 等检查 |
| `tools/source_hunt.py` | 源码暴露与 CI/CD 风险扫描入口 |
| `tools/source_intel.py` | 从源码、JS 和 recon 产物提取路由、GraphQL 和业务逻辑假设 |
| `tools/js_reader.py` | 为 `js-reader` agent 准备 cached JS 物料 |
| `tools/request_guard.py` | 请求前置检查、限速、断路器和审计 |
| `tools/scope_checker.py` | 确定性 scope 检查 |
| `tools/surface.py` | 攻击面排序，支持 scanner / intel / js_intel / browser / memory 确定性加权和可解释评分明细 |
| `tools/resume.py` | 历史目标续接摘要 |
| `tools/remember.py` | 发现与模式记忆写入 |
| `tools/intel_engine.py` | 情报聚合 |
| `tools/validate.py` | 发现验证与 CVSS 4.0 |
| `tools/report_generator.py` | 报告生成 |
| `tools/token_scanner.py` | Token 风险扫描 |
| `tools/memory_gc.py` | 记忆日志轮转与清理 |

---

## 侦察能力

侦察阶段会尽可能构建目标的可测试攻击面，主要产物包括：

```text
recon/<target>/
├── subdomains/      子域名结果
├── live/            存活主机和 HTTP 探测结果
├── ports/           端口扫描结果
├── urls/            URL、参数化 URL、API 端点、敏感路径
├── js/              JS 端点和潜在密钥
├── dirs/            目录 fuzz 结果
├── params/          参数发现结果
├── exposure/        配置文件暴露结果
└── cicd/            CI/CD workflow 扫描结果
```

支持的目标类型：

- 域名
- 单 IP
- CIDR 网段
- 域名 / 主机列表
- CTF / 本地靶场目标

---

## 漏洞测试能力

漏洞候选扫描会将发现按类别保存到 `findings/<target>/`：

```text
findings/<target>/
├── summary.txt       人类可读扫描摘要
├── summary.json      结构化扫描摘要
├── findings.json     结构化候选 finding 索引
├── upload/
├── sqli/
├── xss/
├── ssti/
├── takeover/
├── misconfig/
├── exposure/
├── ssrf/
├── cves/
├── redirects/
├── idor/
├── auth_bypass/
├── mfa/
├── saml/
├── metasploit/
└── manual_review/
```

其中 `summary.json` 会记录扫描模式、跳过模块、live/ordered target 数量、各类别计数、高价值 PoC 计数和人工复核项，便于 Claude Code agent 快速读取当前扫描状态。

`findings.json` 会把分散的 scanner `.txt` 产物归一成候选 finding 列表，包含 `id`、漏洞类型、URL、severity、confidence、源文件、行号和验证/报告状态。`/validate` 可以通过 finding id 预填目标、类型和 endpoint，`/report`/报告生成器也可以优先消费该结构化索引。

产品强调“候选发现需要验证”，因此扫描结果不会被直接视为最终漏洞。建议流程是：

```text
扫描候选 → 人工复现 → /triage → /validate → /report
```

---

## 记忆系统

Hunt Memory 是本项目区别于普通扫描器的关键模块。

默认目录：

```text
hunt-memory/
```

主要数据：

| 文件 / 目录 | 作用 |
|---|---|
| `journal.jsonl` | 挖掘日志，记录行为和结果 |
| `patterns.jsonl` | 成功漏洞模式，支持跨目标复用 |
| `audit.jsonl` | 请求审计记录 |
| `targets/<target>.json` | 目标画像，包含技术栈、端点、发现和测试历史 |

记忆系统支持：

- 自动记录会话摘要
- 记录已测试端点
- 记录未测试攻击面
- 复用跨目标成功模式
- 续接上次测试状态
- JSONL 文件自动轮转，避免无限增长

---

## 请求守卫与靶场模式

### 普通模式

普通模式下，`request_guard.py` 会在主动请求前记录和提示：

- URL 是否在 scope 内
- 是否命中排除域名
- 是否命中排除漏洞类型
- `yolo` 模式下是否使用了不安全 HTTP 方法
- host 是否触发 circuit breaker
- 是否建议等待速率限制

同时，每个请求会写入审计日志。

### CTF / Lab 目标

这类目标无需额外配置开关即可直接使用。

靶场模式适用于：

- 本地实验环境
- CTF 题目
- 内部练习靶场
- 用户明确授权的沙箱目标

启用后，请求侧限制继续保持 advisory-only：

- 不做外部 policy allowlist 阻断
- 不做 unsafe method 阻断
- 不做 circuit breaker 阻断
- 不做任何请求侧节流/冷却类阻断
- 不要求外部 policy 文本、allowed methods 或 `scope_snapshot.json`

审计记录仍会保留，便于复盘。

---

## MCP 集成

项目提供三个 MCP 集成方向。

### Burp MCP

用于让 Claude Code 读取 Burp Suite 中的 HTTP 流量，辅助：

- 查看 proxy history
- 复现请求
- 基于真实流量寻找端点
- 辅助 SSRF / XXE / blind injection 等 OOB 测试

### Caido MCP

用于让 Claude Code 读取 Caido 中的 HTTP 流量，辅助：

- 查看代理历史
- 基于已捕获流量寻找高价值端点
- 复放请求
- 辅助批量验证和上下文整理

### HackerOne MCP

用于访问公开漏洞赏金情报，包括：

- 已披露报告搜索
- 项目公开统计
- 项目公开 policy 和 scope 信息

---

## 输出产物

本项目的主要输出分为四类：

| 目录 | 内容 |
|---|---|
| `recon/` | 侦察数据、URL、技术栈、参数、JS、CI/CD 线索 |
| `recon/<target>/browser/` | 浏览器态 XHR/API/GraphQL、参数、表单和摘要 |
| `findings/` | 漏洞候选、验证摘要、源码暴露结果 |
| `findings/<target>/source_intel/` | 源码/JS 业务逻辑假设、路由、GraphQL operation 和关键词摘要 |
| `findings/<target>/js_intel/` | JS 阅读物料、LLM 读码后的端点、认证模型、sink 和攻击面假设 |
| `evidence/<target>/browser/` | playwright-cli 页面快照、请求、控制台、存储状态、可选截图和最新采集指针 |
| `reports/` | 报告草稿、报告索引、PoC 图片引用 |
| `hunt-memory/` | 目标画像、测试历史、请求审计、成功模式 |
| `targets/<target>/sessions/` | 本地 agent session、trace、bump 文件和 session 级 recon 工作区 |

这些目录共同支持复盘、续接、报告生成和跨目标经验复用。

其中 `hunt-memory/`、`findings/` 和 `reports/` 是目标级长期产物；`targets/<target>/sessions/` 是自治 agent 的运行级产物。默认新开 agent session 不会清空目标级历史，研究员仍可通过 `/pickup` 和 `/surface` 读取历史状态。

---

## 本地运行方式

在项目根目录启动 Claude Code：

```bash
claude
```

可选：创建本地配置文件。

```bash
cp config.example.json config.json
```

常用配置字段：

| 字段 | 说明 |
|---|---|
| `chaos_api_key` | 子域名侦察增强用 key |
| `h1_api_token` | HackerOne 相关能力预留配置 |
| `output_dir` | findings 输出目录 |
| `recon_dir` | recon 输出目录 |
| `reports_dir` | reports 输出目录 |
| `nuclei_severity` | nuclei 默认严重度 |
| `katana_depth` | 爬取深度 |
| `ffuf_threads` | fuzz 并发 |
| `interactsh_server` | OAST 服务配置 |

也可以直接运行底层工具：

```bash
python3 tools/hunt.py --target target.com --recon-only
python3 tools/hunt.py --target target.com
python3 tools/hunt.py --target target.com --scan-only --scanner-full  # 包含默认跳过的 XSS lane
# 仅当前命令显式需要临时排除时使用；默认不继承跳过项
python3 tools/hunt.py --target target.com --scan-only --scanner-skip module1,module2
python3 tools/source_hunt.py --target target.com --repo-path /path/to/repo
python3 tools/intel_engine.py --target target.com --tech nextjs,graphql
python3 tools/token_scanner.py contracts/Token.sol
```

---

## 推荐工作流

### 先记住这条续接规则

| 场景 | 用法 | 说明 |
|---|---|---|
| 想知道目标历史状态 | `/pickup target.com` | 读取目标级历史、未测端点、structured findings 和下一步建议 |
| 想继续测试目标 | `/hunt target.com` 或 `/autopilot target.com --normal` | 默认创建新的本地 agent session，避免旧运行状态串扰 |
| 想继续上一轮 agent 的精确状态 | `python3 tools/hunt.py --target target.com --agent --resume latest` | 复用上一轮 `agent_session.json`、trace 和 working memory |

简单理解：

- `/pickup` = “看历史和下一步建议”
- 默认 `/autopilot` = “开一轮干净的新自治测试”
- `--resume` = “继续上一次那个 agent 的脑子和执行轨迹”

### 标准 Web 目标

```text
1. /scope target.com
2. /recon target.com
3. /surface target.com
4. /hunt target.com
5. /triage
6. /validate
7. /report
8. /remember
```

### 已有历史目标

```text
1. /pickup target.com
2. /surface target.com
3. /hunt target.com
4. /remember
```

`/pickup` 面向目标级历史续接，适合先判断“上次测到哪里、还有哪些 finding 待验证、哪些端点还值得继续”。如果需要继续上一轮自治 agent 的精确本地状态，可在查看 `/pickup` 后显式续接：

```bash
python3 tools/hunt.py --target target.com --agent --resume latest
python3 tools/hunt.py --target target.com --agent --resume <session_id>
```

### 源码安全检查

```text
1. /source-hunt target.com --repo-path /path/to/repo
2. 查看 findings/<target>/exposure/repo_summary.md
3. 对高信号 secret / CI/CD finding 做人工确认
4. /validate
5. /report
```

### CTF / Lab

```text
1. /recon <target>
2. /hunt <target>
3. 根据题目目标手动验证 exploit path
```

---

## 产品边界

本项目定位为安全测试辅助工作台，而不是完全自动化漏洞确认系统。

它可以帮助完成：

- 信息收集
- 攻击面排序
- 候选漏洞扫描
- 方法论提示
- 证据整理
- 报告草稿生成
- 历史状态保存

最终仍需要研究员确认：

- 漏洞是否真实可复现
- 影响是否成立
- 资产是否属于授权范围
- 报告是否可提交
- PoC 是否足够清晰

---

## 总结

智能漏洞赏金工作台将安全测试中的侦察、扫描、验证、报告和记忆沉淀组合为一个本地化产品。它适合需要长期、多目标、可复盘工作的安全研究员，也适合在 CTF / Lab 环境中快速组织测试流程。

它的核心不是“自动提交漏洞”，而是帮助研究员更快地回答三个关键问题：

1. **哪里最值得测？**
2. **这个发现是否真的有影响？**
3. **如何把有效发现沉淀为下一次测试的优势？**
