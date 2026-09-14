# claude-bug-bounty → ccst 内容对账表（2026-09-14）

> 目的：消灭"原项目某段内容去哪了"的考古成本。claude-bug-bounty（弱模型教学路线，
> skills 9,883 行 + rules 357 行 + 根级 SKILL.md 1,223 行双副本）与 ccst（强模型契约
> 路线，skills 1,646 行）同源分化；本表是对全部块的逐块审判记录。
> 判定框架：三问试金石（①模型见过吗 ②可从证据推理吗 ③需真实成本才知道吗）+
> 盲答自检（先盲答，答得出 = ①/②，不入库）。
> 改写历史：`39bf09b`（7月拆百科，checklist→专项skill+知识卡）→ `1be2efa`
> （S1 原生路由，description 改写为入口契约）→ `f75eff6`（判断层删除，三问落地）。

## 一、原项目 rules/hunting.md（20 条）

| 原条目 | ccst 去向 | 判定 |
|---|---|---|
| #0 授权语境 | CLAUDE.md + override.md + config ctf_mode | ccst 更强（config 驱动） |
| #1 READ FULL SCOPE FIRST | `/scope` + scope_hash 校验 | 机械化（原版靠自觉） |
| #2 NEVER HUNT THEORETICAL | triage-validation 7Q Gate Q1/Q2 | 已有 |
| #3 KILL WEAK FAST | claim 契约必填 `kill_condition` | 机械化（门禁不是提示） |
| #4 资产显式 scope 核查 | scope manifest + out_of_scope wins | 机械化 |
| #5 5-MINUTE RULE | rules/hunting.md Low-Signal Rotation | 已有（按信号不按时钟） |
| #6 AUTOMATION=高重复率 | 无对应 | ①判断层，不加 |
| #7 IMPACT-FIRST | Operator Contract 高价值优先 | 已有 |
| #8 少饱和漏洞类 | 无 | 不适用（猎人选目标经济学，非深度工具） |
| #9 DEPTH OVER BREADTH | depth contract 16 字段 | 机械化 |
| #10 SIBLING RULE | rules/hunting.md:143 | 已有且更强（evidence-linked，防盲测） |
| #11 A→B SIGNAL | rules/hunting.md:147 + 身份证据锚 | 已有（见下文 A→B 专项段） |
| #12 NEW==UNREVIEWED | coverage-prompts 卡 + Version/sibling lens | 已有 |
| #13 FOLLOW THE MONEY | rules/hunting.md:158 | 已有 |
| #14 20-MINUTE ROTATION | Low-Signal Rotation + Rotation 指纹 | 已有 |
| #15 业务影响>漏洞类 | Q2 impact tier evidence bar | 已有 |
| #16 VALIDATE BEFORE WRITING | `/validate` owner | 机械化 |
| #17 凭证泄露需利用证明 | credential/public-package 卡链路段 | 已有 |
| #18 MOBILE 攻击面 | mobile-pentest skill（77 行契约版） | 已有 |
| #19 CI/CD 攻击面 | cicd-security skill（74 行契约版） | 已有 |
| #20 SAML 高密度 | signature-scope-mismatch + xxe 卡 | 已有 |

小计：17 已有（多数更强）、3 不加（#6 判断层 / #8 不适用 / #11 可推理）。

## 二、原项目 rules/reporting.md（12 条）

11 条由 ccst rules/reporting.md（120 行）+ report-writing skill 全覆盖（禁理论语言、
PoC 最低标准、CVSS 匹配、never-submit、IDOR 双账号、标题公式——逐条同源）。

原项目独有 2 条，均为赏金谈判经济学：
- **#10 ESCALATION LANGUAGE**（降级申诉话术）→ backlog 低优先，实战遇到再议
- **#11 独立 bug 拆开报** → ①可推理，不入

## 三、skills 层：12 同名 + 3 ccst 没有

12 个同名 skill 全部改造为契约形态（教学手册 → Entry/Evidence/Stop 契约 + 决策树，
probe shapes/tool syntax 归模型）。行数：bug-bounty 1,645→108、web2-vuln-classes
1,838→189、web2-recon 626→224、report-writing 501→145、triage-validation 309→342
（反向增厚：NEVER SUBMIT 68 行是 AB 评测 T05 证明的校准砝码，保留）。

3 个 ccst 没有的 skill 的去向：

| 原 skill | 去向 | 判定 |
|---|---|---|
| graphql-audit（523 行） | knowledge/cards/graphql.md（88 行触发卡） | 已覆盖 |
| argus（142 行路由表） | vuln_scanner 自动管线 + web2-vuln-classes Pattern Map | 已覆盖 |
| client-reverse（292 行） | Pattern Map 签名信号行（86104f1，2026-09-14 补） | 唯一路由缺口，已补一行 |

## 四、原 bug-bounty 百科 163 段的块级去向

| 原版块 | 去向 | 判定 |
|---|---|---|
| 工具命令手册（ffuf/Semgrep/Go binaries，~40%） | 模型知识① + tools/recon_engine.sh 内建 | 不搬 |
| 漏洞类 checklist（IDOR/SSRF/Race/OAuth/SSTI/ATO 等，~30%） | web2-vuln-classes 决策树 + 57 张活跃卡 | 不搬（逐类盲答全过） |
| TOP 1% MINDSET（Pre-Hunt 4 步 + Mindset Rules 7 条） | **bb-methodology Developer-View Pre-Hunt Recall 整段保留**（斜体保留原条目名溯源），second-order→second-order-sink 卡、diffs→view-differential 卡、trust boundary 链路升级 4 层→7 层、读披露报告→disclosed-researcher agent、follow money→rules/hunting.md | **整段在位且部分更强** |
| 7Q Gate / 4 Gates / Never Submit | triage-validation skill（唯一 owner） | 保留（校准缺口，③+AB 证据） |
| H1/Bugcrowd/Intigriti/Immunefi 模板 | report-writing + rules/reporting.md | 已有 |
| Quick Wins / Tech Fingerprinting 表 | scanner 自动查 + intel 命令 + ① | 不搬 |
| 语言 grep（pickle/type juggling 等） | ① + insecure-deserialization 卡边界部分 | 不搬 |
| Cloud misconfig（metadata/IMDS） | ssrf-internal-impact 卡（含红线：证明触达即停，不读凭证） | 已有且红线更强 |
| Subdomain Type→Strategy 表 | path-pattern-management-exposure 卡（borderline，pull 观察中） | 边缘观察 |
| Real Examples（Coinbase/Vienna 链） | ①公开披露案例，模型见过 | 不搬 |
| 根级 SKILL.md 1,223 行 | — | 旧版双副本事故现场，反面教材（不维护单一真源的代价） |

## 五、A→B Cluster Hunting 专项（2026-09-14 追加对账）

原版三组件的分解审判：

1. **6 步 Cluster 协议**（CONFIRM→MAP→TEST→CHAIN→QUANTIFY→REPORT）= 真决策方法，
   **已在 rules/hunting.md**：Sibling Rule（145）、A-to-B Signal Method（147）、
   one-report-per-chain 在 triage-validation chain precedence。已存在，不新建。
2. **Known A→B→C 组合表（10 行）** = ①全覆盖（IDOR读写升级→api-idor 卡 78 行、
   SSRF→metadata→IAM→ssrf-internal-impact 卡、open redirect→OAuth→triage-validation
   282 行条件表、GraphQL field auth→graphql 卡，其余 5 行盲答全过）。表的价值在
   "确认 A 后想到 B"的姿态，姿态由身份证据锚 + A-to-B 段持有更强形态；10 行具体链
   是姿态的例子，例子归模型。不入库。
3. **Real Examples** = ①（公开披露案例）。不入库。

## 六、agents/ 对比（10 vs ccst 11）

同名 8 个全部重写缩小（token-auditor 195→72、web3-auditor 174→94、report-writer
193→79）。关键差异：
- 原项目 `model: claude-sonnet-4-6` 硬钉模型；ccst `model: inherit` + 弹性降级
- 原项目 agent 内全文重抄 7Q Gate（validator 与 skill 第四处重复）；ccst agent 只写
  判定权和输出格式，Gate 细节归 triage-validation 唯一 owner
- ccst 独有：js-reader（JS 攻击面假设）、disclosed-researcher（历史报告挖掘）
- 原项目 hooks（3 个 echo 提醒）被状态机 owner 体系完全替代

## 七、从原项目实际搬入 ccst 的全部内容（终局清单）

| 项 | 落点 | 状态 |
|---|---|---|
| OOB marker 归因（唯一幸存工程借鉴） | oast_listen.py markers 子命令 | f3554af 已落地 |
| client-reverse 签名路由缺口 | web2-vuln-classes Pattern Map 一行 | 86104f1 已落地 |
| escalation 话术 | backlog | 实战触发再议 |
| 其余全部（163 段 + 20 条 rule + 12 skill + 10 agent） | 已有更强形态 / 判①归模型 / 不适用 | 无动作 |

对比线闭环。后续若再翻原项目，本表是第一查询点：先查此表，再决定是否需要重新考古。
