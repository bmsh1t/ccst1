---
id: information-disclosure-source-config
type: technique-card
related_skills:
  - src-hunting
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

本卡给 `src-hunting` 和 `triage-validation` 提供信息泄露的影响建模和补漏清单。

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

- `src-hunting`
- `triage-validation`

## 晋升到 Skill / Queue 的条件

- 有非公开证据和可验证影响链时写入 action queue，类型 `information-disclosure-source-config`。

## 源码问题方法：可达性、守卫与运行桥接

本节把已有源码取证与 Candidate 合同展开为可操作方法；保留本卡 `draft` 身份，
不代表新知识已通过盲答或晋升。适用于已有源码/JS/依赖材料以及明确调查问题；
仅有组件名称、危险函数名或公开仓库 URL 时，先回答材料/路径缺口，不宣布漏洞。

### 从问题找入口，不从 sink 命中推漏洞

1. 写出待区分的解释，例如“调用者能选他人对象”与“服务端按当前租户重取对象”。
   标明来自请求、队列、文件、消息还是浏览器的输入，以及攻击者实际可控的字段/角色。
2. 原生 Read/Grep 定位路由注册、导出调用者、消息订阅或任务入口；反向从 sink 找调用者、
   正向从输入追参数，直到两者在同一版本和构建条件下连接。只定义未注册的 handler、
   未导入模块、测试代码、不可满足分支不是可达路径；动态注册缺实现时是未知而非不可达。
3. 按赋值、解码、规范化、类型转换、拼接、存储/重读列出数据流。指出哪一步保留或消除
   可控性。异步/二阶路径需同一对象及消费时状态；相同字段名不证明是同一值。
4. 阅读入口、中间件、服务层和 sink 前的 guard：认证不等于对象授权；比较的是谁与谁、
   使用规范化前后哪个值、失败是 return/throw 还是仅日志、异常分支是否仍能落入 sink。
   授权查询 `id AND tenant_id=current_tenant` 能阻断指定跨租户路径；前端隐藏按钮不能。
   guard 的位置按被保护的影响判断：先取行、再核对所有权、失败时阻止返回/序列化，也能阻断
   未授权数据返回，不要求一律先于 lookup。写入、外部发送等已经发生的副作用则不能靠后置
   return/throw 撤销；必须检查实际影响前的控制流及异常是否被转成放行。
5. 说明 sink 的真实语义与影响对象：查询是否参数化、模板是否解释输入、路径是否先限定
   根目录、出站 URL 是否受实际解析/重定向规则约束。不把名称含 eval/exec/render 的包装器
   当作已经证明执行，也不因出现 escape/filter 就认为任意上下文安全。

输出应能定位每个边的原件与行范围，并说明可达条件、guard 的反证及尚未读到的边。
不必构建 AST 或穷尽所有函数；停止于已回答的问题或明确的材料缺口。

### 源码与黑盒事实的双向连接

- 源码发现对象 lookup 缺租户条件：提出同一动作、两个自有身份/对象的最小对照；
  原件解释候选，实际返回数据与服务端副作用才解释运行影响。是否执行由现有 owner 决定。
- 黑盒出现差异：用实际方法/path/参数/状态定位路由与 consumer，检查缓存、代理、默认值
  或部署分支是否也能解释差异；不要先认定差异就是源码中的问题。
- 记录仓库来源、已知 revision、**当前字节 hash/原件 + file:line**。dirty 工作树以保存
  的字节为准；无 Git 不虚构 revision。行号本身不能绑定内容，源码变更后旧行号不再复用。
  同时讨论 HEAD 与工作树时，分别给出各自可展开的原件和字节 hash；某一份未取得就标未知。
  分支名、另一版本的 hash 或省略号路径不能代替当前分析字节的引用。
- lockfile 是声明的依赖版本，不一定是部署版本；构建开关、生成代码、运行配置、权限、
  依赖实际加载版本都可能改变路径。只有公开 main 分支时，把部署对应标 unknown。
- 若源码显示开放而运行拒绝，保留“源码条件下开放”与“本次运行条件下拒绝”两条证据；
  检查版本、入口、身份、网关/feature flag，不用较新分析覆盖反证，不因一次拒绝判永久安全。
  若源码版本已知不同，不把两条证据拼成可利用链。
- 下一项对照只改变一个待区分因素，固定其余身份、对象、编码、入口、构建和配置；缺少固定
  条件时，先读对应部署原件或请求轨迹。状态码变化本身不能识别部署版本或拒绝层；应以同次
  请求的 handler 到达/守卫分支证据定位，仍无法区分就保留两种解释，不把相关性写成原因。

### 正例与阻断反例

同一合成问题：“当前租户能否读取另一租户的记录？”

```python
# 已注册路由传入 request.actor 与 request.query["id"]。
def read_record(actor, record_id, db):
    return db.get(record_id)

# 在同样的已注册路径上，服务端所有权检查先于返回。
def read_owned_record(actor, record_id, db):
    record = db.get(record_id)
    if record.tenant_id != actor.tenant_id:
        raise PermissionError("tenant mismatch")
    return record
```

第一段只有在路由实际注册、输入可控、上游没有对象级 guard、db.get 不做租户过滤且部署
对应成立时，才形成条件化跨租户读取候选；未做运行对照不能声称已读取真实数据。
第二段在 actor 租户可信且异常不被转成放行时阻断这条路径，不说明其他写接口也安全。
若第一段根本未注册，sink 存在不证明可达；若只拿到该函数片段且缺路由/中间件，则两段的
外部可达性均未知。guard 自身 actor 来源未知时也不能断言保护有效。

### 成功证据、停止与重开

- 源码层完成：问题有条件化回答，入口/数据流/guard/sink 的关键原件可展开，最强反例及
  未决条件明确。它不是 Finding/报告资格；纯源码影响也由 assessment owner 显式评估范围。
- 无法读源码、动态加载实现不在材料中、文件过大、编码不可读、构建产物缺失或缺工具：
  返回 partial/blocked、已读范围、未知剩余量及下一精确文件/符号/版本入口，不自动联网补齐。
- guard 或不可达证据只终止本路径；预算停止不判 clean。新部署版本、注册路径、身份、
  guard 实现或运行反证能重开；用新原件引用接续，保留旧条件与结论。
- 进入验证门需 file:line、字节绑定、完整相关数据流、前提与反例。源码建议不自动执行、
  开 Action、确认 Finding 或提交报告；相邻影响方法按当前问题读
  `knowledge/playbooks/web2-evidence-contracts.md`，跨会话结果按
  `skills/whitebox-audit/SKILL.md` 返回调查核心。
