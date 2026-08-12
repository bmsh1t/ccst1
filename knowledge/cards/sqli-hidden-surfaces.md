---
id: sqli-hidden-surfaces
type: technique-card
related_skills:
  - web2-vuln-classes
  - web2-recon
  - bb-methodology
  - triage-validation
trigger_tags:
  - sqli
  - hidden-input
  - request-metadata
  - path-segment
  - sibling-params
  - second-order
  - non-parameterizable
  - order-by
  - identifier
  - auth-secret
  - mfa-secret
risk: low-to-medium
maturity: draft
load_priority: high
deep_refs:
  - knowledge/payloads/sqli-low-risk-probes.md
source_refs:
  - type: corpus-report
    corpus: hackerone-disclosed-reports
    id: "1663299"
  - type: corpus-report
    corpus: hackerone-disclosed-reports
    id: "31756"
  - type: corpus-report
    corpus: hackerone-disclosed-reports
    id: "983710"
---

# SQLi 非显式输入面

## Quick Recall

- 常规 query/body 参数无信号时，不代表 SQLi lane 已完成；继续检查非显式输入面。
- 优先从目标证据出发：请求元数据、path/routing segment、cookie/session、JS/source/browser 参数、导入/上传字段、日志/审计/风控/报表链路。
- Header 示例是候选形态，不是固定字典：`X-Forwarded-For`、`X-Real-IP`、`Forwarded`、`User-Agent`、`Referer`。
- 路径示例是候选形态，不是固定字典：`/tenant/{id}`、`/report/{type}`、`/search/{keyword}`、slug、分类、地区码。
- sibling 参数迁移：从 A 接口提取 `sort`、`order`、`status`、`type`、`orgId`、`tenantId` 等少量高信号字段，喂给同业务 B 接口。
- Parser/encoding 差异：XML entity、URL/Unicode 编码、大小写、分隔符或 content-type 转换可能绕过前置过滤，解码后才进入后端 SQL 查询。
- SQLi 也别只盯值位：`ORDER BY`、列名/表名、占位符名、事务控制和跨表字段这类非参数化位置，经常是“看起来参数化了但实际没保护到”的盲区。
- SQLi 读到认证相关表时，不只停在 email/hash/schema；主动检查是否存在 MFA/TOTP secret、reset token、API key、session seed、OAuth link secret、step-up token 等认证连接器字段。
- 若认证连接器字段可读，再评估能否低影响串成 `数据提取 -> step-up/MFA/reset/token 流程 -> victim session/role proof`；报告时不打印 secret、一次性验证码或完整 token。
- 验证顺序：baseline -> 单变量扰动 -> 稳定差异 -> 最小证据 -> 必要时再工具化确认。
- 只把可复现的状态码、长度、错误类型、排序、布尔响应、字段集合或 DBMS 指纹差异作为信号。
- 单次 500、WAF/路由差异、缓存 miss 或不可复现异常不能升级为 Candidate。
- 大 payload、绕过矩阵和工具参数按需读取 `knowledge/payloads/sqli-low-risk-probes.md`。

## 技巧与薄判断层

### 1. 请求元数据

- **操作**：从目标证据选取被应用信任、记录或消费的 Header/cookie/trace 字段；对可能进入字符串查询的位置做 `baseline -> ' -> ''` 成对比较。
- **判断**：先确认 `client -> edge/proxy -> application` 的最终值；代理覆盖、重复 Header 合并或日志写入只证明传输/存储，不证明 SQL sink。
- **转向**：当前响应无差异但值进入日志、风控或报表时，保存唯一无害 marker，转 `store -> trigger` 二阶验证。

### 2. 路径段

- **操作**：保持 method、suffix 和路由形状，对 `/a/b/c` 逐段单变量比较：`/a/'` vs `/a/''`，再 `/a/b/'` vs `/a/b/''`。
- **判断**：用合法值、不存在值和扰动证明请求仍进入同一 handler；统一 404、SPA fallback 或 rewrite 差异不是 SQL 信号。
- **转向**：引号只造成框架错误、系统路径/源码泄露时，单独记录信息泄露；继续 SQLi 需要查询特异差异。

### 3. Sibling 参数束

- **操作**：从 A 的真实请求取得完整参数束，例如 `?limit=1&xxxid=100`；原样附到同业务 B，再按顺序比较：
  `B baseline -> B?limit=1&xxxid=100 -> B?limit='&xxxid=' -> B?limit=''&xxxid=''`。
- **判断**：整束对照只用于激活隐藏 binder/query branch；稳定变化后再二分移除、逐字段隔离，分别区分“被接收、业务生效、影响查询、可注入”，不能从参数生效直接跳到 SQLi。
- **转向**：B 与 A 无共享资源、handler、schema 或 query builder 证据时，停止追加参数，不构造通用字典。

### 4. 非参数化查询位置

- **操作**：发现排序列/方向、投影字段、动态表/列名、`GROUP BY` 或分页表达式时，用合法 A、合法 B、无效标识符做对照；不要对标识符机械使用引号。
- **判断**：排序变化只证明字段被消费；未知列/别名/ORM 错误随输入变化，或稳定 DBMS 差异，才支持继续确认。

### 5. Parser、编码与结构化载体

- **操作**：确认 query/form/JSON/XML/multipart、EXIF/QR 等载体的解析链；一次只改变一个编码、字符集、容器或 metadata 字段，比较 raw input、规范化值和查询响应。
- **判断**：只有前置过滤看到的值与 query builder 消费的值不同，才是 parser differential；WAF 接受/拒绝、上传成功或 QR 解码成功本身不是 SQLi。
- **转向**：没有 parser/source 证据时不加载绕过矩阵；把载体交给对应 upload/XML/browser 路径。

### 6. 二阶 SQLi

- **操作**：记录 `写入 endpoint/字段 -> 持久化或队列 -> 触发 endpoint/job -> 可观察差异`；使用测试账号、唯一无敏感 marker 和已知异步窗口，分别保存 store、trigger、control。
- **判断**：写入成功、后台展示变化或一次异步错误只是 Signal；重复触发且差异与 marker 关联，才进入 Candidate。

### 7. 已确认 SQLi 的影响转向

- 认证/MFA/reset/session/OAuth 字段是影响评估，不是默认枚举目标；只在自有/授权测试账号上证明中间 token/step-up 到 session/role 的低影响差异。
- 公开报告只记录字段存在性、长度/指纹、流程状态和身份差异，不打印 secret、一次性验证码或完整 token。

## 触发信号

- source/schema/错误显示字段进入动态查询、排序、投影、标识符或后台检索。
- 同业务 endpoint 参数集合不同，但共享资源、handler、schema 或 query builder。
- JS/XHR/browser 流量出现 UI 当前路径未传、服务端仍绑定的字段。
- store 后的值被审计、统计、报表、搜索索引或异步任务再次查询。

## 最小验证

- 选择目标证据最强且影响最低的一个输入面；保存稳定 baseline、合法 control 和反事实 control，只改变一个输入/转换维度。
- 归一化动态字段后比较错误、布尔、字段集合、排序、结果范围和 DBMS/ORM 指纹；复测 2-3 次并交换请求顺序。
- 记录 `why now/endpoint/method/input/source evidence/query context/baseline/control/observed difference/positive meaning/negative pivot/stop condition/evidence ref`。

## 常见误判 / 死路

- 每个假设写成 `输入来源 -> binder/parser/store -> 查询位置 -> 预期差异 -> control -> 下一问题`。
- 分开判断：输入可达、binder 接收、查询消费、查询可注入、业务影响；前一层不能替代后一层。
- 强 Signal：DB/ORM 查询错误、可重复布尔反转、输入一致的标识符错误、DBMS 指纹或二阶 trigger 关联。
- 弱 Signal：单次 500、长度/排序变化、WAF block、统一 404、缓存 miss、超时或普通业务空结果。
- 无稳定差异、只改变路由/WAF、无法关联查询，或需要破坏性写入/批量枚举时停止并转相邻机制。

## 晋升到 Skill / Queue 的条件

- 只有类别推测：保持知识建议，不创建 Action。
- 有明确 endpoint、method、input、source evidence、query context 和 next question：可写入 Action Queue。
- 有稳定 baseline-vs-perturbation 差异：交给 `web2-vuln-classes` 深入验证。
- 需要 parser、二阶、认证态、browser 或 source 证据：转对应深层路径，不在本卡扩大枚举。

## 关联 Skills

- `web2-vuln-classes`
- `web2-recon`
- `bb-methodology`
- `triage-validation`

## 可晋升经验

- 同类框架/网关中某输入面多次出现稳定查询差异，并有可复现 evidence ref。
- 某 path/routing 变量或 sibling 参数在不同 endpoint 重复触发同类后端分支。
- 晋升时记录适用条件、原始操作、反例、最小验证和停止条件，不保存目标特定值。
