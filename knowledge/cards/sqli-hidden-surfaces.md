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
maturity: proven
load_priority: high
deep_refs:
  - knowledge/payloads/sqli-low-risk-probes.md
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
- 若认证连接器字段可读，再评估是否能低影响串成 `数据提取 -> step-up/MFA/reset/token 流程 -> victim session/role proof`；报告时不打印 secret、一次性验证码或完整 token。
- 验证顺序：baseline -> 单变量扰动 -> 稳定差异 -> 最小证据 -> 必要时再工具化确认。
- 只把可复现的状态码、长度、错误类型、排序、布尔响应、字段集合或 DBMS 指纹差异作为信号。
- 单次 500、WAF/路由差异、缓存 miss 或不可复现异常不能升级为 Candidate。
- 大 payload、绕过矩阵和工具参数按需读取 `knowledge/payloads/sqli-low-risk-probes.md`。
- 深挖时优先使用本卡和 `knowledge/payloads/sqli-low-risk-probes.md` 中已蒸馏的 Header、
  EXIF/QR/XML、二阶、parser/DBMS 差异和证据模型；历史 CTF 来源只在审计文档中追溯，不进入默认上下文。

## 能力定位

本卡用于 SQLi 测试中常规 query/body 参数无信号时，补充非显式输入面、跨接口参数、请求元数据和二阶链路的联想方向。输出候选假设、发散问题和最小验证提示，供当前 SQLi lane 选择使用。

## 核心原则

- 显式 query/body 参数无信号时，不代表 SQLi lane 已完成；需要回看所有“请求可控、前端未显式传、被存储后再使用、或被服务端转换后进入查询构造”的输入面。
- 标准验证链路是输入面枚举 -> baseline -> 单变量扰动 -> 稳定差异 -> 最小证据 -> 必要时再工具化确认。
- 请求元数据、路由片段、cookie/session 线索、跨接口参数、导入/上传字段、日志/审计/风控/搜索/排序/报表等，都是非显式输入面的例子，不是固定清单。
- 自动化默认不固定打某几个 header 或路径，不做长时间 time-based 枚举、高并发探测、破坏性写入、真实数据修改或批量导出。

## 思路分支

- 输入面扩展：把“用户可控输入”从 query/body 扩展到请求元数据、路径/路由变量、cookie、内容协商字段、前端未传但后端读取的参数、以及二阶存储/日志触发链路。
- 同业务横向复用：从 sibling endpoint、JS/source、浏览器 XHR、历史请求和 schema 中提取参数/字段名，验证同一业务查询函数是否存在未暴露分支。
- 差异闭环：只把可复现的状态码、长度、错误类型、排序、布尔响应、字段集合或 DBMS 指纹差异作为信号；单次 500 或 WAF/路由差异只记 Signal/Dead End。
- 二阶建模：如果输入先进入日志、审计、风控、统计或报表，再在后台查询中触发差异，必须记录 store step 和 trigger step。
- 认证连接器链：如果 SQLi 可读用户、认证、MFA、reset、token、session、OAuth/linking 表或字段，不要只把它当“数据泄露”；优先判断这些字段是否能驱动后续认证流程并形成可验证 session/role 差异。
- 工具化门槛：只有出现稳定 baseline-vs-perturbation 差异后，才考虑交给 sqlmap/ghauri/人工 payload 矩阵做低风险确认。

## 技巧家族 / Payload 家族

- 请求元数据扰动：针对被服务端信任、记录或转换的 header / cookie / trace id 做低风险成对扰动。
- 路由变量扰动：逐段建模 path segment、rewrite 后路径、slug、租户/分类/报表类型等服务端查询输入。
- sibling 参数迁移：从同业务接口提取高信号参数，少量迁移到 B 接口，再做单变量差异验证。
- 二阶触发链路：区分 store step 和 trigger step，重点看日志、审计、风控、统计、报表、搜索索引、导入预览。
- Parser/encoding 绕过：如果 XML/JSON/form/multipart/content-type 转换路径不同，尝试低风险等价扰动；例如 XML entity 编码后的 SQL 片段可能先过 WAF，再由 XML parser 解码进入查询。
- 低风险 probe 家族：单引号/双单引号、括号、布尔等价、编码等价、排序/字段集合差异；长 payload 和工具矩阵见 deep refs。

## 候选形态示例

这些只是联想种子，不是固定字典；只有目标材料、请求语义、JS/source、
历史请求、相邻接口或稳定差异支持时才优先尝试。

- 请求元数据：`X-Forwarded-For`、`X-Real-IP`、`Forwarded`、`User-Agent`、`Referer`、`Accept-Language`、追踪 ID、客户端版本字段。
- 路由片段：`/user/{slug}`、`/tenant/{id}`、`/report/{type}`、`/search/{keyword}`、CMS slug、分类名、地区码、版本号。
- sibling 参数复用：把 A 接口里的 `sort`、`order`、`status`、`type`、`orgId`、`tenantId`、`scope` 少量喂给同业务 B 接口。
- 二阶链路：登录日志、访问审计、风控黑白名单、统计报表、搜索索引、导入预览、上传 metadata。
- 认证连接器：MFA/TOTP secret、recovery/reset token、email verification token、API key、OAuth/link secret、session seed、remember-me secret、step-up/challenge token 相关字段；这些是链路候选，不是默认枚举目标。
- 编码/parser 形态：XML entity、URL/Unicode 编码、大小写/注释/分隔符变体、JSON/form/XML content-type 差异；示例只是候选，不代表默认绕过矩阵。
- 低风险扰动形态：单引号、双单引号、括号、布尔等价扰动或编码等价扰动；必须单变量对照，不能高频 time-based。

## 默认不执行的动作

- 不把具体 header、路径格式、参数名、payload 或工具选择写成必选流程。
- 不把请求元数据、路由片段、跨接口隐藏参数或二阶链路视为穷尽列表；它们只是“非显式输入面”的常见示例。
- 不执行高频 time-based、OOB 扩大验证、批量数据枚举、破坏性写入或会影响真实业务状态的动作。
- 不在公开报告中打印可用 secret、一次性验证码、完整 session/JWT/API key；只记录字段存在性、长度/指纹、流程状态和身份差异，原始敏感证据留在本地 evidence。

## 适用场景

- 常规 query/body 参数没有 SQLi 信号，但目标存在复杂 API、日志、风控、搜索、权限或资源查询逻辑。
- recon、JS、浏览器 XHR 或 source-intel 显示同一业务有多个 sibling endpoint。
- 目标有代理/WAF/CDN、客户端识别、审计日志、访问统计、黑白名单、风控、报表或后台管理功能。
- `/autopilot --deep` 中 SQLi lane 不能只停在 `?id=`、`q=`、`search=` 等显式参数。

## 触发信号

- 请求元数据被后端信任、转换或记录，例如代理链、客户端标识、来源、内容协商、追踪 ID、cookie/session 辅助字段等。
- URL path segment、路由变量或 rewrite 规则可能承载资源名、slug、租户、地区、分类、权限路径、版本或 CMS 路由。
- 某接口有高信号参数，另一个同业务接口前端未传这些参数，但后端可能共享查询函数或字段绑定。
- JS/source/browser 流量暴露了内部、管理、配置、导出、搜索、报表、审计、统计等同业务 endpoint。
- 单引号、双单引号、括号或编码后的等价扰动导致状态码、长度、错误、排序或响应结构稳定变化。

## 补充 Checklist

- 是否只测试了 query/body，而没有回看请求元数据、路径变量、cookie/session 或 trace/client 字段？
- 是否从 JS/source/browser XHR、历史请求、schema、OpenAPI/Postman 泄露中提取了同业务参数？
- 是否对 path segment 逐段建模，而不是把所有路径差异都当作路由 404？
- 是否考虑了日志、审计、风控、搜索、排序、报表、导入/上传 metadata 的二阶查询？
- 如果能读认证相关表/字段，是否检查了 MFA/TOTP secret、reset/recovery token、session/token seed、OAuth/linking secret 等“能继续驱动认证流程”的连接器？
- 是否把疑似信号写回 action queue，避免只在总结里写“后续测试 SQLi”？

## 发散问题

- 后端是否把请求元数据、cookie、追踪 ID、客户端来源、路径变量或导入字段写入日志表，或用于风控/审计/报表查询？
- 路由中间件是否把 path segment、rewrite 后的路径或 slug 抠出来做资源、权限、分类、租户或 CMS 查询？
- 同业务接口的参数是否能横向复用，触发后端公共查询函数里的隐藏分支？
- JS/source/browser 里出现但 UI 当前路径不传的参数，是否仍被后端读取？
- SQLi 可读出的字段是否能和登录、MFA、reset、invite、OAuth linking、remember-me 或 token refresh 流程对接，形成可证明的 session/role 改变？
- 响应差异是数据库语法/布尔/类型差异，还是只是路由/WAF/缓存差异？

## 最小验证

- 先列出目标相关输入面：显式参数、请求元数据、cookie/session 辅助字段、path/routing segment、JS/source-derived 参数、导入/上传字段、stored/log-backed 二阶输入。
- 对低风险、只读请求做成对扰动，比对 baseline、单引号、双单引号、括号或等价编码后的状态、长度、错误、排序、字段集合和时间。
- 对 path/routing segment 逐段建模；每次只改变一个 segment，确认差异不是路由 404、缓存 miss 或 WAF 规则。
- 从已知接口提取参数集，将同业务 sibling endpoint 追加少量高信号参数，再对单个参数做成对扰动。
- 对所有疑似信号先做 2-3 次稳定性复测，再决定是否交给 `sqlmap -r` 或 `ghauri`。
- 优先记录最小证据：请求、响应差异、受影响输入面、DBMS 指纹或稳定布尔差异。
- 读到认证连接器字段时，用自有/授权测试账号或靶场账号做最小链路验证：先证明字段可读，再证明中间 token/step-up/reset/MFA 流程可被驱动，最后只用只读身份页或低影响 endpoint 证明 session/role 差异。

## 晋升到 Skill / Queue 的条件

- 只是“可能有隐藏 SQLi 输入面”时，保留为知识启发，由当前 SQLi lane 决定是否继续。
- 出现稳定 baseline-vs-perturbation 差异时，交给 `web2-vuln-classes` 做 SQLi lane 深入验证。
- 出现明确 endpoint/input/next question 时，写入 `tools/action_queue.py`，类型可标记为 `sqli-hidden-surface`。
- 需要二阶触发、认证态、浏览器态或 source 证据时，转对应 Skill / browser / source enrichment，而不是盲打 payload。

## 关联 Skills

- `web2-vuln-classes`
- `web2-recon`
- `bb-methodology`
- `triage-validation`

## 停止条件

- 单引号/双单引号/括号扰动只产生 WAF、路由 404、缓存 miss 或不稳定网络抖动。
- 非显式输入面无法稳定影响响应，且没有错误、布尔、时间、排序或字段集合差异。
- 继续验证需要破坏性写入、批量请求、高延迟 time-based 枚举或真实数据修改。
- 只有一次性报错，无法复现或无法关联到数据库查询。
- 认证连接器字段只是 masked、空值、不可用历史值，或后续 step-up/reset/MFA 流程绑定了不可绕过的服务端状态。

## 检查要求

- 不要只凭 500 或报错文本升级为 Candidate，必须有稳定对照。
- time-based 只能作为最后确认路径，必须有 control 请求，不能用高并发或长时间 sleep。
- 如果输入面位于日志、审计、风控等二阶路径，必须记录 store step 和 trigger step。
- 报告前必须说明攻击者可控输入、查询影响、可复现差异和实际业务影响。

## 可晋升经验

- 某类请求元数据在特定框架、网关或业务系统中反复进入 SQL 查询。
- 某类 path/routing segment 命名与数据库资源查询强相关。
- 某类参数集可以跨 sibling endpoint 复用并触发隐藏后端分支。

## 源报告（on-demand）

- source_report_ids: `1663299`, `31756`, `983710`
- 用途：这些 ID 只作为本地案例库查询指针。只有当前证据已命中本卡触发信号，且需要真实攻击链形状、报告写作先例或相似案例时，才按需查询 gitignored 的 `distill/` 本地缓存；不要默认拉取全文，不把报告正文、目标域名、payload 或 PII 写入知识卡。
