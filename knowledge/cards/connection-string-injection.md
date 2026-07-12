---
id: connection-string-injection
type: technique-card
related_skills:
  - web2-vuln-classes
  - security-arsenal
  - triage-validation
trigger_tags:
  - connection-string
  - jdbc
  - driver-option
  - protocol-handler
risk: high
maturity: draft
load_priority: low
deep_refs: []
---

# 连接串/驱动/协议处理器参数注入致文件读与 RCE

## Quick Recall

- 触发：用户输入进入 JDBC/连接串、driver option、协议 handler 或外部资源配置。
- 最小验证：先确认解析层读取单个受控选项，再用无害资源观察文件/网络行为差异。
- 证据门：必须区分纯解析错误与真实文件读、网络访问或代码执行影响。
- 停止：scheme/参数严格白名单，或只到达无副作用解析层。

## 适用场景

- 用户可控 DB 连接串、驱动名或驱动参数
- 存在 JNDI/JDBC/协议处理器解析用户 scheme
- 配置字段可注入连接/查找语义

## 触发信号

- 连接串参数可指向本地库/文件或恶意主机
- 协议处理器对非网络 scheme 执行网络查找
- 配置字段可触发 JNDI lookup

## 发散问题

- 连接串/驱动参数里哪些能改变文件/库/网络行为？
- 处理器会把什么 scheme 当作网络查找？
- 能否把查找定向到攻击者控制的 sink？

## 推荐动作

- 枚举驱动/连接串支持的危险参数。
- 用低风险 OAST/只读探针验证外连或文件读。
- 确认是否可达反序列化/库加载 sink。

## 关联 Skills

- web2-vuln-classes
- security-arsenal
- triage-validation

## 停止条件

- 连接串/scheme 被严格白名单且参数不可注入
- 只到达无副作用的解析层

## 检查要求

- 必须证明达成文件读/外连/库加载/反序列化中至少一项实际影响，且低风险可复现。

## 可晋升经验

- 连接串与协议处理器是被低估的 RCE 面：先枚举其危险参数与查找语义。

## 源报告（on-demand）

- source_report_ids: `1529790`, `1547877`, `153026`, `838196`, `1966083`, `411519`, `2065306`
- 用途：这些 ID 只作为本地案例库查询指针。只有当前证据已命中本卡触发信号，且需要真实攻击链形状、报告写作先例或相似案例时，才按需查询 gitignored 的 `distill/` 本地缓存；不要默认拉取全文，不把报告正文、目标域名、payload 或 PII 写入知识卡。
