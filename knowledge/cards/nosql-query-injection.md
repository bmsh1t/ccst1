---
id: nosql-query-injection
type: technique-card
related_skills:
  - web2-vuln-classes
  - triage-validation
trigger_tags:
  - nosql
  - operator-injection
  - mongodb
risk: medium
maturity: draft
load_priority: medium
deep_refs:
  - /root/tool/ccst/ctf-skills/ctf-web/sql-injection.md
---

# NoSQL / Query Operator Injection

## Quick Recall

- NoSQL 注入重点不是 SQL payload，而是输入是否进入查询对象、过滤器、表达式或类型转换。
- 高信号入口：登录、搜索、筛选、JSON API、GraphQL resolver、Mongo 风格查询、数组/对象参数。
- 先用合法 baseline，再做单变量 operator/type 差异；示例 `$ne`、`$regex`、`$where` 只是候选形态。
- 登录场景里不要只盯 password；username 也可能接受 operator，例如目标相关的管理员前缀正则配合 password 非空条件。
- 命中后优先证明认证绕过、对象集合扩大、权限过滤失效或布尔差异，不批量枚举真实数据。

## 能力定位

本卡给 `web2-vuln-classes` 补充 NoSQL 查询语义、parser/type confusion 和 operator injection 思路。

## 触发信号

- 技术栈或错误出现 MongoDB、Mongoose、BSON、DocumentDB、Couch、Elastic DSL、NoSQL。
- JSON body、filter、where、query、search、username/password、selector、criteria 等字段可控。
- 数组/对象包裹、重复参数、content-type 切换会改变响应或错误。

## 思路分支

- Auth bypass：登录查询把用户输入拼入对象条件。
- Filter widening：搜索/列表过滤被 operator 扩大集合。
- Type confusion：字符串、数组、对象、布尔、null 的校验与查询语义不一致。
- Expression sink：`$where`、脚本表达式、模板化查询或动态 DSL。

## 技巧家族 / Payload 家族

- Operator 形态：不等于、正则、范围、存在性、数组成员、表达式。
- 组合形态：username 正则/范围 + password 非空，或固定 username + password operator；根据响应差异收敛，不固定顺序。
- Parser 形态：JSON 对象、form 嵌套参数、重复参数、content-type JSON/form 差异。
- Evidence 形态：登录成功/失败、结果数量、字段集合、排序、错误类型和响应时间稳定差异。

## 补充 Checklist

- 是否测过 JSON body 和 form-urlencoded 两种 parser？
- 是否区分认证绕过和普通搜索结果扩大？
- 是否只在自有/测试对象或公开数据上验证？
- 是否排除前端过滤、缓存和 WAF 差异？

## 最小验证

- 建立合法查询和错误查询 baseline。
- 单变量插入 operator/type 变体，比较状态、长度、结果数、字段集合和错误。
- Candidate 前需要 replay、对照组、影响解释和数据最小化说明。

## 常见误判 / 死路

- 单次 500 不等于 NoSQLi。
- 前端把对象序列化失败不代表服务端查询可控。
- 正则搜索命中扩大可能是正常功能，需要证明权限或过滤绕过。

## 关联 Skills

- `web2-vuln-classes`
- `triage-validation`

## 晋升到 Skill / Queue 的条件

- 有 endpoint、输入字段、baseline-vs-operator 稳定差异时写入 action queue，类型 `nosql-query-injection`。
