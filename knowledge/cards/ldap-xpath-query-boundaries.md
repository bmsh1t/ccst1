---
id: ldap-xpath-query-boundaries
type: technique-card
related_skills:
  - web2-recon
  - web2-vuln-classes
  - triage-validation
  - security-arsenal
trigger_tags:
  - ldap-injection
  - ldap-filter
  - ldap-dn
  - xpath-injection
  - directory-query
risk: medium
maturity: draft
load_priority: low
deep_refs: []
source_refs: []
---

# LDAP Filter、DN 与 XPath 查询边界

## Quick Recall

- 触发：LDAP/AD/目录搜索错误、LDAP filter/DN 拼接、企业通讯录/员工搜索或 XML-backed XPath 查询。
- 先区分 LDAP search-filter、Distinguished Name 和 XPath context；三者的保留字符与闭合方式不同。
- Active Directory 的 `unicodePwd` 不可读取；不能把普通 LDAP 的 `userPassword` 风险外推为 AD hash 泄露。
- 最小验证使用合法/非法 baseline、语法 control 和自有测试对象，观察稳定的认证、结果集或属性差异。
- 只有认证/session 改变、非预期目录对象/属性读取或可重放查询边界影响才能进入 Candidate。

## 能力定位

本卡补充 SQLi/NoSQL 和隐藏认证路线之外的目录查询语义。它提供 query context、oracle 和误判边界，
不把 LDAP 后端指纹直接升级为注入，也不执行批量账号、组或属性枚举。

## 触发信号

- 错误出现 `InvalidSearchFilter`、`javax.naming`、`System.DirectoryServices`、`ldap_search`、
  LDAP error code、bad search filter 或 XPath expression/parser 信息。
- 登录、员工搜索、组织图、通讯录、目录同步、组/角色查询或 XML-backed authentication 接收可控字符串。
- source/config 显示字符串拼接 LDAP filter、DN、XPath 表达式，而不是参数化/安全 builder。
- 输入中的 `*`、括号、反斜杠、NUL、逗号、等号、引号或 XPath operator 产生稳定语法/结果差异。

## 思路分支

- Search-filter context：输入位于 `(attr=value)`，关注 RFC 4515 escaping、括号平衡、AND/OR/NOT 和 wildcard 语义。
- DN context：输入参与 `uid=value,ou=...` 等 distinguished name，关注 DN escaping；不能复用 filter payload 结论。
- XPath context：输入进入 XML node predicate，关注 quote、boolean predicate、节点/属性选择和结果集 oracle。
- Directory type：区分 AD 与 OpenLDAP/389-DS/ApacheDS 等；可读属性、默认 ACL 和错误语义不同。
- Oracle：比较 true/false control、结果数量、字段集合、身份状态和稳定 timing，不只看单次长度变化。

## 技巧家族 / Payload 家族

- 语法探针族：一次只测试一个 context-relevant 保留字符，观察 parser/filter 错误是否稳定出现。
- Boolean control 族：构造等价真/假条件或存在/不存在属性对照，要求结果方向可重复且与 control 一致。
- Wildcard/prefix 族：只在自有测试对象或训练目录上验证结果集/count oracle，不批量推断真实员工属性。
- Auth 族：保持测试账号不变，只比较正常、语法变体和明确 false control 是否改变 session/身份。
- Source 族：优先从代码/错误确认 filter、DN 或 XPath 拼接位置，再选择对应验证形态。

## 补充 Checklist

- 当前输入到底位于 LDAP filter、DN、bind username、XPath string 还是普通数据库查询？
- 是否存在合法、明确 false、语法错误三组 control，而不是只凭一次 500/长度变化判断？
- 目录是 AD 还是普通 LDAP；所声称属性是否真实可读且受当前 ACL 影响？
- 搜索结果差异是否来自分页、模糊搜索、缓存、排序或用户枚举文案？
- 认证候选是否真的签发 session/token，还是只改变错误消息？

## 最小验证

1. 保存正常搜索/登录、无匹配输入和语法错误输入三组 baseline。
2. 根据 source/error 确认 filter、DN 或 XPath context；每次只改变一个保留字符或 boolean 条件。
3. 使用自有测试对象验证 true/false control 是否稳定改变结果数量、字段或认证状态。
4. 对 AD 不尝试证明 `unicodePwd` 可读；只验证实际可见属性或授权边界。
5. Candidate 前保留可 replay 请求、context 证据、control 结果和实际 auth/data impact。

## 常见误判 / 死路

- LDAP/AD 错误、NTLM/SSO 指纹或员工搜索存在不等于 LDAP injection。
- 通配符返回更多结果可能是产品正常搜索语义；必须有 context/control 和越界数据证据。
- 单次 500、响应长度或时间差异可能来自 parser error、锁定、限速或后端不可用。
- AD 不会通过 LDAP search 返回 `unicodePwd`；不要声称由 blind LDAP injection 获得 AD password hash。
- XPath quote error 只证明表达式解析受影响，不证明认证绕过或数据读取。

## 关联 Skills

- `web2-recon`
- `web2-vuln-classes`
- `triage-validation`
- `security-arsenal`

## 晋升到 Skill / Queue 的条件

- 只有目录/错误指纹时保持 Signal，并继续确认 query context。
- 有稳定 true/false control、认证或属性差异时写入现有 Authz/SQLi action queue。
- session/身份改变或非预期目录数据可重放后，进入 `triage-validation`。

## 可晋升经验

- 多目标复现的 filter/DN/XPath context 识别信号、可靠 oracle、AD/普通 LDAP 误判或授权差异。
