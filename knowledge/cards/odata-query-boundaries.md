---
id: odata-query-boundaries
type: technique-card
related_skills:
  - web2-recon
  - web2-vuln-classes
  - triage-validation
  - security-arsenal
trigger_tags:
  - odata
  - odata-filter
  - odata-expand
  - odata-batch
  - odata-metadata
risk: medium
maturity: draft
load_priority: low
deep_refs: []
source_refs: []
---

# OData 查询、导航与批处理边界

## Quick Recall

- 触发：`OData-Version` / `DataServiceVersion`、`$metadata`、`$filter`、`$select`、
  `$orderby`、`$expand`、`$batch` 或 OData entity-set 路径。
- OData operator 可用、公开 metadata 或 `$metadata` 200 只是 schema/query signal，不是漏洞。
- 分别检查 entity、field/projection、predicate/order、navigation relation 和 batch inner-operation 的授权边界。
- 最小验证使用自有对象和 owner/peer 对照；保存同一查询在 direct 与 batch、公开字段与受限字段上的差异。
- 只有非预期对象/字段读取、状态改变或 edge/backend 策略差异才能进入 Candidate。

## 能力定位

本卡补充普通 API/SQLi/IDOR 路线容易漏掉的 OData 语义边界。它帮助 AI 区分“查询语言正常工作”、
“字段/关系授权不一致”和“外层/内层 parser 策略不同”，不把 OData 当成普通 SQL 语法，也不接管
API、IDOR 或 SQLi 的 lifecycle。

## 触发信号

- 响应包含 `OData-Version`、`DataServiceVersion`、`@odata.context`、`@odata.count` 或 entity-set link。
- 路径或文档出现 `/$metadata`、`/odata/`、`/_api/`、`/api/data/v*`、`/sap/opu/odata/`。
- 请求使用 `$filter`、`$select`、`$orderby`、`$expand`、`$top`、`$skip`、`$count` 或 `$batch`。
- 同一数据可通过 Web/mobile、direct OData、gateway 或 multipart batch 访问。

## 思路分支

- Schema boundary：公开 metadata 是否只暴露公开 schema，还是提供了未在 UI/API docs 中出现的高价值 entity/operation。
- Entity boundary：不同身份对同一 entity-set、key、function/action 的对象范围是否一致。
- Field boundary：字段不能被 `$select` 返回时，是否仍能参与 `$filter`、`$orderby`、`$count` 或错误 oracle。
- Navigation boundary：顶层对象授权成立后，`$expand`/navigation property 是否重新验证关联对象和字段。
- Batch boundary：edge/WAF/gateway 是否只校验 outer multipart，请求进入 backend 后 inner operation 获得不同身份或策略。
- Normalization boundary：direct、encoded option、gateway rewrite 和 batch inner request 是否解析成同一查询对象。

## 技巧家族 / Payload 家族

- Metadata 族：只读 `$metadata`、service document、entity-set/function/action 名称；先做 schema inventory，不直接升级。
- Query option 族：对自有对象分别比较 `$select`、`$filter`、`$orderby`、`$count`，一次只改变一个 operator 或字段。
- Navigation 族：从 owner 可访问对象展开一层 relation，比较 owner/peer/cross-tenant 的对象数量和字段集合。
- Batch 族：保持 inner method/path/body 不变，只比较 direct 与 `$batch` 包装后的 status、字段和身份结果。
- Parser 族：原始 `$`、URL 编码 option、gateway JSON/transcoding 等只是解析差候选，必须回到实际对象/字段影响。

## 补充 Checklist

- 是否记录 entity-set、key、operation、query option、身份、对象归属和响应字段？
- `$filter`/`$orderby` 是否允许引用调用者本不应观察的字段，并形成稳定结果/排序/count oracle？
- `$expand` 后的关联对象是否属于同一用户、组织或租户？
- `$batch` 的 inner request 是否继承 outer auth、CSRF、tenant 和 method policy？
- 响应差异是否只是分页、默认排序、缓存或数据变化，而不是授权边界？

## 最小验证

1. 保存合法 owner baseline：entity、公开字段、对象归属、query option 和响应摘要。
2. 用 owner/peer 或两个测试租户保持 query 不变，只替换单个对象/字段/relation。
3. 若存在 `$batch`，把同一个只读请求分别 direct 和 batch 发送，比较 inner status、字段集合和身份结果。
4. 对字段级候选使用公开字段作为 control；只有受限字段改变结果、顺序、count 或返回字段时继续。
5. Candidate 前保留可 replay 请求、身份/对象矩阵和稳定的非预期数据或状态影响。

## 常见误判 / 死路

- `$metadata`、service document、entity 名称或 query option 可用不等于敏感数据暴露。
- `$filter=...` 返回 200 只证明语法/字段被接受，不证明 SQLi、WAF bypass 或字段授权缺失。
- `$expand` 返回空数组可能是正常 relation/filter 结果；缺 owner/peer 对照时不要升级。
- direct 与 batch status 不同可能来自 multipart 格式错误；inner operation 未被 backend 接收时不是策略差异。
- OData 语法错误、延迟或 500 单独不能证明 SQLi；需要 DB/parser 证据或稳定数据语义差异。

## 关联 Skills

- `web2-recon`
- `web2-vuln-classes`
- `triage-validation`
- `security-arsenal`

## 晋升到 Skill / Queue 的条件

- 只有 metadata/operator 信号时保持 API discovery Signal。
- 有字段、navigation、batch 或身份差异时写入现有 API/IDOR/SQLi action queue，不创建 OData finding owner。
- 非预期对象/字段或状态影响可重放后，进入 `triage-validation`。

## 可晋升经验

- 多目标复现的 projection/predicate 授权差、navigation relation 越权或 batch outer/inner policy 差。
