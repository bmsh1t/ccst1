---
id: sqli-low-risk-probes
type: payload-pack
related_cards:
  - knowledge/cards/sqli-hidden-surfaces.md
related_skills:
  - web2-vuln-classes
trigger_tags:
  - sqli
  - low-risk-probe
  - baseline-diff
risk: low-to-medium
maturity: draft
load_priority: low
---

# SQLi 低风险 Probe 家族

## Quick Recall

- 本附录只在 SQLi lane 已有具体输入面、baseline 和最小验证目标时读取。
- Probe 目标是制造稳定差异，不是直接扩大利用。
- 每次只改一个变量；先比较状态、长度、错误、字段集合、排序、布尔响应。
- time-based、OOB、批量枚举和数据导出不属于默认低风险 probe。

## 适用边界

- 输入面已经明确：query/body/header/path/cookie/hidden param/二阶 store step。
- 请求是低风险、只读或测试资源内的最小动作。
- 已有 baseline 响应，并能重复请求 2-3 次确认稳定性。

## Probe 家族

- 引号闭合差异：单引号、双单引号、成对引号恢复，用于观察语法/错误/长度变化。
- 括号/类型差异：括号、数字/字符串形态切换，用于观察类型转换或查询构造差异。
- 布尔等价差异：等价真/假条件形态，用于观察字段集合、排序、数量或布尔响应差异。
- 编码/parser 等价差异：URL 编码、Unicode/XML entity、大小写、注释、分隔符和 content-type 等价形态，用于区分 WAF/路由、parser 解码和后端 SQL 查询差异。
- 排序/字段集合差异：针对 `sort`、`order`、`fields`、`filter`、`status` 等查询构造参数。
- 二阶最小触发：记录 store step 和 trigger step，只验证响应差异，不导出真实数据。

## 不默认执行

- 高频 time-based、长 sleep、OOB 扩大验证。
- 批量枚举表、列、用户或真实业务数据。
- 破坏性写入、数据修改、删除、导出或后台状态改变。
- 对无稳定 baseline 的目标做 payload spray。

## 证据要求

- baseline 请求和 probe 请求。
- 单变量说明。
- 至少一个稳定差异：状态码、长度、错误类型、排序、字段集合、布尔响应或 DBMS 指纹。
- WAF/路由/缓存差异排除说明。
