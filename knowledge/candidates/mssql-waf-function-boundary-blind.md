---
id: mssql-waf-function-boundary-blind
type: technique-card
related_skills:
  - src-hunting
  - triage-validation
trigger_tags:
  - mssql
  - waf-boundary
  - blind-differential
  - ashx
risk: high
maturity: draft
load_priority: low
deep_refs:
  - knowledge/cards/sqli-hidden-surfaces.md
  - knowledge/playbooks/web2-evidence-contracts.md
source_refs: []
---

# MSSQL WAF 黑名单下的差分验证框架

候选状态：独立方法草稿，尚未完成目标复现、整链盲答或晋升审核。这里登记的是
函数边界、编码和响应校准的验证方法；WAF 接受一个字符串或出现 302 本身不等于
SQL 注入成立。

## Quick Recall

- ASP.NET/ashx 参数被 token 黑名单拦截时，先建立放行/阻断边界，再选择目标上下文
  中实际可用的表达式；不把关键词替换表当作通用字典。
- `+` 在 query/form 解码链中可能变为空格，拼接型对照必须使用 `%2B` 并保留原始
  请求证据。
- `RIGHT(LEFT(x,N),1)`、`CHARINDEX` 和算术异常可以组成布尔差分，但每一步都要有
  已知真/假对照，排除应用错误、WAF 错误页和网络波动。
- 读取上下文值、数据库标识或业务数据属于独立影响，不能从“表达式被执行”直接
  升级为批量提取。

## 触发信号与适用条件

只有在已观察到一个参数确实进入查询/排序/过滤上下文，并且 WAF 对常见 token 有
稳定阻断时，才进入本方法。先保存合法请求、同批无害输入和服务健康基线；必须有
低频、可停止的验证窗口，不能以大量请求撞限速、封禁或 Rapid-Fail。

## 最小验证

1. 对同一参数记录合法值、语法无害值和已知函数值的响应，分类为应用响应、WAF
   阻断、连接失败或未知。`000`、超时和 302 先重试少量并与 baseline 交换顺序，
   不直接算作布尔结果。
2. 只在参数可控性已有证据时测试编码后的拼接形态，例如
   `kw=%25%27%2B<EXPR>%2B%27`；固定 `EXPR`，先判断是否进入同一 handler，再改变
   一个函数或常量。保存服务器实际收到的规范化形态。
3. 用已知常量校准字符判断：`RIGHT(LEFT(<VALUE>,<OFFSET>),1)` 得到单字符，
   `CHARINDEX(<CHAR>,<CHARSET>)` 区分命中/未命中，再用受控的算术差异观察业务响应。
   这里的 `<VALUE>`、`<OFFSET>`、`<CHAR>` 和 `<CHARSET>` 只能来自当前问题，不从
   目标外推数据库表名或敏感字段。
4. 对 200/302、正常/错误页或排序差异至少发送“已知命中、已知未命中、已知明文”
   三个对照，并重复有限次数。上下文函数在 `ORDER BY` 等位置可能返回 NULL；错误
   页面也可能来自类型转换或 payload 构造错误，不能混算。
5. 一旦得到稳定的最小差异，停止扩大字符集和数据范围，把结果写为当前参数、
   当前表达式、当前响应和当前影响。需要读取服务名或数据库 ID 时另立只读问题；
   不提取凭据、用户表或大批量数据。

## 证据要求

证据需包含原始请求/响应、解码层、WAF/应用区分、baseline/control、重复次数、
响应映射和停止条件。只有输入被同一查询上下文消费且差异可重复，才支持 SQLi
Candidate；函数放行、状态码变化或单次错误不能单独过门。

## 常见误判与停止条件

- 黑名单词被拒不说明查询参数化；冷门函数被接受也不说明表达式已执行。
- `000` 常是网络/封禁，302 可能是 ASP.NET 错误或类型转换；未完成三对照校准时停止。
- `db_name` 等词变体均被拦时，不继续加大绕过；可记录该观测并转回已观察的上下文
  信息路径。确认应用健康受影响、触发限速或需要批量字符请求时立即停止。

## 下一步与来源

准入后并入 `sqli-hidden-surfaces` 的 WAF/解析差分段，保持 SQLi、WAF 和报告证据
各自归属。直接来源为 v2.3 `skills/specialized/src-hunt-lane/references/kill-chains/
waf-bypass-mssql-blind.md`，SHA-256 `41c7cc214ede1fbc593de6084ccaf1f41def08c8381572f3802abf8fdd455a83`，
第 1–45 行；对应新增 shortlist 行为 `shortlist.md` 第 97 行（SHA-256
`ac77785a8533d1153d66c83dd63cad8f690da5ed1c05169fd9e854d15a7c9ddd`）。

