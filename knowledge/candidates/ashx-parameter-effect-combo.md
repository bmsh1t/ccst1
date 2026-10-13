---
id: ashx-parameter-effect-combo
type: workflow-card
related_skills:
  - src-hunting
  - triage-validation
trigger_tags:
  - ashx-rpc
  - parameter-differential
  - upload-boundary
  - xml-parser
risk: high
maturity: draft
load_priority: low
deep_refs:
  - knowledge/cards/sqli-hidden-surfaces.md
  - knowledge/cards/upload-parser.md
  - knowledge/cards/xxe-xml-parser.md
source_refs: []
---

# ashx 数字 RPC 的参数生效性与上传解析组合面

候选状态：独立方法草稿，尚未完成目标复现、整链盲答或晋升审核。组合中的参数差分、
上传落点和 XML 解析是三个独立证据边；一条边失败不能被另一条边补成完整链。

## Quick Recall

- `*.ashx?act=`、多数字 API 前缀和 DTcms 上传脚本名是入口线索，不是漏洞结论。
- 先验证参数是否真的改变查询或业务分支；“响应不变”可能是摆设参数，也可能是
  参数化安全，必须用可解释的差分对照区分。
- 上传成功只证明接收。需要独立证明文件落点、读取权限、处理器和清理状态；不要
  使用脚本、宏、超大文件或会影响他人的内容。
- XML/ZIP 变体只用于确认解析器行为。`SYSTEM` 被拦或 `PUBLIC` 被接收都不自动
  证明文件读取、SSRF 或 RCE。

## 触发信号与适用条件

已观察到数字 RPC、`upload_ajax.ashx`、`UpFileAction`、`uplaod_logo` 等路径/模板
指纹，且当前范围允许使用自有测试资源。需要一个正常查询基线、一个可回滚上传目标、
匿名与会话态对照，以及可读回的结果路径。浏览器重定向、SSO 壳和脚本通道必须分开
记录。

## 最小验证

1. 对每个已观察参数保存 baseline、缺省值、单变量变体和无效类型。列表过滤类参数
   可用 `%`/`_` 或等价无害值做结果数量差异；数字参数可用 `<ID_VALUE>+1` 做
   类型/算术差分。先证明参数生效，再判断是否进入查询或强转分支。
2. 只有出现稳定参数差异后，才用一个无害引号/语法对照观察错误归因。将直拼错误、
   参数化拒绝、WAF 响应、统一 fallback 和缓存差异分别登记；单次 302 或全量返回
   不直接判定注入。
3. 对已观察的上传入口使用自有、可删除的文本 marker，记录 multipart 字段、存储
   路径、公开/会话读取权限和 read-back 内容。上传处理扩展名、文件名、大小和
   MIME 的变化一次只改一个；RCE 文件名绕过、压缩炸弹和资源耗尽均停止。
4. 若上传内容确实进入 XML/ZIP 解析链，先用无害内部实体与外部实体对照，记录
   parser 错误、转换产物或一次性回调；不读取本地敏感文件、不扫描内网、不把 callback
   当作文件读取。`PUBLIC`/`SYSTEM` 的 WAF 差异只作为 parser/WAF 线索。
5. 每条边分别核对清理：删除测试 marker，确认目录/对象/预览没有残留；再决定是否
   关闭当前分支。浏览器会话触发 SSO 而脚本通道匿名时，分别保留两套结果，不能混算。

## 证据要求

每一边至少有请求/响应、输入与控制、参数或文件的实际消费证据、影响对象、权限上下文
和清理回执。只有“参数生效 + 稳定查询差异”才进入 SQLi 验证；只有“匿名写入 +
可读回自有 marker”才进入上传授权判断；只有 parser 行为和影响路径同时成立才转
XXE/SSRF 影响评估。

## 常见误判与停止条件

- 摆设参数全量返回不等于 SQL 注入；参数化查询也可能有合法过滤差异。
- 上传回包成功、文件名被改写、浏览器 302 或 WAF 拒绝都不能证明未授权写入或 RCE。
- `SYSTEM` 拒绝、`PUBLIC` 接收、脚本与浏览器结果不同，分别保留为条件化观察。
- 没有自有可回滚资源、read-back 不确定、服务出现异常或需要批量枚举时停止。

## 下一步与来源

准入后拆分合并到 `sqli-hidden-surfaces`、`upload-parser` 和 `xxe-xml-parser`，不保留
第二套 ashx 组合系统。直接来源为 v2.3
`skills/specialized/src-hunt-lane/references/kill-chains/ashx-unauth-combo.md`，
SHA-256 `649b9c135efb0d36ddb1dcf86c4f87e22cbd6c5d1da546983a8d904a789b76f2`，第 1–39 行；
对应新增 shortlist 行为 `shortlist.md` 第 98 行（SHA-256
`ac77785a8533d1153d66c83dd63cad8f690da5ed1c05169fd9e854d15a7c9ddd`）。

