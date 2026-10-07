# F10 设计：失败状态与成功缓存分离

## 边界与文件

仅修改以下五个已有文件；任务文档另行维护：

- `tools/disclosure_search.py`：查询结果、缓存准入、材料选择及 Markdown 状态／时间。
- `mcp/hackerone-mcp/server.py`：仅 search 响应消费点，沿现有 HackerOneAPIError 暴露坏结构。
- `tests/test_disclosed_pattern_dedup.py`：隔离 provider、owner、缓存和 Markdown 的真实接线。
- `agents/disclosed-researcher.md`：让消费者保留 partial/unavailable/stale 事实。
- `.trellis/spec/backend/error-handling.md`：记录 disclosure owner 的失败和保全契约。

不接入 Intel/Store，不改 stats/policy、通用传输、TLS、查询构造、报告判断或任务调度。

## 查询结果与聚合

provider 的 `search_disclosed_reports(...) -> list[dict]` 不变。owner 内两个查询 helper
改用一个小的运行时结果记录：报告列表、成功请求数、失败诊断；仅 writer 消费，不能
写入 cache 或升级为通用 provider 框架。每次调用及其响应解析共享同一个错误边界。

- 请求返回合法列表且每个条目可解析才算成功；合法空列表也是成功。坏请求的局部解析
  结果不冒充完整结果，但不得丢弃其它成功请求的报告。
- same-target 保留 program→无报告时 keyword fallback。program 失败后 fallback 成功，
  报告可读但整体仍 partial；两次都成功为空才是完整成功零结果。
- similar 保留最多五个现有关键词、URL 去重和 same-program 排除；一次失败继续后续请求。
  没有 tech/vertical 关键词时不执行查询，不制造失败。
- 全部已执行请求成功：complete；至少一个成功且至少一个失败：partial；无成功且存在
  失败或 client 不可用：unavailable。错误包含查询标识、类型及去换行的有界原因，单条
  至多 500 字符，不转储完整上游响应；无持久错误计数或 last_error_at。

## Provider 输入边界

`server.py:140-159` 必须区分合法 `nodes=[]` 与缺失／null／错误类型的 data、hacktivity_items、
nodes。后者抛已有 HackerOneAPIError，不再在 provider 内提前变成空结果。
节点必须为对象；report/team 仅允许缺失、null 或对象。无 report 的节点和既有空 report
对象继续跳过，但 `[]`、false、0、空字符串等非对象即使是假值也必须报错，不能用真假值
代替类型校验。severity/date 等实际执行字符串操作的字段保留合法 null/缺失语义，错误
类型显式失败。只校验当前 search 消费的结构，不增加所有字段必填或全 GraphQL schema。

## 缓存读取与发布

保持 `state/disclosure_cache/<target-key>.json` 及成功 payload 五个既有字段不变：target、
same、similar、coverage_status、cached_at_ts；不添加新字段。

读取有效性与 TTL 分开：先保留可用成功快照，再判断其是否过期。错误编码／JSON／根结构、
桶或记录类型、不可解析／非有限时间戳不成为健康材料，并有可见诊断。时间 0 与既有可解析
的数字字符串保持兼容；不因本批增加未来时间漂移策略。已有 target 字段若不匹配当前目标，
不得消费；仅缺少 coverage_status 的历史快照按桶推导，已提供字段只接受 covered /
no_mcp_coverage。mcp_unavailable、partial 或错误类型不算完整成功快照。
旧版本错误写成 no_mcp_coverage 的空快照无法与真正零结果区分，不猜测／迁移。

仅 complete 发布新的成功 cache，包括完整成功零结果。partial/unavailable 不调用 writer，
即使原 cache 损坏也保留原 bytes。fresh cache 命中保持原时间且不请求上游。
`--no-mcp` 保持显式跳过，不读取／修改 cache，也不加载 client 或 inventory。

复用 `artifact_io.write_text_atomic`，保留现有 JSON 序列化格式；同时用于生成 Markdown，
不新增发布原语。cache 与 Markdown 独立原子发布：成功 cache 可先落盘，随后 Markdown
失败仍显式失败，不回滚成功 cache，也不声称跨文件事务或并发刷新串行化。

## 材料选择与可见状态

| 现场 | 本次查询状态 | 展示材料 | 是否更新 cache |
|---|---|---|---|
| no-mcp | skipped | 空文档，明确跳过 | 否，且不读 cache |
| 有效 fresh cache | cached | 原成功快照及原查询时间 | 否 |
| complete，有报告 | complete | 本次完整报告 | 是 |
| complete，零报告 | complete | 真正成功零结果 | 是 |
| partial，有报告 | partial | 仅本次成功请求报告，不混旧数据 | 否 |
| partial，无报告 | partial | 有效旧快照；没有则明确无可用材料 | 否 |
| unavailable | unavailable | 有效旧快照；没有则明确无可用材料 | 否 |

Markdown 分别展示查询状态、材料来源（live/cache/none）、材料查询时间及是否过期。
生成时间改称 Generated at，不再将渲染时间冒充旧材料的 Last updated。
live partial 的时间只属于其成功子集，不能称为“完整成功刷新时间”；cache 总是保留
cached_at_ts。使用旧材料时即使有报告，仍需并列显示本次 partial/unavailable。

保留现有报告表、顺序、Target memory recall 命令。MCP coverage 的 covered/no_mcp_coverage
继续描述完整材料的覆盖；partial 新材料使用明确的 partial 展示值，不保存该值到 cache。
无可用材料且查询不可用保持 mcp_unavailable；有缓存时覆盖来自缓存，与本次查询状态
分别展示。消费者不得把“空章节”或旧 covered 单独概括为本次完整成功。

`write_disclosed_patterns(...) -> Path`、CLI 参数及正常生成文档时的返回码 0 不变；查询失败
不等于文件写失败。发布失败上抛，CLI 不打印成功路径。renderer 现有位置参数保持可用，
writer 通过关键字传入新的运行时诊断／来源时间，不新增 JSON CLI。
未显式传入 query_status 的直接 renderer 调用不生成查询事实，不能由空表推断完整成功。

## 兼容、风险与回滚

- 保留默认 72 小时、现有 TTL 强制刷新用法、查询上限、fallback 和 report 字段容忍范围。
- 拒绝非有限 TTL，避免 NaN 使过期比较恒假；有限 TTL≤0 明确强制刷新。
- no-mcp、健康缓存及完整成功零结果保留原有使用方式，不创建新状态或做数据迁移。
- partial 结果不缓存，因此可能重复请求；这是数据保全取舍，不新增重试调度器。
- Markdown 按现有行为重新生成，不保留手工追加 Read in full，也不混合旧新内容。
- 网络与本地文件不能事务化；原子替换保证单文件完整性，不保证目录 fsync 或跨文件提交。
- 本批独立工作提交；回滚只撤销代码／指导，不删除 cache，不改真实 runtime。已丢失的
  历史报告无法由本次修复恢复。
