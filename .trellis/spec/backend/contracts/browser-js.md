# Browser and JavaScript Contracts

> Browser evidence、增量发现和 JavaScript 分析契约。

## Scenario: MCP 浏览器文件证据与有界增量发现

### 1. Scope / Trigger

- 修改 `/autopilot` 浏览器工具权限、MCP artifact 导入、Browser Surface 增量或浏览器
  continuation 时适用。
- 浏览器执行 owner 是当前 Claude 会话中的 Playwright MCP 和 Chrome DevTools MCP；本项目不
  通过 Bash 启动 `agent-browser` 或 `playwright-cli`，CLI 只可作为历史 raw-parser 测试输入。
- 浏览器启动由宿主直接配置官方 MCP；项目不维护双槽启动器、固定 CDP 端口或 Profile 锁。
  旧启动命令按 `docs/native-tools.md` 迁移，不自动修改个人配置或清理原浏览器数据。
- `capability_profile` v2 只在 `local_files` 中报告本地 importer 是否存在；不能据此推断
  live MCP。`session_status=unchecked`，实际会话工具必须由当前控制器确认，
  不再发布漏洞类别 readiness 或 bridge_ready 判定。

### 2. Signatures

```bash
python3 tools/browser_mcp_import.py --target <target> --network-json <path> [--har <path>] [...]
python3 tools/browser_mcp_import.py --target <target> --focused-manifest <manifest.json> [--max-urls 8] [--enqueue]
```

Focused manifest 为 `{"target":"...","captures":[{"url":"https://...","source":"playwright-mcp","network":"...","snapshot":"..."}]}`。

```python
browser_export_items(payload) -> tuple[list[object], bool]  # 所选条目、来源失败状态
public_request_payload(payload, *, source="", from_capture=False) -> dict
write_browser_surface(..., requests_path=None, requests=None) -> dict
```

Importer 通过共同入口选择条目，使用 `from_capture=True` 生成一次请求投影并保存至
`requests.json`；同时把该投影传入 Surface 的 `requests`，此参数只接收共同解析器输出。
直接文件调用仍走同一解析器，默认兼容已有投影。公开正文保持
`postData.kind=request-body-shape`，不增加 Store schema 或新持久化 owner。

### 3. Contracts

- 浏览器选择时机由 `rules/playwright-browser-mcp.md#1-何时使用` 统一定义，常驻
  runtime-protocol 与手动/自动执行入口引用它。可交互业务面未知、新身份/状态或动态流程
  缺证据时主动观察；保留新空 Autopilot 的 Recon 启动顺序，纯 API/源码问题和有效既有证据
  不强制浏览器。不新增关键词路由器、工具次数配额或第二套 readiness owner。
- 原生 MCP 连续流程按 `docs/evidence-runners.md#在执行时捕获原件` 的有界批次捕获/登记；
  材料按需保存，不要求每个点击/快照后中断写回；HAR 专用收尾的条件以该合同为准。
  真实 attempt/时间、严格原件准入、失败恢复与回执消费不放宽。
- 会话复用、切换与清理由同一浏览器规则定义；只关闭本任务拥有且不再供用户检查的会话，
  不关闭无关页面。状态流程和原件未回收、关闭失败时不切换后端。
- 每轮第一次浏览器动作前只做一次无副作用的 page-list/session probe；仅 timeout、断连或
  context closed 可重试一次。缺失、配置、权限或协议错误不重试。
- 二次失败通过既有 Action Queue/checkpoint 记录 blocker，并切换 JS/source/API 证据；不得
  新增浏览器 health 状态 owner。下一轮、环境修复后或显式 operator retry 可重新探测。
- Playwright MCP 优先用原生 `filename`，Chrome DevTools MCP 用原生 `filePath`；模型只
  编排 artifact 路径，不复制 tool response 正文。
- 同一入口支持列表、既有 requests/networkRequests/consoleMessages 等集合、HAR log.entries、
  单条 `networkRequest`，以及一层 `structuredContent`/`data` 外层包装。按现有顶层集合优先，
  否则选择第一个对象包装；已选空包装不回退 raw 文本，不递归进入正文。失败状态来自所选
  包装及其外层的 `success=false`、`isError=true` 或 error/failed/failure/timeout/stale；
  未选兄弟包装、业务正文中的同名字段不决定采集状态。
- focused capture 只接受绝对 HTTP(S)、同目标的 AI 选择材料，默认最多 8 条 capture。
  仅完整声明相同的条目去重；同 URL 的不同原件或状态分别归档。同 URL 首项保留原 receipt
  身份，其余项绑定完整声明；原 manifest 重试不重复捕获，旧首项及私有原件保持不变。
- raw network/console/cookie/storage/state/HAR/screenshot 写 `.private/browser/`。内部分析的
  `requests.json` 与 Recon URL 保留精确查询值、重复参数与编码，不视为可公开发布的材料。
  `request_shapes.json` 继续按 URL 形状关联元数据；旧去值记录不自动补造原值。
  Surface 表单从私有原始 snapshot 提取 action 与 hidden 参数名，不从已删 input 的摘要提取。
  body/console/snapshot 摘要仍保留结构、计数、hash 和原件引用；已有 body shape 再投影不变。
  Console 的顶层数组与对象内数组均进入同一条目摘要，原文仍私有。原生文本按完整等级
  识别：`WARN` → `warning`，`WARNING` 保持 `warning`，`VERBOSE` 保留 `verbose`；
  Playwright 的可选 `[ 123ms]` 前缀不改变等级；正文内等级词不用于猜类型。
  不对等级做 `warn` 子串替换。正文只在
  `postData`/`requestPostData` 的带 `mimeType` 包装中读取 `text`；原生详情 `requestBody`
  直接保留正文，`requestHeaders` 的 Content-Type 供类型提示；`body/payload/data`
  中同名字段属于业务 JSON，不能按字段名递归解包。`mimeType` 作为类型提示，不能成为
  表单参数。捕获文本不 trim、不重新序列化，bytes/hash 对应其 UTF-8 表示；对象正文仍为
  JSON 表示摘要，不宣称恢复了网络字节。明确空文本为 `empty`、0 字节及空内容 SHA-256；
  未捕获正文（包括只有 params/mimeType 的包装）为 `missing`、null 字节数、空 hash，
  不用 params 重建原文。Surface 参数与请求形状共用同一投影，原件读取/来源校验独立保留。
  已有 `content_type_hint` 必须经过 importer 保留。业务 JSON 数组提取对象键，不能把
  `name` 的值公开成参数；仅明确 formData/表单类型的条目数组按字段描述解释 name。
  请求 method/resourceType/status/url_sha256 与正文在共同入口生成；status 顶层优先、response
  回退。Surface 只去除 URL 值，参数从同一 body shape 提取；page→JS map 只读已保存的
  canonical url/resourceType，不再解析请求正文。
  WebSocket frame、SSE event
  和 GraphQL batch 也只发布有界的 transport、顺序、marker、大小、SHA-256 及
  `network_private_json` 的 request-index 引用；消息正文只留在 private raw artifact。
  消息元数据最多 64 条，`message_count` 保留完整捕获数量；request-index 使用过滤前原数组
  位置。原始导入只从实际 frames/events/GraphQL 正文生成实时摘要，不信任原件自带的
  `realtime`；已有投影可复用合法索引/摘要，实际消息优先，哈希字段不得夹带非 SHA-256 文本。
- 缺失/无效 network 时可用 HAR 补内部请求材料；仍缺核心 network 则是 `partial/error`，
  不能解释为 tested-clean。
- 原件字节归档及严格 `read_browser_observation_capture` 准入独立于发现投影。原生 MCP
  wrapper 的可导入不代表其可登记实验；reader 仍要求可识别原始 JSON/HAR、来源哈希和
  真实请求时间等字段，不用导入时间补造观察时间。
- capture `summary.json` 必须先发布，再刷新 page→JS map；否则当前 capture 的 JS 会延迟到
  下一页面并错误归因。Surface 差分包含 XHR、API、参数和 JS。
- 导入默认只发布材料和差分。显式 `--enqueue` 要求活动 Store；仅有采集成功且出现新
  target-owned Surface 或非重复 snapshot shape 时，通过 `add_material_review` 保存不可变
  材料快照并登记 work，返回 action ID 和命令收据。重复材料不生成新工作，不做关键词价值过滤。

### 4. Validation & Error Matrix

| 条件 | 结果 |
|---|---|
| Web 业务/交互未知，或身份/状态改变而缺当前基线 | 依据问题调用可用 MCP 建基线；不可用保留未观察项 |
| 纯 API/源码问题，或已有同目标/身份/状态的有效浏览器证据 | 选择对应原生工具或复用证据，不强制双后端/调用次数 |
| 一段连续导航/填表/提交/读回 | 同会话完成有界捕获，结束或中断后登记，不逐点击重建会话 |
| 首次 probe timeout/断连/context closed | 短暂等待后最多重试一次 |
| MCP 缺失/配置/权限/协议错误，或第二次 probe 失败 | 本轮停止浏览器重试，checkpoint blocker，切换非浏览器证据 |
| manifest target 不匹配 | fail-fast `ValueError` |
| relative/file/off-target URL | `skipped`，记录 `invalid_url/off_target` |
| 超过 8 条 | 额外条目 `budget_exhausted` |
| 单 capture 文件损坏/复制失败 | 该项 `error`，其余继续，批次 `partial/error` |
| network 缺失但 HAR 可解析 | 用 HAR 建 Surface，HAR 原件保持私有 |
| 重复 snapshot 且无新 Surface | 归档但不入队 |
| Console 顶层数组含 N 条对象 | 公共 count 与 summary 均为 N，正文仅在 private 原件 |
| Console 文本含 WARN、WARNING、VERBOSE | count=3、types=[verbose, warning]，不生成 warninging 或降为 log |
| 表单 postData 的 text 已捕获 | form、实际文本 bytes/hash，参数不含 mimeType |
| 空 text / 缺 text | empty + 空内容 hash / missing + 无内容 hash，不补造正文 |
| 所选 MCP 包装失败且有有效 HAR | 选择 HAR，其原件哈希与请求投影一致 |
| 所选包装失败且无有效 HAR / 合法空包装 | error，不用外层残留 raw 文本伪报成功 |
| 原始条目自带 realtime，实际 frames 已捕获 | 忽略自带摘要，从实际消息计算 hash/计数/原索引 |
| 70 条实时消息、前面有无效请求条目 | message_count=70、预览 64 条，request-index 不重排 |

### 5. Good / Base / Bad Cases

- Good：持久 MCP session 访问 2 个同目标页面，文件导入后当前页面的 JS/API 立即进入 Surface，
  差分可见；显式 `--enqueue` 才登记对应待审工作。
- Base：瞬时断连只重试一次；仍失败时保留 blocker 并切换 JS/source/API，下一轮可重试。
- Bad：浏览器不可用时无限重试、创建第二套 health 状态、把 MCP 正文复制进 prompt/公共 JSON，
  或把 raw URL corpus 直接作为浏览器访问清单。
- Good：原生 Chrome 列表和单条详情直接导入，列表未捕获的正文为 missing；详情的
  requestBody 保留真实 bytes/hash。发现投影成功与完整实验准入分别验证。

### 6. Tests Required

- 离线回放原失败 capture：8 份 console 共 17 条，两份登录 text 各 38 字节。
  对照直接 HAR、MCP 导入、Surface 参数、普通 JSON 同名字段及 name 数组、类型提示透传、重复参数/换行、空/缺正文、
  GraphQL、shape 幂等和真实 CLI。校验原件 bytes/hash/0600、重复导入不重写、严格 reader
  拒绝篡改；不运行网络或个人 runtime，不把本地回归当成完整模型验收。
- 解析链路定向回归：每条请求只解析一次，HAR/MCP/Surface 的 status/body 一致，无扩展名
  script 可归入当前 page→JS map；过滤前原索引、64 条预览及完整总数、原始 realtime
  注入、所选包装失败/HAR 回退、外层失败优先、空包装和单层深度均有反例。
- 隔离 localhost 原生 MCP 调用：列表、console、表单提交及原生 request/response 文件与
  服务端字节对照；保存未改写的 tool result 再导入，确认公开摘要不含密码、严格 reader
  仍拒绝未满足实验格式的原件。不把一次性隔离服务成功当成个人会话配置已修复。
  原生 console 与等级别名反例断言 count/types、仅公共摘要字段，以及私有原件字节不变。
- 主动选工具须另做真实 agent 验收：只提供业务目标和合成页面，不在提示中指定浏览器工具；
  用原生调用记录核对未知业务、身份变化或动态流程的观察与证据。增加纯 API/静态对照场景，
  不以调用次数计分。源文送达、手工 MCP 调用或 hook 回放不证明模型已正确选择工具。
- `tests/test_browser_analysis_fidelity.py`：MCP/HAR 导入至 Recon/Surface 的精确 URL、旧 shape
  join、hidden 参数名、body shape 幂等、raw 引用/权限与有界预览；不以 query 去值证明隐私。
- `tests/test_autopilot_inline_contract.py`：slash command 允许 Bash、Playwright MCP 和
  chrome-devtools MCP，不锁回 Bash-only；固定 first-use probe、瞬时错误单次重试和 blocker handoff。

### 7. Wrong vs Correct

#### Wrong

`json.dumps(postData)` 把格式包装计为正文；按 `text` 字段名递归拆业务 JSON。

```text
MCP response body -> model copy -> public evidence / second browser queue
```

#### Correct

保留来源字段及所选包装状态 → 每条请求生成一次投影 → Surface/JS 消费已有字段。

```text
first-use probe -> MCP filename/filePath -> browser_mcp_import archives raw
-> public_request_payload -> saved requests + Surface / page-JS map
-> AI selects / explicitly registers review work
```


## Scenario: Recon JS 链接分析器调用契约

### 1. Scope / Trigger

修改 `recon_engine.sh` 的 xnLinkFinder/LinkFinder 选择、参数、输入或输出时适用。

### 2. Signatures

```text
run_xnlinkfinder BIN TARGETS_FILE SCOPE_FILE OUTPUT_FILE TARGET
run_legacy_linkfinder BIN RESPONSE_FILE OUTPUT_FILE
```

### 3. Contracts

- `quick/normal` 只保留完整 JS inventory 和有界候选；`deep/full` 匿名上下文优先 xnLinkFinder，
  缺工具、非零退出或认证上下文使用逐 URL LinkFinder。
- xnLinkFinder v8.2 在非 TTY 中从 stdin 读取原生 URL 列表；不得改回 `-i FILE`。
  保留工具自身的重定向、单响应 `-mrs 20` 限制和 timebox，不新增下载器或 HAR 转换。
- 先确定链接分析器，再逐个 curl 前 50 个 target-owned URL 做内置 endpoint/secret 提取；
  选中 LinkFinder 时，前 25 个 URL 直接共用当前正文，不再下载一次。只用一个私有临时文件，
  每 URL 清空后写入，正常结束与退出均清理。内置请求保持 10 秒，供 LinkFinder 共用的请求
  使用原 LinkFinder 的 15 秒上限。下载失败跳过整个正文且不重试，LinkFinder 失败也标 `partial`。
  原生 xnLinkFinder 与内置 secret 提取仍可能分别请求同一 URL；后续显式 secrets-hunter 仍是独立刷新。
- xnLinkFinder 必须使用 `-sf SCOPE_FILE`、现有 `RATE_LIMIT`、depth=1 和工具级 timebox；v8.2 的
  depth=1 只请求显式输入，depth>1 才递归请求发现链接。`-sf` 是不安全的域名子串匹配，不能独立
  充当项目 scope owner；启动前必须拒绝越界输入，发布前再由 `url_belongs_to_target()` 严格过滤输出。
- 任一输入 JS 使用 IP、单标签或越界 host，或 TARGET 带显式端口时，整批回退逐 URL LinkFinder；
  xnLinkFinder 的域名 scope 不能表达这些边界。
- 认证 header 只在采集时逐 URL 按 target scope 选择，不能传给链接分析器或跨 origin 的递归分析。
- 两条路径继续发布既有 `js/linkfinder_endpoints.txt`，不新增 Surface/Queue owner。
- scope 构建失败时清空临时 scope 并回退；xnLinkFinder 非零退出时保留已有部分输出，
  再追加 LinkFinder 结果并统一 exact 去重。
- scope 构建或 xnLinkFinder 执行失败后，即使 LinkFinder 回退成功，`js_analysis` 仍为
  `partial`；两个分析器都不可用时 `link_analyzer=unavailable`，不能用回退结果掩盖失败路径。

### 4. Validation & Error Matrix

| 条件 | 结果 |
|---|---|
| deep/full、匿名、xnLinkFinder 可用 | stdin 输入原生 URL 列表，保留工具原有限制、严格过滤输出；不运行 LinkFinder |
| curl 或 LinkFinder 失败 | 记录失败、phase 保持 `partial`；不分析不完整正文、不隐式重取 |
| xnLinkFinder 非零退出 | 保留部分输出、记录 warning，追加逐 URL LinkFinder 结果，phase 保持 `partial` |
| scope 构建失败 | 清空 scope，记录 warning，回退逐 URL LinkFinder，phase 保持 `partial` |
| IP、单标签、越界输入或显式端口 TARGET | scope 留空，不启动 xnLinkFinder，回退逐 URL LinkFinder |
| 认证上下文 | 不运行 xnLinkFinder，逐 URL 隔离认证信息 |
| 两个工具均不可用 | `link_analyzer=unavailable`、phase=`partial`，endpoint 数为 0，不把 JS coverage 标为 tested-clean |

### 5. Good / Base / Bad Cases

- Good：scope 内非常见 TLD 和相对 API 路径被保留，认证信息不跨 origin。
- Base：分析成功但没有 endpoint，保留空 artifact 和 analyzer 状态。
- Bad：非 TTY 使用 `-i FILE` 后静默空结果，或把同一认证 header 交给递归 crawler。

### 6. Tests Required

- Shell 语法和静态 wiring 固定 profile、scope、rate、depth、fallback 与输出路径。
- fake xnLinkFinder 必须断言目标文件字节进入 stdin、参数包含 `-sf/-all/-d/-rl/-mrs` 且没有 `-i`；
  同时覆盖恶意后缀域输出过滤、非零退出时保留已过滤的部分输出和显式端口回退。
- 临时直接调用至少验证一个 API 路径和一个认证路径能被已安装 LinkFinder 提取，
  与内置解析共用一次 curl，失败保留 `partial`，正常与中断退出清理临时正文。

### 7. Wrong vs Correct

#### Wrong

```text
xnLinkFinder -i targets.txt + shared auth headers
```

#### Correct

```text
anonymous deep/full: xnLinkFinder -sf scope ... < targets.txt
authenticated/failed: LinkFinder on the current curl response, then reuse the temporary file
```

---

## Scenario: 证据触发的第三方深度 JS 恢复适配器

### 1. Scope / Trigger

新增或修改调用本地第三方 JS 恢复工具的适配器时适用。适配器只补充已有 deep-JS
lane 的原始 artifact，不能成为 Recon 默认步骤，也不新增 Surface、Queue、Inventory 或 finding
owner。

### 2. Signatures

```bash
python3 tools/deep_js_packer.py --target TARGET --mode bundle|page \
  --signal webpack-runtime|dynamic-import|chunk-map|source-map|minified-unreadable|missing-lazy-chunk \
  --evidence-ref REPO_RELATIVE_ARTIFACT [--url TARGET_OWNED_URL]
shuji --version  # pinned operator contract: 0.8.0
```

`bundle` 最多接收 5 个已定位 bundle；`page` 必须接收恰好 1 个 target-owned 应用入口。

### 3. Contracts

- 调用必须有仓库内真实 `evidence_ref` 和具体 runtime/chunk 信号；JS 数量、候选文件存在或
  scanner-negative 都不是触发条件。
- 初始 URL、上游递归 JS、Source Map 和重定向目标均经 `url_belongs_to_target()`；外域 URL 不得
  到达上游 session。
- `--browser` 的 Playwright context 必须在任何导航前安装 route；同目标 HTTP(S) 请求复用统一
  limiter，越界子资源/跳转 abort，不能绕过 Requests/DownloadJs 包装。context 必须强制
  `service_workers="block"`，避免 Service Worker 接管的请求绕过 route。
- child 必须匿名：清除 `BBHUNT_COOKIE`、`BBHUNT_BEARER`、`BBHUNT_API_KEY`、
  `BBHUNT_SESSION_ID` 及全部 `BBHUNT_AUTH_*`，且 Requests session 设置 `trust_env=False`。
- 禁用与目标恢复无关的外部 IP/proxy 探测；限制 5 workers、5 req/s、10 分钟 wall time、500
  文件和 200 MiB 临时工作区。
- 恢复 source 以内容哈希发布至 `recon/<target>/js_dump/packer/files/`；HTML、SQLite、日志只作为
  `raw/` artifact。`manifest.json` 原子记录 `ok|partial|unavailable|error|skipped`、输入、证据、
  耗时和失败摘要；同时记录 `browser_requested`、`browser_status` 和
  `browser_failure_summary`，不能从 worker 退出码推断浏览器阶段成功。
- `.js/.mjs/.cjs/.map/.ts/.tsx/.vue` 恢复文件都必须由现有 `js_reader.py` 消费，大小/vendor 预算
  继续在 reader 侧统一执行。`js_reader` 达到文件上限时优先选择 `js_dump/packer/` 的恢复文件，
  不能让旧缓存先占满预算。
- `selected_js_files` 只是进入当前材料包的候选，不代表已经审阅。所有发现但未选文件必须在
  `skipped_js_files` 中保留 `path`、`size`、`reason`，并由 `omitted_count` 汇总；原因至少覆盖
  `file_cap`、vendor、oversize、stat error 和 hash error。skipped 不等于 clean 或 forbidden。Claude 可以用
  原生 Read/Bash 对明确本地路径做有界补读，或显式提高现有 cap/关闭 vendor skip；默认预算不变。
- `max_files <= 0` 或 `max_file_bytes <= 0` 必须 fail-fast。selected 为 0 但仍有 skipped 文件或
  recon artifacts 时，Hunt 继续暴露可补读材料；只有真实空 inventory 才报告 no material。
- worker 成功退出但未恢复 source 时必须为 `partial`；`partial`/`unavailable` 不关闭现有
  `deep-js-review` action。
- Packer 的 Source Map 私有 helper 只允许在隔离 worker 内替换为 `shuji@0.8.0`。调用前必须
  解析 v3 map（含 indexed `sections[*].map`），清空 `sourceRoot`，并把每个 `sources` 项改为
  带 identity/content hash 的唯一安全平面文件名；不得使用 Shuji `--preserve`、不得保留
  `reverse-sourcemap` fallback。`manifest.json` 必须分别记录 `source_map_status` 和
  `source_map_failure_summary`，没有 Source Map 尝试时保持 `skipped`。

### 4. Validation & Error Matrix

| 条件 | 结果 |
|---|---|
| evidence 不存在、越出 repo 或 signal 非法 | 参数错误，不启动 child |
| bundle/page URL 越出 target | 参数错误，不启动 child |
| 本地工具缺失 | `unavailable` manifest，保留 candidates |
| 上游尝试外域 Source Map/JS | child 拒绝请求，保留诊断，不产生 off-target artifact |
| `--browser` 启动/context/导航失败，静态恢复成功 | manifest 的 browser 状态为 `error`，整体为 `partial` |
| `--browser` 失败且没有任何恢复 artifact | manifest 的 browser 状态与整体状态均为 `error` |
| worker 超时/超工作区 | `partial`（已有 source/raw）或 `error`（无 artifact） |
| worker 退出 0 且恢复 source 为 0 | `partial`，不可标记成功 |
| 相同 source 内容再次恢复 | 复用已有哈希文件，`reused_files` 增加 |
| Source Map 缺 version 3、sources/content 不对齐、混用 root sources 与 indexed sections、或 section offset 非法 | 在 Shuji 前拒绝；记录 Source Map `error` |
| Source Map 含绝对路径、`../`、Windows path、query 或重复 basename | 生成唯一平面名，所有输出留在 worker workspace |
| 需要 Source Map 且 `shuji` 缺失/非零退出 | Source Map 为 `unavailable/error`；其它 Packer source 存在时整体 `partial` |
| 同一 Source Map 在单个 worker 内重复命中 | 已恢复文件算可复用成功，不因新增文件数为 0 误报失败 |
| reader 文件/字节预算非正数 | 参数错误，不生成误导性空摘要 |
| reader 全部候选被 cap/vendor/oversize/stat 跳过 | selected 为空但 skipped/reason/count 保留，Hunt 仍允许精确补读 |

### 5. Good / Base / Bad Cases

- Good：已观察到 webpack runtime 的 1--5 个 bundle 恢复 lazy chunk，随后由现有
  `js_reader.py` 消费。
- Base：page entry 只得到 HTML/SQLite 或工具缺失，manifest 保留 `partial/unavailable`，原始
  deep-JS 候选仍在。
- Base：默认 cap 只选前 N 个文件，后续路径以 `file_cap` 进入 skipped；Claude 根据证据精确
  Read 某个 omitted 文件，不把默认 cap 当成已审结论。
- Good：恶意 `sourceRoot=../../` 和多个 `index.js` 被归一成不同安全文件名，Shuji 恢复结果
  仍经现有哈希发布和 `js_reader.py` 消费。
- Bad：把全部 JS inventory 投给恢复工具；继承认证 Cookie；或让外部 Source Map/重定向绕过
  target scope。
- Bad：把不可信 source path 直接交给 `shuji -p/--preserve`，或 Shuji 缺失后静默回退
  `reverse-sourcemap` 并把其它 chunk 结果标为完整 `ok`。

### 6. Tests Required

- `tests/test_deep_js_packer.py` 覆盖 evidence、target scope、匿名环境、外域 Requests/Playwright URL、
  Service Worker 禁用、浏览器阶段状态、worker/速率/时间/工作区上限、零恢复 partial、哈希复用、
  missing tool、多扩展名 js-reader 消费、Source Map v3/indexed shape、安全唯一文件名、真实 Shuji
  argv、缺工具/非零退出状态以及单 worker 重复恢复。
- `tests/test_js_reader.py` 必须覆盖旧缓存达到文件上限时，Packer 恢复文件仍进入读取材料。
- `tests/test_js_reader.py` 还必须覆盖 cap 尾部/all-skipped 的完整 reason/count、vendor/oversize/
  stat failure、非正预算 fail-fast，以及 selected 不等于 reviewed 的摘要语义。
- `tools/hunt.py` 回归必须覆盖 selected 为 0 但 skipped/recon material 存在时继续建议有界补读。
- 使用临时 localhost fixture 验证 bundle 恢复、page 模式和原子 manifest；不得依赖真实目标或
  `~/.claude`。
- 修改命令/skill 文案时，固定 Autopilot、`/js-read` 和 `web2-recon` 都只描述证据触发及
  `partial/unavailable` 语义。

### 7. Wrong vs Correct

#### Wrong

```text
all JS URLs + inherited auth environment -> third-party recovery -> success on exit 0
```

#### Correct

```text
concrete runtime evidence + target-owned bounded URL -> anonymous scoped child
-> browser status + Service Worker block -> hash-published source artifact
-> prioritized existing js-reader; zero source or browser fallback remains partial
```

```text
Source Map: v3 parse -> safe unique flat sources -> shuji@0.8.0 without --preserve
-> explicit source_map_status -> existing hash publication
```

Wrong: `selected_js_files=[]` -> “没有 JS 材料”或“其余文件安全”。

Correct: selected + skipped(reason/count/path) -> Claude 按证据精确补读或显式调整现有预算。

## Deep-JS acquisition selection

`select_bundle_urls` preserves explicitly supplied URL order. Without explicit
URLs it uses candidate-file order after existing URL/target checks and exact
deduplication, capped by max_bundles. Filename-token scoring is retired. Source
candidates remain unchanged; this window is not a relevance judgment. Resource
recovery, browser/source-map handling, timeouts and acquisition budgets retain
their existing contracts. Regression: tests/test_deep_js_selection.py.
