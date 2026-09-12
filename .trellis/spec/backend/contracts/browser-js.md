# Browser and JavaScript Contracts

> Browser evidence、增量发现和 JavaScript 分析契约。

## Scenario: MCP 浏览器文件证据与有界增量发现

### 1. Scope / Trigger

- 修改 `/autopilot` 浏览器工具权限、MCP artifact 导入、Browser Surface 增量或浏览器
  continuation 时适用。
- 浏览器执行 owner 是当前 Claude 会话中的 Playwright MCP 和 Chrome DevTools MCP；本项目不
  通过 Bash 启动 `agent-browser` 或 `playwright-cli`，CLI 只可作为历史 raw-parser 测试输入。
- `capability_profile` 只能把本地 importer 报为 `artifact_bridge`；它不能从 helper 文件存在
  推断 live MCP。会话 MCP 未被当前控制器 probe 时保持 `ready=false`、
  `runtime_status=unchecked`，并通过 `bridge_ready` 单独表达导入能力。

### 2. Signatures

```bash
python3 tools/browser_mcp_import.py --target <target> --network-json <path> [--har <path>] [...]
python3 tools/browser_mcp_import.py --target <target> --focused-manifest <manifest.json> [--max-urls 8]
```

Focused manifest 为 `{"target":"...","captures":[{"url":"https://...","source":"playwright-mcp","network":"...","snapshot":"..."}]}`。

### 3. Contracts

- 每轮第一次浏览器动作前只做一次无副作用的 page-list/session probe；仅 timeout、断连或
  context closed 可重试一次。缺失、配置、权限或协议错误不重试。
- 二次失败通过既有 Action Queue/checkpoint 记录 blocker，并切换 JS/source/API 证据；不得
  新增浏览器 health 状态 owner。下一轮、环境修复后或显式 operator retry 可重新探测。
- Playwright MCP 优先用原生 `filename`，Chrome DevTools MCP 用原生 `filePath`；模型只
  编排 artifact 路径，不复制 tool response 正文。
- focused capture 只接受绝对 HTTP(S)、同目标、exact 去重后的 AI 选择页面，默认最多 8 条。
- raw network/console/cookie/storage/state/HAR/screenshot 写 `.private/browser/`；公共侧只保留
  URL/body/console/snapshot 形状、计数、hash 和私有路径引用。WebSocket frame、SSE event
  和 GraphQL batch 也只发布有界的 transport、顺序、marker、大小、SHA-256 及
  `network_private_json` 的 request-index 引用；消息正文只留在 private raw artifact。
- 缺失/无效 network 时可用 HAR 补公共请求形状；仍缺核心 network 则是 `partial/error`，
  不能解释为 tested-clean。
- capture `summary.json` 必须先发布，再刷新 page→JS map；否则当前 capture 的 JS 会延迟到
  下一页面并错误归因。Surface 差分包含 XHR、API、参数和 JS。
- 只有高价值且出现新 target-owned Surface 或非重复 snapshot shape 的批次，才以 generation
  幂等写入既有 Action Queue。

### 4. Validation & Error Matrix

| 条件 | 结果 |
|---|---|
| 首次 probe timeout/断连/context closed | 短暂等待后最多重试一次 |
| MCP 缺失/配置/权限/协议错误，或第二次 probe 失败 | 本轮停止浏览器重试，checkpoint blocker，切换非浏览器证据 |
| manifest target 不匹配 | fail-fast `ValueError` |
| relative/file/off-target URL | `skipped`，记录 `invalid_url/off_target` |
| 超过 8 条 | 额外条目 `budget_exhausted` |
| 单 capture 文件损坏/复制失败 | 该项 `error`，其余继续，批次 `partial/error` |
| network 缺失但 HAR 可解析 | 用 HAR 建 Surface，HAR 原件保持私有 |
| 重复 snapshot 且无新 Surface | 归档但不入队 |

### 5. Good / Base / Bad Cases

- Good：持久 MCP session 访问 2 个同目标页面，文件导入后当前页面的 JS/API 立即进入 Surface，
  一个 generation continuation 入队。
- Base：瞬时断连只重试一次；仍失败时保留 blocker 并切换 JS/source/API，下一轮可重试。
- Bad：浏览器不可用时无限重试、创建第二套 health 状态、把 MCP 正文复制进 prompt/公共 JSON，
  或把 raw URL corpus 直接作为浏览器访问清单。

### 6. Tests Required

- `tests/test_browser_mcp_import.py`：真实 MCP envelope、文本输出、HAR fallback、私有值不泄露、
  URL scope/budget、当前 capture JS 差分、snapshot 去重、实时消息 shape 和队列幂等。
- `tests/test_autopilot_inline_contract.py`：slash command 允许 Bash、Playwright MCP 和
  chrome-devtools MCP，不锁回 Bash-only；固定 first-use probe、瞬时错误单次重试和 blocker handoff。

### 7. Wrong vs Correct

#### Wrong

```text
MCP response body -> model copy -> public evidence / second browser queue
```

#### Correct

```text
first-use probe -> MCP filename/filePath -> browser_mcp_import -> private raw + public shape -> Surface -> existing Action Queue
```


## Scenario: Recon JS 链接分析器调用契约

### 1. Scope / Trigger

修改 `recon_engine.sh` 的 xnLinkFinder/LinkFinder 选择、参数、输入或输出时适用。

### 2. Signatures

```text
run_xnlinkfinder BIN TARGETS_FILE SCOPE_FILE OUTPUT_FILE TARGET
run_legacy_linkfinder TARGETS_FILE MAX_JS OUTPUT_FILE
```

### 3. Contracts

- `normal` 只保留完整 JS inventory 和有界候选；`deep/full` 匿名上下文优先 xnLinkFinder，
  `quick`、缺工具、非零退出或认证上下文使用逐 URL LinkFinder。
- xnLinkFinder v8.2 在非 TTY 中必须从 stdin 读取 `TARGETS_FILE`；不得改回 `-i FILE`。
- xnLinkFinder 必须使用 `-sf SCOPE_FILE`、现有 `RATE_LIMIT`、depth=1 和工具级 timebox；v8.2 的
  depth=1 只请求显式输入，depth>1 才递归请求发现链接。`-sf` 是不安全的域名子串匹配，不能独立
  充当项目 scope owner；启动前必须拒绝越界输入，发布前再由 `url_belongs_to_target()` 严格过滤输出。
- 任一输入 JS 使用 IP、单标签或越界 host，或 TARGET 带显式端口时，整批回退逐 URL LinkFinder；
  xnLinkFinder 的域名 scope 不能表达这些边界。
- 认证 header 只允许逐 URL 按 target scope 选择，不能传给跨 origin 的递归分析。
- 两条路径继续发布既有 `js/linkfinder_endpoints.txt`，不新增 Surface/Queue owner。
- scope 构建失败时清空临时 scope 并回退；xnLinkFinder 非零退出时保留已有部分输出，
  再追加 LinkFinder 结果并统一 exact 去重。
- scope 构建或 xnLinkFinder 执行失败后，即使 LinkFinder 回退成功，`js_analysis` 仍为
  `partial`；两个分析器都不可用时 `link_analyzer=unavailable`，不能用回退结果掩盖失败路径。

### 4. Validation & Error Matrix

| 条件 | 结果 |
|---|---|
| deep/full、匿名、xnLinkFinder 可用 | stdin 输入、只请求显式输入、严格过滤后发布现有 endpoint artifact |
| xnLinkFinder 非零退出 | 保留部分输出、记录 warning，追加逐 URL LinkFinder 结果，phase 保持 `partial` |
| scope 构建失败 | 清空 scope，记录 warning，回退逐 URL LinkFinder，phase 保持 `partial` |
| IP、单标签、越界输入或显式端口 TARGET | scope 留空，不启动 xnLinkFinder，回退逐 URL LinkFinder |
| 认证上下文 | 不运行 xnLinkFinder，逐 URL 隔离认证信息 |
| 两个工具均不可用 | `link_analyzer=unavailable`、phase=`partial`，endpoint 数为 0，不把 JS coverage 标为 tested-clean |

### 5. Good / Base / Bad Cases

- Good：scope 内非常见 TLD 和相对 API 路径被保留，认证信息不跨 origin。
- Base：分析成功但没有 endpoint，保留空 artifact 和 analyzer 状态。
- Bad：非 TTY 使用 `-i FILE` 后零请求却返回 0，或把同一认证 header 交给递归 crawler。

### 6. Tests Required

- Shell 语法和静态 wiring 固定 profile、scope、rate、depth、fallback 与输出路径。
- fake xnLinkFinder 必须断言目标文件字节进入 stdin、参数包含 `-sf/-all/-d/-rl` 且没有 `-i`；
  同时覆盖恶意后缀域输出过滤、非零退出时保留已过滤的部分输出和显式端口回退。
- 本地 HTTP fixture 至少验证一个 API 路径和一个认证路径能被已安装版本提取。

### 7. Wrong vs Correct

#### Wrong

```text
xnLinkFinder -i targets.txt + shared auth headers
```

#### Correct

```text
anonymous deep/full: xnLinkFinder -sf scope ... < targets.txt
authenticated/failed: per-URL LinkFinder fallback
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

### 5. Good / Base / Bad Cases

- Good：已观察到 webpack runtime 的 1--5 个 bundle 恢复 lazy chunk，随后由现有
  `js_reader.py` 消费。
- Base：page entry 只得到 HTML/SQLite 或工具缺失，manifest 保留 `partial/unavailable`，原始
  deep-JS 候选仍在。
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
