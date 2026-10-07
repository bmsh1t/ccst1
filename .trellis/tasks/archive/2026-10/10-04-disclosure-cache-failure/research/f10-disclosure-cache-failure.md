# F10 只读研究（2026-10-07）

基线 `df0eafd`；两项一次性探子分别探索 production owner/调用链与测试/消费者，均优先
使用 fast-context，再做精准检索。主线程亲读完整 disclosure_search、现有测试、研究 agent
指导、provider search 分支及共享原子 writer；研究阶段未改产品代码、运行测试或调用上游。

## 真实 owner 与根因

- `tools/disclosure_search.py:370-406`：CLI→`write_disclosed_patterns()`→两类查询→Markdown。
  CLI 仅打印文件路径、正常返回 0，没有 JSON 输出协议；未发现其它生产 Python 调用者。
- `:135-211`：查询 helper 只返回 `list[DisclosedReport]`。same 的调用和解析被 broad catch
  转为 `[]`；similar 仅捕获调用异常，坏响应迭代仍会意外崩溃。成功空、部分失败、全部失败
  因而不能由 writer 区分。
- `:109-132`：唯一 cache 路径为 `state/disclosure_cache/<target-key>.json`；payload 是
  target/same/similar/coverage_status/cached_at_ts，无版本字段。reader 在 TTL 过期后丢弃
  材料；writer 直接覆盖并自行写入 `time.time()`，不是原子发布。
- `:328-353`：cache miss 后总是写回，包括 client 不存在、全部查询被吞错、部分查询失败。
  `:234-244` 的 Last updated 是渲染时间，不是 cache 成功时间。
- 缺失 coverage_status 的旧缓存按桶推导；历史 mcp_unavailable 是已知不可用，不能当作
  成功快照。过去错误写成 no_mcp_coverage 的空缓存与真实成功空缓存不可无损区分，不能
  凭新代码猜测历史来源或自动恢复已经丢失的报告。

## Provider 边界

- `mcp/hackerone-mcp/server.py:44-80` 已有 `HackerOneAPIError`，处理 HTTP/URL/JSON/
  GraphQL errors；search `:85-159` 是同步 urllib 链路。
- `:140-159` 的 `(data.get("data") or {}).get("hacktivity_items", {}).get("nodes", [])`
  把缺失／null envelope 当作成功空列表；owner 无法识别已被 provider 抹掉的失败。
- 最小协议校验若纳入本批，只限 search 的 envelope/nodes/记录消费点，并沿已有异常返回；
  不改 stats/policy、认证、TLS、查询转义或通用传输层。合法无 report 节点和可选字段不能
  误判成必须补齐所有字段。具体改动范围须在最终设计中明确。
- owner 接口本身也需拒绝 None、非列表或坏条目，不能让一个坏查询抹掉其它查询的成果。

## 消费者与复用

- `agents/disclosed-researcher.md:51-61,76-96` 运行 CLI 并读取 Markdown，随后可能人工追加
  Read in full。现有失败指导要求不可达时空文档；应改为区分查询状态、材料时间与 stale。
  本批保全对象是成功查询 cache，不扩大为任意 Markdown 编辑合并。
- `tools/intel_engine.py:964-965`、`commands/intel.md:28-30` 保持 disclosure 独立；不要
  移入 Intel artifact/continuation 或 Store 领域 owner。
- `tools/artifact_io.py:15-49` 是已有原子发布能力；可复用 `write_text_atomic` 保持现有
  JSON 序列化字节格式。其余发布/fsync/replace 故障已有 `tests/test_artifact_io.py:22-48`
  覆盖，F10 只需验证 disclosure 消费者接线与旧 cache 保全。
- `tools/intel_sources.py:305-409` 可参考 stale 与查询错误分离的语义，不能直接套其 cache
  engine：路径/schema 与持久 last_error_at 不符合本批无新状态约束。
- 规范入口：`.trellis/spec/backend/error-handling.md:3-26,38-40`，
  `.trellis/spec/backend/database-guidelines.md:191-237`，
  `.trellis/spec/backend/quality-guidelines.md:7-28`。

## 测试与验证预算

- `tests/test_disclosed_pattern_dedup.py:16` `_report` 可复用；`:102-134` 覆盖健康查询与
  cache hit 字节不变；`:136-161` 是健康的 program-empty→keyword-hit，不是失败回归。
- `:72-78` 仅 renderer 三态测试，不足以验证真实查询失败；`:81-94` 已固定 no-mcp 不加载
  client、不读 inventory、不建 state 的契约，可补预置 cache 保全。
- `/tmp/ccst-audit-2026-10-02/reproduce.py:227-246` 与 `results.json:55-59` 有失败刷新
  毁掉旧报告的历史证据；不要 import/run 整个脚本，其顶层会执行全部审计并改 results.json。
- 用 tmp_path、固定时钟、fake `_load_h1_client` 的 `search_disclosed_reports` 与隔离的
  `_load_tech_stack_hint`，覆盖 total failure/client missing＋有无旧 cache、完整成功零结果、
  partial 有无报告、fallback 恢复、TTL hit、TTL=0 刷新、坏上游/坏缓存及 publication failure。
  不直接 mock 两个查询 helper 成空列表，否则绕过真正吞错点。
- 对旧文件比较 bytes、cached_at_ts 与 mtime；Markdown 同时断言来源时间、partial/stale/
  unavailable，而不只验证列表长度。查询计数应证明一次失败不阻止其它查询继续。
- 研究阶段计划的 focused 命令（最终执行结果见下方；provider 接线用例也在该文件）：

  ```bash
  python3 -m pytest -q tests/test_disclosed_pattern_dedup.py
  ```

## 决策与后续规划

原 PRD 一方面要求失败保全成功 cache，另一方面写“部分失败……健康查询仍按现有路径保存
成功材料”，没有明确整份单快照是否可被 partial 替换。在单一保全方案确认后用户要求
继续，现采用不替换完整成功 cache、partial 有报告只展示新材料、无新报告可读有效旧
快照的策略；不引入逐关键词 provenance 或混合快照。program 失败后 fallback 成功仍
保留 partial 事实，不能假装全部查询成功。
设计与验收矩阵见 design.md/implement.md；两份 jsonl 各含三条真实上下文。database-guidelines
超过自动注入上限，故只在本记录保留其原子发布契约及 :191-237 定位，按需读取原文。
用户已以“go”批准最终规划摘要并激活；实现与定向验证结果见下方。

最终规划独立复核补充：`server.py:145-148` 的 `if not report` / `team or {}` 会把空列表、
false、0、空字符串等坏类型当缺失。设计已明确缺失/null/对象之外一律拒绝，包括假值；
增加真实 provider→owner 的 `report=[]` 等回归，避免协议错误仍覆盖成功 cache。

## 实现与验证（2026-10-07）

- 实现前运行 `python3 -m pytest -q tests/test_disclosed_pattern_dedup.py -k failed_refresh
  --maxfail=2`：**2 failed**，分别证明无缓存时制造成功空缓存、有缓存时覆盖旧字节。
- 四文件实现后新增子集 **65 passed / 11 deselected**；随后补 TTL=0 同时刻强制刷新，
  `-k complete_empty` **2 passed**。上述为实施阶段结果，不当作最终整文件结果。
- 主线程读取完整五文件范围，补直接 renderer 只展示显式查询事实，以及非有限 TTL
  在发布前拒绝；前者防止 mcp_unavailable 同时声称 complete-zero，后者防止 NaN
  让过期比较恒假。错误契约已同步，有限负数／零 TTL 的刷新语义保留。
- 主线程运行 `python3 -m pytest -q tests/test_disclosed_pattern_dedup.py`：**80 passed**，
  随后的 `git diff --check` 通过。无全仓 suite/build、安装、线上请求或真实目标读写。
- 两项独立只读复核覆盖生产链及测试／消费者／契约，未重复执行测试。发现一项 P2：
  `_load_cache` 将已提供但非法的 coverage_status 按历史缺字段推导。主线程收紧为只有
  字段缺失时推导，已提供状态必须表示完整成功；用新鲜 cache 的 `{}` / partial / null
  回归证明不会 cache-hit。随后运行：

  ```bash
  python3 -m pytest -q tests/test_disclosed_pattern_dedup.py -k 'bad_cache or healthy_cache or failed_refresh'
  ```

  **30 passed**，随后 diff check 通过；这是最后修正后的相关子集，不是一次完整 83 项运行。
- 其余未发现阻塞问题，AC1–AC6 已有行为证据；用户以“ok”批准五文件提交，2026-10-07
  工作提交为 `6245fb0`，任务已归档。收尾未重复行为测试，未推送，不开展 F11。

## Bug Analysis：失败不能成为成功缓存

### 1. Root Cause Category

B（跨层契约）与 E（隐含假设）：列表长度被同时用作请求健康和材料覆盖，provider 的假值
兜底、缓存写入及渲染时间共同掩盖失败；D（测试缺口）只验证成功缓存和手工渲染状态。

### 2. Why Fixes Failed

规划复核发现 provider 假值类型仍可伪装无报告；最终生产复核又发现“缺字段兼容”被扩大到
非法状态值。两者均在实际消费点收紧并补真实链路回归，不靠上层无条件捕获或空值兜底。

### 3. Prevention Mechanisms

| 优先级 | 机制 | 已落地动作 |
|---|---|---|
| P0 | 运行时契约 | 请求成功数／失败诊断与报告分离，只有 complete 可保存成功 cache |
| P0 | 输入边界 | provider 类型校验先于真假值判断；cache 仅缺字段兼容，不接受非法状态 |
| P1 | 回归与文档 | 真实 provider→owner、旧 bytes/mtime/时间断言、原子失败测试及七节错误契约 |

### 4. Systematic Expansion

已检查此 owner 的 same/similar/fallback 与缓存／Markdown 两个发布点，不扩大到其它 provider
或新状态系统。复核优先寻找缺失、空、失败和未知之间的混淆，而非仅数报告条目。

### 5. Knowledge Capture

- [x] `.trellis/spec/backend/error-handling.md` 与实际消费者指导同步。
- [x] 验收记录区分初轮 80 项与最后修正后 30 项；没有线上／全仓验证声明。
- 工作与规范一并进入五文件提交 `6245fb0`，不另建指南、模板或任务；journal 引用工作提交。
