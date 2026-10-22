# 架构与成本重点审核

2026-10-22，源码 `d8a91a1`，仓库 `/root/tool/ccst(rename-_Ya66f2)/ccst3/ccst`。这是只读审核，未修改产品源码、方法、任务状态、个人 runtime 或真实目标。三个独立只读探子检查状态聚合、记忆增长、规则/模型成本；主线程阅读架构契约并做针对性复现。按 Linux 单操作者、多个独立目标、每目标 SQLite 和本地原件文件评估，不按多租户 SaaS 负载评价。

## 结论

保留现有架构主干。目标内单一事实 owner、显式初始化/写入、模型判断与机械证据分离、按需方法加载，都有清楚边界；静态 import 图未发现循环 SCC，Store 未反向 import Coverage/Checkpoint/runner。不建议新建控制器、ORM、向量服务、通用缓存层，也不因模块行数大就拆模块。

优先改进：接口导航与模型无效往返；同次读取的重复计算；数据增长后的算法复杂度。保留外部证据的新鲜字节校验及组装前后 binding 检查。一次 Store revision 未改变不能证明原件未变，不能把所有复验都删掉。

## 排序后的发现

### 1. 可见无效往返消耗模型预算，但尚不能归因于规则长度

上一轮 7 个独立会话及 B2 的压缩后续接共 80 次可见工具调用，其中45次没有取得新增材料：20次无可达代理、13次文件搜索无结果、11次 unchanged Read、1次文件不存在。其中30次是在已无新增结果后，以同样工具和同样输入再次调用。首次查无结果可能有信息价值，不把45次都视为错误；30次重复更值得处理。

B1 的15次 ListAgents和6次Glob没有生成请求计划；空组多次读取未变文件，同样耗尽回合。两组计价合计$0.852586，占包括压缩续接的总成本30.75%。这是失败会话的成本比例，不是已经证明可直接节省的比例。

当前 `commands/autopilot.md:32` 与 `skills/runtime-protocol.md:75` 已要求先用绑定记忆、按owner展开，成功组C2也使用了现有接口。因此不能再把“缺少另一套恢复控制器”当根因。先修下面的真实接口导航缺口；若后续改宿主指令，应针对重复无信息调用做固定失败基线复验，不能直接宣称加一句规则就会修好。

证据：`formal/sessions/b_recall_1/visible.jsonl`、`b_empty/visible.jsonl`、`b_recall_2/visible.jsonl`，均只含净化后的可见文本/工具信息。

### 2. 顶层帮助隐藏现行接口，纠错说明链接落不到实际合同

`tools/experience_recall.py:408` 只有第一参数为现行命令时分流到新parser；裸 `--help` 进入旧parser，未列出query/history/context及索引、关系等10个现行子命令。主线程在隔离生产副本直接执行 `main(['--help'])` 确认。C2可见日志也出现过这个旧帮助，接口可发现性确实不佳。

`skills/runtime-protocol.md:33`、`:79` 指向 `commands/target.md` 查版本、来源与纠错详情，但该文档没有version/sources/link/retract-link调用说明。实际七个来源相关命令在 `tools/target_memory.py:751` 定义，link还要求conditions、reason和expected-revision。

最小修正：顶层帮助展示现行子命令及 `<command> --help`；target文档补短导航和必要参数，不再复制实现或增加新工具。README另有低优先历史描述漂移：`:390` 仍把已退役request-diff写成可用；`:361` 将可选autopilot角色描述为自主循环。

### 3. bounded 状态输出仍重建完整 Coverage，同次读取还重复算输入清单

路径：`tools/autopilot_state.py:1599` → `_load_autopilot_control_facts` → `resume_read.py:160` → `runtime_state.py:1300` → `coverage_matrix.py:962`。最终只返回少量端点/历史，不改变底层遍历全部reviews、URL、findings和当前证据的成本。现有契约已承认“输出有界不等于读取有界”；这里是热点成本，不是另一个写入owner。

同一 `read_matrix` 在开始、内部rebuild、结束计算3次 `coverage_source_fingerprint`，内部结果在外层`:971`被新值覆盖。一次总指纹又通过Surface状态查询和显式调用分别构建同类输入manifest。主线程在有效Surface索引、40条合成URL上测到：3次总指纹、8次输入清单、1次完整matrix构建。profile下约0.092秒，说明小目标当前并非不可用；次数证据比单次耗时更有代表性。

最小修正：先在同一次获取中复用已捕获输入清单，避免被覆盖的中间指纹计算，同时保留组装前后的漂移检查。完整Coverage与轻量恢复视图是否进一步分开，要按实际路由/闭合需求处理，不能删掉影响授权和完结判断的事实。

源：`tools/coverage_matrix.py:327`、`:345`、`:962`、`:1364`；`tools/surface_index.py:724`、`:749`。

### 4. 已知 Surface 缓存过期仍执行完整证据读取

`tools/surface_projection.py:437` 已有当前Store binding，`:441` 先建完整manifest，`:445` 才判断store/revision不匹配。manifest中的 `_semantic_evidence_ledger` 又读取当前证据并验证原件。任何note/goal/action写入使revision变化后，这部分工作无法使旧projection有效，最终仍返回stale。

隔离复现：发布Surface后保存一条handoff；再次读取返回 `stale/store-revision-mismatch` 前，仍调用一次完整manifest、一次current truth与closure_records。

最小修正：先做store/revision快速拒绝。仍可能有效的投影继续完整字节校验；不新增跨请求缓存。

### 5. 文本检索每个查询词重复序列化同一文档，分页只限制输出

`tools/recall_index.py:471` 在healthy FTS后做子串补齐，对每个未命中词都调用 `_document_text`；该函数`:306`会重新json.dumps完整record。250条、每条4KiB、12个不命中的查询词，在实际FTS与词法函数中触发3000次全文序列化，结果为空；不是250次。验证时只替换generation来源，FTS反序列化、MATCH与生产词法代码均真实运行。

`query_text:549` 对每分区传limit=None，`:559`才切页，因此每页都重新获取/扫描/排序。需要完整排序和准确余量的部分是当前合同，不能为了成本让结果漏项；可省的是每词重复构造、已由FTS命中文档的补充匹配和同请求已验证generation重读。

最小修正：每文档只构造一次casefold文本，补齐未被FTS命中的来源；复用同请求generation。保留中文子串命中及来源/排名cursor绑定。这一重复序列化模式原先fresh-source路径也存在，88d8f05的正确性修复让healthy FTS路径也承担它，应继续优化，不能撤销并集修复。

### 6. 长来源链出现平方增长，有界根记录不能约束传递依赖

`tools/target_store.py:1317` 为每条经验分别执行 `_recall_dependencies`；`:1079`每次重建seen，沿整条链重新读取、解析和校验相同历史版本。主线程用生产walker、最小内存SQLite合成schema验证：120个唯一版本的线性链，从每个根展开共访问7260次版本，即120×121/2。

另外`:3227`的健康传播以while反复扫描全部nodes；按根到叶顺序、叶子不健康时，每轮只向上传一层，同样存在平方增长。这一项是源码推导，本轮未单独做完整Store时序基准。

最小修正：单次只读快照内共享精确版本/依赖节点读取，健康传播改为反向邻接队列；保留origin/basis区别、精确版本、hash和单调失效语义。不要跨revision盲存“健康=true”。小库浅链影响有限，积累后的连锁经验更值得关注。

### 7. 可选关系分页可返回相同的零进度游标

`tools/relation_recall.py:258` 在全图校验和邻接准备前启动默认1秒计时，`:351`才检查预算。准备阶段耗尽预算时没有走任何边，`:375`仍返回初始状态cursor；下一页重复准备，又返回同cursor。

主线程用同一合法合成图验证正常情况下有1条路径，再控制monotonic时钟模拟准备耗时1.01秒：连续两页examined_edges均为0且cursor完全相同。此为确定性边界复现，不声称已测出真实大图的卡住阈值，也不是当前默认Autopilot必走的路径。

最小修正：明确准备和遍历预算边界，至少保证可恢复分页推进，或在不能推进时返回明确的预算调整要求；不让调用者无提示重复同一页。保留全图/来源校验。

### 8. 同次记忆读取还有两处小型复用遗漏

`target_store.py:3836` 先组装最近经验页，`:3837`再单独组装handoff；handoff已经在页内时，其来源图重复处理。隔离单条handoff样本测得 `_experience_health` 两次。可从本页取最新handoff；页外才查询，不能丢掉旧窗口之外的独立handoff。

`experience_recall.py:248` 最后 `acquire_snapshot` 没传 `knowledge_parse_capture`，导致已命中解析缓存后又重新解析整套知识。正确同型调用可见 `recall_index.py:81`。补传该缓存即可，仍重新检查知识原件、review receipt和健康；该点本轮为源码核对，没有读取真实知识内容或做解析计时。

## 成本实账口径

只复核此前固定 `claude-opus-4-8` / Claude CLI 2.1.304 的7会话，没有新付费实验。回执是 `costBasis=list` 的CLI估计，不是供应商账单。

| 范围 | CLI计价 |
| --- | --- |
| 7个初始会话 | $2.466211 |
| B2压缩及其续接追加 | $0.306449 |
| 合计（不含之前入口探针） | $2.772660 |

完整范围普通输入258,940，cache-read 1,611,520，输出26,888，cache-write为0；缓存占全部输入计数86.16%。按回执计价关系拆分为普通输入$1.294700、缓存输入$0.805760、输出$0.672200。不能把缓存输入按普通价计算，也不能将静态文件字节数直接当token。

声明常驻 `CLAUDE.md` 加13个@import共14文件、67,568字符、141,888字节（约142KB）。这是一项固定上下文成本，不是全部无用内容；没有证据支持删原6k规则能改善深度。runtime protocol、src-hunter和选中lane已允许同会话复用，当前没有强制每轮读取全库。十个native agent均model:inherit，所以使用Opus时不会因为README写了Haiku偏好就自动省钱。

## 最小优先顺序

1. 修真实接口导航；在已有失败基线上评估无效重复调用，不新增controller。
2. 清除同次重复工作：指纹/清单复用、Surface提前拒绝、每文档一次序列化、handoff和知识解析复用。
3. 修关系分页零进度；有长链场景时优化来源读取和健康传播。
4. 对真实目标规模做后续profile，再决定是否细分轻量恢复与完整Coverage。此轮不用新服务或牺牲新鲜度换数字。

## 验证与限制

7个定向复现全部得到预期问题证据；这是发现被确认，不是功能修复后通过。生产源码从固定commit归档到临时目录；网络、原仓库数据/个人配置/tests读取由audit guard拒绝。SQL链与时钟是明确合成边界；没有真实大库、全链路网络调查或长期成本统计。profile时间带计数开销，不作通用性能承诺。

源码未修改，工作区干净，未新建Trellis任务或改旧任务状态；未运行项目tests、安装依赖、读取真实目标/知识正文、全局配置、隐藏思考。运行证据在 `/tmp/ccst-architecture-cost-result.json`，成本复算在 `/tmp/ccst-architecture-cost-model-evidence.json`，复现配方在 `/tmp/ccst-architecture-cost-check.py`。临时文件不是永久任务归档。
