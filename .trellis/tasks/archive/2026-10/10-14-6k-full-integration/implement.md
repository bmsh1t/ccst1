# 6k 完整接入实施计划

版本：2026-10-17 / D1=A。对应 [PRD](prd.md)、[设计](design.md)。任务已归档。
B6/B7验收及两批代码提交完成；[回执](research/b7-git-acceptance-2026-10-17.md)。个人runtime未部署。
原 [风险门](research/implementation-risk-review-2026-10-15.md) 及
[协议消歧](research/risk-review-closeout-2026-10-16.md) 继续有效。

## 1. 启动前门槛

- [x] G0：已取得 2026-10-15 原规划的明确实施批准，并执行
  `python3 .trellis/scripts/task.py start .trellis/tasks/10-14-6k-full-integration`。
  不创建替代任务，不因当前 task pointer 为空而丢弃这份规划。
- [x] 确认 cwd 为 C=`/root/tool/ccst(rename-_Ya66f2)/ccst3/ccst`，重读架构合同、
  本设计及相应 backend 规范；规范中的历史路由不覆盖当前架构。
- [x] 按 [原文加载图](research/context-reading-map.md) 完整阅读基础文档及本批涉及的
  canonical 规范/台账。两个 JSONL 只提供可完整注入的基础上下文，不等于已读取大文件；
  调整上下文后须用真实 renderer 确认 PRD/design/implement 未被截断或降为路径索引。
- [x] 阅读 [续接与规划收尾记录](research/planning-closeout-2026-10-15.md)。先前个人
  runtime 的意外安装尚无恢复证明；本任务不得修复或同步该目录。规划检查从脚本/parser
  源码确认参数，不运行 `install.sh --help`；整个实施验收组按 §3.1 隔离，不只 installer。
- [x] 对比当前脏工作树与规划基线；逐文件保存本批修改前实际字节、hash 和差异归属。
  不 reset、不整文件恢复既有改动；若用户期间修改了相同位置，先合并理解。
- [x] 使用临时目录以外的恢复包，覆盖全部受保护脏文件及待改源码；保留 mode、HEAD、
  index 清单及 staged/unstaged binary patch，并在新目录实测字节/权限恢复。不能只存 hash
  或把旧版缺字节说成已备份；每次发布前仍核对当前 before，备份不授权覆盖后续工作。
- [x] 再核对 62 项来源及 B 对照材料的 hash。变化必须更新研究结论；重大范围或兼容
  变化返回规划评审。A/B 外部目录只作来源，不能成为产品运行依赖。
- [x] 用 `mktemp -d /tmp/ccst-6k-accept-XXXXXX` 建立 WORK，再准备隔离开发副本
  S=`WORK/staging` 和验收副本 F=`WORK/repo`。
  按逐文件源码白名单从 C 当前工作树复制到 S，记录相对路径、before hash 与原字节，
  包含既有脏增量而非仅 HEAD。F 的候选代码/方法 payload 从 S 生成并记录候选 hash；
  旧版场景用已保存的 C before 方法字节播种，经 F 自己 bootstrap，不直接拼装健康回执。
- [x] 白名单覆盖实际依赖的代码、知识、规则、安装资源、现有测试及合成 fixture，禁止
  整库盲拷；排除目标/runtime 数据、私有材料、`.env`、令牌、模型和越界符号链接。
  缺少资产必须失败，不能从 C fallback。准备临时 HOME/XDG/TMPDIR/runtime/memory 根、
  I/O/网络哨兵和两个显式初始化的测试目标；全部命令及 pytest 子进程用环境白名单。
  本批不新增项目测试文件、测试框架或 benchmark；验证脚本仅位于 WORK。

## 2. 有序实施批次

B1–B5 的修改位置全部是 S；下文路径仍用 C 相对路径命名。C 的代码、方法、manifest、
入口及 Rules 在 B6 前保持原状。F 是可重建的验收副本，不是 C 的发布来源收据。

### B1：兼容 reader 与文件发布 owner

- [x] 五项歧义已在设计 §4.3–§4.4 定义终态、屏障、身份、slot 和重试分派；本项仅指
  设计处置，实施及机械恢复验收见后续各项。2026-10-16 用户 `go` 已确认本次协议。
- [x] 修改 `tools/hot_method.py`：保留 catalog/diagnostics 和现有输出，支持 v1 只读、
  v2 来源/活动绑定、完整目录、版本化 `--read`/`--origin`、A 的 `--apply` 与 guarded
  `--recover`。读返回锁内捕获并验证的正文，不在校验后重新打开可变路径。
- [x] 实现设计 §4 的唯一协议：目录锁、独立 blobs、before/after 硬链接见证、新路径
  可移动 slot、transaction→pending 屏障、正文→manifest、decision→receipt→pending
  清理；逐阶段文件/目录 fsync。先历史分派再 CAS；恢复方向不可反转，终态不可复活。
- [x] 普通 A 仅接受 v2 且限定 method/index；治理参考、原生 Skill 和共享晋升拒绝。
  首次 `--bootstrap` 只准 v1→v2，复用同一发布/恢复协议，不做平行初始化工具。
- [x] 低层 create-only 若无可复用 API，只在 `tools/artifact_io.py` 加窄小原语；
  不改变原普通 atomic-write 的保证，不反向导入 `distill_digest` 或知识业务 owner。
- [x] 从 S 构建 F，B1 完成门跑满 V2 的 **16 个独立恢复尝试**：apply/bootstrap 各自
  在 pending 后、正文中途、manifest 后但 decision 前、applied receipt 同步后且 pending
  未清四处退出，每处用两份独立 fixture 分别 complete/restore。前三处各自得到 after+
  applied 或 before+restored；receipt 后 complete 只核对清理，restore 必须拒绝
  terminal_applied，全部活动文件/receipt/pending 不变。bootstrap restore 回到 v1。
- [x] 追加异常矩阵：两方向 decision 后再中断及反向拒绝；已有终态不复活；第三种字节、
  原本存在文件被删除；新路径 slot 两个合法位置、两处皆缺、双占位；同字节换 inode、
  见证/父目录/mode 变化、符号链接及
  名称冲突拒绝；准备残留精确重试；两写者 CAS；T1→T2→T1 和 T2 pending 时历史重试
  （含 bootstrap）。blob/见证/slot/transaction/pending/body/manifest/decision/receipt/清理的文件及
  目录同步故障逐项注入，特别核对 unlink 后 pending 已无但调用非零、reader 可读完整
  终态、显式 recover 能补同步的区别。核对实际字节/身份、receipt、decision、pending
  与跨进程 read，不只看 exit code；拒绝型用例不得改冲突路径。C 不动，失败只改 S。

### B2：来源原件、适配正文与初次版本绑定

- [x] 按 [来源台账](research/source-disposition-matrix.json) 保管全部 62 项真实原字节，
  落到逐项 `planned_archive_path`；另保存被本批改动的 C before 字节。
- [x] 修改 `knowledge/methods/clown/README.md`、来源参考
  `skills/src-hunter/SKILL.md`、知识库 `README.md`/`打穿短表.md`：明确唯一原生入口、
  完整方法展开、来源健康、治理优先级及 A 的读写边界；不以摘要替换方法。
- [x] 修改该根下 `references/hunt-iter.md`，落实完整准入条文、三问、主控独立复核、
  真实 reviewer、私有来源保管与正文维护/目标经验/共享发布的分界。
  新增完整 `references/vuln-report-format.md`，仅作来源准入参考，不接管 C 定级。
- [x] 适配 `references/researcher-blackbox-whitebox.md`：分隔误拼浏览器段、残表与
  Phase 0 缺失诊断；C 补充注明来源和作者，不宣称恢复原文。
- [x] 修复索引到 `prototype-pollution-test.md` 的 `KNOWN_GADGETS` 和 `waf-bypass.md`
  的 `WAF_PRODUCT_MATRIX` 内嵌章节。其余方法及 dig-scope/src-value 参考只修真实
  必要的链接/宿主冲突；不整库改写，保留条件、步骤、反例及有效旧机制。
- [x] `knowledge/clown-hot-method-manifest.json` 准备 v2：62 origins、档案 hash、
  活动 sha256、origin_refs、maintenance_scope、初次 revision_ref。治理映射引用
  既有 C owner，不要求修改所有消费者或覆盖 AGENTS/Trellis/用户配置。
- [x] 适配正文和 bootstrap payload 只在 S 准备；从保存的 before 方法树构建 F 再试
  `--bootstrap`、V1/V2。C 的正文和 manifest 均留到 B6，不只推迟 manifest 更新。
  源缺损/许可未独立核实保持可见；不把来源保管数量当能力验收。

### B3：完整目录与同一原生调查入口

- [x] 修改 `tools/context_pack.py`：显式取得完整方法目录，JSON/text 一起展示
  guide、index、未排名 catalog、版本、健康及真实读取命令；保留 `hot_methods` 键。
  方法目录与正文已读状态分开，focus 不过滤目录，卡的 `--known-catalog` 不偷换语义。
- [x] 修改 `skills/src-hunting/SKILL.md`、`skills/runtime-protocol.md`、
  `commands/hunt.md`、`commands/context-pack.md`：移除 selected/focus 才可读的旧描述，
  接完整相关方法、hash 绑定读取、A 的维护与降级诊断；不引第二调查循环。
- [x] 在 `commands/autopilot.md` 接同一 core/观察合同，并把实际关键原生依赖
  `skills/src-hunting/SKILL.md` 加入现有 critical-runtime manifest。
  不往该安装副本清单塞未安装的 knowledge/tools；checkout 方法健康另行检查。
- [x] 在临时已初始化目标运行 V3。手动、hunt、Autopilot 保持共同方法职责；不得
  强制 Recon/scanner/Queue，方法故障不阻断 Store 事实恢复，也不被当作技术阴性。

### B4：独立无裁决观察与浏览器原件登记

- [x] 在 `tools/validation_runner.py` 新增 `record_native_observation` 及
  `record-observation` argparse 分支。保留 `record_native_evidence`/`record-evidence`
  的 Finding、subject/identity v3 和 cleanup 合同，不将 finding-id 改成可选后复用。
- [x] 新 envelope、CLI、逐步 family/时间/描述/执行事实按设计 §5–§6 校验。
  命令 actor 与 HTTP actor 分开；首次/无 predecessor 原样调用 `start_attempt`，保留
  owner 的精确收据重放；有 predecessor 从 `execution` 复用原 attempt/source/start/
  action/token，不 start/reclaim，不一律复查当前 claim。可选关联须匹配原值；补证可由
  不同登记 actor 提交，其重试保留自己的 actor；集合级 family/endpoint 检查仍由 Store 拥有。
- [x] 调整该文件必要的 `_store_observation`、`_record_primary_execution`、
  `_sync_primary_store`、`sync_runner_artifacts` 分支：envelope/summary 的
  `kind="native-observation"` 与 summary 的 `lane="native_observation"` 显式配对。
  按 lane 分派，空 result 不 skipped；未知/错配不能落入 Finding，元数据/predecessor 不丢。
- [x] 原件、summary create-only；新目录为 `evidence/<target>/native-observations/`。
  登记回执独立发布；避开 `_finalize_runner_summary`/main 的旧 summary 覆写尾部。
  已存在字节不符明确冲突；登记失败只给登记重试，不重执行。
- [x] 窄改 `tools/browser_mcp_import.py`：捕获实际选中 export（含 HAR fallback）的 bytes，
  同一份 bytes 用于解析与私有归档；summary 发布前绑定 `network_source` 的
  path/sha256/bytes/format。保留重序列化 discovery 投影，不把它或 requests fingerprint
  当原件基线；不重写通用 identity/去重/清理算法。
- [x] 在 `tools/browser_evidence.py` 增加低层原始 JSON/HAR→有序步骤转换：只读原件、
  结构化解析、不联网、不写 Recon/Store、不反向 import runner/publisher。
  用既有 private artifact owner 发布私有步骤 envelope，并加 create-only 字节守卫；
  不把 `private_artifacts` 普通写入误称不可变或跨文件事务。
- [x] 新 capture 核对 `network_source`；旧 HAR 复用已有 digest 元数据；旧 JSON 无
  捕获基线则 `unverifiable_capture`，保留材料，不补造历史 hash。必须用留存原始导出
  建新 capture 身份后才作已验证登记。解析已核对的 bytes，坏 UTF-8/JSON 不有损替换。
- [x] 浏览器模式必须 `--execution-json`；首次 started_at 来自真实执行记录。
  补证核对 Store 原 attempt，按新 capture 身份保存新原件；完整 ordered snapshot +
  原 predecessor 重试，旧 capture/operation 保留。不重写 importer 通用去重算法。
- [x] 修改 `tools/structured_findings.py` 显式排除新 lane/kind 并拒绝错配；缺响应保留 partial，
  零步真实未知执行仍为 unknown，无假 observation。复用 Scope/target-owned 原件校验，不导入外域流量。
- [x] 修改 `docs/evidence-runners.md`、`docs/tool-index.md`，列完整 envelope、
  浏览器 execution metadata、空结果语义、补证与登记失败重试实例。
- [x] 运行 V4/V5；复用现有 TargetStore/identity/private-artifact owner，**不改 schema**。
  需改 `target_store.py` 或扩大身份/cleanup 合同才能通过时，停止并回到设计查根因。

### B5：记忆、campaign 及专项连续性

- [x] `skills/runtime-protocol.md#cognitive-write-timing` 继续唯一拥有目标写回时机；
  `rules/retrospective.md` 引用它，消除“目标层默认只建议”的冲突。保留只读/预览不写、
  机械登记立即完成；A 方法维护与共享人审不冒充这个时机合同。
- [x] `rules/campaign.md` 明确 seeds 的来源/所属目标/剩余活面/工作材料路径/下一意图，
  开始续接读取、切换前保存、切换后从已初始化新目标读取 current_handoff。
  这是原生文件读取，不虚报自动 seeds consumer，不建 campaign DB。
- [x] `skills/mobile-pentest/SKILL.md` 的退休 API 卡引用转到现有 Web/API 完整方法
  及证据 owner。其他 whitebox/credential/recon/triage/report/CI-CD/Web3/meme 专项
  默认不改；检查可达与依赖，Web3 非 HTTP 生命周期仍明确后置。
- [x] 运行 V6，证明 V4 的真实 operation/step 能被经验及 handoff 消费且跨进程恢复。
  `target_memory`、recall、Resume、Store、cleanup、报告 owners 只读复用，不批量重构。

### B6：先隔离验收，再维护窗口切换

- [x] B1–B5 的候选代码与消费者在 S 齐备；F 完成 V1–V7。V7 从 F 运行 installer/doctor
  及现有测试，knowledge/tools 也只能来自 F；它们默认不改且不访问个人 runtime。
- [x] 进入 C 的维护窗口：关闭入口、目录/正文读取及相关消费者，停止写者、Git 切换和
  同步。逐路径核对 C 仍匹配保存的 before，变化则停止重审，不能覆盖期间的新工作。
- [x] 明确切换执行者与相关会话/编辑器/同步任务的停用情况；本会话除指定切换/回读外
  不触碰 C 受影响路径。不把 flock/进程快照称为整机强制隔离；无法确认排他则不切换。
- [x] 先发布兼容代码，再在 C 以本地实际 before 和已审 payload 执行新 bootstrap，
  最后发布准备好的入口、Rules、critical-runtime 清单；F 的事务/receipt 不作为 C 收据。
  A6 增量在 C bootstrap 后用新事务 apply，不复制 F 的日志或见证。
  回读方法版本和 checkout 消费者一致后才重开；未同步个人 runtime 的入口保持停用/drift。
  中断保持维护关闭，按守卫恢复，不宣称整库原子切换。
  pending 未解决不宣布完整生效；工程切换不授权个人 runtime 安装/同步/提交。
- [x] 汇总 V1–V7 的真实回执、失败/恢复结果及 A1–A9 映射；未通过的标准保持未勾选。
  不把静态文本一致、schema 合法、doctor clean 或工程接通称为在线能力增益。
- [x] 逐文件复核最终 diff：无摘要替代、隐藏 fallback、宽泛吞错、双真源、死代码、
  私有事实泄漏、无关重构或既有 cleanup/degraded/advisory/reframe/指标回退。
  只补受改合同的必要规范；提交、个人 runtime 部署及目标操作须另获明确授权。

## 3. V1–V7 行为验收

全部从 F 的代码和测试在白名单环境/隔离数据根执行，所有网络发送入口设为失败哨兵；这些用例只保存/登记合成原件，
不执行请求。临时脚本真实 import owner 或启子进程，不只比对文件计数/字符串。
普通批次先运行一项约 60 秒内的最窄相关检查；成功即停止该批验证。**B1 是显式例外：
必须跑满上述 V2 故障矩阵，不受单项/60 秒预算替代。**最终共享合同接通需
覆盖下列七组，按风险分组，不顺带跑全量测试、构建或不相关 lint。

| 场景 | 必须观察到的结果 | 映射 |
|---|---|---|
| V1 来源/一致读取 | 62 原件逐一核对实际 bytes/hash 和去向；正常读取在禁止打开 A/B 根的临时进程仍成功；从目录展开完整相关方法、真实内嵌章节和报告准入原文。v1 只读、v2 可读，白盒 source_incomplete/缺原件/changed/坏 manifest 分别可见；read 返回的是当次已校验字节。 | A1、A2、A8、A9 |
| V2 A 维护/中断/冲突 | 主控用无目标事实的完整来源核对门槛/三问，apply→新进程 read 可追溯正文/manifest/reviewer/来源；工具只机械拒绝缺来源、坏 hash、越界、治理修改、同 ID 换材料，不代替语义审核。完整运行 B1 的 16 项基础矩阵及追加异常矩阵，以设计 §4 的唯一状态结果断言。 | A1、A6、A8、A9 |
| V3 共同入口/文本与 JSON | 临时 Context Pack 的 JSON/text 均有完整未排名方法目录、guide/index、版本/诊断/可执行 read 命令；focus 和已知卡目录不能隐藏方法。手动/hunt/Autopilot 引同一 core，目录不冒称正文已读；源坏时现有 Store 事实仍可恢复。抽查各专项与 Mobile 替代链接确实存在。 | A2、A3、A8、A9 |
| V4 中性观察到原 owner | 无 Finding/Action 保存多步原件：method、family、实际时间、描述/缺失不变，Store result=""、无 candidate/Finding/closure/Action 自动解决，真实 step 可展开。相同参数重试同 operation；补证用原 predecessor/完整快照。首次错 token/actor 拒绝；claim 释放/改派后精确 start 重试及补证仍成功，补证可换登记 actor 但不换原关联；错 predecessor/关联及不满足 Store 集合级 family/endpoint 拒绝。零 runs unknown 无假 :0；坏 JSON/时间/原件/冲突在 mutation 前失败。 | A3、A5、A7、A9 |
| V5 浏览器原件保真 | 原始 JSON/HAR 与捕获基线逐字节对应，包含选择 HAR fallback 和输入在捕获后变化场景；顺序、重复 URL、时间、空/缺 body、base64、截断可区分。首次登记前和登记后改 raw 均被基线核对拒绝；旧 HAR 有效基线可用，旧 JSON 无基线明确不可验证；坏 UTF-8/JSON 不静默替换。缺响应 partial，只有 surface/外域/越界有诊断。新 capture 补充同一 attempt 完整快照并保留旧记录；重试/失败零网络重放。summary 不覆写，kind/lane 错配不产生 Finding。 | A3、A5、A7、A9 |
| V6 记忆/换目标/恢复 | V4 的 operation/step 经现有 owner 保存为恰当 note/条件经验/handoff，重启新进程能展开原件和当前 next_intent。两目标切换后不串 current_handoff，campaign 文件保留剩余活面及路径；压缩后走同一恢复协议。只读/预览调用前后 Store/owner 字节或 revision 不变，重要节点保存由唯一时机合同指导；种子 done/预算停止不变技术证伪或 Coverage 完成。 | A3、A4、A5、A7、A9 |
| V7 隔离部署/兼容/回退 | 模块 __file__、installer、doctor、pytest 均在 F；故意缺 fixture 资产不能回退 C，继承的 snapshot/memory/runtime/auth/proxy 被白名单清除。临时安装一致，src-hunting 漂移阻止自动启动，用户改动/未知退休文件保留。在 F 演练 B6 before→代码→bootstrap→入口顺序和中途失败保持关闭；真实 C before 未被 B1–B5 改。错误 cwd/混合版本/origin_only/pending 有诊断。守卫回退不回放或删除新目标事实、原件、经验、cleanup/报告收据。 | A3、A7、A8、A9 |

### 3.1 真实入口与命令

以下是后续实施的运行清单，**不是本轮已执行记录**。先按启动门槛准备并导出临时 `WORK`，
其 `repo` 已按逐文件白名单/hash 从 S 准备，不能只有空目录；测试目标取 `fixture.invalid`
与 `other.invalid`，不发网络请求。所有 material 文件来自上述用例的显式构造，不是
真实目标快照。先启用该组 I/O/网络哨兵，再运行下列环境包装；环境清理不是 OS sandbox。
命令中的新选项按设计实现后才能执行。

```bash
set -euo pipefail
: "${WORK:?prepare the isolated staging and fixture first}"
WORK=$(realpath -- "$WORK")
case "$WORK" in
  /tmp/ccst-6k-accept-*) ;;
  *) printf '%s\n' 'WORK must be the prepared temporary acceptance root' >&2; exit 1 ;;
esac
FIXTURE="$WORK/repo"
TARGET=fixture.invalid
test ! -L "$FIXTURE"
test -f "$FIXTURE/install.sh"
mkdir -p -m 700 "$WORK/home" "$WORK/tmp" "$WORK/memory" \
  "$WORK/xdg-config" "$WORK/xdg-cache" "$WORK/xdg-data" "$WORK/xdg-state" "$WORK/xdg-runtime"

run_fixture() {
  env -i PATH=/usr/local/bin:/usr/bin:/bin LANG=C.UTF-8 TZ=UTC \
    HOME="$WORK/home" TMPDIR="$WORK/tmp" HUNT_MEMORY_DIR="$WORK/memory" \
    CCST_RUNTIME_ROOT="$WORK/home/.claude" \
    XDG_CONFIG_HOME="$WORK/xdg-config" XDG_CACHE_HOME="$WORK/xdg-cache" \
    XDG_DATA_HOME="$WORK/xdg-data" XDG_STATE_HOME="$WORK/xdg-state" \
    XDG_RUNTIME_DIR="$WORK/xdg-runtime" PYTHONNOUSERSITE=1 \
    PYTHONDONTWRITEBYTECODE=1 PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 \
    bash --noprofile --norc -c 'cd -- "$1" || exit; shift; exec "$@"' fixture "$FIXTURE" "$@"
}

run_fixture python3 - <<'PY'
import importlib
from pathlib import Path
root = Path.cwd().resolve()
for name in ("hot_method", "context_pack", "knowledge_registry", "validation_runner",
             "browser_mcp_import", "browser_evidence", "target_store", "runtime_doctor"):
    module = importlib.import_module("tools." + name)
    assert Path(module.__file__).resolve().is_relative_to(root), module.__file__
PY
run_fixture python3 tools/hot_method.py --repo-root "$FIXTURE" --catalog --diagnostics --json
run_fixture python3 tools/target_store.py init --store --repo-root "$FIXTURE" --target "$TARGET"
run_fixture python3 tools/target_store.py init --store --repo-root "$FIXTURE" --target other.invalid
run_fixture python3 tools/context_pack.py --repo-root "$FIXTURE" --target "$TARGET" --json
run_fixture python3 tools/context_pack.py --repo-root "$FIXTURE" --target "$TARGET"
run_fixture python3 tools/validation_runner.py record-observation --repo-root "$FIXTURE" --target "$TARGET" --attempt-id fixture-attempt-1 --evidence-json "$WORK/native-observation.json" --actor fixture-reviewer --json
: "${CAPTURE_REF:?use the real fixture capture receipt}"
run_fixture python3 tools/validation_runner.py record-observation --repo-root "$FIXTURE" --target "$TARGET" --attempt-id fixture-browser-1 --browser-capture-ref "$CAPTURE_REF" --execution-json "$WORK/execution.json" --actor fixture-reviewer --json
run_fixture python3 tools/target_memory.py --repo-root "$FIXTURE" --json set "$TARGET"
run_fixture python3 tools/target_memory.py --repo-root "$FIXTURE" --json show "$TARGET"
run_fixture bash ./install.sh </dev/null
run_fixture python3 tools/runtime_doctor.py --repo-root "$FIXTURE" --runtime-root "$WORK/home/.claude" --json --fail-on-drift
```

`CAPTURE_REF`、manifest hash、事务 ID 和 predecessor 均从真实 owner 回执取得，不猜测。
V2 的 read/apply/bootstrap/recover 命令见设计 §3.2，必须传实际 expected-manifest；V4/V5
补证登记必须另传最初的 `--expected-operation`。不能只运行上列成功路径代替失败/恢复断言。

快照/认证/代理/PYTHONPATH 等不列入白名单；特殊用例仅在同一包装内注入该用例的临时
override。原有合同复用以下精确回归入口，沿用同一函数，只选当批受影响项：

```bash
run_fixture python3 -m pytest -q tests/test_validation_runner.py -k 'record_evidence or native_registration_preserves_each_step_method or invalid_claim or interrupted_sync or legacy_saved_shape'
run_fixture python3 -m pytest -q tests/test_target_store.py::test_unknown_external_effect_can_be_supplemented_without_reexecution tests/test_target_memory_cli.py::test_handoff_operation_refs_are_bound_atomic_and_idempotent_across_processes
run_fixture python3 -m pytest -q tests/test_browser_analysis_fidelity.py tests/test_runner_candidate_store.py tests/test_practical_audit_fixes.py::test_browser_import_registers_private_raw_and_rejects_foreign_paths
run_fixture python3 -m pytest -q tests/test_install_script.py::test_install_script_produces_runtime_doctor_clean_tree tests/test_runtime_doctor.py::test_managed_upgrade_retirement_and_user_conflicts tests/test_ai_native_skill_convergence_baseline.py::test_cognitive_write_timing_keeps_event_saves_and_immediate_execution_owners
```

架构边界仅当新增 import/低层 helper 实际变化时加跑相关 existing architecture 测试。
失败先判断是否归因于本批；不为 unrelated/environment/flaky 失败扩大修复或重复运行。
所有实际结果、命令、临时材料 hash 与回执整理到本任务验收记录，不能把计划命令写成通过。

## 4. 回退点与保护清单

| 时点 | 允许动作 | 禁止动作 |
|---|---|---|
| B1–B5 未切换 | 仅调整 S/F；C 原状不动，保留其既有脏改动 | 提前改 C 活动正文/入口、reset/checkout 整库、重放旧目标快照 |
| B6 部分发布或中断 | 保持 C 维护关闭；按逐路径 before/after 守卫恢复自有代码，方法用下列协议 | 宣称整库原子、复制 F 收据当 C 发布、重开混合版本消费者 |
| bootstrap/apply 有 pending | 无 decision/receipt 时显式选方向；有则只准同向恢复或终态核对清理，严格按设计 §4.4 | 反转方向、receipt 后原地撤销、盲改 hash/删 pending、无守卫反写 |
| 已完成方法版本需撤回 | 主控/工程权限内发布新的反向修订，保留来源和全部历史收据 | 改旧 receipt、删除版本档案、重新开放治理自动写入 |
| 新观察/经验已登记 | 保留当前 Store 和原始证据，修复消费者向前；旧协议不能读则入口明确不可用 | DB/schema 回退、清证据、重执行未知效果、把 partial 称完成 |
| 个人 runtime 部署/恢复未授权 | 保留历史事件状态；本任务只处理 checkout 改动与临时安装验收回执 | 未经另行授权安装/同步/回滚/提交或下载模型 |

`CLAUDE.md`、C AGENTS、根 red-lines/reporting/hunting、installer/doctor、TargetStore/schema、
evidence identity、cleanup、report/delivery、recall/Resume、现有知识卡及能力索引默认不改。
来源矩阵引用它们表示已有责任保留，不是批量编辑许可。真实接线若需要超出上列边界，
须先定位不可复用的具体合同并回到规划，不能顺带进行整体架构收敛。
