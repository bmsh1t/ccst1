# 隔离实施阶段记录（2026-10-16）

> 历史检查点：下文保留隔离实施阶段结论；最终提交与归档见 [B7](b7-git-acceptance-2026-10-17.md)。

2026-10-17 续接：三件规划的阶段状态已更新，最新版 V7 已重新绑定 638 份候选并通过。
后续收尾、归档回执与仍未满足的门槛见 [续接收尾记录](closeout-2026-10-17.md)。

## 当前结论

原任务继续为 `in_progress`。B1–B5 的候选已在 S 实现；F 的 V1、V3–V7 和 V2
机械恢复矩阵通过。**V2 的合格新来源→真实语义方法增量尚未证明，B6 未执行，不能称完整生效。**
没有提交、真实目标操作、模型下载或个人 runtime 安装/恢复。

```text
C = /root/tool/ccst(rename-_Ya66f2)/ccst3/ccst
W = /tmp/ccst-6k-accept-XQES5z
S = W/staging
F = W/repo
HEAD = 99a653b14ece0f925a625c8645a690aaa8a7a218
```

所有产品编辑仅在 S，产品执行/pytest/安装验收仅在 F；C 只更新本任务进度文档。
2026-10-16T19:52:26Z 再核对 C 原 575 份源码及 79 条受保护脏路径的 bytes/mode，零差异。
最新机器记录为 `W/results/c-protection.json`，切换前仍须重新核对，不能沿用本次读数覆盖新工作。

## 1. 候选边界

`W/candidate-files.json` 显式列出 **25 个修改路径、63 个新增路径**，总候选 638 文件。
新增仅为完整报告准入来源参考和 62 份原件 blob；不新增仓库测试、框架或平行数据库。

- B1：`tools/hot_method.py` 是唯一方法读取/发布/恢复 owner。兼容 v1 只读、v2 活动/
  来源绑定、版本化 captured read、A 范围、bootstrap、目录锁、独立 blob、inode 见证、
  slot、同步屏障、固定恢复方向和历史精确重试。
- B2：保留 62 原件共 770659 bytes、全部 56 活动正文/上下文、87 行短表场景，真实
  内嵌章节、完整准入条文及 S52 缺损诊断。7 份适配正文和 v2 manifest 已准备并由 F
  自己 bootstrap。原件/活动正文/治理消费者不混同。
- B3：Context Pack JSON/text 都消费完整未排名目录、guide/index、版本/hash、真实 read
  命令及健康；focus 不过滤，目录不冒称已读。手动/hunt/Autopilot 共用 src-hunting。
- B4：`validation_runner` 的独立 `record-observation`；低层 browser 原件 reader、importer
  单次 bytes 基线、create-only 原语及 kind/lane 判别。旧 Finding/identity/cleanup 不放宽。
  文档为 `docs/evidence-runners.md#native-observation-registration` 和 tool-index。
- B5：retrospective 引唯一写回时机；campaign 原生 seeds 开始/续接/切换保存及新旧目标
  **都 set 后 show**；Mobile 转现有完整 Web/API 方法和 evidence owner。

未改 installer/doctor、TargetStore/schema、evidence identity、memory/recall/Resume、
cleanup、report/delivery owner。C 的上述产品文件也没有提前发布。

## 2. 实际证明

所有下列脚本/产物位于 W，不是新增项目测试。

| 验收 | 实际结果与记录 |
|---|---|
| V1 | `b2/v1-results.json`：62 原件逐字节/hash、56 活动正文 captured read、完整报告原文/内嵌章节/87 行短表；真实 F bootstrap、before manifest 及旧 CAS 拒绝 |
| V2 机械 | `b1/final-{base,extra,review}.log` 及最新对应 results JSON：16 基础 + 40 异常 + 15 回归全部通过；同一冻结 owner，汇总 `b1/final-completion.json` |
| V3 | `results/b3.json`：54 项目录跨两个无关 focus 完整，JSON/text、guide/index 真命令读取、损坏方法仍恢复原 Store，critical 清单真实加载 |
| V4 | `acceptance/accept_b4.py` → `results/b4.json`；多步/跨 family/真实时间/空 result、无 Finding、unknown 零步、完整快照补证、不可变 summary 与真实 retry；坏 JSON/编码/URL/时间/原件/已存在字节冲突在 mutation 前拒绝；已登记 raw 变化时拒绝重登记 |
| V4 Action | `acceptance/accept_b4_actions.py` → `results/b4-actions.json`；首错 actor/token 拒绝，partial 后 blocked→ready→新 claimant；旧精确 start 重试成功，不重新认领；不同登记 actor 补证仍保留原 token/关联和原 predecessor；Store 集合级 family/endpoint 不放宽 |
| V5 | `acceptance/accept_b5_browser.py` → `results/b5-browser.json`；JSON/HAR 有序重复 URL、空/缺 body、base64/HEAD、捕获错误/截断 partial、新 capture 同 attempt 全量补证、旧证据保留；登记前/后 raw 变化拒绝；旧 HAR 基线可用、旧 JSON 不补造 hash；坏 UTF-8/JSON/常量/结构/base64 明确失败；surface/外域有诊断 |
| V5 单次捕获 | 同一脚本真实 importer：HAR fallback、捕获后原输入变化、仅传空 HAR 时不得二次捕获；保存与解析同一份 bytes |
| V6 | `acceptance/accept_b6_memory.py` → `results/b6-memory.json`；消费最新 V4 真 operation/step 保存 note/handoff，两目标跨进程 set/show、source-ref recall/history、Resume 恢复 next_intent；新目标 init 不选 active，之后显式 set；恢复前后全文件 hash（SQLite 除外）和各 Store binding 不变，无 Finding/negative 自动产生 |
| V7 | `acceptance/accept_b7_runtime.py` → `results/b7-runtime.json`；F installer 初次 doctor clean；真 src-hunting runtime diff 阻断 bootstrap，未探测能力/读目标状态；未知用户 command/退休 Skill 保留；错 root/缺 F 依赖/旧 reader 读 v2/origin_only 明确拒绝，不回退 C |
| V7 顺序演练 | F 内新 sub-checkout 从真实 before→兼容代码→自己 bootstrap→入口；manifest 后真实退出、pending 遮蔽、显式 complete 后才发入口；代码 guarded restore 拒第三态；现有合成 Store/原件完整。维护标记仅覆盖验收脚本拥有的消费者，**不是 C 排他证明** |

方法 owner SHA256：`f69fc8d9b7bd988a7fd7c8d519a59acc54f239eff618af36b3207f927e37fe80`。
F/S manifest SHA256：`ce595c6608fb3c7f5968418862d7ae30dd672eac1be4177ff8a2a290e88f69ef`。
旧的 `b1/completion.json` 是更早版本，仅作历史；以 final-completion 和最新候选 inventory 为准。

### 相关既有回归

- `test_validation_runner.py` 窄选择：42 passed，98 deselected。
- browser fidelity、runner candidate、private raw 路径：12 passed。
- Store unknown-effect supplement、memory handoff 跨进程：2 passed。
- installer clean / managed conflict / upgrade user state：3 passed。
- 变更基础层与全图无环：`results/final-checks.json` passed。

共 **59 个相关既有用例通过**。没有跑 build/全量 suite/无关修复。

另有两项既有检查失败，已核对原字节，未重复运行或扩修：

1. architecture 测试旧 allowed list 不含 `target_store` 既有的 `migration_receipts` import；
   本候选的 Store 与该测试均与 before 逐字节相同。变更的 artifact_io/contracts 仍无业务
   依赖，browser_evidence 仍只依赖 target_paths，全工具依赖图无环。
2. cognitive-write-timing baseline 用逐字中文断言，与本任务开始前已有精简措辞不符；
   该 timing 段 before/after 完全相同。B5 只把 retrospective 接回这份唯一时机合同。

证据：`results/b4-architecture.log`、`b5-legacy-memory.log`、`preexisting-check-failures.json`。

## 3. 独立复核及取舍

只读子代理提供具体位置；主会话点验并负责改动/最终验收：

- 修复仅传 har_path 时空 HAR 被再捕获、capture_error 丢失导致误 complete、JSON
  base64Encoded 未校验；补齐原 export 顶层截断/partial 诊断与严格 JSON 常量拒绝。
- 复用既有 exact_endpoint_identity，非法 userinfo/控制/空白 URL 在 attempt 前拒绝。
- 修复 campaign 新目标只 init、不 set 会残留旧 active 的文档分支，并真实验收该分支。
- 未采纳“枚举拒绝所有未知旧 lane”：旧 `run_request_diff(..., lane=...)` 公共接口允许自定
  lane，强加枚举会破坏兼容。新协议的未知 kind、缺 kind/错配的新 lane 均明确拒绝；
  不把旧无 kind 的合法自定 lane 静默重释为新观察。

## 4. V2 真实语义维护仍未证明

当前 47 篇方法正文与完整上游来源一致；可核对的附件导航缺陷已在 B2 修复。
没有找到独立于已收录正文的新完整报告/手法差分；不能为跑通发布而制造合成高危报告、
重复原文、换同构措辞或晋升 2.3 的延期候选。

主会话点验当前 `hunt-iter.md` 门槛/三问与 `vuln-report-format.md` 的实际成果前提：
“已有同类、无新差分不动文件”“这是增量补，不是整理旧库”；自报高危/payload 不是准入。
故没有执行一笔伪称语义合格的日常 A apply。机械矩阵证明 CAS/来源/hash/恢复协议，
不证明新的方法内容已满足语义门槛；**A6 保持未勾选**。
后续应在获得真实完整合格来源后，由主会话按当前版本完整核对门槛/三问，再在独立 F
fixture 作受审 apply→新进程 captured read，保留实际 reviewer/来源与前后版本。

## 5. 保存、隔离与下一步

执行包装器 `W/run_fixture.py` 实测 bubblewrap：只挂 F、临时 HOME/XDG/memory/tmp/results
及只读 acceptance/inputs，C/S/个人 runtime 不可见；独立网络 namespace 加 Python socket
审计哨兵。外层代理/认证/快照变量不继承；不是仅 `env -i` 冒充 OS sandbox。

当时仅保存了 `20261016T193656Z-candidate-XQES5z` 中间包；后续候选、合成原件及
SQLite 备份尚未再次归档，不能把该包称为最终版。续接归档回执见上述收尾记录。
原 before 恢复包
仍为 `20261015T160219Z-XQES5z/recovery.tar.gz`，SHA256
`adb8e25f2c23aa39c60610220b70db9ace6ffe5e4488b4159ee144976cbc05e3`，未覆盖。
续接打包需纳入 638 份 S 候选、临时验收/结果、合成原件与 SQLite backup() 一致备份。
方法日志只作原始审计材料，**inode 见证不可跨 checkout 恢复或移植为 C 收据**。

下一步顺序：

1. 补真实合格来源的 V2 语义维护实例；不降低 A 准入、不伪造证据。
2. 确认 C 全部相关读写消费者、编辑器、其他会话和 Git/同步已停用，由指定执行者负责
   切换/回读；本轮已请求状态确认。未确认绝不 B6，不擅自杀进程。
3. 全部前提满足后重新核对 C before，以 C 自己的旧字节执行全新 bootstrap，再发入口；
   F 收据不复制成 C 成功。中断保持维护关闭。个人 runtime 仍须单独授权，未同步入口
   继续停用/显式 drift；不安装、不提交。

本记录是阶段交接，不 archive 原任务，不调用会自动提交的 finish-work/日志脚本。
