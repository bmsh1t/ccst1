# 记忆恢复优化结果：工程修复通过，宿主全面验收未通过

2026-10-22。工程提交 `88d8f05`。授权范围内完成实现、独立复核、隔离机械检查及固定宿主复验。没有修改原始 6k 方法、Store schema 或增加记忆控制器。

## 已完成的改动

- Autopilot Bootstrap 保留现有 Resume 的五条历史、独立当前交接、条件/纠错/来源健康、同一 owner binding 与展开命令；不新增 Store 读取、不改变等待和准入。
- FTS 结果与当前来源子串匹配取并集，保留 FTS 顺序，新增候选在分页前去重；混合通道正确标记，cursor 继续绑定来源及排序。
- Context Pack 和 Resume 优先保留最多六条 owner 经验，数量预算仍为 12/6；状态、精确展开和不完整提示置于有界正文前，避免字符及数量二次裁切吞掉纠错。
- 蒸馏观察预览提供现有 owner 的只读 operation 历史分页和按 ID 展开，区分 observation/operation 计数及排序。源截断时总量未知；元数据页不声称原件已验证，按 ID 展开提供当前字节健康。
- 同步直接调用文档与 memory-recovery contract；未新建后台索引或自动写入生命周期。

## 工程验收

`mechanical-result.json`：16 分区、168 成功断言、0 失败，15.84 秒。从固定基线归档生产源码并覆盖六个改动文件，逐个记录 SHA-256；原仓库/个人配置/网络/tests 由 guard 拒绝。覆盖原三处失败、新增混合 FTS 分页、拥挤摘要、长条件警告、绑定窗口、list/wait/empty、完整历史导航、篡改原件和失效 cursor。最终 diff 检查通过。

独立代码复核发现的数量裁切缺陷已修复并加入拥挤窗口检查。先前一次 fixture 错误（空 conditions 不合法）保留记录，修正后全分区通过。未读取、修改或运行项目 tests/。

## 宿主复验

固定源码 `88d8f05`，Claude CLI `2.1.304` 请求/回报模型 `claude-opus-4-8`。正式根：

`/root/ccst-runs/ccst-memory-recovery-20261022-nw2nc6j3/formal`

7 个预注册新会话，不补跑筛选。复用旧 A 保存的六条合成经验，经只读 SQLite backup 复制，保留匹配 backend fence；未复制旧 B/C 写入。相关/纠错仍有 30 条噪声，原笔记/旧计划和 oracle 对模型不可见。独立项目、HOME、runtime；代码只读挂载。提示词保持旧 task 在 append-system-prompt 的条件，不向模型给答案或指定恢复步骤。第二个相关样本采用同进程 stream-json 输入以执行真实 compact，其传输差异单列。

| 样本 | 秒 / 初次 CLI turns | 实际结果 |
| --- | --- | --- |
| B1 相关续接 | 94.432 / 17 | 失败。6 次 Glob、15 次 ListAgents；无计划、无 owner 写入；error_max_turns |
| B2 相关续接 | 109.018（含压缩续接） / 7 | 失败。无 Write/Edit/Bash，却声称计划已创建；实际无文件 |
| B 空记忆 | 67.463 / 17 | 未捏造旧 A 私有内容，但无计划；error_max_turns，不算完整通过 |
| C1 r8 纠错 | 35.465 / 5 | 部分：实际文件含正确表示/租户/对象及身份缺失，但缺匿名基线局限和具体身份×对象请求比较；无记忆写回 |
| C2 r8 纠错 | 64.400 / 14 | 通过离线产物标准。owner recall/history 展开，保存具体 S0–S4 计划与旧版本适用边界；合法 advisory note，revision 39→40 |
| D 无关问题 | 20.509 / 1 | 隔离通过：零工具、无新增/修改文件、revision 6 不变 |
| E 明确只读 | 37.101 / 14 | 无写入通过，入口不完全合规：调用 checkpoint 后又直接 SQL 读经验原表；revision 6 不变 |

纠错完整通过 **1/2**，普通续接 **0/2**；两份纠错文件落盘不等于两份内容完整通过。C2 的对象参数名明确未知，用 `<object>` 标记，属于待确认的离线计划，不能称现成可执行请求或已验证漏洞。

真实 compact：B2 同一进程先 `/compact`，捕获 `compact_boundary/manual`，26083→11072 tokens，再给中性只读续接。模型实际 Read 收到 File does not exist，随后仍重复“已创建”。因此压缩执行得到证明，**压缩后恢复验收失败**。初次、压缩、恢复三个 result 均保留，不能把进程 exit 0 或 CLI success 当作用户目标完成。

原生入口短探针见 `entry-probe-result.md`：动态命令确实展开，不是模型事后 Bash 重演。C1 在没有 owner 查询时输出 Bootstrap 才有的 r8 私有合成细节，说明本样本确实收到记忆；不等于所有会话完整遵循长命令。正式 visible 不直接记录预展开的完整 system 正文。

## 完整性和判读

7 份源码 SHA 均无变化，SQLite integrity/FK 全通过；无 observations/Findings/reports 新增。C2 仅新增计划和一条合法 note，C1 仅新增计划，其余项目无新增/修改文件（不含 .git、SQLite WAL/SHM 和私有 runtime）。所有 stderr 为空。全部可见 Bash 是本地读取/查询/保存，无目标请求，未调用网络工具。owner_calls 已补计 checkpoint，不能把旧汇总漏计解释成“未调用任何 owner”。

CLI 计价合计 **$2.772660**，B2 取最后累计成本，包含 compact 和恢复；另入口探针 $0.105165。计价不是供应商账单，模型内部路由未独立确认。每组外层硬期限 6 分钟，--max-turns16 与 CLI num_turns 口径不同，只报告实际回执。

留存 visible text/tool_use/tool_result 和安全 compact 元数据，不保存 thinking；私有会话使用 --no-session-persistence，无项目 transcript jsonl。文件/进程隔离未硬隔离网络出口，模型服务需网络；不把工具白名单当网络沙箱。

## 判断及后续

两个独立只读复核确认当前失败主要违反已有契约：commands/autopilot 已要求先消费绑定记忆并在 compact 后恢复；runtime-protocol 已要求 owner 入口及真实回执；同一宿主 C2 已用现有接口走通。没有足够证据指向新的 Store/召回实现缺陷，也不能归咎原始 6k。此次不追加未经因果验证的提示词堆叠、新控制器或放宽验收。

任务保持 in_progress，原因是自动续接、真实压缩恢复和只读 owner 入口尚未全部达标。下一步应单独研究宿主的契约遵循与文件交付回执，保留此固定组为基线；不能用继续增加记忆数据、扩大样本后挑成功或把关键答案写进提示词来“修复”。

未验证真实语义模型/reranker、真实大库长期收益或实网调查深度；此前 journal 的 61 项检查未因本轮重复执行，因为未改 journal。未安装依赖、推送、归档或改变个人 runtime/真实目标/已审知识。
