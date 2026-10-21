# Campaign Rules（资产战役纪律：模糊目标 → 活面清单）

> 集团/品牌发现、回灌、跨目标续接时读取；已有具体 target 但仍有集团意图也读取。
> 直接完整读取 `rules/dig-scope-workflow.md`、`rules/src-value-hunting.md`
> 及其 runtime adapter。锁面/自由跳、一种子闭环、活筛、归属/股权、回灌与深挖节奏
> 由原规则定义；本文件只接跨目标工作材料和 CCST owner，不另定业务规则。

## 两阶段归属（先发现，后确立）

**发现阶段（尚无合法 target）**：品牌名/集团名不是 target——不要传给任何需要
`--target` 的工具（准入会拒绝中文品牌、含空格品牌，也不得虚构 target 或借用
旧目标的 Store）。种子队列落 campaign 工作区文件（`campaigns/<品牌slug>/seeds.md`），
这是操作员工作材料，不是 target-owned 状态，也不新建 campaign 数据库。
开始或跨进程续接先原生读取该文件；没有既存文件时才在非只读的发现工作中创建，
不依赖会话摘要或旧 active target 猜战役进度，也不声称有自动 seeds 数据库 consumer。

**目标确立后**：选定一个活面 → `python3 tools/target_store.py init --store --target
<该面域名>` 显式初始化 → 从此该面的队列/lead/证据/经验全部写它的 Store；
发现该面的种子来源在首个 lead 的文本里标注（哪条种子、哪次测绘捞到的）。
已初始化目标的续挖按 hunting.md 现有 owner 走；若当前仍是集团续接，同时恢复 seeds，
不重新初始化、不把跨目标工作材料当该目标事实。

## 保存、切换与续接

`seeds.md` 保留每条 seed 的发现来源、已筛选/剩余活面、各面所属的实际目标、当前进度、
可回读的工作材料路径及下一种子意图；活面未确立合法目标时明确标未绑定，不借用旧 Store。
这里只存工作线索/定位信息，不复制凭据、完整响应或目标私有报告。

切换、暂停或 compaction 前，先把剩余活面、材料路径和下一意图保存回同一 seeds 文件；
当前目标内的重要观察/判断与 next_intent 则按唯一
[`cognitive-write-timing`](../../skills/runtime-protocol.md#cognitive-write-timing) 经现有目标 owner
保存，不能用 campaign 进度替代真实 operation/step 或 current_handoff。

换到已确立的活面，先确认其 Scope/Auth 和初始化状态；新目标先走上述显式初始化，
之后按 [Shared Memory Continuity](../../skills/runtime-protocol.md#shared-memory-continuity)
显式携带该 target 读取它自己的 `current_handoff`、`next_actions` 和未完成工作。
恢复无需先切换共享 active pointer；`target_memory set` 仍可主动选择目标或通过 `--goal`
设置意图。并发和子代理始终显式携带 target。跨进程续接、压缩后恢复同样先读 seeds，再从选定目标 owner 恢复；
不能拿旧目标 handoff、旧 active pointer、摘要或有界历史推断当前意图。
只读/预览仅读取这些材料，不初始化、不 set、不写回。

种子 `done` 只是本次工作进度，不是技术 refuted 或 Coverage complete；预算停止时
未完成的活面、真实未知效果及后续意图继续保留，不为“闭环”伪造终局。

## 测绘执行（owner：现有 recon 工具面）

- 资产发现只用现有工具面：`tools/hunt.py --recon-only`、recon-agent 管线
  （subfinder/httpx/katana/waymore）、fofamap MCP（FOFA 检索）；不自建测绘循环。
- 先活筛再进站；控股关系过一遍（存疑/参股默认不挖，登记 lead 不进站）。

## 边界

- 集团进度与各目标的 Action/Finding/observation 分开；不启动第二调度器。
- 范围外线索登记为被动 chain context，不进站验证；实际 Scope/Auth 始终由当前 owner 落实。
- 预算/用户停止时保留剩余活面及交接，不能为原文“种子闭环”伪造 complete/exhausted。
