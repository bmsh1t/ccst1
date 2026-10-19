# Campaign Rules（资产战役纪律：模糊目标 → 活面清单）

> 来源：clown `AGENTS.md`「最短执行备忘」锁面/自由跳战役段（CC BY 4.0，
> 来源与 hash 见 `knowledge/clown-hot-method-manifest.json`，按本仓 owner 形态改写。
> 适用条件：集团/品牌发现、种子回灌、跨目标切换或续接；即使已选定具体
> URL/域名/IP，当前仍有集团意图时也恢复本文件的 seeds 与相应目标 owner。
> 仅调查固定目标时读 `rules/hunting.md`，不因磁盘有旧 campaign 文件自动切模式。
> 冲突时以 `rules/red-lines.md` 与 `rules/hunting.md` 为准。

## 形态判定（锁面 vs 自由跳）

- **锁面**：固定站/文档/资产清单的资产簇、重要组和同皮差异统一见
  `rules/hunting.md#current-target-context`；本层不另定义。
- **自由跳**：用户只给集团名/品牌——先跑本战役层产出活面清单，再逐面进站。

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
[`cognitive-write-timing`](../skills/runtime-protocol.md#cognitive-write-timing) 经现有目标 owner
保存，不能用 campaign 进度替代真实 operation/step 或 current_handoff。

换到已确立的活面，先确认其 Scope/Auth 和初始化状态；新目标先走上述显式初始化，
之后新旧目标都用 `python3 tools/target_memory.py set TARGET` 显式选择，再运行
`python3 tools/target_memory.py show TARGET --json` 读取它自己的 `current_handoff` 和
`next_actions`。跨进程续接、压缩后恢复同样先读 seeds，再从选定目标 owner 恢复；
不能拿旧目标 handoff、旧 active pointer、摘要或有界历史推断当前意图。
只读/预览仅读取这些材料，不初始化、不 set、不写回。

种子 `done` 只是本次工作进度，不是技术 refuted 或 Coverage complete；预算停止时
未完成的活面、真实未知效果及后续意图继续保留，不为“闭环”伪造终局。

## 种子队列纪律

- 起手把用户词 + 业务名/品牌 + 全资子公司 + 根域/备案写成种子（**数量无上限，
  禁止砍成固定条数**）。
- **种子闭环**：发现后去重、核对存活与范围，保留未调查活面及证据来源；
  优先处理已有高信号问题，不用追加测绘回避深入验证。换种由信息缺口和预算决定。
- **优质根域回灌**：确认优质面即登记「搜域 R」（从 host 向上归约的业务簇根/
  品牌根，非叶子 host）为新种子；只在新增范围内证据能回答当前问题时扩面。
- **续挖**：先读 seeds 及已选目标的 covered/leads/current_handoff；已做工作不盲目重复，pending 不丢失。
  回扫新增 host 或换种仍受当前入口的意图、范围和继续预算约束。
- 不停在问句上：「要不要继续」由 autopilot continuation 合同承担，本层不重复。

## 测绘执行（owner：现有 recon 工具面）

- 资产发现只用现有工具面：`tools/hunt.py --recon-only`、recon-agent 管线
  （subfinder/httpx/katana/waymore）、fofamap MCP（FOFA 检索）；不自建测绘循环。
- 先活筛再进站；控股关系过一遍（存疑/参股默认不挖，登记 lead 不进站）。

## 深挖优先（反扩面空转，不砍能力）

- 已有活面不因追加种子而失踪；测绘条数不证明覆盖。
- 限流/429 只挖现有池；多会话禁止对同一 pending 重复测绘。
- **禁偏科**：不得连日只堆未授权读/同构列表；注入/SSRF/XSS/RCE 打在
  **有差分面**的参数上（探针按栈选，不是每个 path 喷 `'`），无入口记 N/A
  并写原因，不空扫。

## 边界

- 本层补充集团发现与跨目标续接纪律，不启动第二调度器。进站后的调查归
  `skills/src-hunter/SKILL.md` 和 `rules/hunting.md`；直接按问题读完整方法，
  `knowledge/methods/clown/references/dig-scope-workflow.md` 是按需资料，无强制热库读序。
- 授权范围判定始终归 `rules/red-lines.md`：种子命中的范围外资产=登记不进站。
