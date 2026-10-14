# Campaign Rules（资产战役纪律：模糊目标 → 活面清单）

> 来源：clown `AGENTS.md`「最短执行备忘」锁面/自由跳战役段（CC BY 4.0，
> `/root/out/clown-src-6k-skill/AGENTS.md`），按本仓 owner 形态改写。
> 适用条件：用户只给集团名/品牌/模糊目标时本文件生效；目标已定为具体
> URL/域名/IP 时直接进 `rules/hunting.md` 目标模型，本文件不适用。
> 冲突时以 `rules/red-lines.md` 与 `rules/hunting.md` 为准。

## 形态判定（锁面 vs 自由跳）

- **锁面**：用户给了固定站/文档/资产清单——目标已定，跳过战役层，但守簇完整性：
  禁止把给定范围偷变成全集团测绘；范围内资产簇的多 host、业务流子域、
  同 host 多 path 都要挖，不挖单点就收。
- **自由跳**：用户只给集团名/品牌——先跑本战役层产出活面清单，再逐面进站。
- 用户标了「重要资产」先打那一组；清单顺序不是执行顺序。
- 同皮壳（登录壳/框架指纹一致）只留 2～3 代表：比对 `jump` / `service=` /
  `moduleId` 是否指向另一业务面，是则另开，否则不重复开矩阵。

## 种子队列（owner：TargetStore work-action / lead）

- 起手把用户词 + 业务名/品牌 + 全资子公司 + 根域/备案写成种子（**数量无上限，
  禁止砍成固定条数**），每种子登记为 pending work-action 或 lead，不落临时 md 文件。
- **一种子闭环**：搜一个种子 → 去重/去废/去非存活 → 剩余活面全部进站挖完 →
  才标 done 并立刻搜下一条 pending；**禁止多种子一次搜完再挖**。
- **优质根域回灌**：确认优质面即登记「搜域 R」（从 host 向上归约的业务簇根/
  品牌根，非叶子 host）为新种子；本种子剩余活面挖完才优先打 R，无新增再换下一条。
- **续挖**：旧目标未清 → 先读 covered/leads/handoff，跳过 done，优先 pending；
  全 done 且未叫停 → 回扫旧种子只捞新增 host，或换新种子再搜。
- 不停在问句上：「要不要继续」由 autopilot continuation 合同承担，本层不重复。

## 测绘执行（owner：现有 recon 工具面）

- 资产发现只用现有工具面：`tools/hunt.py --recon-only`、recon-agent 管线
  （subfinder/httpx/katana/waymore）、fofamap MCP（FOFA 检索）；不自建测绘循环。
- 先活筛再进站；控股关系过一遍（存疑/参股默认不挖，登记 lead 不进站）。

## 深挖优先（反扩面空转，不砍能力）

- 本种子还有未挖活面时**禁止开新种子测绘**；不拿测绘条数充数当覆盖。
- 限流/429 只挖现有池；多会话禁止对同一 pending 重复测绘。
- **禁偏科**：不得连日只堆未授权读/同构列表；注入/SSRF/XSS/RCE 打在
  **有差分面**的参数上（探针按栈选，不是每个 path 喷 `'`），无入口记 N/A
  并写原因，不空扫。

## 边界

- 本层只做「目标发现与战役调度」；进站后的打法归 `rules/hunting.md` +
  热库读序（clown SKILL.md → 打穿短表 → focus 匹配知识文件）。
- 授权范围判定始终归 `rules/red-lines.md`：种子命中的范围外资产=登记不进站。
