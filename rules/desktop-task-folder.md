# CCST 目标工作目录与清理

保留资产、提取源码、工作材料与正式报告分开的原则。当前工作目录是选定的 CCST
checkout；目标材料按下表归属，不另建桌面任务树或第二套 queue/state/findings。
本文中的 KEY 使用现有 target_storage_key / 工具返回值，不自行清洗目标名。

## 1. 当前目录

| 内容 | 位置与负责接口 |
|---|---|
| 公网 URL、域名、接口清单与采集来源 | `recon/KEY/` 内工具返回的资产文件；URL 清单只放 URL，不混入 JS 正文 |
| 提取 JS、source 与分析材料 | `recon/KEY/js/` 或采集工具返回的实际子目录；已有材料原位读取 |
| 原始请求、响应与其他证据 | `evidence/KEY/` 及工具返回的已登记证据根 |
| 浏览器原件、Cookie、storage、HAR、console、截图 | `.private/browser/KEY/`；认证材料遵守现有 AuthSession 私有存储合同 |
| 临时脚本、接口清单、方法矩阵、线程必读与 DONE | `evidence/KEY/work/`；只保存工作材料和 owner 引用 |
| Action、Finding、覆盖依据、当前意图与续接 | `state/KEY/metadata.sqlite3`，通过现有 TargetStore/Action/Finding/记忆接口读写 |
| 正式报告及派生索引 | `reports/KEY/`；通过 `/report` 或 `/validate` 的既有 publisher 发布、登记 |
| 尚未绑定具体 target 的集团种子、剩余活面与跨目标进度 | `campaigns/<slug>/seeds.md`，遵守 [campaign](ccst/campaign.md) |

`findings/KEY/`、`.private/validation/KEY/` 等既有输出根继续有效。生产者返回的路径优先，
不得为目录美观移动已登记原件、修改证据 ref 或把私有材料搬进共享目录。

## 2. 开始、续接与交付

1. 从 checkout 运行项目命令。已知目标先确认 Scope/Auth 和初始化状态；新目标走
   `python3 tools/target_store.py init --store --target TARGET`，不手建数据库或猜状态文件。
2. 已初始化目标用 `python3 tools/target_memory.py set TARGET` 选择，随后
   `python3 tools/target_memory.py show TARGET --json` 恢复真实意图与交接；明确只读时不 set/init。
3. 需要产出工作材料时建立 `evidence/KEY/work/线程必读.md`，指向当前
   `rules/hunt-iter.md`、目标及 owner 引用。真实跨代理交付另含 `DONE.md` 的迭代候选；
   不复制 Action/Finding 状态，不把工作矩阵的勾选当作 Coverage 已关闭。
4. 尚无具体 target 的集团发现先建或恢复 `campaigns/<slug>/seeds.md`；线程说明先放
   同一 campaign 工作目录，具体目标确立后再接它自己的 Store。不得借旧目标保存新目标状态。
5. URL 清单与提取 JS 分开；只按需要创建对应材料目录，不创建空报告或占位状态。
   暂存 JS 有分析价值时保存到采集 owner 的目标目录；已登记原件保持原位。
6. 报告写法、发布和更新遵守 [vuln-report-format](vuln-report-format.md)；报告路径取
   publisher 回执，不通过重命名或覆盖文件改变已发布报告。续跑/增量仍使用同一目标 owner。
7. 用户另要桌面结构时，仅导出明确要求的交付副本；真实状态、证据与恢复位置仍按上述 owner。

## 3. 用户要求清理时

清理只处理本次明确指定的临时工作材料，不以“有没有报告”决定删除目标根。

- 先从当前 Action/operation/记忆 owner 核对未完成执行、未知效果与 cleanup 义务；完成
  必要的证据回收和交接。需要保留的稳定结论按 `skills/runtime-protocol.md#cognitive-write-timing`
  保存；方法候选按 hunt-iter 核对，不用删除工作目录代替处理未完成义务。
- 列出本次临时脚本、缓存或导出副本，确认未登记为证据、未被报告/交接引用，且可丢弃后，
  只删除这些明确文件。无洞、无报告、矩阵未命中都不代表材料可以整根删除。
- 保留 Store、已登记证据、不可变报告、历史回执及续接仍需要的原件。派生索引由对应
  工具重建；不手工清空报告索引来隐藏现有报告。
- 浏览器 snapshot/console/HAR 也可能是证据；保存于 `.private/browser/KEY/` 的原件
  按相同引用检查处理，不能凭“临时文件”后缀就删除。
- 不删除、重置或清空浏览器 Profile、Login Data、Web Data、密码、自动填充或整库 Cookies；
  不执行全站 storage clear、Clear-Site-Data，也不关闭用户仍需检查的浏览器。
- 临时认证文件按原 AuthSession/执行 owner 的生命周期处理；不能把用户登录态随工作目录删除。

## 4. 自检

- 目标与 KEY 是否来自现有 owner，材料是否落在该目标自己的目录？
- URL、提取源码、私有浏览器原件与正式报告是否各归对应位置？
- 工作笔记是否引用真实状态，而非另写 queue/state/findings 或 covered 权威文件？
- 报告是否取得当前裁决/目的地绑定及 publisher 回执？
- 清理列表是否排除了已登记、被引用或仍有恢复用途的材料与浏览器配置？
