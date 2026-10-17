# 6k 完整接入设计

版本：2026-10-17 / D1=A。B6/B7完成并归档；[B7](research/git-delivery-plan-2026-10-17.md)另授权Git交付。

## 1. 设计边界

目标仓库 C 为 `/root/tool/ccst(rename-_Ya66f2)/ccst3/ccst`。本设计落实
[PRD](prd.md) 的 R1–R6、A1–A9。原任务已启动；个人 runtime 安装/同步、提交及目标操作不在授权内。
现有 `docs/architecture-contract.md` 和 Store-only 实现是架构基准；专题规范中的历史
legacy、固定 top-k、旧 Skill 路由示例不恢复为当前行为。

保留一个主会话调查控制器、原生 `src-hunting` 入口、每目标一个 TargetStore，以及
现有执行、Experience、handoff、报告和共享知识 owner。新增的是缺失的调用合同，
不是另一个调查 runtime、方法注册表或目标数据库。TargetStore 的 schema、实体 ID、
迁移收据和历史原件不变；下文的版本化文件协议不升级 Store。

### 1.1 责任分工

| 责任 | 唯一 owner | 本批变化 |
|---|---|---|
| 全局问题、方法选择、解释、停止/转向 | 原生主会话 + `skills/src-hunting/SKILL.md` | 接入完整 6k 方法和调查节奏；消除 selected/focus 才能读取的旧说明 |
| 自动继续、等待、预算、执行回收 | `commands/autopilot.md` 及现有 runtime | 保留，不照搬 6k 的无限继续或 2.3 controller |
| 方法正文、来源和活动版本健康 | 现有 `knowledge/methods/clown/`、manifest、`tools/hot_method.py` | 增加一致读取、受控维护与中断恢复；不负责语义判定 |
| 方法差分是否满足 A | 主会话 | 核对真实来源与完整准入条文；子代理仅提议 |
| Scope/Auth、操作与登记 | 原执行 owner、`validation_runner`、TargetStore | 补无 Finding 的原生观察登记；不改变执行授权 |
| 当前意图、条件经验、交接及召回 | TargetStore、`target_memory`、`experience_recall`、Resume | 消费新增真实 observation 引用；统一写回时机 |
| 跨目标种子工作材料 | `rules/campaign.md` + `campaigns/<品牌slug>/seeds.md` | 补显式保存、恢复及目标切换指引，不建 campaign DB |
| 技术裁决、交付资格、报告、外部提交 | 原 assessment/delivery/report owners | 保留各自身份、证据与回执，不由方法准入代替 |
| 已审共享卡、Skill 编排、治理 Rules | 原人工审核/发布流程 | A 不放开这些权限 |

## 2. 来源保存与唯一活动正文

### 2.1 布局

沿用现有方法根 `knowledge/methods/clown/` 和全部既有可用路径，不把根设成 `.`，
不通过 `../` 越出允许根。原生安装仍只发现根级 `skills/src-hunting/SKILL.md`；
方法根内的 `skills/src-hunter/SKILL.md` 是完整来源参考，不是第二个可安装入口。

| 位置 | 内容与读写边界 |
|---|---|
| `knowledge/clown-hot-method-manifest.json` | 唯一方法来源/活动字节绑定；不是目标事实或 Skill 路由表 |
| `knowledge/methods/clown/README.md` | 宿主适配、规则优先级、来源缺损及展开方法 |
| `knowledge/methods/clown/skills/src-hunter/知识库/` | 49 个来源文件的活动位置：索引、短表、47 篇其他方法；完整相关正文不以卡片摘要替代 |
| `knowledge/methods/clown/skills/src-hunter/SKILL.md` | 保留完整来源方法关系；适配其路径与转接声明，不接管全局循环 |
| `knowledge/methods/clown/references/` | 五篇完整来源规则参考，包括 `vuln-report-format.md`；它只供 6k 方法准入按原文对照，不替代 C 当前报告/定级规则 |
| `knowledge/methods/clown/.history/blobs/<sha256>` | 创建后不可覆盖的实际字节：全部 62 份原始来源、修改前后正文与 manifest；按 digest 去重，不进入活动目录 |
| `knowledge/methods/clown/.history/transactions/`、`decisions/`、`receipts/` | 不可变准备记录、终结方向及终态收据；均属同一文件发布日志，不保存目标事实 |
| `knowledge/methods/clown/.history/witnesses/<事务ID>/` | 本 checkout 的 before/after inode 硬链接见证；不是不可变内容备份，不参与发现或跨 checkout 复制 |
| `knowledge/methods/clown/.history/pending.json` | 唯一未完成文件发布标记；只用于显式恢复，正常读取不修复 |

每个来源在台账中只有一个原件保管位置；一个活动方法只有一个规范正文路径。
原件/版本档案不是并行知识库，不参加自动方法发现。治理来源可以映射到多个职责引用，
但不复制多份竞争的生效规则。初次切换也保存改动前的 C 字节，而不只保存 A 原件。

[62 项来源矩阵](research/source-disposition-matrix.md) 和其 JSON 台账逐项列明源 hash、
当前保存状态、原件去向、活动消费者和处置。54 份当前副本的字节一致仅证明搬运状态，
不证明其正文完整或已经接通。

### 2.2 规则及内容适配

- 6k 的机制、条件、完整相关步骤、反例、短表和迭代节奏保留。短表用于开场与发现，
  命中指针必须展开相关完整方法；表外方法、没有匹配的方法和原生推理仍可使用。
  不强制先扫全库、先 Recon 或按固定类型配额行动。
- 调查中的类型优先级、种子闭环与高价值线索深挖接入 C 的主会话；单站阴性不删除通用
  方法。上游永久类别禁令、桌面布局、代理地址、宿主偏好、破坏性清理和无限继续保留
  在来源档案中，但不成为 C 的默认约束。
- `references/hunt-iter.md` 是方法维护语义的唯一详细正文。`references/vuln-report-format.md`
  保存完整的 6k 来源文本，供主会话核对其实际“漏洞等级”准入条文；该副本是来源依据，
  不是 C 当前报告规则或新的 severity owner。C 的 Finding/assessment/report/delivery
  owners 与 C 活动规则仍决定报告含义和发布。报告格式来源正文若缺失或 hash 不符，维护
  不得假称已完成准入核对。
- 6k 的“高危/严重”在这里是**方法收录准入依据**，不是另一个 C Finding 定级器。
  不回写 C 的技术裁决、交付资格或 Coverage；通过文件形状检查也不代表语义准入通过。
- `KNOWN_GADGETS` 与 `WAF_PRODUCT_MATRIX` 分别定位到
  `prototype-pollution-test.md` 和 `waf-bypass.md` 的真实内嵌章节，修正活动索引，
  不制造两个空附件。
- 白盒来源保留前 43 行误拼浏览器规则、残表及 Phase 0 缺损的诊断。适配正文分隔误拼段，
  指向 C 现有 `whitebox-audit` 的可用方法；补充说明标为 C 编写且有依据，绝不称恢复了
  遗失原文。能读取后续章节不抹去 `source_incomplete`。
- 历史示例不是当前目标事实；历史绝对路径只能是 provenance，不参与运行路径解析。
  来源许可保持现有“上游声明、未独立核对许可证原件”状态，不编造已验证许可。

### 2.3 版本化 manifest

活动 manifest 使用 `ccst-hot-method/2`；新 reader 兼容 v1 **只读**，日常维护只接受 v2。
旧 reader 遇到 v2 明确报不支持，不通过旧 hash 语义假装兼容。这是方法文件协议升级，
不是 Store schema 变化。

| 字段/集合 | 合同 |
|---|---|
| `source_id`、`bundled_root`、`root_env` | 保留当前含义及相对路径/包含关系校验 |
| `origins[]` | 稳定来源 ID、原始相对路径、`origin_sha256`、根内 `archive_path`、处置、缺损说明及 repo-relative 消费者引用 |
| `entries[]`、`context_files[]` | 保留 `path`/`role`/`sha256`；`sha256` 唯一表示当前活动字节，不另存一份同义 active hash |
| 活动条目的 `origin_refs` | 引用实际原件记录；C 自编适配不能伪装成 A 的逐字副本 |
| 活动条目的 `maintenance_scope` | `method`、`index`、`governance_reference` 或 `entry_reference`；A 仅可更新前两类中的方法内容/必要链接 |
| `revision_ref` | 当前版本的不可变修改收据引用；初次接入也保留审核依据与前版 |
| manifest digest | 整份实际 manifest 字节的 CAS 版本与目录版本；收据路径使用事务 ID，避免自身 hash 循环 |

原始 hash 永久不随维护改变；合法修订更新活动 `sha256` 并保留旧版本。直接改正文但
不经发布仍是 `changed`，不能自动采纳新字节。治理映射不再是 reader 丢弃的注释；
reader/台账检查其路径、来源绑定和可展开引用，但不执行或强制加载它们。

保留 `CCST_CLOWN_SNAPSHOT` 的显式诊断用途。v2 下该变量选外部源时是 `origin_only`：
按原始 hash 校验来源，不冒充当前活动方法；必须显式读取来源，禁止维护/恢复外部根。
正常活动读取依赖 C checkout 内文件，无 `/root/out` 依赖。v1 外部快照仍可按旧合同
只读检查，不静默将来源版本替代已修订活动版本。

## 3. 原生加载和一致读取

### 3.1 入口与发现

保持 `cd C` 后启动平台/调用命令的现有部署合同。`.ccst-installed.json` 只记录文件归属
与 hash，不包含 checkout-root 指针；不假称可在任意 cwd 找到方法。显式 CLI 使用
`--repo-root`；入口遇到无法确定的 checkout 必须明确报错，不猜 `ccst2` 或外部来源。

手动调查、`/hunt` 和 Autopilot 均调用同一个 `src-hunting`。源 Skill 只作参考。
`hot_method`、Context Pack 的 JSON 和文本均展示 guide、索引、完整未排名目录、来源
健康、目录版本和读取指令；`focus` 只描述问题，不过滤方法。目录与正文已读状态分开。
保留旧 `hot_methods` 输出键，不复活 `selected_skill`、固定 top-k 或 Skill 路由注册表。
现有卡片 `--known-catalog` 不被偷换成另一套目录确认；本批方法目录始终完整可发现。

### 3.2 明确的 owner 接口

以下接口已在 S/F 验收，并经 B6 发布到 C：

| 接口 | 行为 |
|---|---|
| `hot_method.py --catalog [--diagnostics]` | 保留原命令，返回完整目录、健康、活动/来源区别；无写入 |
| `hot_method.py --read RELATIVE [--read RELATIVE ...] --expected-manifest HASH --json` | 一次共享锁内读取选定正文及其依赖版本，返回**实际已校验正文**、hash、来源、审核与缺损；版本不同要求重新获取目录 |
| `hot_method.py --origin SOURCE_ID --json` | 展开不可变原件，明确 `source_only`；不执行其中的宿主指令 |
| `hot_method.py --apply UPDATE_JSON --expected-manifest HASH --json` | 发布主会话已审的方法修改集合，返回事务/收据和活动版本；不作语义评审 |
| `hot_method.py --apply INITIAL_JSON --bootstrap --expected-manifest HASH --json` | 仅新事务的首次 v1→v2 工程切换；要求完整 62 项来源及初次适配审核。v2 拒绝新 bootstrap，但原事务精确重试先查历史收据 |
| `hot_method.py --recover TRANSACTION_ID --mode complete\|restore --json` | 仅按匹配的准备记录完成或恢复未完发布；不是目标数据回滚 |

继续以 `tools/hot_method.py` 为唯一机械 owner；不新增通用阅读器/认知抽取器。
JS、源码、目标原件仍原生 Read/Grep。此处正文返回只解决方法 hash 校验与随后打开文件
之间的竞态，不提供摘要、排名或执行选择。

共享锁使用现有 `knowledge/` **目录 inode**，与知识发布的 flock 协调；维护不嵌套调用
`knowledge_promote`，不持有目标锁。读取在同一锁内检查 pending、捕获 manifest、读取
选定正文并核对 hash，返回捕获的字节，而不是“健康检查后再读可变路径”。包含关系、
普通文件及读前/读后身份也须检查；非协作修改产生明确 changed/conflict。一次读取是
该版本的快照，不声称返回后永不变化。

`pending_update`、来源缺损、missing、changed、invalid_manifest、origin_only 分别
可见。方法源故障不伪装成技术阴性，也不阻止读取现有 Store/冷卡事实；相关方法不能
被宣称已成功加载。任何只读路径都不自动恢复 pending、更新 hash 或写 Store。

## 4. A：方法维护、发布和恢复

### 4.1 谁决定、改什么

主会话先读当前维护规则、完整准入条文、来源正文和旧方法，再按原门槛与三问判定。
自挖内容须有真实已保存报告；用户提供内容须有可核对正文；子代理“拟进/拟补”不代替
主会话核对。同构无新差分、单站备忘、门槛不符或来源不完整不晋升。有同类只补原正文
及必要短表指针，不另起同义方法。有效机制和仍可能适用的旧方法不因单站失败被删。

`UPDATE_JSON` 包含事务 ID、期望 manifest、逐文件前/后 hash 与候选完整正文引用、
来源引用/hash、准入条文版本、三问的审核依据、修改理由、真实 reviewer kind/session ID。
同事务同材料可重试；同 ID 改材料冲突。新增方法必须给出新方法身份、来源和完整正文，
已有同类的去重判断由主会话完成，不用关键词机器判重。

工具只检查可验证的形状、路径、字节、版本与维护范围。reviewer 字段是可追溯声明，
不是身份认证；记录 `main_session`，绝不伪装人工签字。CLI 的“accepted”仅指机械发布
成功，不能把主会话自报改成真实模型能力或已审共享知识的证明。

A 不准修改 `CLAUDE.md`、根 Rules、原生 Skill 编排、维护/准入规则参考正文或 review
权限。治理参考即使保存在 methods 下也仍属于人工审核范围。首次集成本身由本规划的
实施批准覆盖，不给后续自动维护授予同等工程修改权限。

### 4.2 私有材料与来源

方法正文和共享版本档案只保留可迁移机制、通用条件及必要反例。目标名、私有 URL、
身份、令牌、原始响应、整份报告或完整 JS 不复制进去。真实来源原件沿用现有私有
evidence/report owner 保管；私有审核明细保留在该私有材料区，方法收据仅含不泄露
目标的 opaque 来源 ID/hash、审核身份与脱敏说明。可公开上游来源可直接保留出处。
来源是 origin 还是证据 basis 必须真实；在别的 checkout 无法访问私有来源时报告
`private_source_unavailable`，不假装独立审过。无法保留可追溯完整来源时不发布。

维护不调用共享 registry 晋升、不修改 knowledge maturity/人工 review receipt，不
自动进入“已审共享”召回。目标经验仍由现有 owner 保存；后续共享卡片必须另走人工
审核/脱敏流程。原有方法库和冷卡并存是不同资料/审核责任，不复制两份活动方法正文。

### 4.3 一组修改的发布协议

五项歧义按本节及 §4.4 收敛；依据与取舍见
[审核收尾](research/risk-review-closeout-2026-10-16.md)。机械矩阵及 [A6 语义维护](research/a6-acceptance-2026-10-17.md)
均在 F 通过；C 另经 B6 本地事务发布。沿用小型方法文件日志，不建数据库。

#### 4.3.1 准备记录与跨进程身份

在同一个 `knowledge/` 目录独占锁内验证根、请求形状，先按 §4.4 分派已有事务，
只有新事务才检查当前协议、无 pending、expected-manifest 和全部 before CAS。
transaction 绑定规范化的完整请求指纹（含 bootstrap 标志、期望版本、路径/候选 hash、
来源和审核依据）、blob、路径元数据及以下见证。重试不得拿当前活动字节重算原 before。

- 原件及 before/after 的内容 blob 独立保存、create-only；**不得把 blob 硬链接成活动文件**。
  已有路径为实际 before inode 建硬链接见证；从候选 blob 另建 after inode 并保留其见证。
  记录 `(st_dev, st_ino)`、普通文件类型、hash、mode、uid/gid；每次操作同时核对见证与
  活动路径。见证也会受同 inode 原地写入影响，必须对照独立 blob，不把它叫不可变备份。
- 已有文件发布/恢复用目标见证的临时硬链接再 `replace`，不从 blob 重写一个新 inode。
  临时别名若已存在须匹配记录的见证，否则冲突。这样 owner 合法重试始终使用原 before/
  after 身份；同字节换 inode、见证缺失或字节/metadata 变化均拒绝，不能 hash-only 放行。
- 新文件在其活动父目录预建唯一隐藏 `slot`，与 after 见证同 inode；名字绑定事务及路径，
  不用 `.md` 后缀、不进入 manifest/catalog。它不是第二正文位置的发现入口。

| 新路径活动名 | slot | 唯一含义/允许操作 |
|---|---|---|
| 不存在 | 匹配 after 见证 | before；发布用同目录 `rename(slot→活动名)` |
| 匹配 after 见证 | 不存在 | after；restore 用同目录 `rename(活动名→slot)`，不是裸 unlink |
| 不存在 | 不存在 | 已发布后被删除或准备损坏，conflict；不得重建 slot |
| 其他组合（含两者都有、错误身份或类型） | 任意 | conflict，保留现场 |

位置转移与进度是同一个原子 rename；另写 `published=true` 无法消除崩溃缝隙。原本存在
的文件消失一律冲突。所有名称（活动/slot/临时名/见证）去重且禁止互相碰撞；不存在目标
仍须在 rename 前重查，排他前提不因使用 rename 而消失。

本版限同一可 hard-link/fsync 的本地文件系统；活动父目录须已存在，挂载及父目录持续
不变。逐组件 `O_DIRECTORY|O_NOFOLLOW` 打开、核对记录的 dev/ino，再用 dir_fd 操作。
不把会被合法 link/rename 改变的 ctime/nlink/目录 mtime 当身份。已有 mode/uid/gid 必须
保留，新文件明确指定；被改文件带 ACL/xattr、无法保持 ownership 或不支持上述原语时，
在 pending 前拒绝，不静默丢 metadata、不降级。准备可增加链接名/ctime/nlink，但不得
改变活动字节、mode 或 ownership。目录重建/inode 回收、同用户恶意改写日志及非协作
TOCTOU 不在保证内；不能确认相关编辑器/Git/同步写者停用就不发布。

见证与 slot 保留到本次事务终态清理之后也不自动 GC；它们只是 checkout 本地恢复材料。
不能复制 F 的 inode 记录到 C，也不能把重建后的见证视为原身份。B6 在 C 新建自身事务。

#### 4.3.2 发布与持久化顺序

1. 创建并核对 blobs、见证和 slot；文件 fsync，涉及的新目录逐层及名称所在目录 fsync。
   再 create-only 发布 transaction，**transaction 文件及 transactions 目录同步成功**。
2. create-only 发布绑定该 transaction 的 `pending.json`，文件及所在目录 fsync 成功后
   才能改任何活动名。准备或 pending 屏障失败不越过下一步；存在的准备材料不自动删除。
3. 先核对全组合法状态，每次操作前再核对该路径的 before/after，逐一发布正文并
   fsync 名称所在目录，manifest 最后。manifest 只是 pending 遮蔽下的版本指针更新点，
   **不是不可逆终态**；它之后、decision 之前的中断仍允许 restore。
4. 核对全部 after/manifest/metadata 和已完成的同步；create-only 发布
   `decisions/<ID>.json` 的 `mode=complete`，同步文件及目录。再发布不可变
   `receipts/<ID>.json`，`outcome=applied`，同步文件及 receipts 目录。
5. 仅在终态 receipt 及必要屏障核对成功后 unlink 本事务 pending，fsync 其父目录。
   返回历史终态、当前观测版本和清理状态；任何失败不做无守卫回滚。

decision 不是另一套业务状态机：它只把一次文件事务的终结方向固定为 complete/restore。
正常 apply 在第 4 步前不写它，不能在初建 pending 时锁定 complete。显式恢复则必须在
任何恢复性活动修改前先持久化选择；重启同向继续，反向拒绝。restore 也以 before manifest
最后、全组核对、`outcome=restored` 收据结束。decision/receipt 的字节绑定 transaction，
receipt 由这些不可变材料确定，重试不换时间/身份；可见但同步失败的原记录只核对及补同步。

bootstrap 使用同一协议绑定 v1 before/v2 after，限本批工程权限；普通新 apply 不接受 v1，
v2 不开放新 bootstrap 的治理权限。`artifact_io` 仍只保证普通单文件替换；必要的窄小
create-only 原语可复用到该低层 owner，目录屏障、锁和恢复仍由 hot_method 负责。

### 4.4 恢复、历史重试与失败观测

先验证根和输入，再按下表分派。apply/bootstrap 重试比较已有 transaction 的完整请求
指纹，同 ID 换材料均拒绝；recover 无新载荷，只核对 transaction 与其绑定材料。
已有记录须能解析到各自绑定的 transaction；属于本事务的 decision/receipt 彼此匹配。
引用缺失、损坏或矛盾不得按历史成功返回；其他事务的 pending 只参与当前状态诊断。

| 已有状态 | 唯一行为 |
|---|---|
| receipt 存在 | **先于当前协议/无 pending/旧 CAS** 返回历史终态和独立当前诊断；普通 apply/bootstrap 重试只读，不清理 pending。applied 表示历史成功，restored 返回未应用诊断/非零，不复活 |
| receipt + 本事务 pending | 只有同终态方向的显式 recover 可核对最终全组、补同步并清理；不再替换活动字节。applied 后 restore 拒绝 `terminal_applied`；restored 后 complete 拒绝 `terminal_restored`，拒绝不改 pending |
| receipt + 无 pending / 其他事务 pending | 历史命令不写活动路径或其他事务。显式同向 recover 仅在无 pending 且当前仍为本终态时可补清理目录同步；已到 T2 只返回历史，不撤回 T2 |
| 无 receipt + 本事务 pending | 普通 apply 只给显式 recover 命令。recover 核对全组/日志，有 decision 只能同向，无则先持久化选择，再按 before/after 状态补齐；不得覆盖第三种状态 |
| 无 receipt + 其他事务 pending | pending conflict；零活动写入 |
| 只有 transaction，无 pending/decision/receipt | 准备未开始活动发布；同材料 apply 补齐准备屏障，再走普通 CAS。recover 返回 not_started，不碰活动路径 |
| decision 存在但 pending/receipt 都缺失 | 协议缺损，拒绝；不能当新事务继续 |
| 尚无 transaction | 新事务正常准入；残留准备材料须逐项与请求/当前 before 核对才能复用，不覆盖不明归属文件；没有持久绑定前不宣称 ID 已永久占用 |

同旧 manifest 的两名写者仅一名成功，另一名 CAS conflict。已应用版本要撤回必须新建
受审反向事务，不改旧 receipt。T1→T2→T1 精确重试（含 bootstrap）只返回 T1 历史结果；
当前 T2 有 pending 时必须明确 `current=pending`，不能把历史成功说成当前可读。

| 同步失败点 | 非零结果及恢复边界 |
|---|---|
| transaction 文件/目录，或 pending 文件/目录 | 无活动替换；报告 pending 实际有无。可见 pending 仍阻止 reader，恢复须先补齐全部准备屏障 |
| 正文/manifest 或 decision 文件/目录 | 活动版本可能已改变；保留 pending，报告观测状态；恢复先核对并同步可见 decision，再按其方向继续 |
| receipt 文件/目录 | 不清 pending；可见 receipt 不覆盖，不可见时也受已持久化 decision 约束 |
| pending unlink 后父目录 | pending 可能已不存在；返回 `cleanup_durability=unconfirmed`、实际 pending/receipt/版本及精确 recover 命令，不伪报“保留 pending”或 accepted |

错误统一区分历史 `outcome`、当前 `manifest/health`、`pending` 实际有无/所属事务、
`cleanup_durability`；检查失败时对应字段为 unknown，不能猜值。普通 reader 持共享锁：
pending 实际存在一律拒绝，无 pending 且实际 manifest/正文/来源及必要收据有效才可读。
因此 unlink 同步失败后可以读到完整终态，但发布调用仍非零；重启若 pending 重现，显式
同向 recover 再核对清理。只读不自动同步/修复；系统调用故障或进程退出测试不证明断电持久性。

## 5. 无 Finding 的原生观察

### 5.1 新入口而非放松旧入口

新增 `validation_runner.py record-observation` / `record_native_observation(...)`。
`record-evidence --finding-id` 继续拥有既有 Finding、subject_step、identity v3 和 cleanup
合同。不得把 `--finding-id` 简单改成可选后混用同一条分支。

新入口复用 schema/run/原件引用校验、私有身份原件、不可变 summary、attempt 及
`TargetStore.record_execution`。Store 已允许 `action_id=None`、无 candidate/Finding，
无需新表。观察 `result=""` 才是无裁决；禁止发明 `neutral` 枚举，也不写
lead/signal/candidate 或用 partial 当技术结论。

计划 CLI：

```text
python3 tools/validation_runner.py record-observation --repo-root C --target TARGET
  --attempt-id ATTEMPT_ID (--evidence-json FILE | --browser-capture-ref CAPTURE_REF)
  [--execution-json EXECUTION_FILE] [--expected-operation OPERATION_ID]
  [--action-id ACTION_ID --claim-token TOKEN] --actor ACTOR --json
```

输入是新的显式 `schema_version=1, kind="native-observation"` envelope，不改变旧 schema-v1
Finding 证据含义。关键字段：source、真实 started_at、outcome、有序 runs；每步包含
精确 URL/method、非空 family、真实 observed_at、描述、原件、缺失/截断/错误及已知
actor/状态事实。没有专属家族声明时，未绑定 Action 的观察显式使用
`runner-observation`，它只标记原生素材类型，不表示漏洞或 canonical Coverage。
target/attempt 等若同时由 CLI 与输入声明必须一致。未知 actor 保持 unknown；不从
POST 推断副作用或补成“已审核”。不接受 Finding、cleanup、closure identity 或结论字段。

`--actor` 是本次登记命令执行者，不是 HTTP actor，也不从 attempt 推断原始 actor。
首次建立 Action 关联须提供 action/token，由 `start_attempt` 检查当时的认领；已有 attempt
的精确重试及补证按 §5.2，不在 adapter 增加一律重查当前 claim 的前置门禁。
保留 Store 对**完整 observation 集合**的关联检查：须有匹配 Action family 的 step，
除 partial 外该 step 还须匹配精确 endpoint；不扩大成每一步都必须匹配。无 Action 时
不从路径猜 family，不伪造 claim。步骤中未知的
`state_changing` 保持 null，`redline_checked` 仅接受真实声明；有关检查沿用已有执行事实
合同，不因这是事后登记就把未知事实升级。公共 argparse 分支只读取各自声明的参数。

- `outcome=complete` 要求所登记步骤的完整原件；缺响应/截断/错误必须显式 partial。
  空 runs 只允许记录真实但效果 unknown 的执行，不捏造 endpoint、step 或经验证据。
- started_at 和各 observed_at 使用原始时区语义归一化，观测不得早于 attempt；生成
  summary 的时间不是请求时间。缺必需身份/时间时保存原件与缺项诊断，不能伪造登记。
- 同次真实执行始终同一 attempt；不同执行即使字节相同也不同 attempt。Action 是可选
  的原执行关联；保留 owner 的首次认领及历史重试合同，不改绑到后来取得的 claim。
- 先完成输入/原件校验，再登记 attempt、发布不可变 summary、登记 operation。
  summary 位于 `evidence/<target>/native-observations/<attempt-key>/<material-id>/`，
  不落入按 validation 目录推断 Finding 的扫描范围。envelope 与 summary 均使用
  `kind="native-observation"`，summary 另有 `lane="native_observation"`；两者不是同一字段。
- sync 按 lane 分派并校验上述 kind/lane 配对，空 result 不是 skipped。公共转换
  传递每步 method、observed_at、描述和 `expected_operation`，不退化成单个生成时间。
  `structured_findings` 明确排除该 lane/kind；未知、缺损或错配的判别组合显式失败，
  不回落到 Finding 路径猜 candidate ID。既有无 kind 的合法旧 lane 保持原合同。
- 原件和 summary 采用 create-only 发布并核对已存在字节；登记状态/回执独立保存，不把
  `sync` 或 operation ID 追加后覆写已发布 summary。现有 Finding lane 的可变尾部不套到
  新 lane。失败保留原件与准确的登记重试入口，不以空成功或自动重放补偿。
- 返回真实 operation ID、每步 observation 引用、原件 hash、完整性和重试命令。
  没有 observation 的 unknown operation 不返回虚构的 `OPERATION_ID:0`。

### 5.2 重试与补证据

分开处理两个入口状态，不为恢复重新认领或开始执行：

- 没有 `expected_operation`：以原始 supplied source、started_at、action/token 和命令
  actor 调用 `start_attempt`。新 attempt 检查当前 claim；历史完全相同调用由 Store 的
  命令收据先行重放，即使 claim 已释放/改派也不由 adapter 拦截。改 actor/材料不是精确重试。
- 有 `expected_operation`：先读 `execution(expected_operation)` 的原 attempt，核对
  attempt ID、source、started_at；复用其 action/token，不再调用 start/reclaim。
  可选 action/token 若提交必须成对且匹配原关联；不得替换为新 token。补证命令可以由
  不同登记 actor 执行，该次命令的重试仍保留自己的 actor。attempt 没有原 actor 列，
  不增加虚构字段或通过新 claim 反推它。Store 继续拥有 predecessor CAS 和关联检查。

相同材料、参数、attempt、登记 actor 与 predecessor 重试，返回同一 operation/receipt。
同次执行补充新材料时，发布新不可变原件和 summary，发送**完整有序 observation 快照**，
并指定 `expected_operation=原 operation`。不能只传新增 step：Store 的 supersession
会替换前一 operation 的当前观察集合。补充后的重试仍带原 predecessor，不能改成
刚生成的新 operation。旧操作和证据永久保留；未知效果和登记失败绝不触发网络重放。

现有条件经验和 handoff 直接消费这些 operation/step 引用。note 可表述建议；negative
仍须满足自己的条件/证据合同，不能把一条中性观察自动变成证伪。技术判断、Coverage、
Action 解决、报告资格均不随登记改变。

## 6. 浏览器原件适配

`browser_mcp_import` 的发现/Recon 路径保留，不把 surface 的默认 GET/URL 形状当实验。
在现有低层 `browser_evidence.py` 增加原件读取/转换函数，返回结构化步骤和待发布字节；
不导入 runner 或 browser publisher，不写 Store/Recon、不联网。`record-observation`
调用它，并由已有私有文件 publisher 保存每步非空 request/response envelope。

浏览器模式要求 `--execution-json`，显式给出 source、真实 started_at、family/逐步 family
及已知执行事实。已有 attempt 的补证据先从 Store 读取原 source/started_at/Action 关联，
输入必须匹配，不用本次捕获时间重新生成它们。首次登记必须有原执行者保存的开始时间；
没有则诊断缺项，不把 capture 导入时间或首请求时间默认当作整个执行的 started_at。
JSON 原生模式直接在 envelope 中给出这些字段，若再传 execution-json 则拒绝多源冲突。

当前 importer 的 `network.raw.json` 是解析后重序列化的 JSON；`network_fingerprint`
绑定公共 `requests.json`，两者都不是原始导出字节的捕获基线。本批在 importer 做窄改：
实际选中的 network export（含既有 HAR fallback）只捕获一次 bytes，同一份 bytes 同时
供规范化与私有原件发布；不在解析后重新读取可能已变化的输入。保留旧 discovery 投影，
在发布 capture summary 前新增 `network_source={path, sha256, bytes, format}`，绑定已保存
原件的路径、digest、长度和实际格式（JSON/HAR/text）。text 仅作发现材料。归档失败或
字节核对失败不得发布成功基线；已有 identity、去重和清理算法不重写。

适配器只读取 target-owned 原件：新 capture 用 `network_source`；旧 HAR 可用既有
`private_artifacts.network_har` 的路径/hash/bytes 基线。旧 JSON 缺此基线时标为
`unverifiable_capture`，保留发现材料但拒绝声称已验证的浏览器登记；须用留存的实际
原始导出另建 capture 身份，或另行取得新捕获，绝不对当前重序列化文件补 hash 冒充
历史基线，也不自动重放网络动作。

首次登记和之后读取均新鲜核对基线、路径身份、实际字节/hash/长度；严格解析 UTF-8、
JSON 和格式结构，坏编码/坏 JSON 保留诊断，不用替换字符掩盖。只解析已核对的同一
bytes，保留每步原始字段、body 编码、真实时间、request ID/出现序号、源 pointer/HAR
entry 及源 hash。导出步骤是带来源的原件切片，不是逐字线上 HTTP 报文；全文继续保留。
digest 证明与已发布基线一致，不是来源真实性认证，也不保证抵抗基线与原件同时被改写。

| 原件状态 | 登记语义 |
|---|---|
| 精确 method/URL、真实时间、完整请求响应 | 保持顺序登记；不判断漏洞 |
| 有请求、无响应/读取错误/截断 | response 不伪造，outcome=partial，保留错误 |
| 显式空 body、已知无 body 的协议响应 | 与未抓到 body 区别；保留原状态、headers 和编码，不用空字串填缺失 |
| 二进制/base64 | 保留编码及字节来源，验证编码合法；不有损 decode 后冒充原件 |
| 只有 surface、截图或 method/URL/时间未知 | 材料可保存，但给缺项诊断；不自动填 GET 或 capture 发布时间。无法构成最小 Store step 时不登记假 step |
| 未识别 payload 结构、坏 JSON、越界原件 | 可见错误；不当作合法空请求列表 |

HAR 中的跨 origin/out-of-scope 请求仍留在原私有 browser capture；只按当前 Scope owner
允许的 target-owned 观察登记，不因同一页面捕获就把第三方流量挂到本 target。未获授权的
body/secrets 不复制到共享方法版本；原始证据保留原件，公共 summary/日志不得展开私密值。

同 capture identity 返回旧 partial 的现状不称为“已补全”。首批补充采用显式新 capture
版本/身份保存完整新材料，保留旧 capture，**继续同一 execution attempt**，登记使用
前述 expected_operation。不得原地改已登记 raw 或重新调用浏览器去补“自己的证据”。
不为此重写 importer 的通用身份/清理算法；已有 capture 消费者保持原合同。

## 7. 记忆、campaign 与能力保留

目标内重要节点写回时机只由 `skills/runtime-protocol.md#cognitive-write-timing` 规定。
`rules/retrospective.md` 改为引用它：稳定结论、反证、条件变化、路径决定及暂停/切换/
compaction 按需写回，不逐观察另写总结。只读/预览不写；方法维护与共享知识审核不是
这个时机合同的别名。

campaign 的 seeds 文件继续保存 seed、已筛选/剩余活面、发现来源、所属目标、进度和
下一种子意图，包含可回读的工作材料路径。开始/续接显式读取该文件；切换前保存剩余
活面及路径，目标内交接只保存当前目标的真实观察/下一意图。切换后显式选择已初始化
目标并读取其 current_handoff，不从旧 active pointer、摘要或有界历史推断当前工作。
没有现成自动 seeds consumer，因此本批是原生读取/写回接线，不虚报自动数据库恢复。
`done` 种子进度不等于技术 refuted 或 Coverage complete。

专项保留：whitebox、mobile、CI/CD、Web3、meme-coin、credential、triage、report、recon
继续可用。Mobile 的 `api-testing-workflow` 退休引用转到现有 Web/API 完整方法及 evidence
owner，不复活包装 Skill。Web3 非 HTTP 原件暂不接入 HTTP Store observation/Finding；
保留方法和原件，不伪造 URL，不在本任务改 Store schema。

cleanup 的真实最终回读、degraded/partial、advisory、reframe、已有指标、立即/延期报告、
交付与未知执行回收均以现有 owner 为准。预算停止只停止新工作，未完成事项留在交接，
执行回收/cleanup/终态心跳不省略。

## 8. 2.3 的最终处置

详见 [三方能力处置矩阵](research/capability-disposition-matrix.md) 和
[2.3 逐文件差分清单](research/v23-delta-matrix.md)。

- 首批借鉴按问题分层、按需展开、专家输入/输出和证据字段表达，落到 C 现有 owner；
  不移入 2.3 的 branch/controller、graph/ledger、report gate 或第二套状态文件。
- 32 个同名相同文件不重复导入。15 个同名改动及知识目录短表改名是机械替换，不当新
  机制；B lane 短表还改写维护依据和入口路由，这些治理重定向不导入。保留 A 正文，
  修正 C 真正需要的链接，不带入乱码、标签折叠和断链。
- 四条新增短表场景与三篇对应手册确有内容增量，但效果、来源准入尚未验证。列为具名
  延后方法候选，不放入本批活动短表或冒称满足 A；后续须按 A 核对完整来源。它们不是
  A 的 62 项承诺内容，也不阻塞 A 的完整接入。
- 19 个专家条目是组织声明，不计为 19 项新能力；Markdown adapter 和 schema 测试不能
  证明宿主生产—接收链。schema/sample 的字段矛盾保留为不整体采用的证据。
- 不添加新 benchmark、模型下载或自动宿主探测系统；已有 cleanup 等增量原样保留。

## 9. 兼容、切换及回退

实现前留存 C 的脏工作树及本批 before 字节，不 reset/checkout 清理既有改动。
**B1–B5 全部在隔离开发副本 S 准备，C 的代码、活动方法、manifest、入口和 Rules 不提前改。**
文档路径仍按 C 相对路径表达。S 来自 C 当前实际工作树的显式源码白名单，包含既有脏增量，
不能只复制 HEAD。验收副本 F 来自 S 的实际候选代码/方法 payload；需旧版的场景用保存的
C before 方法字节播种，再经 F 自己 bootstrap。F 的工具、依赖、installer 和测试均在 F
内运行，不通过 C 的脚本加 `--repo-root F` 假装隔离；缺文件不能用 C fallback 补足。

B6 先完成 F 的验收，再进入 C 的维护窗口：停用本 checkout 的入口、目录/正文消费者，
停止相关写者、Git 切换和同步；仅禁止写者不够。重新核对 C 与保存的 before，一致后
先发布兼容代码，再用 C 的实际旧版本执行全新的 bootstrap，最后发布已准备的原生入口、
Rules 和 critical-runtime 清单。回读方法版本及本次 checkout 消费者一致后才解除维护；
依赖尚未同步的个人 runtime 的入口仍保持停用/显式 drift，不冒称已经部署。
F 的 bootstrap receipt 不能复制成 C 发布证明。若 C 已变化，停止并重审差异，不能覆盖。
这不是整个 checkout 的原子事务；任何中断都保持维护关闭，按已保存的逐路径 before/after
守卫及方法 pending 恢复，未全部就绪不得称“完整生效”或重开不兼容消费者。
排他范围是 C 的受影响路径及其全部相关读写消费者，不要求无关进程退出整台机器；
本会话也只允许指定切换/回读流程触碰这些路径。须协调其他会话、编辑器、同步/监视任务，
锁或某次进程列表都不能单独证明排他。不能确认时保留 S/F 候选，不执行 B6，不擅自杀进程。

验收组及其子进程统一环境白名单：临时 HOME、XDG、TMPDIR、runtime/memory 根，禁用
用户 Python site 和 pytest 自动插件；默认不继承快照、认证、代理、PYTHONPATH 等变量。
按场景只注入临时 override，检查核心项目模块 `__file__` 落在 F；原件/数据/模型与不安全
符号链接不从 C 复制。额外 I/O/网络哨兵阻断越界访问，环境清理本身不冒称 OS sandbox。

真实安装/同步须另获明确授权；本批只从 F 运行现有 installer/doctor，指向同一临时
HOME/runtime。安装仍只管理 commands/agents/skills，knowledge/tools 留在其启动 checkout
（验收为 F）。不新增安装目录、更改 ownership receipt 语义或把用户 runtime 当测试场。
切换检查同时覆盖安装副本、checkout 方法版本与原件健康；doctor clean 单独不证明
活动方法、目录消费或模型能力。

旧公共命令保留。新 reader 对 v1 只读兼容、v2 对旧 reader 可见失败；原生 Skill 与工具
版本不一致返回明确诊断。外部目录、用户修改的托管文件、退休但未被拥有的 Skill
均按现有 receipt 规则保留，不批量删除。

回退只撤本批可证明拥有且仍匹配的代码/文档变更；方法通过 guarded recover 或新的
反向修订恢复。已产生的新方法版本、原始来源、Store 数据和实际执行证据不删除。
有新观察/经验后不能回放旧目标快照；若旧消费者不能安全读取新协议，维持该入口
不可用并修复向前，而不是恢复数据或静默降级。

## 10. 验收与未证明边界

[实施计划](implement.md) 的 V1–V7 映射全部 A1–A9。关键证据必须来自真实 reader、CLI、
owner 或临时进程的结果：完整相关方法读取、A 修改后再读、并发/中断恢复、无 Finding
观察到经验/交接、浏览器 partial 补充、隔离安装与回退。纯文件计数和 schema 外形
检查只能证明结构，不能替代这些行为。

本任务不承诺恢复遗失的白盒原文、不宣称 2.3 新方法已验证、不证明在线调查能力或
效率提升、不补非 HTTP Store 生命周期。它们均有明确处置，不是本批待用户裁决问题。
