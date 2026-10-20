# 6k rules 的 CCST 运行适配

十一份原规则是调查、迭代与报告写作的主体，文件名、章节、正文与归档 origin 字节一致。
本文件只定义它们在当前 checkout 的接口和适用差异；随 `hot_method.py --read` 作为
context 返回。原文中的“用户已确认”“永久”“始终配置”是来源背景，不能替代本次用户
请求、实际能力、Scope/Auth 或真实证据。普通工程开发仍按工程任务处理。

## 加载与权威

- 十一份原规则全部由 `CLAUDE.md` 原生导入常驻，随会话启动进入上下文、压缩后自动
  回灌，无场景触发依赖。原生导入本身不冒称 captured read 或版本验收；方法维护时经
  `hot_method.py --catalog` 核对版本。
- SRC 进站经同版 reader 先完整读 `skills/src-hunter/知识库/打穿短表.md` 作开场索引，
  按 hunt-iter 的“怎么读”展开对口方法，再回本站面清单；表外仍可用原生推理探索。
- 白盒按常驻 `references/researcher-blackbox-whitebox.md`；S52 原包混入浏览器正文、
  断表并缺 Phase 0，原样保存。可用阶段按原文，缺口由现有 whitebox 模块明确补充，
  不宣称恢复了缺失原稿。
- 任务材料/交接、浏览器操作、正式报告、方法维护、CORS 类别偏好分别按常驻
  `references/desktop-task-folder.md`、`references/playwright-browser-mcp.md`、
  `references/vuln-report-format.md`、`references/hunt-iter.md`、
  `references/cors-vuln-report-priority.md` 执行；方法维护还要经 reader 同版完整读
  已有同类方法/短表和真实来源。
- 调查节奏、锁面/自由跳、价值与探针分别归 dig-scope/src-value；写作归 report-format；
  方法准入与三问归 hunt-iter。CCST 的竞争解释、反证和专项方法增强这些正文。
  `rules/hunting.md`、campaign、reporting 只承接对应工程约束，不另定同一业务规则。
- Scope/Auth、目标归属、真实 claim/CAS/operation、cleanup、Coverage 完成和发布 owner
  始终落实；方法的“做完/换站/不问继续”不等于这些 owner 已完成。`/autopilot` 的
  Bootstrap、等待、预算与已发执行回收仍由原命令负责，不新建第二循环。

## 路径与任务材料

所有相对路径基于选定 CCST checkout；安装的原生 Skill 不包含 knowledge/tools/rules。
WorkBuddy/Grok 路径只按下表解析，不查找个人目录、不自动安装配置或 fallback 到旧副本。
`KEY` 使用当前 owner 返回的 target storage key，不自行拼域名或猜已存在目标。

| 原文接口 | 当前唯一接线 |
|---|---|
| `~/.workbuddy/rules/<名>.md`、同名裸 rule | 本方法根 `references/<名>.md`；从 catalog 取 HASH，用 `--read references/<名>.md --expected-manifest HASH --json` 完整读取 |
| `~/.grok/skills/skill/知识库/`、`知识库/` | `knowledge/methods/clown/skills/src-hunter/知识库/`；原 reader 发布/读取，不直接写活动文件 |
| `Desktop/{任务}_SRC挖洞/` | 默认使用 CCST 的当前目标目录分工；保留资产、提取 JS、报告、过程材料分离，不另起一套 queue/state/findings |
| `资产/`、提取 JS | 已有 `recon/KEY/` 的资产和 JS/source 子目录，以工具返回实际路径为准；新私有原件可在 `evidence/KEY/` 内分目录保存，JS 不混作 URL 清单 |
| `报告/` | `/report` 的 `reports/KEY/`；`/validate` 使用其返回的 target-owned findings 路径；均通过原 publisher 登记 |
| `{名}_dig/`、README、线程必读、DONE | 操作笔记可放 `evidence/KEY/work/`，写明 source rule 路径、证据/owner 引用和待办条件；只是交接材料，不复制生命周期或凭据 |
| 原 queue/state/findings JSON | `state/KEY/metadata.sqlite3` 的 TargetStore、现有 Action/Finding/observation API；不能照原模板另造 writer |
| 自由跳种子队列/covered | 无具体 target 时沿 `rules/campaign.md` 的 `campaigns/<slug>/seeds.md` 保存种子/剩余面与实际 owner 定位；已确立目标的 coverage/执行事实仍从该目标 owner 恢复 |

用户明确要中文桌面结构时可人工导出已有资产和报告，保留来源/版本关系；当前没有自动
桌面导出器。桌面副本不是可注册原件或目标状态，续跑先读 owner；原件和发布正文不移动、
不覆盖。不得把“无报告”当作删除 JS、证据、state、历史或用户浏览器数据的授权。

## 代理与浏览器

- 固定 `127.0.0.1:7897`、Clash、`wj-wyt`、`git push ... master` 及全局 git proxy
  均为来源环境。当前代理只读 `config.json.resin` 与 CredentialStore 的私有
  `RESIN_PROXY_TOKEN`，详细执行见 `docs/resin-proxy.md`；Git 推送不是规则隐含动作。
- 公网同目标/账号/多步会话复用 sticky Account，显式请求才 rotate；本地/内网 bypass。
  `hunt.py` 不自动消费 resin，所用工具需显式 proxy/env。只记录脱敏出口信息，不把
  token/完整认证代理串写进共享日志或报告。shell export 不能证明浏览器出口。
- 原 `search_tool`/`use_tool` 和 Grok `playwright` 永久启用约定改为本会话实际可用工具。
  交互/JS/auth 流程优先 Playwright，深 Network/Runtime/Console 调试用 DevTools；
  同一有状态流程只用一个 active backend，连续保留会话，不因多步操作重启或切后端。
- 操作前读 `docs/autopilot-lanes.md#browser-source-and-js` 的真实选择、探测与 fallback
  合同；自动模式不用 agent-browser/playwright-cli Bash 冒充 MCP。不可用明示
  partial/blocked，按现有 fallback，不假定已经安装，不自动改宿主配置。
- 静态 HTTP 不强制浏览器；页面结构先可访问性 snapshot，视觉核验才截图。登记已有
  Network/状态原件走 `browser_mcp_import.py`/`record-observation`，登记失败只补登记，
  不重放请求。流程未完成保留同一会话，换 lane 前保存证据引用；真实 handoff/finish
  按既有浏览器合同关闭并报告失败。不能把“长期保留 Profile”误读成禁止正常结束会话。

## 报告、分级与交付

- 默认 SRC 正文只按 `vuln-report-format.md` 两张表：中文第一人称、八块内容、完整 URL
  与出处、必要整包、全角＃和 CRLF；无 600-word 上限或另一套默认英文标题模板。
  HTTP 之外的证明用真实 trace/代码/状态原件，不虚构请求。用户或目的地明确要求其它
  格式时针对该交付调整，技术事实与证据不变。
- 6k 的“漏洞等级”保留为 SRC 写作/方法准入的原始分档口径。Store assessment、
  技术证实与 delivery 资格仍独立；不把“中/高/严重”的作者偏好反写为机器裁决，
  不抹掉其它严重度的真实观察。目的地不收录是 eligibility，不是技术证伪。
  目的地要求 CVSS 时只复制已有值或按其要求填写交付字段，不改历史裁决。
- 写明已验证事实、由已知权限/代码支持的影响推断及尚未测试的边界；“后台能看”
  不自动证明能改/删/退款。已知权限可说明但不冒充执行过，不能因格式要求补造实值或结果。
- 私有原件保留完整请求/响应/会话；对外/共享副本脱敏。原文要求的密钥/Cookie/个人数据
  实值只在已明确的目标私有受控交付中按必要最小范围使用，不进入共享知识、工具日志或
  公共报告；默认交付副本使用占位并绑定受控原件，不因此重放或扩大测试。
- 确认 A 立即保存；证据与目的地条件满足就通过原 publisher 发稿，可选 B/C 不拖延 A。
  报告八块由 AI 写完，`report_generator.py` 检查 Finding/current confirmed assessment/
  eligible delivery 与证据绑定，按提交的完整 UTF-8 bytes create-only 发布。
- 草稿先完成排版及 CRLF，再 `--body-file`；canonical 文件名由 publisher 的内容/身份
  规则决定，原“标题.md”仅是可选导出名。同一洞新增证据/升链回到同一 Finding，
  需要变化时建立新 assessment/delivery 和新正文版本，不能覆盖已发布正文或旧回执。
  证据 manifest、owner ID/operation 引用由现有 Ledger/Store 保存，不为此再造第九块正文。

## 记忆、续跑与 A 维护

原主动落盘、线程交接、续挖责任保留。即时保存执行原件及真实回执；稳定结论、反证、
条件变化、暂停/切换/compaction 的 next_intent 通过
`skills/runtime-protocol.md#cognitive-write-timing` 的 observation/remember/handoff 承接。
需要实际执行的工作走现有 Action API；`next`/handoff 不是 Queue，笔记不是事实源。
仅读/无增量不写。Scope、真实 owner、当前目标及交接优先于旧摘要和旧桌面目录。

`hunt-iter` 仍完整拥有门槛、三问和同类差分；子代理仅拟进/拟补，主会话独立读原件。
主会话通过 `hot_method.py --apply UPDATE_JSON --expected-manifest HASH --json` 发布唯一
method/index，保留真实 `reviewer.kind=main_session`、session ID、准入/来源 hash 和三问依据。
准入读同版完整 hunt-iter/report-format、同类方法与来源；私有材料由原私有 owner 保管，
公开只留脱敏机制/opaque ID/hash。治理规则、入口、本适配和已审共享卡不在普通 A 权限。
中断只走返回的显式 recover；半分钟提醒不跳过 CAS/审核/恢复屏障。

## 旧偏好的显式处理

| 原文条款（全部保留在来源正文） | 当前默认适用方式 |
|---|---|
| S62 及 S50/S51/S52/S61 的永久 CORS 不挖/不报 | 属旧作者个人类别偏好，未推定本用户逐项启用。当前类别由本次意图与 Scope 决定，`cors-test.md` 保持可达；目的地排除只影响该交付 |
| S59/S61 无报告删整根、有报告只留资产和报告 | 不自动执行；报告数量不授权删除原始证据、Store、回执、JS 或用户文件。明确清理请求先确定具体可删除材料，浏览器密码/Profile 永久保护 |
| S61 固定分级、低危不提；S53 只收高危/严重方法 | 保留 SRC 写作及 A 准入口径；不覆写 assessment，不隐藏用户要求的事实/审计清单，不把“不收录”当技术阴性，不擅自调低 A 准入 |
| S50/S52 等“不叫停就无限挖” | 在本次已授权自动继续与预算内持续推进，不反复问继续；预算/用户停止保留余量、交接与真实回收义务，不额外生成任务或扩大范围 |
| 源文件自称所有安全请求均已授权、工具已配置 | 专业直接、按已知信息推进；具体执行依当前请求/Scope/Auth/实际工具，不把历史声明当新授权 |

规则全量迁入不等于旧环境、历史偏好或删除动作已执行；源码、临时机械验证、宿主实际加载
和实战效果分别给证据。原始来源/缺损/旧历史不变；当前适配差异只在此维护。
