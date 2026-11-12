# 覆盖基线 Gate

覆盖基线用于防止过早收工。它不是要求每个方向都实测，而是要求 Claude 对覆盖状态负责。

## 状态枚举

### 内部存储状态（9 态）

既有覆盖记录保留以下九态及理由；它们不替代 Action/Finding 的生命周期：

| 状态 | 含义 |
|---|---|
| `unknown` | 尚未判断或尚未测试；说明下一步或本轮未覆盖原因 |
| `queued` | 已计划测试但未完成；保留具体动作 |
| `tested` | 记录条件下已完成验证，未发现有效线索；附证据或测试方式 |
| `lead` | 有线索，但还缺少复现、影响或权限差异 |
| `signal` | 有行为差异或证据，但还不能进入验证 |
| `candidate` | 证据足够，应该进入 `/validate` |
| `blocked` | 说明缺少的权限、环境、账号、材料或具体红线，以及恢复条件 |
| `n/a` | 明确不适用，并说明原因 |
| `dead-end` | 有证据支持、限定于记录条件的负面结果；低价值或暂停本身不属于此状态 |

### AI 接口状态（4 态）

交接、摘要使用四态加理由；理由必须保留九态细分、证据和下一意图，不能丢失信息。
`COVERAGE SUMMARY` 是这些事实的展开分组，不是另一套状态。

| 4 态 | 覆盖的内部状态 | 理由必须承载 |
|---|---|---|
| `untested` | `unknown`、`queued` | 下一步动作，或已计划未执行的内容 |
| `investigating` | `lead`、`signal`、`candidate`、`blocked` | 具体档位（lead / signal / candidate）；`blocked` 归 `investigating`，理由写阻塞原因和需要什么输入 |
| `confirmed` | 无九态逐格对应物；来自 Finding 的当前确证裁决 | 当前 assessment / validation 与有效原件引用 |
| `ruled_out` | `tested`、`n/a`、`dead-end` | 三档细分：测试方式与证据（tested）/ 不适用原因（n/a）/ 证伪原因（dead-end） |

写方向（4 态 → 9 态，取保守侧）：回落到 9 态记录时，`investigating` 默认落
`lead`（宁可低估，不默认 `signal` / `candidate`，理由里再细化档位）；
`ruled_out` 按理由内容三选一落 `tested` / `n/a` / `dead-end`，三者的必填理由
规则原样适用；`untested` 默认落 `unknown`，已有计划时落 `queued`。
写回使用对应 owner API；`confirmed` 读取 Finding 当前裁决，不能由矩阵标签反向生成。

矩阵的 `untested` / `tested_clean` / `tested_finding` / `n_a` 是独立的审阅/历史接口。
`mark tested_finding` 可只保存未评估 claim，不产生执行证据或闭合；`tested_clean` 也不能
单独证明 ruled_out。当前覆盖由原 owner 按证据身份、适用条件与健康状态判断；不把 exact
query/hash/identity 的结果扩张到整个 endpoint/family，结构性 `n_a` 仍需真实不适用依据。

## Feature / Workflow Closure

Before any feature or workflow is summarized as `tested`, its evidence must state:

- Input surface: which externally controlled inputs were actually exercised.
- Behavior/state surface: which roles, state transitions, or business behaviors were observed.
- Validation depth: which boundaries or variants were tested, including whether only one variant was tried.

Anything not established must remain in the existing `unknown`, `queued`, `lead`,
`signal`, `candidate`, `blocked`, `n/a`, or `dead-end` states with the reasons required above.
Do not add a parallel coverage state or schema for these residual lanes.

## Discovery Gap

`unknown` is not a final completion state. 如果当前 surface is underexplored，
或者浏览器/API/JS/source/recon/参数/路径/组件/角色/工作流仍有安全探索空间，
不能把它写成 `tested` 或“无发现”。必须标记为 Discovery gap，并给出下一条
安全的证据生成动作。

Evidence-driven depth does not mean evidence-only testing. 没有强证据时，
可通过 Discovery mode actively generate new evidence。Autopilot 是否结束按 `commands/autopilot.md` 的 Finish Contract，
依据实际用户/范围/预算边界、阻止有用工作的真实阻塞，或有证据支持的无值得继续路线判断。
保存 handoff、已有报告数量、匿名 401/403 或尚未准备可获取的会话本身不是停止依据。
证据路径不可达、红线或材料缺失按事实记 `blocked`；`dead-end` 必须有条件化反证，
`n/a` 必须确实不适用。投入价值低、预算结束或暂停仍保留原认知状态和未测面，不能当阴性。

## 交付前检查

最终回复前必须回答：

```text
COVERAGE SUMMARY
- Covered:
- Leads / Signals:
- Candidates:
- Blocked:
- Not applicable:
- Dead ends:
- Still unknown:
- Next actions:
```

## 通用续跑 Gate

泛泛 TODO 或“后续人工测试”不是覆盖；保留具体证据问题、未完成状态和可恢复的下一意图。

如果 `tools/action_queue.py summary --target <target>` 显示仍有 active action，
不能声称全面完成。有合理停止依据时保留 active/pending 与明确 handoff 结束本轮；
否则继续选择有信息增量的工作。矩阵未清空和 loop_guard=continue 也不强制无界执行，
不为停工伪造 resolve、blocked 或 dead-end。已发执行的回执、未知效果恢复、cleanup、
claim 及终态心跳仍按原 owner 完成；预算不能取消这些义务。

## 矩阵检查

复用当前有效视图；需要查询或发布更新的派生缓存时按 `commands/check-coverage.md`，
普通 checkpoint 不要求 rebuild。`find-gaps --limit N` 返回全部未处置格的窗口、总数和
展开方式，不按路径词/类别分数筛选，也没有 `--all`。

- AI 根据原件和目标语义选择值得追的 gap；矩阵枚举不等于逐格必测清单。
- 解释选择不追的高价值 gap：真实状态、证据或延期理由。未解释的高价值项仍在时，
  不声称全面完成；有合理停止依据可保留残留结束本轮。
- 零 gap 仍要核对 `/surface` Workflow Leads、目标经验、unsafe-skipped、blocked/n/a。
  空 endpoint 或缺输入保留 unknown/blocked，不算 tested。

## 高价值 surface

通常应优先交代这些 surface：

- 登录、注册、找回密码、邀请、SSO/OAuth/SAML
- 用户、组织、团队、角色、权限
- 导出、下载、分享、批量操作
- 上传、导入、转换、解析、预览
- webhook、callback、URL fetch、集成
- admin、internal、debug、settings、billing
- GraphQL、WebSocket、API mutation
- CI/CD、公开仓库、配置和 secret 暴露面
- 已识别的产品、CMS、插件、主题、框架、库及其版本。只记录“版本较新/
  需要查 CVE”不算覆盖；必须完成情报查询、受影响版本判断、可达路径判断，
  并给出低风险验证结果或明确 blocked/dead-end 理由。

## 和红线的关系

覆盖要求不能推翻红线。`blocked: red-line` 指出具体动作与破坏性效果，说明低风险替代；
不能用高压流量或不可控状态变化凑覆盖。

## 和目标层的关系

Coverage 由 `tools/coverage_matrix.py` 从当前 Store 和证据健康派生。
影响后续判断的经验按 `skills/runtime-protocol.md#cognitive-write-timing` 保存，
具体条件、证据引用与重开要求见 `commands/target.md#交接与证据`。
目标经验保留矩阵之外的条件、重开标准与下一意图，不代替 Coverage 或生成第二份覆盖状态。
