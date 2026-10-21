# Hunting Rules

Load this engineering contract for `/hunt` or `/autopilot`. The complete 6k
`rules/dig-scope-workflow.md` and `rules/src-value-hunting.md` own hunting
semantics and cadence; load them through the original reader as required by
`rules/README.md`. Its runtime adapter owns environment differences.

Owner boundaries:

- `CLAUDE.md` owns operator intent, CTF interpretation, and loading boundaries;
  6k dig-scope owns fixed-target/asset-cluster semantics.
- `rules/ccst/red-lines.md` owns concrete side-effect decisions.
- `rules/ccst/coverage-gate.md` owns lifecycle names, coverage states, and completion claims.
- `rules/ccst/tool-ai-boundary.md` owns the AI/tool split and scanner-output interpretation.
- `skills/runtime-protocol.md` owns memory continuity and captured knowledge reads.
- `commands/autopilot.md` owns inline control and bounded specialist use.
- `skills/src-hunter/modules/triage-validation.md` owns candidate proof; 6k report-format
  owns report prose; `rules/ccst/reporting.md` owns evidence/delivery checks.

---

## 测试行为红线（不可违反）

来源：clown `skills/src-hunter/SKILL.md`「安全红线」节（CC BY 4.0），
与 `rules/ccst/red-lines.md`（目标副作用）互补：本节管测试行为本身，
red-lines 管对目标系统的破坏性副作用。两者冲突时从严。

1. **越权验证最小伤害**：默认读/列表差分证明跨用户·跨租户。写越权仍要测，
   顺序是先添加（看能否挂到他人名下）→ 再删除自己刚添加的那条；不动他人
   已存在的订单/地址/密码/角色。无创建口只能动现成对象时，只改自己能改回
   的测试字段，打一次，过了立刻改回，改不回就停在回包。扣钱、清库存不做；
   禁止批量、禁止真资损。操作详文：热库 `知识库/idor-test.md`「写越权怎么打」。
   「只读红线」不得理解为「写 IDOR 不用测」。
2. **禁止登出/注销/吊销**：用户提供的登录态（Cookie/Token）在测试全程严禁
   调用 logout/signout/revoke 及等价会话销毁动作；不测「退出后会话还有效」。
   保持用户会话始终有效。改绑/改密探过立刻改回，不把用户号改死。
3. 类别偏好沿用当前完整 6k 规则：默认 SRC 不挖 CORS，见 `rules/cors-vuln-report-priority.md`。
   用户明确的新指令可改变当前任务偏好；工程规则不覆盖已生效的项目规则。

---

## Current Target Context

The target set supplied by the current command is the active execution context.
Keep observations, preferences, artifacts, state, and write-back isolated to it.
Do not let another target's history select or suppress this target's lanes.

Localhost, private IP, CIDR, list, and named targets remain valid inputs. Any
CTF interpretation comes from `CLAUDE.md`, not this rule.

### 锁面与资产簇

完整读取 `rules/dig-scope-workflow.md` §0/§3/§4；模式、重要资产组、同皮/同闸、
多 host/path 和进站节奏只在原文定义。这里仅落实目标隔离及真实 Scope/Auth；原文中的
业务 host 线索不自动成为可执行范围。集团材料与各目标 Store 的接线见 `rules/ccst/campaign.md`。

### Temporary preferences do not cross targets

A request to skip or focus a bug class, lane, scanner module, exclusion, or test
input applies only to the target and invocation where it was stated.

New target defaults:

```text
scanner module flags = supported options for the selected pass, consistent with project/task exclusions
XSS checks remain enabled unless explicitly excluded
scanner_full = full-mode depth extras, not an XSS gate
excluded bug classes = current project rules (SRC: CORS) plus explicit task preferences/command flags
```

Do not import skips from an old target, CLI session, example, heuristic, or
target-history note. These temporary choices do not erase persistent project rules or
preferences explicitly carried forward by the user; current explicit instructions take precedence.

## Scanner Contract

AI/tool responsibilities remain in `rules/ccst/tool-ai-boundary.md`.

### Broad scanner input and completion contract

- 常规 broad breadth 只通过
  `python3 tools/hunt.py --target <target_shell> --scan-only --quick` 进入现有
  scanner owner 和单 target runtime lock。
- `urls/all.txt`、`all_historical.txt`、gau、wayback、waymore 等 raw corpus 是完整
  证据语料，不是通用 Nuclei 的默认输入。已成功完成的 quick breadth 不因 Deep
  模式、raw URL 数量或空结果而重复执行。
- bounded Surface/projection 只是默认消费窗口，不是 AI 能力上限。需要长尾证据时，
  可按 Surface page/source/shape 分页、用 `rg` 查询 raw artifact，或根据组件、CVE、
  路径、参数和行为证据构造专项列表并运行 targeted templates。
- 集成 scanner 的 Nuclei supplement 默认开启（用
  `BBHUNT_DISABLE_NUCLEI_CVES=1` 关闭），只接收有界 origin
  （`BB_NUCLEI_MAX_TARGETS`，quick/standard/full 上限 50/100/200），
  用于显式选择的有界 CVE breadth 观察，不替代组件适用性判断或专项验证。
  SQLi/SSRF 由 AI 根据目标证据直接选择 browser/curl/raw
  请求；需要稳定 HTTP 请求对时可选 `request-diff`，需要回调时使用 OAST Listener。
- `summary.json` 是最新执行投影，running/skipped/unavailable/incomplete 也会发布；
  文件存在不证明完成。每轮 `nuclei_runs/<run-id>/` 保留输入、raw JSONL、日志、
  退出码与状态；lane 计数区分已完成和未完成 origin，失败输入仍留在 remaining。
  不从旧类别文件推断本轮 scanner-pass，不自动创建 Finding/Assessment/Action。
  successful/sampled 只描述选定上游模板执行，不表示 tested-clean、安全或穷尽。

## Rotation

空转/肥瘦/同闸、进站与换种按完整 dig-scope §2/§4，价值及探针按 src-value。
证据 fingerprint、条件反证和真实 handoff 的工程补充见
`skills/src-hunter/SKILL.md#evidence-driven-rotation`；低收益、预算或 scanner-negative
不能写成技术 refutation、Coverage complete 或 exhausted。保留未完成面及重开条件。
确认 A 的证据与目的地条件成立即可交付，可选 B/C 不延迟其保存/发布。
