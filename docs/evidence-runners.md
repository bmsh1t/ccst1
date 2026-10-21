# Evidence Runners

这些工具是可选的证据执行平面，不是 `/autopilot` 或 `/validate` 的主脑。

## 原则

- Claude 负责选择 hypothesis、攻击面、链路方向、影响判断和报告价值。
- 工具只负责稳定 replay、diff、raw evidence、Store 观察登记和可复现输出。
- runner 输出是证据，不是最终结论；是否继续、降级、链式扩展或报告仍由 Claude 判断。
- 不要为了清队列而运行 runner；只在它能减少漂移、补足证据或复现复杂步骤时使用。
- MCP/browser/source/JS 观察帮助 Claude 选择真实实验；已有完整执行材料可直接登记，不为接入状态而重复请求。

## 执行与登记速查

从选定 checkout 执行，始终显式传 target；不确定参数时只读对应子命令 `--help`。

| 当前需要 | 现有入口 |
| --- | --- |
| 查看当前 Finding / 历史处置 | `python3 tools/target_store.py findings --target TARGET --id ID` |
| 无 Finding 的已执行观察 | 下节 `record-observation`，不创建占位 Finding |
| 已有 Finding 的完整原件 | `record-evidence --target TARGET --finding-id ID --evidence-json FILE --json` |
| 未决覆盖 | `python3 tools/coverage_matrix.py rebuild --target TARGET`，再 `find-gaps --target TARGET` |
| 保存当前交接 | `python3 tools/target_memory.py handoff --target TARGET '具体停止依据和进度' --next-intent '下一问题' --operation-ref OPERATION_ID:STEP --json` |

Store 和 Coverage 命令本来输出 JSON，**不加 `--json`**；handoff 的摘要是必填位置参数。
`OPERATION_ID:STEP` 必须来自登记回执。保存 handoff 不构成停止理由，Autopilot 按共享 Finish Contract 判断。
保留完整命令结果与退出码；管道需 `set -o pipefail`，不能以 tail/head 或后续命令的成功掩盖登记拒绝。

### 在执行时捕获原件

用已有浏览器 HAR/export 或 curl trace 捕获实际请求；适当的 raw sender 用于字节敏感实验。
下例仅用于已核对 Scope/副作用的请求；原生 curl 不自动继承项目 Auth/父 Scope，
不加自动跟随跳转。认证用受控私有配置/会话来源，不把令牌放 argv 或日志输出。
`capture_dir` 是本次独立的目标私有目录，`request_url` 是已选定的完整请求 URL：

```bash
umask 077
mkdir -- "$capture_dir" || exit
date -u +%Y-%m-%dT%H:%M:%S.%NZ > "$capture_dir/started_at.txt"
request_exit=0
curl --silent --show-error --max-time 30 --trace "$capture_dir/request-response.trace" --trace-time \
  --dump-header "$capture_dir/response.headers" --output "$capture_dir/response.body" --url "$request_url" || request_exit=$?
date -u +%Y-%m-%dT%H:%M:%S.%NZ > "$capture_dir/finished_at.txt"
printf '%s\n' "$request_exit" > "$capture_dir/exit-code.txt"
```

检查保存的真实退出码和回包；传输失败/缺响应按 partial，HTTP 401 等仍是实际响应。
`artifacts.request` 可引用带真实发送字节的 trace；同时登记 `response` 与 `response_headers`，
必要时附 trace。时间取此次捕获，不能猜测、手填近似值或用登记时间替代。
HAR/trace/受控原件保持真实身份；脱敏请求仅为明确标注的复现示例，不能当线缆原件。
不要手写 Content-Length、占位 token 或替换 User-Agent 后宣称是原始请求。

## Native Observation Registration

已执行但尚无 Finding（也可无 Action）的原生观察使用独立的 `record-observation`。
它只登记留存材料，绝不执行命令、发请求或追认原执行许可。不要创建占位 Finding 来保存
中性观察；已有 Finding 的证据/cleanup 仍用下一节 `record-evidence`，原合同不变。

### 原生原件 envelope

`--evidence-json` 是新的显式 envelope，不是旧 Finding schema-v1 的另一种 result：

```json
{
  "schema_version": 1,
  "kind": "native-observation",
  "source": "saved-native-export",
  "started_at": "2026-10-16T10:00:00+00:00",
  "outcome": "complete",
  "runs": [
    {
      "url": "https://TARGET/api/observed",
      "method": "GET",
      "family": "observed-workflow",
      "observed_at": "2026-10-16T10:00:01+00:00",
      "description": "Original read-back of the observed workflow state",
      "actor": "unknown",
      "state_changing": null,
      "artifacts": {
        "request": ".private/validation/TARGET/observed.request.txt",
        "response": ".private/validation/TARGET/observed.response.txt"
      }
    }
  ]
}
```

```bash
python3 tools/validation_runner.py record-observation --repo-root ROOT --target TARGET \
  --attempt-id ORIGINAL_ATTEMPT --evidence-json /tmp/observations.json --actor RECORDER --json
```

- 顶层只接受 `schema_version/kind/source/started_at/outcome/runs` 和可选
  `target/attempt_id/family`；重复声明的目标、attempt 必须与命令一致。
- runs 保留原顺序、重复 URL、每步精确 method/family/真实含时区 `observed_at`、非空描述。
  每步可选 `actor/object_scope/variant/error/body_truncated/state_changing/redline_checked`；
  原件引用必须是同目标已有非空普通文件。不得放 Finding、结论、closure identity 或 cleanup。
- `source/started_at` 来自原执行记录，不能用登记时间代替。每步不得早于执行开始。
  `--actor` 是本次**登记命令执行者**，不是 HTTP actor；未知 HTTP actor 保留 unknown。
  未绑定 Action 且无专属 family 时用 `runner-observation`，不推断漏洞类别或 Coverage。
- `outcome=complete` 要求完整原件；缺响应、读取错误或截断用 `partial`。零 runs 仅允许
  真实效果 `unknown`，不伪造 endpoint 或 `:0`。未知副作用保持 null；只有真实已审核的
  state-changing 步骤才能声明 `state_changing=true, redline_checked=true`，不按 POST 推断。
- summary 为 `kind=native-observation, lane=native_observation, result=""`；空结果是无裁决，
  不写 candidate/Finding，不解决 Action，也不产生技术阴性、报告资格或 Coverage 完成。
  真实 `store_operation_id` / `observation_refs` 可由既有经验及 handoff owner 引用。

### 浏览器已捕获原件

```bash
python3 tools/validation_runner.py record-observation --repo-root ROOT --target TARGET \
  --attempt-id ORIGINAL_ATTEMPT --browser-capture-ref CAPTURE_SUMMARY \
  --execution-json /tmp/original-execution.json --actor RECORDER --json
```

浏览器模式必须提供独立的原执行 metadata（不能同时传 evidence-json）：

```json
{
  "schema_version": 1,
  "source": "saved-browser-export",
  "started_at": "2026-10-16T10:00:00Z",
  "family": "observed-workflow",
  "steps": [
    {"source_index": 0, "actor": "owner", "state_changing": false,
     "description": "Original captured read-back"}
  ]
}
```

可选 target/attempt_id 必须匹配命令；family、actor、object_scope、variant、description、
state_changing、redline_checked 可在顶层声明默认事实，或在 `steps` 用原件的零基
`source_index` 明确覆盖。method/URL/时间只能来自原件，不由 metadata 补造。

importer 保存一次实际选中 export 的原始 bytes，并在 capture summary 的
`network_source={path,sha256,bytes,format}` 绑定基线；包括 HAR fallback，之后输入变化
不会改变已捕获原件。读取 fresh 核对同一 bytes，保留顺序、request ID、源 pointer、
空/缺 body、base64 编码及截断；私有步骤 envelope 是有来源的原件切片，不是假造线上报文。
捕获级错误或步骤缺项保持 partial。外域/Scope 外请求留在原 capture 并诊断，不登记到
本目标；只有 surface 或缺精确 method/URL/真实时间的材料不伪造实验步骤。
text 仅能用于发现，坏 UTF-8/JSON/base64 不静默替换。旧 HAR 可复用既有原件 hash/长度；
旧 JSON 无捕获基线时明确 `unverifiable_capture`，不能给当前重序列化文件补 hash 冒充历史。
应使用留存的实际导出建立新 capture 身份，不为补登记而重新操作浏览器。

### 不可变登记、重试与补证

原件及 `evidence/TARGET/native-observations/<attempt-key>/<material-id>/summary.json`
create-only；登记收据单独保存在相邻 `registrations/`。同名不同字节冲突，不追加 sync 后
覆写 summary。此为文件发布与 Store 登记两个边界，不承诺跨文件/数据库事务。

成功输出真实 operation/step；partial/unknown 或登记失败退出 1，输入错误退出 2。
失败保留已发布原件与 `registration_retry_command`：运行返回的命令只登记既有 summary，
不读取新执行输入、不重放请求。修复原件/Store 故障后精确重试；不能直接改已发布 summary。

同次执行的新材料必须发送**完整有序快照**，保持原 attempt/source/started_at，传
`--expected-operation ORIGINAL_OPERATION`；不要只传新增 step，也不要把补证重试的前驱
改成刚返回的新 operation。旧 operation/summary/原件保留。浏览器补证另建 capture 身份，
原 capture 不原地覆盖，仍是同一次 execution attempt。

首次可选 `--action-id ID --claim-token TOKEN`，由 Store 检查当时 claimant/登记 actor；
无前驱的精确 start 重试走历史收据，claim 已释放或改派不能强制重新认领。带原前驱的补证
复用旧关联，不 start/reclaim；可换登记 actor，但可选 action/token 必须仍匹配原关联。
Store 保留集合级 family/精确 endpoint 检查，不要求每一步都匹配同一个 Action。
登记与经验判断仍分离：note 可记录建议，negative 需满足既有条件/证据合同。

## Native Evidence Registration

已有 Finding 的浏览器、curl、raw sender 等实验，先按 `/hunt` 契约保存
canonical Candidate，再登记已存在的原始材料。该入口不执行命令、不发请求、不造 diff；
多步、不同方法、多字段身份上下文、multipart/binary 都不必改写为请求对。
创建 Candidate 前从实际 subject 请求确定完整 URL（含 query/编码）和 method；
不要先用去 query 的接口目录建 ID，再为适配登记重复创建同一主张。
已有不同 endpoint 的误建空候选按下方显式处置，不能覆盖身份或伪造一次无 query 请求。

`--evidence-json` 使用现有 schema-v1 summary 的观察字段：

```json
{
  "schema_version": 1,
  "source": "browser",
  "generated_at": "2026-09-16T10:00:00Z",
  "attempt_id": "native-attempt-1",
  "result": "tested_finding",
  "observed_difference": "Control and repeated test-owned transition produced the recorded state difference.",
  "runs": [
    {
      "url": "https://TARGET/api/orders/1",
      "method": "GET",
      "actor": "owner",
      "artifacts": {
        "request": ".private/validation/TARGET/control.request.txt",
        "response": ".private/validation/TARGET/control.response.txt"
      }
    },
    {
      "url": "https://TARGET/api/orders/1",
      "method": "POST",
      "actor": "peer",
      "object_scope": "other_object_same_org",
      "variant": "replay",
      "artifacts": {
        "request": ".private/validation/TARGET/transition.request.bin",
        "response": ".private/validation/TARGET/transition.response.bin"
      }
    }
  ]
}
```

```bash
python3 tools/validation_runner.py record-evidence --target TARGET \
  --finding-id FINDING_ID --evidence-json /tmp/native-observations.json \
  --state-changing --redline-checked --json
```

多步实验的完整字段示例（baseline/对照步骤与锚点步骤同材料；`subject_step` 是
**顶层零基 run 索引**，指向与 Finding 的 endpoint/method 精确对应的执行步骤；
`variant` 只接受：baseline / browser_observed / id_swap / method_diff /
origin_diff / replay / role_diff / tenant_diff / token_missing / unauth_denied /
version_diff）：

```json
{
  "schema_version": 1, "source": "curl", "generated_at": "2026-10-14T01:16:30+00:00",
  "attempt_id": "unique-attempt-id", "result": "tested_finding",
  "observed_difference": "...", "subject_step": 1,
  "runs": [
    {"url": "http://TARGET/api/Users", "method": "POST", "actor": "anonymous", "variant": "baseline",
     "artifacts": {"request": "evidence/TARGET/x.request.txt", "response": "evidence/TARGET/x.json"}},
    {"url": "http://TARGET/api/Users", "method": "POST", "actor": "anonymous", "variant": "role_diff",
     "artifacts": {"request": "evidence/TARGET/y.request.txt", "response": "evidence/TARGET/y.json"}},
    {"url": "http://TARGET/rest/user/login", "method": "POST", "actor": "owner", "variant": "replay",
     "artifacts": {"request": "evidence/TARGET/z.request.txt", "response": "evidence/TARGET/z.json"}}
  ]
}
```

登记成功后，后续 `handoff --operation-ref` 使用的完整 operation ID 在输出顶层
`store_operation_id`（同 `sync.store.operation_id`）；Candidate 未持久化时先
`python3 tools/target_store.py create-finding --target TARGET --finding-id ID
--endpoint URL --method METHOD --family FAMILY --title T --claim C`（幂等键默认
`create-finding:<finding-id>`，同键不同内容会被拒绝）。

- `generated_at` 写原实验时间，必须含时区；`source` 写实际采集工具。
- Store 目标必须提供真实 `attempt_id`（材料字段或 `--attempt-id`）。小数秒会完整保留；
  同一次登记重试沿用 ID，真实重新执行使用新 ID。
- URL、方法、类别从指定 Finding 读取；`runs` 必须含其精确 endpoint/method 对应的
  执行步骤。多步实验仍选一个 Finding 锚点，其余输入/状态读回/OOB 记录留在同一材料中。
- 每步 `artifacts.request/response` 指向已有、非空、同目标的原始文件；可附加
  `screenshot`、`callback`、`trace` 等引用。登记只保留引用和 SHA-256，不复制原始材料。
  内部 summary 保留精确 URL（参数值、重复参数、编码）；私有身份材料绑定其表示。
  旧去值摘要保持旧表示兼容，不伪造原值，不能代替精确 endpoint 绑定。
  若历史 probe JSON 已同时包含 request/response 且尚未登记，两项可引用同一个原文件；
  使用采集返回的真实路径和原始实验 metadata，不照抄示例路径或另拆文件。
  已有 Store operation 的材料沿用其收据；此入口不转换已登记的 probe attempt。
- `actor` 使用 共享观察角色词汇（如 anonymous/owner/peer/low_role/admin/cross_tenant）；
  锚点步骤必须明确角色。`object_scope`、`variant` 可省略，默认 unknown/replay；
  具体账号、会话和业务条件保留在原始证据，不在摘要中写凭据。
- `result` 是 **AI 对已执行材料的判断**：tested_finding/candidate/tested_clean/dead_end/partial。
  输出固定标注 `assessment_source=ai`、`lane=native_evidence`，不伪装成自动语义判定。
  `tested_finding` 只产生可交给 `/validate` 的 Candidate，七问、四 gate 和报告标准保持不变。
- 已知缺失响应、截断或执行错误必须是 `partial`：保存已获得材料，退出 1，不升级 Finding。
  完整实验至少保留输入/输出，不把截图或假设文字单独当执行证明。
- 发生过状态改变时使用 `--state-changing --redline-checked`，只读实验可用
  `--no-state-changing`；这些记录不追认或扩大原实验的执行许可。
- 同一 attempt/材料重复登记复用 operation/path；Store 事务登记失败时
  返回非零并保留 `sync.status=partial`，修复原因后重跑登记即可，不重发请求。
  绑定 Queue 的执行仍需预先 claim，登记只写观察，继续/停止仍由 Claude resolve。
- 参数/绑定拒绝先判断发生在执行前还是登记阶段。已执行保留原 attempt、时间和原件，仅修正登记；
  未执行不补造原件，未知效果先恢复。读取失败不允许使用旧快照继续。

登记成功后按 `/validate` 的 scaffold → 判断 → preflight → apply 流程继续。
现有 `replayed` 字段表示材料来自已执行实验；此命令本身只做登记，来源由
`native-evidence:<source>` 明确区分。无需修改 witness、报告 schema 或另立生命周期。

### 误建未绑定 Finding 的处置

`review-candidate` 只复核一份 runner 材料。误建的 canonical Finding 另由 Store 处置：
仅限没有观察、裁决、Action 或 Coverage review 绑定的候选，不能撤回已验证/已报告的结论。

```bash
python3 tools/target_store.py dispose-finding --repo-root ROOT --target TARGET --finding-id MISTAKEN_ID \
  --status withdrawn --replacement-id CORRECT_ID --reason '误建身份，实际证据归属 CORRECT_ID' \
  --command-id WITHDRAWAL_ID --actor OPERATOR
python3 tools/target_store.py findings --repo-root ROOT --target TARGET --id MISTAKEN_ID
```

无替代项可省 `--replacement-id`；替代项必须是同 Store 的另一条 active Finding。
原 claim/证据不改，处置不是技术 refuted。活动分页/待验证与 Runner 候选池排除 withdrawn；
不带 `--status` 的 Store 分页及按 ID 查询仍保留历史，`--status active|withdrawn` 在分页前过滤。

显式重开：

```bash
python3 tools/target_store.py dispose-finding --repo-root ROOT --target TARGET --finding-id MISTAKEN_ID \
  --status active --expected-disposition WITHDRAWAL_ID --reason '恢复该主张进行新调查' \
  --command-id REOPEN_ID --actor OPERATOR
```

后续处置需当前精确前驱 ID。同命令/内容重试返回旧回执；错误前驱、同 ID 不同内容、
绑定证据或 Action、外目标/不存在替代项均拒绝。新证据、Action 和验证前必须先重开。
当前 schema 为 v18；旧库可读，新命令会提示显式 `upgrade-schema --backup ABSOLUTE_PRIVATE_BACKUP`，
由已有数据操作授权决定是否升级，不自动迁移或删除候选。

### 候选材料的显式复核

已完成判断的具体候选仍被推荐时，先读取候选池的 `summary_path`、`summary_sha256` 和
实际材料，再显式关闭。不要用 Finding 已报告这一条件批量关闭其它 attempt：

```bash
python3 tools/validation_runner.py review-candidate --repo-root ROOT --target TARGET \
  --summary-json SUMMARY_PATH --expected-summary-sha256 REVIEWED_SHA256 \
  --review-id REVIEW_ID --status closed --reason "已复核并报告，材料无新增" --actor OPERATOR --json
```

返回 `recorded` 或同内容重放的 `already_recorded`；输入/归属/材料冲突退出 2。
同目录 `candidate-review.json` 是此材料复核的唯一 owner，保留事件历史。
收据绑定 Store generation、Finding、attempt、operation、summary 哈希；关闭时检查完整
`artifact_bindings`（含 diff）和登记原始材料。关闭不产生技术阴性、报告资格或 Queue 完成。
新 summary/attempt、Store generation 或附件变化使原关闭失效，并保留可见 `review.status=stale`
及原因；损坏的 Store 或收据仍明确报错。显式 open/stale 不再读取无关旧 assessment 以自动隐藏。

重开使用 `--status open --review-id NEW_ID --expected-review-id PREVIOUS_ID`，以及前一收据中的
`binding.summary_sha256`。这是撤销该收据的关闭，即使旧附件已损坏也可执行；损坏材料仍显示
stale，不能升级为可验证证据。后续再次关闭需重新审阅当前材料，提交当前哈希和最新 review ID。
同 ID 不同内容拒绝；所有后续事件都要求精确前驱。操作不修改 Finding 或报告正文。

### 绑定已认领行动

`record-evidence` 可显式传入 Store execution Action 的 claim：

```bash
python3 tools/validation_runner.py record-evidence --repo-root ROOT --target TARGET \
  --finding-id FINDING_ID --evidence-json /tmp/native-observations.json \
  --action-id ACTION_ID --claim-token CLAIM_TOKEN --actor OPERATOR --json
```

`--actor` 是认领行动的命令操作者，和 `runs[].actor` 的 owner/peer 观察角色分开。
行动 ID 与 token 必须成对提供，endpoint/family 必须一致；错误、过期 claim 或 work
行动在材料发布前拒绝。未绑定调用仍可登记独立实验，不按 endpoint 自动认领。
完整或部分 summary 都保留绑定和操作者，登记失败可用原生入口原 argv 重试，或将已保存
summary 交给 `sync_runner_artifacts(summary, repo_root=...)` 重试登记。
登记重试沿用原 attempt 和执行材料；真实重跑必须分配新 attempt。
登记不完成行动，显式 resolve 使用返回的 `store_operation_id`；partial/unknown 不能完成。

Store 验证的默认正文/延期正文模式、回执与重试见 [validate](../commands/validate.md)；
正文发布和缺稿索引见 [report](../commands/report.md)。两者都不代表外部提交或自动完成 Action。

## 常用 runner

### Native HTTP execution

AI selects the requests, sequence and comparison method using browser, curl or a
suitable raw sender. Preserve each real request and response, then register the
saved material through `record-observation` or `record-evidence` as appropriate.
There is no required pair schema, fixed difference vocabulary or automatic verdict.
The `request-diff` execution entry, dedicated diff modules and `tools/probe.py`
request/ledger wrapper are retired;
existing pair summaries remain readable, reviewable and registration-retryable.

For an experiment to be registered through the native contract, record its unique
attempt ID and original execution time before sending; claim any execution Action
first. Retain that metadata alongside the raw files. A bound parent continuation
requires an executor that enforces its child/parent Scope. The existing shared
HTTP API supports this binding (call from the selected checkout):

```python
from argparse import Namespace
from pathlib import Path
from tools.auth_session import session_from_args
from tools.validation_runner import request_once

root = Path("ROOT").resolve()
session = session_from_args(Namespace(
    target="TARGET", repo_root=root, context_file="CONTEXT"), env={}).bind_target("TARGET")
response = request_once(repo_root=root, target="TARGET", url="https://TARGET/path",
                        session=session, context_file=session.context_file)
```

This API checks child/parent Scope before sending and on each redirect; it follows
allowed redirects. The AuthSession comes only from the bound private source.
The caller reviews side effects before sending and saves `request_text`,
`response_text`, redirect/retention metadata and original execution metadata under
the target's private validation directory before interpreting them. Do not print
credentials. Truncated/error material remains partial. This function performs no
attempt creation, persistence or registration. For byte-exact or stateful
experiments, select a suitable executor; unrestricted shell/browser tools do not
inherit this API's Scope boundary from later registration.

Historical probe calls may already have registered an execution. Use their existing operation
and observation refs directly with Store consumers. `record-evidence` cannot
convert an already registered probe attempt into a Finding witness. Do not issue
another request or invent a new attempt merely to register those same bytes again.

Action Queue's `kind` remains separate from its descriptive `type`:

```bash
python3 tools/action_queue.py --repo-root ROOT add --target TARGET --kind execution \
  --type native-http --metadata-json '{"endpoint":"https://TARGET/path","family":"Authz"}' \
  --evidence "Recorded request observations" --next-question "What does it establish?" \
  --action "Review the execution evidence" --json
```

Execution actions require endpoint/family; ordinary work uses `--kind work` and
omits those fields. Register a bound experiment with its original attempt, claim
and operator through the native evidence contract above. Do not repeat requests
to produce a summary or manufacture a new execution from an existing probe receipt.

### Request smuggling capability gate

`sender_semantics.py --require ...` reports whether a local sender can preserve
the required byte-exact and connection-reuse semantics; the AI builds the raw
probe from the observed wire shape. An unsupported sender capability is a
handoff, not evidence of a vulnerability.

## 相关状态工具

### Target case state

只在 actor/session/object/private marker 连续性有价值时使用。它只保存上下文事实，不保存待办、
不排序路线。对象与归属由 Claude 原生读取材料后判断，再通过显式 Case 命令记录。

```bash
python3 tools/target_case_state.py summary --target <target> --json
python3 tools/target_case_state.py add-actor --target <target> --actor <name> --role <role> [--json]
```

### Evidence ledger

用于查看已记录证据，避免重复验证同一个已经关闭的事实。它是记忆，不是攻击面过滤器。

```bash
python3 tools/evidence_ledger.py summary --target <target>
```

### Checkpoint / action queue

用于长会话收束、恢复、交接。它们给 Claude 提示，不替 Claude 排优先级。

```bash
python3 tools/checkpoint.py --target <target>
python3 tools/action_queue.py list --target <target> --json
python3 tools/action_queue.py claim --target <target> --id <action-id> --actor <operator> --json
python3 tools/action_queue.py resolve --target <target> --id <action-id> \
  --status blocked --notes '<reason>' \
  --store-id <claim.store_id> --expected-version <claim.version> \
  --claim-token <claim.claim_token> --actor <claim.claimed_by> --json
```

Checkpoint 只展示 Store 中的未决工作和原始候选；AI 显式 add/claim/resolve。
不会自动提案入队、覆写 Coverage 或补出下一条行动。完成必须引用本次 claim 的 operation、工作产物或领域收据。

保留**本次** claim 的完整 JSON 回执：`target`、`store_id`、`id`、`version`、
`claim_token`、`claimed_by`。上例占位符都取同一回执，不能在 resolve 前重新 claim/list
来补齐旧命令身份。`--actor`、`--store-id`、`--expected-version` 必填；已领取工作还须
原 `--claim-token`。未领取的管理转换使用调用者显式取得的 list 快照，不伪造 token。
同一 Store、输入和完成证明仍通过现有校验时，已提交同身份同内容重放返回原回执；
证明原件缺失、变化或失效仍可拒绝。尚未提交的迟到旧命令拒绝，不结算后来领取的工作。
返回的 `resolved_from` / `receipt` 描述原命令，不是当前 Action 的新视图。
