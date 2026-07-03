# Target Case State v1 规划

## 1. 目标

把项目从“发现 endpoint 后临时重新思考怎么验证”，升级为：

```text
目标状态已知 → 自动知道用哪个 actor/session/object → 生成下一条验证动作
```

该能力服务于实战中最常见、最高价值的状态型漏洞：

- IDOR / BOLA
- 订单、地址、发票、报表等数据泄露
- 组织 / 租户越权
- 权限绕过
- 业务逻辑状态绕过

核心判断：

```text
Validation Runner 解决“怎么验证”
Target Case State 解决“下一步拿谁验证什么”
```

关键要求：

```text
Target Case State 不能把 AI 降级成固定扫描器。
它必须让 AI 更聪明地组合 actor / session / object / evidence，
从而挖掘复杂攻击链，并高效选择下一条最高价值验证动作。
```

## 2. 为什么不放进 skills / knowledge

当前 skills / knowledge 已经覆盖通用经验：

- IDOR/BOLA 判断规则
- 两账号验证原则
- actor/object/replay evidence gate
- checkpoint next action
- validation runner 执行方式

但它们不应该保存目标运行时状态，例如：

- `user_a` / `user_b` 是谁
- 哪个 session 属于哪个 actor
- 哪个 order / address / invoice 属于谁
- private marker 是什么
- 哪个 backlog 正在等待验证

这些是目标专属、运行时、可能敏感的数据。正确归属是：

```text
skills / knowledge = 通用经验、判断规则、bypass 技巧
state/<target>/case_state.json = 当前目标的临时实战状态
```

## 3. 架构定位

不新增第 5 层主记忆。Target Case State 是现有 4 层里的 Target Memory 增强。

```text
Core 4 Layers:
1. Target Memory
2. Skill Orchestration
3. Knowledge Library
4. Check Gates

Cross-cutting Planes:
A. Evidence / Execution Plane
B. Learning / Promotion Plane
```

本规划落点：

```text
Target Memory 增强
  + Evidence Runner 输入来源
  + Checkpoint 下一步编排来源
```

## 4. AI 优势必须被显式利用

该模块不是 checklist，也不是“把 IDOR 测一遍”的固定扫描器。它的价值是给 AI
提供结构化状态，让 AI 做人类高级猎人的事情：

1. **攻击链联想**
   - 从 source map / hidden API / browser XHR 推出 authz / IDOR / export / report 链。
   - 从普通对象读取扩展到批量导出、报表、发票、组织成员、invite、admin-like workflow。
   - 从信息泄露连接到 token / object id / tenant id / GraphQL node id / internal route。

2. **跨证据组合**
   - 结合 `recon/`、`browser/`、`findings/`、`memory/evidence/ledger.jsonl`、`case_state.json`。
   - 识别“单点看似低危，但组合后能进入高价值链”的路径。
   - 把 scanner-negative 结果、actor matrix gap、source hints 组合成下一条验证动作。

3. **动态优先级判断**
   - 优先选择能最大化影响证明的 actor/object/session 组合。
   - 不按列表顺序机械测试，而是按“可验证性 × 影响 × 新信息增益 × 风险成本”排序。
   - 对已经 dead-end 的 lane 自动降权，对新发现的 connector 自动升权。

4. **假设升级 / 降级**
   - peer 403/404 → 不是结束；AI 应判断是否存在 alternate endpoint、bulk export、GraphQL node、mobile API、versioned API。
   - peer 200 但无 private marker → 不是直接报漏洞；先降为 candidate，寻找私有字段、对象差异或第二对象确认。
   - anonymous config leak → 判断是否能连接 OAuth redirect、client id、tenant discovery、internal API。

5. **最小高价值验证**
   - 工具只执行 replay / diff / evidence / ledger。
   - AI 选择“最小但最能证明链路”的验证动作。
   - 避免大字典、盲扫、重复跑已覆盖组合。

因此 `next` 输出不能只返回一个命令；至少要包含：

```json
{
  "hypothesis": "peer user_b may read order_123 owned by user_a via order API",
  "chain_context": [
    "browser observed owner order endpoint",
    "object has private email marker",
    "actor matrix lacks peer/id_swap coverage"
  ],
  "why_now": "high impact, all required sessions exist, exact runner available",
  "runner": "idor-actor-pair",
  "command": "python3 tools/validation_runner.py ...",
  "required_evidence": ["owner session", "peer session", "private marker"],
  "downgrade_rule": "peer denied or no private marker",
  "chain_extensions_if_blocked": [
    "try export/report endpoint for same object",
    "try mobile/versioned API path",
    "try GraphQL node/global id if discovered"
  ],
  "write_back": "complete-backlog val_001 with tested_finding/tested_clean/candidate"
}
```

## 5. 新增文件

```text
tools/target_case_state.py
tests/test_target_case_state.py
```

运行时状态文件：

```text
state/<target_key>/case_state.json
```

`state/` 是本地 runtime 目录，不应发布，不应进入知识库。

## 6. case_state.json v1 数据结构

```json
{
  "schema_version": 1,
  "target": "https://example.com",
  "target_key": "https:_example.com",
  "updated_at": "2026-07-03T00:00:00Z",

  "actors": {
    "user_a": {
      "role": "user",
      "label": "owner test account",
      "notes": "",
      "created_at": "2026-07-03T00:00:00Z",
      "last_seen": "2026-07-03T00:00:00Z"
    }
  },

  "sessions": {
    "sess_user_a": {
      "actor": "user_a",
      "kind": "bearer",
      "header_name": "Authorization",
      "header_value": "Bearer ...",
      "source": "manual",
      "validity": "unknown",
      "last_checked": "",
      "notes": ""
    }
  },

  "objects": {
    "order_123": {
      "type": "order",
      "object_id": "123",
      "owner_actor": "user_a",
      "endpoint": "https://example.com/api/orders/123",
      "private_marker": "user_a@example.com",
      "status": "active",
      "notes": ""
    }
  },

  "hypotheses": [
    {
      "id": "hyp_001",
      "vuln_class": "IDOR",
      "endpoint": "https://example.com/api/orders/123",
      "object_ref": "order_123",
      "actors": ["user_a", "user_b"],
      "status": "open",
      "why_now": "owner object endpoint found in browser traffic",
      "next_action": "Run idor-actor-pair",
      "created_at": "2026-07-03T00:00:00Z"
    }
  ],

  "validation_backlog": [
    {
      "id": "val_001",
      "runner": "idor-actor-pair",
      "endpoint": "https://example.com/api/orders/123",
      "owner_actor": "user_a",
      "peer_actor": "user_b",
      "object_ref": "order_123",
      "status": "pending",
      "priority": "high",
      "required_evidence": [
        "owner session",
        "peer session",
        "owner private marker"
      ],
      "stop_condition": "peer 403/404 or no private marker",
      "chain_extensions_if_blocked": [
        "try export/report endpoint for same object",
        "try GraphQL node/global id if discovered",
        "try mobile/versioned API equivalent"
      ],
      "created_at": "2026-07-03T00:00:00Z"
    }
  ]
}
```

## 7. CLI 设计

### 7.1 summary

```bash
python3 tools/target_case_state.py summary --target <target>
```

输出目标：

```text
Actors: 2
Sessions: 2
Objects: 3
Open hypotheses: 4
Pending validation backlog: 2
Top next action: idor-actor-pair order_123 user_a -> user_b
```

### 7.2 add-actor

```bash
python3 tools/target_case_state.py add-actor \
  --target <target> \
  --actor user_a \
  --role user \
  --label "owner test account"
```

角色建议枚举：

```text
anonymous
user
low_role
admin_like
service
unknown
```

### 7.3 add-session

```bash
python3 tools/target_case_state.py add-session \
  --target <target> \
  --session sess_user_a \
  --actor user_a \
  --kind bearer \
  --header-name Authorization \
  --header-value "Bearer xxx"
```

session 类型：

```text
cookie
bearer
browser_state
api_key
custom_header
unknown
```

### 7.4 add-object

```bash
python3 tools/target_case_state.py add-object \
  --target <target> \
  --object order_123 \
  --type order \
  --object-id 123 \
  --owner-actor user_a \
  --endpoint https://example.com/api/orders/123 \
  --private-marker user_a@example.com
```

object 类型不强制枚举，但优先覆盖：

```text
order
address
invoice
cart
report
profile
file
message
workspace
organization
```

### 7.5 add-hypothesis

```bash
python3 tools/target_case_state.py add-hypothesis \
  --target <target> \
  --vuln-class IDOR \
  --endpoint https://example.com/api/orders/123 \
  --object-ref order_123 \
  --actor user_a \
  --actor user_b \
  --why-now "browser observed owner order endpoint"
```

### 7.6 add-backlog

```bash
python3 tools/target_case_state.py add-backlog \
  --target <target> \
  --runner idor-actor-pair \
  --endpoint https://example.com/api/orders/123 \
  --owner-actor user_a \
  --peer-actor user_b \
  --object-ref order_123 \
  --priority high
```

### 7.7 next

```bash
python3 tools/target_case_state.py next --target <target>
```

输出结构化 JSON：

```json
{
  "next_action": "run_validation_runner",
  "hypothesis": "peer user_b may access order_123 owned by user_a",
  "why_now": "all required actor/session/object evidence exists and actor matrix gap is high-value",
  "runner": "idor-actor-pair",
  "endpoint": "https://example.com/api/orders/123",
  "owner_actor": "user_a",
  "peer_actor": "user_b",
  "object_ref": "order_123",
  "command": "python3 tools/validation_runner.py idor-actor-pair ...",
  "required_evidence": ["owner session", "peer session", "owner private marker"],
  "downgrade_rule": "peer 403/404 or no owner-private marker",
  "stop_condition": "peer 403/404 or no owner-private marker",
  "chain_extensions_if_blocked": [
    "try export/report endpoint",
    "try GraphQL node/global id",
    "try mobile/versioned API equivalent"
  ],
  "write_back": "complete-backlog val_001 after runner result"
}
```

### 7.8 complete-backlog

```bash
python3 tools/target_case_state.py complete-backlog \
  --target <target> \
  --id val_001 \
  --result tested_finding \
  --evidence-ref evidence/<target>/validation/<finding-id>/summary.json
```

backlog 状态枚举：

```text
pending
running
tested_clean
tested_finding
candidate
blocked
dead_end
```

## 8. 优先级与 next 选择模型

`next` 不应简单取第一条 backlog。应按实战价值排序：

```text
score =
  impact_weight
  + evidence_readiness
  + chain_potential
  + novelty_gain
  - risk_cost
  - already_tested_penalty
```

建议 v1 使用可解释字段，而不是复杂黑箱模型：

| 因子 | 含义 |
|---|---|
| `impact_weight` | order/invoice/report/admin/workspace 高于普通 profile |
| `evidence_readiness` | owner session、peer session、object endpoint、private marker 是否齐全 |
| `chain_potential` | 是否能连接 export、GraphQL、mobile API、tenant/org、admin-like workflow |
| `novelty_gain` | 是否覆盖新的 actor/object/lane 组合 |
| `risk_cost` | 是否状态改变、是否需要写入、是否可能影响真实订单/支付 |
| `already_tested_penalty` | ledger/case_state 已测过则降权 |

输出必须解释：

```text
为什么现在测它？
为什么不是测别的？
如果失败，下一条链路是什么？
```

## 9. Validation Runner 集成规划

当前已有 runner lane：

```text
authz-public-exposure
sqli-result-diff
marker-replay
idor-actor-pair
idor-skeleton
```

目标增强：

```bash
python3 tools/validation_runner.py idor-actor-pair \
  --target <target> \
  --owner-actor user_a \
  --peer-actor user_b \
  --object-ref order_123 \
  --from-case-state
```

自动读取：

```text
owner session header
peer session header
object endpoint
private marker
```

等价于手工提供：

```bash
--url ...
--owner-header ...
--peer-header ...
--expect-marker ...
```

## 10. Checkpoint 集成规划

checkpoint 读取：

```bash
python3 tools/target_case_state.py summary --target <target>
python3 tools/target_case_state.py next --target <target>
```

输出应包含：

```text
Hypothesis:
  Peer user_b may access order_123 owned by user_a.

Why now:
  Browser observed owner order endpoint and object has private marker.

Exact replay draft:
  python3 tools/validation_runner.py idor-actor-pair --from-case-state ...

Required evidence:
  owner session, peer session, private marker

Downgrade rule:
  peer 403/404 or response lacks private marker

Stop condition:
  same as above

Write-back:
  update backlog val_001 -> tested_finding / tested_clean / candidate
```

## 11. 分阶段实施

### Phase A：独立状态工具

状态：已实施。

范围：

```text
tools/target_case_state.py
tests/test_target_case_state.py
```

不改 validation runner，不改 checkpoint。

成功标准：

```text
case_state.json 能稳定 CRUD
next 能输出结构化下一步
测试全绿
```

已验证：

```text
tools/target_case_state.py
tests/test_target_case_state.py
本地 Juice Shop 目标 case_state CLI smoke：
  add-actor → add-session → add-object → add-backlog → next → validation_runner → complete-backlog
```

### Phase B：接入 validation_runner

范围：

```text
tools/validation_runner.py
tests/test_validation_runner.py
```

新增参数：

```text
--from-case-state
--owner-actor
--peer-actor
--object-ref
```

成功标准：

```text
idor-actor-pair 可以不手写 token/header/object URL
```

### Phase C：接入 checkpoint

范围：

```text
tools/checkpoint.py
tests/test_checkpoint.py
commands/checkpoint.md
```

成功标准：

```text
checkpoint 能优先输出 case_state backlog 的 exact runner command
```

### Phase D：文档和规则

范围：

```text
commands/validate.md
commands/autopilot.md
rules/hunting.md
.trellis/spec/backend/quality-guidelines.md
```

成功标准：

```text
Claude CLI / autopilot 知道什么时候用 case_state
```

## 12. 测试规划

新增：

```text
tests/test_target_case_state.py
```

覆盖：

1. 初始化空 state
2. add actor
3. add session
4. add object
5. add hypothesis
6. add backlog
7. next 返回最高优先级 backlog
8. 缺 session 时 next 给 blocked reason
9. 缺 object private marker 时返回 `candidate_ready=false`
10. complete-backlog 写回状态
11. next 解释 `why_now`、`downgrade_rule`、`chain_extensions_if_blocked`
12. 已测过的 actor/object/lane 组合降权

增强：

```text
tests/test_validation_runner.py
```

覆盖：

1. `idor-actor-pair --from-case-state`
2. owner/peer header 自动加载
3. object endpoint 自动加载
4. marker 自动加载
5. 缺 actor/session/object 时 fail-fast

增强：

```text
tests/test_checkpoint.py
```

覆盖：

1. checkpoint 输出 case_state next action
2. 有 backlog 时优先使用 backlog
3. 没 backlog 时保留原有 coverage/ledger gap 逻辑

## 13. 不做范围

第一版不做：

```text
自动登录
自动刷新 session
浏览器 profile 管理
复杂权限图谱
多租户完整建模
token 加密存储
UI
大型数据库
```

只做本地 JSON 状态机。

## 14. 最终验收标准

必须满足：

1. 能登记 `user_a` / `user_b`
2. 能登记两个 session
3. 能登记 `order_123` 属于 `user_a`
4. 能生成 `idor-actor-pair` runner 命令
5. 能执行后写回 backlog 状态
6. checkpoint 能提示下一步
7. 全量 pytest 通过
8. 不影响现有 validation runner
9. 不把 target-specific state 提交进 git
10. `next` 输出不是 checklist，而是带 hypothesis / why_now / exact replay / downgrade / chain extension 的 AI 编排动作
11. 失败后能给出聪明的替代链路，而不是机械停止

## 15. 推荐执行顺序

先做 Phase A。

原因：

- 最小可回退
- 不影响现有稳定链路
- 可以先验证状态模型是否真的好用
- 后续再接 validation runner / checkpoint

如果 Phase A 做完发现实际输出没价值，则停止，不继续扩大。
