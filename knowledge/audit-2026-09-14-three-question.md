# 知识卡存量审计 — 三问试金石（2026-09-14）

> 判定框架：每卡过三问（模型见过吗 / 从当前证据可推理吗 / 需要真实成本才知道吗）。
> 关键判据：这些卡的身份行是**触发信号 + 边界条件 + 停止条件**（决策契约），
> 不是漏洞教学（模型常识）。触发卡的价值不在"教模型 SQLi 是什么"，在
> "什么信号该进入这条 lane、什么证据算够、什么时候停"。
> 0 张卡有 pull 记录（pull-log 2026-09-14 才建立）——本审计是唯一判据。

## 判定分布

| 判定 | 数量 | 说明 |
|---|---|---|
| keep | 52 | 触发信号 + 停止条件是真决策契约（Skill 层的案例级延伸） |
| retire | 3 | 三问不过：内容是模型常识或通用工作流，无真实成本增量 |
| borderline | 5 | 契约价值真实但存在与 Skill 重叠/失效风险，观察至有 pull 数据 |

> 复审修正（写报告后逐卡复看原文）：`coverage-prompts` 初判 retire 有误。
> 其内容不是"覆盖率数据"（那确实是机械输出），而是**覆盖维度的发散清单**
> （API 不只测 detail 还有 export/share/invite/bulk；权限不只 4 角色还有
> 过期 token/权限变更后旧 session）——这是"容易漏掉的面"的经验沉淀，
> 模型不提示时会漏（三问③），且明确声明"不是强制全测清单"。改判 keep。

## retire（3 张）—— 建议退役

| 卡 | 理由 |
|---|---|
| `api-testing-workflow` | "API testing 不是只扫 /api/，要合并 docs/JS/XHR/mobile"——通用方法论，模型常识（①），任何合格模型做 API 测试都会这么做（②）。无边界条件、无停止条件、无踩坑增量。 |
| `rest-basket` | "GET /rest/<resource>/<numeric-id> 无 Authorization 仍 200"——这是 juice-shop 单目标的具体观察（公开靶场，模型见过①），且其一般形态已被 `rest-numeric-id-cross-actor` 完整覆盖（触发/边界/反例俱全）。双卡重复，留后者的泛化版。 |
| `dead-ends` | 触发="线索只有关键词/低置信扫描"——这是 triage-validation Skill 的 noise 分类的子集（已有 precondition-unrealistic / information-only 分类）。三问：分类规则模型可推理（②），无独立增量。**例外**：若卡内含具体死路案例（真实目标踩坑），把案例迁入 case corpus 后再 retire。 |

## borderline（5 张）—— 观察至有 pull 数据

| 卡 | 保留理由 | 风险 |
|---|---|---|
| `path-pattern-management-exposure` | "命名规律反哺发现"的信号清单有真实增量 | 清单可能过时（命名习惯演化）；无停止条件 |
| `public-package-artifact-intelligence` | 触发条件（lockfile/SBOM/镜像信号）具体 | 与 intel 命令的 component-intelligence 职责重叠 |
| `wordpress-surface-intelligence` | WP 特定面（wp-json/admin-ajax/wp-content）信号具体 | WP 生态模型训练数据极多（①边缘）；版本情报时效性强，卡内静态清单会腐 |
| `cdn-response-differential` | CDN/源站差分的判别方法有真实操作增量 | 属于方法论边缘；若无具体判别特征则滑向常识 |
| `custom-protocol-state-recovery` | "输入必须有 PCAP/来源"的边界有效 | 过窄，更像一条 rule 而非卡；若 12 个月无 pull 则 retire |

## keep（52 张）—— 三问通过

通过形态分三类（抽样列理由，全量不重复）：

**A. 触发信号卡（lane 入口条件）**——什么信号进什么 lane，这是 Skill
router 的案例级扩展，Skill 12 个不可能覆盖 60 类具体信号：
`api-idor`（多账号/租户边界信号）、`graphql`（global ID/subscription）、
`grpc-api-boundaries`（trailers/protobuf/reflection）、`odata-query-boundaries`
（$metadata/$filter 信号）、`ldap-xpath-query-boundaries`、`websocket-realtime-api`
（握手 vs 消息级权限区分）、`xs-leak-oracle`（时间/大小 oracle）。

**B. 边界/反例卡（停止条件）**——真实成本换来的"别掉进去"：
`business-logic-state-machines`（先还原状态机再找缺校验——payload 优先是死路）、
`node-prototype-pollution`（不是固定打 __proto__，先找 merge/clone sink）、
`xss-client-injection`（先识别输出位置/编码层，不是固定打 script 标签）、
`xxe-xml-parser`（关键不是有 XML 字符串而是 parser 处理 DTD——直接反直觉）、
`proxy-cache-boundaries`（先建模链路再上 payload）、`view-differential`
（校验视图≠执行视图——踩过才知道的坑）。

**C. 高价值链路卡（影响证明路径）**——什么算够证据：
`controlled-rce-impact`（受控影响证明的边界）、`ssrf-internal-impact`
（callback 只是入口，高价值在内部身份/链式影响）、`upload-to-execution`
（上传后是否被执行才是关键，不只扩展名绕过）、`information-disclosure-source-config`
（泄露本身不是终点，价值在能否链到下一步）。

**D. 案例蒸馏卡（实战验证过的形态）**——`rest-numeric-id-cross-actor`
（maturity tested，juice-shop 验证过的泛化形态：anonymous 401 但
owner/peer 同 body——触发/边界/反例/最小验证俱全，含 digest 溯源）、
`auth-credential-recovery-flows`（reset token 绑定关系建模）、
`stale-derived-authz`（权限变更后旧 token 不失效）、
`payment-callback-idempotency`（回调签名绑定与幂等）。

## 执行说明

- retire 3 张需人裁决后执行：`python3 tools/knowledge_retire.py --id <slug> --reason "<三问结论>"`
- borderline 5 张不 retire，等待 pull 数据（2026-09-14 起 pull-log 开始积累）
- `dead-ends` retire 前先确认案例迁移（如有）
- 下一轮 review 周期建议：首次 pull 数据积累 30 天后
