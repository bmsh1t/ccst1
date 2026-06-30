# 分阶段攻击面验证计划模板

用途：把一次目标特定实战脚本里的“阶段划分、证据门槛、停止条件”沉淀成通用计划，而不是把目标域名、payload 或高风险动作直接写入工具链。

## 使用原则

- 这是计划模板，不是自动执行器。
- 所有目标、端点、actor、凭据、payload 都必须来自当前目标的 `surface`、`checkpoint`、`coverage_matrix`、`action_queue` 或人工确认。
- 默认只做只读、低影响验证；任何写操作、登录尝试、状态改变、批量枚举、明显高风险 payload 都必须先形成 `unsafe-skipped-review` 或明确人工授权。
- 每个阶段结束后先回写证据和队列状态，再进入下一阶段。

## 输入

```text
target: <target>
storage_key: <state/findings storage key>
auth_context: <none | guest | user | admin | custom actor>
scope_boundary: <program/scope note>
source_artifacts:
  - findings/<target>/manual_review/unsafe_skipped.txt
  - evidence/<target>/coverage_matrix.json
  - state/<target>/action_queue.json
  - recon/<target>/...
```

## 阶段 0：前置检查

目标：确认当前测试是否应该继续，而不是盲目运行脚本。

检查项：

```text
- scope 是否明确
- auth actor 是否明确
- 是否存在未处理 unsafe-skipped-review
- action_queue 是否已有更高优先级任务
- coverage_matrix 是否已有同类 resolved 记录
- 当前目标是否处于 WAF / rate-limit / lockout / guard 状态
```

输出：

```text
continue | checkpoint | blocked | needs-operator-approval
```

## 阶段 1：低风险只读验证

目标：收集可复核证据，不改变远端状态。

适合动作：

```text
- GET/HEAD 只读端点确认
- API 文档 / OpenAPI / Postman collection 审阅
- JS endpoint / parameter / route 复核
- 公开版本、插件、组件信息确认
- 对同 endpoint family 的状态码/响应长度/内容类型差异做小样本对比
```

禁止直接做：

```text
- 登录尝试
- 写入、删除、上传、修改状态
- 大范围枚举
- 时间延迟型 payload
- OOB/SSRF/RCE 类高影响验证
```

证据回写：

```text
- coverage-gap: resolve 后写 coverage_matrix
- weak signal: 只写 evidence ledger 或 action_queue lead，不写 validated finding
- unsafe lane: 写入/保留 unsafe_skipped-review，不伪装成 tested_clean
```

## 阶段 2：中风险聚焦验证

进入条件：

```text
- 阶段 1 已产生明确 next_question
- actor / endpoint family / vuln_class 已明确
- action_queue 中有对应 queued item
- 不需要默认凭据、批量枚举或状态改变；否则停在 checkpoint
```

适合动作：

```text
- 小样本 IDOR/BOLA 对比
- 参数边界对比
- 导出/分页接口的只读差异验证
- 插件/组件版本与已知 CVE 的被动关联
- secret triage 的 redacted / hash 化验证记录
```

输出状态：

```text
tested | dead-end | blocked | candidate | validated | n/a
```

回写要求：

```text
- 必须引用 source artifact
- 必须有 stable id 或 endpoint+vuln_class metadata
- 不能把 candidate 写成 validated
- 不能把 blocked 写成 tested_clean
```

## 阶段 3：高风险验证门槛

进入条件：

```text
- 明确授权
- 明确停止条件
- 明确回滚/影响控制策略
- 已经在 action_queue 中标记 redline_required
```

高风险示例：

```text
- POST/PUT/PATCH/DELETE 状态改变
- 上传 canary
- 登录/默认凭据尝试
- 时间延迟型 SQLi
- XXE 文件读取
- SSRF/OOB/RCE 类验证
```

默认行为：

```text
不自动执行，进入 unsafe-skipped-review 或 checkpoint。
```

## 阶段结束检查

每个阶段结束都要回答：

```text
1. 本阶段新增了什么证据？
2. 哪些 action_queue item 被 resolve？
3. 是否需要写 coverage_matrix / unsafe_skipped_reviews / secret_verifications？
4. 是否产生新 unsafe-skipped lead？
5. 是否需要 checkpoint，而不是继续深入？
```

## 禁止沉淀为通用能力的内容

```text
- 目标域名硬编码
- 目标专属路径列表
- 默认凭据列表
- 未确认授权的主动攻击 payload
- 绕过 WAF/冷却后继续打的目标特定流程
- 无 source artifact 的自然语言结论
```
