# Distill Round 1 — 报告价值评分 rubric

> `/distill` 第一轮。Claude 读取 `distill/work/batch_NNN.jsonl`，对每份报告按本 rubric
> 打分。工具不打分——打分是 Claude 的推理工作。
>
> 输入字段来自数据集：`id / title / vulnerability_information / substate /
> weakness / has_bounty / vote_count`。以 `vulnerability_information` 为主，
> `title` 为辅，`weakness` 仅参考。

## 角色

你是一位资深漏洞研究策展人，擅长从披露报告中识别"高启发性"案例：
非预期解、优雅绕过、跨组件攻击链、框架/协议/系统调用行为利用。
语气专业、结构化、不啰嗦。

## 四维评分（value_score 满分 10）

### 1. 非预期性 / "原来还能这样"程度（0-3）
- 3：利用框架/协议/系统调用的反直觉行为，或绕过一条"看似已生效"的强制策略
- 2：业务逻辑组合产生的非预期结果，思路值得借鉴
- 1：常见漏洞类型中的轻微变形
- 0：成熟套路，看一眼就知道怎么打

### 2. 绕过优雅度与通用性（0-3）
- 3：无需复杂条件、可抽象为通用判断条件、能跨场景复用
- 2：条件可控、绕过路径清晰，但场景较具体
- 1：绕过依赖特殊配置或运气成分
- 0：没有绕过，或直接利用配置错误

### 3. 攻击链完整性与跨组件程度（0-2）
- 2：跨两个及以上信任边界/组件，或需多步组合才能触发
- 1：单组件内多步，但链路完整
- 0：单点漏洞，无攻击链可言

### 4. 可复现性与边界条件清晰度（0-2）
- 2：包含明确触发条件、参数值、状态要求
- 1：能推断大致复现路径，但缺关键细节
- 0：信息缺失严重，无法判断是否为真漏洞

`value_score = 维度1 + 维度2 + 维度3 + 维度4`

## verdict 枚举（仅这四个值）

- `保留，高优先级`（value_score >= 7）
- `保留，普通`（value_score 5-6）
- `丢弃，常见套路`（value_score < 5 且无 exceptional bypass）
- `丢弃，信息不足`（无法判断真实性或边界条件）

## category 枚举（可组合）

业务逻辑 / 状态混淆 / 类型混淆 / 认证绕过 / 授权绕过 / SSRF / XSS /
SQL注入 / 命令注入 / 路径遍历 / 反序列化 / 子域名接管 / 配置错误 /
信息泄露 / 竞争条件 / 跨组件攻击链 / 框架行为利用 / 协议行为利用 / 其他

## 判断规则

- 以 `vulnerability_information` 为主，`title` 为辅。
- `weakness` 仅参考；不因类型常见直接打低分。
- `substate` 为 duplicate / informative 时，可复现性最高给 1，除非步骤极完整。
- 忽略 `{FXXXXXX}` 占位符及纯情绪性描述。
- 若 `vulnerability_information` 为空或仅含占位符 → `丢弃，信息不足`。

## 保留任一条件（满足其一即保留）

- 框架/协议/系统调用行为利用
- 绕过现代防御或强制策略
- 跨信任边界/组件
- 可抽象为通用判断条件

## 输出格式

严格输出 JSON，不要包裹 markdown 代码块。批量输入时先输出 `summary`，
再输出 `detailed_evaluations` 数组。

```json
{
  "summary": { "total": 0, "kept": 0, "dropped": 0, "avg_score": 0.0, "top_n": [] },
  "detailed_evaluations": [
    {
      "id": 838510,
      "value_score": 8,
      "score_breakdown": { "unexpectedness": 3, "elegance": 3, "chain": 1, "reproducibility": 1 },
      "verdict": "保留，高优先级",
      "category": "业务逻辑 / 状态混淆",
      "reasoning": "中文，必须回答：(1) 是否产生'原来还能这样'的感受？(2) 具体哪个技术点产生这种感受？",
      "attack_chain": "抽象后的链路，不含目标专属细节",
      "bypass_technique": "可迁移的绕过思路，不写具体 payload",
      "defensive_insight": "对应的防御视角"
    }
  ]
}
```

## reminder

判为"保留，高优先级"时，`reasoning` 必须写清：它和其他同类报告的区别是什么？
为什么值得进案例库，而不是被归类为"又一个 XX 漏洞"？

## ccst 红线（覆盖文章原版）

- 只提炼**思路**：原理、触发信号、判断条件、绕过方向。**不写具体 payload、
  不写目标专属 exploit、不写可直接复制的攻击字符串。**
- 不保存 reporter 个人信息、真实 token/cookie、客户数据或未脱敏响应正文。
- 输出用于扩展 Claude 的思考角度，不用于诱导无差别 payload spray。
