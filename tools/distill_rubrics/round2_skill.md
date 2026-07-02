# Distill Round 2 — Skill 价值判断 rubric

> `/distill` 第二轮。只对第一轮 `保留` 的报告运行。判断这条知识**值不值得
> 固化成知识卡**，还是 Claude 已经会了（天花板效应）。工具不判断——判断是
> Claude 的推理工作。

## 角色

你是一位安全知识工程专家，擅长判断哪些知识值得固化为知识卡，哪些只需一次性
Prompt 引导。判断标准：稀缺性、高频性、可迁移性、来源质量。

## 三层决策标准（核心）

| 条件 | 处理方式 |
|---|---|
| AI 不知道 + 频繁遇到 | 写成知识卡（worth_skill = true） |
| AI 不知道 + 极少遇到 | Prompt 引导即可（worth_skill = false） |
| AI 知道但不系统 | 可写卡，提供系统化顺序与决策树 |

## is_ai_likely_known 判断依据（天花板检测）

- 训练数据是否常见？
- Google 前五条能否解释清楚？（能 → AI 大概率已知，不用写卡）
- 是否只需直接提问就能答对？
- 知识截止后公开发表 → 大概率不知道
- 仅某研究者单篇博客提过 → 大概率不知道
- 系统性组合利用链 → 模型通常不掌握完整步骤

**这一步和本仓库已有的 A/B 天花板效应结论一致：模型已掌握的通用方法论，
写进卡片是零增量。真正值得写的是稀缺、可迁移、模型尚不具备的特殊思路。**

## 评估维度

- `is_ai_likely_known`：true / false
- `scene_frequency`：高频 / 中频 / 低频
- `migration_potential`：高 / 中 / 低（能否跨场景复用）
- `source_quality`：高 / 中 / 通用

## 输出格式

严格输出 JSON，不要额外解释。字段名对齐 `tools/distill_reports.py --ingest` 的
消费契约（`ingest_candidates`）。

```json
{
  "candidates": [
    {
      "knowledge_point": "Java Ghost Bits 绕过",
      "card_title": "Java Ghost Bits 语义差绕过",
      "source_report_ids": [838510],
      "value_score": 8,
      "verdict": "保留，高优先级",
      "category": "框架行为利用",
      "is_ai_likely_known": false,
      "scene_frequency": "高频",
      "migration_potential": "高",
      "source_quality": "高",
      "worth_skill": true,
      "applies_when": ["char 转 byte 的输入处理", "安全检查与执行视图分离"],
      "trigger_signals": ["(byte)ch 或 &0xFF 截断", "Unicode 高字节被静默丢弃"],
      "divergent_questions": ["原始 Unicode / 低 8 位字节 / 协议解析三者是否一致？"],
      "recommended_actions": ["拆三视图对比，找语义差"],
      "related_skills": ["web2-vuln-classes", "security-arsenal"],
      "stop_conditions": ["无 char->byte 截断路径", "检查与执行在同一视图"],
      "validation_requirements": ["需可 replay 请求 + 明确的视图不一致证据"],
      "promotable_experience": ["某框架反复出现视图分离时优先测此模式"]
    }
  ]
}
```

## worth_skill = false 时怎么写

- `worth_skill: false` 且 `suggested_handling` 说明如何处理：
  通用 Prompt 即可 / Prompt 引导即可 / 合并到更上层的系统卡中。
- 此时可省略卡片正文字段（`applies_when` 等）。

## 卡片字段纪律（对齐 knowledge/card-template.md 与 promotion-rules.md）

- 写思路，不写大段 payload。
- 写触发信号，不写空泛教程。
- 写停止条件，避免知识库只扩散不收敛。
- 写检查要求，确保输出能回到验证 gate。
- `related_skills` 从现有 skill 名中选：`bb-methodology` / `web2-vuln-classes` /
  `web2-recon` / `triage-validation` / `security-arsenal` 等。

## 不应产出为卡片（promotion-rules.md 的"不应晋升"）

- 只属于单个目标的临时线索
- 未经验证的漏洞结论
- 真实 token / cookie / 密钥 / 个人数据 / 客户数据
- 大段扫描输出、HTML、响应包
- 明确属于红线层的规则
- 会诱导无差别 payload spray 的内容

## 产出后的流向

`worth_skill = true` 的候选经 `--ingest` 写入 `knowledge/candidates/`（复核队列），
**不直接进 `knowledge/cards/`**。人工复核后经 `/kb promote` 才迁入正式卡片。
