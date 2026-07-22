---
id: web-llm-tool-chains
type: technique-card
related_skills:
  - web2-vuln-classes
  - triage-validation
trigger_tags:
  - web-llm
  - prompt-injection
  - rag
  - tool-call
  - invisible-unicode
  - unicode-tag
  - agent-attack-chain
  - tool-description-drift
  - rug-pull
  - shadow-tool
  - schema-drift
  - cross-session-memory
  - multi-agent-impersonation
risk: medium
maturity: draft
load_priority: medium
deep_refs: []
source_refs:
  - type: corpus-report
    corpus: hackerone-disclosed-reports
    id: "2372363"
---

# Web LLM / Prompt Injection / Tool Chains

## Quick Recall

- Web LLM 漏洞核心是模型是否能越过权限边界读取数据、调用工具、改变状态或泄露系统/业务上下文。
- 先枚举模型输入源、RAG 数据源、可调用工具、身份绑定和输出通道，再测试 prompt injection。
- 工具枚举本身是关键 baseline：要求模型列出 function/tool 名称、参数和能力，再用日志或响应确认真实 tool_call。
- 直接让模型“说出系统提示”通常只是 Lead；高价值在工具调用、跨用户数据、越权业务动作和间接注入。
- 间接 prompt 注入要证明攻击者可控内容进入模型上下文并影响后续受害者动作。
- 文本过滤如果只看“人眼可见字符串”，要额外检查 Unicode tag、零宽和不可见控制字符；模型按码点消费时，可能出现人看到的与模型看到的不一致。

## 能力定位

本卡给 `web2-vuln-classes` 补充 LLM/RAG/agent 工具链的攻击面建模和最小验证。

## 触发信号

- Chatbot、AI assistant、RAG search、文档问答、邮件/工单总结、agent tool、function calling。
- 模型能访问账号数据、订单、文档、URL、代码仓库、浏览器内容或内部 API。
- 输出显示引用来源、工具调用结果、权限错误、系统提示片段、SSE/stream error、内部模型服务地址或 tool-call metadata。

## 思路分支

- Direct prompt injection：当前用户输入影响模型行为。
- Indirect prompt injection：网页/文档/邮件/评论等攻击者内容影响其他用户/agent。
- Tool abuse：模型调用搜索、邮件、订单、账号、文件、HTTP fetch 等工具。
- Excessive agency：模型可直接调用高风险工具，例如 debug SQL、账号删除、邮件发送、订单修改，而缺少权限/确认门。
- Data boundary：跨用户、跨组织、未授权文档或隐藏上下文泄露。
- Backend/error disclosure：SSE 或 JSON 错误泄露模型 provider、internal host:port、重试框架、tool/function 名称或参数 schema；先按信息泄露线索处理，只有能链到工具边界、内部服务访问或敏感配置时才升级。

## Agent 六阶段覆盖视角

只在现场证据表明目标具备 Agent、RAG、长期记忆或工具调用能力时，用以下六阶段检查相邻缺口；
它不是固定全测矩阵，阶段未覆盖只产生 `next action` 或 `unknown`：

1. **基础设施**：模型服务、MCP/工具 Server、transport、工具描述/schema、版本和执行凭据是否一致。
2. **感知**：用户输入、网页/文档、检索结果和工具返回经过哪些解析、拼接、引用与过滤后进入模型上下文。
3. **规划**：模型如何选择工具、拆分任务、绑定当前用户/目标，并处理确认门、冲突指令和失败重试。
4. **记忆**：会话、长期/向量记忆和多 Agent 共享记忆由谁写入、读取、传播、删除与重置。
5. **行动**：真实 tool call 的名称、schema、参数、调用身份和权限是否与规划阶段一致，是否出现 shadow tool 或 rug pull。
6. **影响**：最终是否造成跨用户数据读取、权限变化、状态修改、外部副作用或可复现的业务影响。

`tool description changed`、rug pull、shadow tool、schema drift、cross-session memory 和
multi-agent impersonation 都只是路由信号；必须回到对应阶段的原始上下文、tool-call 和影响证据。
其中 rug pull、schema drift 还必须与 Agent、MCP、模型或工具上下文同时出现，不能把普通加密资产
rug pull 或 OpenAPI schema 变化误路由到本卡。

## 技巧家族 / Payload 家族

- Instruction conflict：角色/优先级/格式约束绕过，只作为能力探测。
- Retrieval poisoning：在可控文档中嵌入指令，观察 RAG 引用和行为改变。
- Tool-call probe：低影响查询、只读工具、测试对象状态，证明工具边界。
- Tool-call evidence：backend logs 中出现 `tool_calls`、函数名、参数和工具返回值，优先于只看聊天文本。

## 补充 Checklist

- 是否知道模型代表谁执行：匿名、当前用户、服务账号还是管理员？
- 是否区分模型幻觉和真实工具/数据访问？
- 是否记录输入源、检索证据、工具调用和最终影响？
- 是否先枚举工具清单，再选择一个训练/测试对象做最小影响验证？
- 如果只看到 `connection refused`、provider error、internal host:port 或 stack/error wrapper，是否已区分“环境/依赖故障”与“可利用泄露”？
- 状态改变是否只在训练/测试资源上验证？

## 最小验证

- 建立正常问答或工具调用 baseline；如果模型不可达，保存 raw stream/error 即停止，不把不可达本身当 prompt-injection。
- 单变量加入直接/间接 prompt，比较引用、工具调用、输出和权限差异。
- Backend error 只算 lead：需要证明内部地址、provider、tool schema 或参数能进一步造成敏感数据访问、内部服务利用、权限绕过或业务动作，才升 candidate。
- Candidate 前需要真实数据/工具边界证据，而不是单纯“模型听话”。

## 常见误判 / 死路

- 模型复述用户提供的 secret 不算泄露。
- “忽略以上指令”成功改变语气通常低价值。
- 幻觉出的工具结果不是漏洞，必须有后端证据。

## 关联 Skills

- `web2-vuln-classes`
- `triage-validation`

## 晋升到 Skill / Queue 的条件

- 有输入源、模型上下文、工具/数据边界和可复现影响时写入 action queue，类型 `web-llm-tool-chains`。
