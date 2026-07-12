# 知识库层

知识库层是 Skills 层的经验压缩库，负责提供可检索的思路、技巧、payload
家族、bypass 思维、补充 checklist、反例、误判/死路和可变形经验。

它不只是联想种子。它既要帮助 Claude 发散，也要提供战术细节和防漏检查；
但它仍然是供料层，不负责指挥流程。

它不负责保存当前目标状态，不负责定义红线规则，也不负责执行或指挥流程。执行顺序、工具选择和收敛判断始终由当前 Skill 负责。

## 和其他层的边界

```text
Skills 层：怎么执行、如何指挥流程
目标层：当前做什么
知识库层：还能从哪些角度想，有哪些技巧/知识/payload 家族，如何补漏和变形思路
检查层：什么不能做、怎样才算验证充分
```

## 组成

```text
knowledge/
  index.md
  card-template.md
  promotion-rules.md
  cards/
    auth-access.md
    api-idor.md
    ssrf-url-fetch.md
    dead-ends.md
  payloads/
    sqli-low-risk-probes.md
    command-execution-probes.md
  playbooks/
    controlled-rce-validation.md
```

同时把现有资料纳入知识库层：

- `skills/security-arsenal/REFERENCES.md`：外部参考库索引
- `rules/playbook-router.md`：证据到参考资料和工具的路由器

## 使用原则

1. 默认只读 `knowledge/index.md`。
2. 只有当前目标、skill、证据或假设命中时，才加载具体知识卡。
3. 知识卡提供思路分支、技巧家族、payload 家族、bypass 思维、补充
   checklist、最小验证和误判/死路；不自动触发高风险动作，也不接管
   Skill 流程。
4. 从目标记忆晋升到知识库前，必须满足 `promotion-rules.md`。
   经验/技巧/bypass 进知识库；判断进 `tools/evidence_rubric.py`；
   路由进 `tools/context_pack.py`；下一步进 `tools/checkpoint.py`；
   可重复执行的 replay/diff/证据保存动作进 `tools/`；结果进 Evidence Ledger。
5. 如果知识卡和 `rules/` 冲突，以 `rules/` 为准。

## 沉淀原则

适合进入知识库的内容：

- 多个目标重复出现的漏洞模式
- 某类技术栈下反复有效的检查思路
- 某类 payload / bypass / parser 差异 / WAF 绕过的可复用技巧家族
- 高价值攻击面识别经验
- 常见误区、误判条件和低价值方向
- 能帮助 Skills 层更好分支决策的可复用经验或反例

不适合进入知识库的内容：

- 单个目标的临时线索
- 未验证的漏洞结论
- 大体积扫描日志
- 敏感凭证或真实用户数据
- 红线和授权规则

## 推荐知识卡结构

新卡和复盘晋升优先使用 `knowledge/card-template.md` 的结构：

```text
能力定位
触发信号
思路分支
技巧家族 / Payload 家族
补充 Checklist
最小验证
常见误判 / 死路
关联 Skills
晋升到 Skill / Queue 的条件
可晋升经验
```

现有 active 卡已完成 v2 frontmatter 和 `Quick Recall` 迁移；新增经验也必须按这个结构沉淀。
