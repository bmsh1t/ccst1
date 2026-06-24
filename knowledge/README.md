# 知识库层

知识库层负责给 Skills 层提供可检索的思路、模式、案例和反例。

它不负责保存当前目标状态，也不负责定义红线规则或执行流程。

## 和其他层的边界

```text
Skills 层：怎么执行
目标层：当前做什么
知识库层：还能从哪些角度想
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
```

同时把现有资料纳入知识库层：

- `skills/security-arsenal/REFERENCES.md`：外部参考库索引
- `rules/playbook-router.md`：证据到参考资料和工具的路由器

## 使用原则

1. 默认只读 `knowledge/index.md`。
2. 只有当前目标、skill、证据或假设命中时，才加载具体知识卡。
3. 知识卡只提供发散方向和检查问题，不自动触发高风险动作。
4. 从目标记忆晋升到知识库前，必须满足 `promotion-rules.md`。
5. 如果知识卡和 `rules/` 冲突，以 `rules/` 为准。

## 沉淀原则

适合进入知识库的内容：

- 多个目标重复出现的漏洞模式
- 某类技术栈下反复有效的检查思路
- 高价值攻击面识别经验
- 常见误区和低价值方向
- 能帮助 Skills 层更好分支决策的案例

不适合进入知识库的内容：

- 单个目标的临时线索
- 未验证的漏洞结论
- 大体积扫描日志
- 敏感凭证或真实用户数据
- 红线和授权规则
