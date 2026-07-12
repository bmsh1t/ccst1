---
id: type-confusion-controlflow
type: technique-card
related_skills:
  - web2-vuln-classes
  - triage-validation
  - security-arsenal
trigger_tags:
  - type-confusion
  - json-shape
  - reserved-key
  - control-flow
risk: medium-to-high
maturity: draft
load_priority: low
deep_refs: []
---

# 攻击者控制参数类型/形状翻转框架控制流

## Quick Recall

- 触发：JSON/表单字段的类型、数组/对象形状或保留键可由请求控制。
- 最小验证：保持业务值不变，只替换一个类型/形状并比较校验、分支和输出。
- 证据门：必须证明控制流或安全判定改变，并记录解析前后形态与实际影响。
- 停止：严格类型/形状校验，或变换不改变任何安全行为。

## 适用场景

- 接口按类型/形状分派逻辑（标量 vs 数组 vs 对象）
- 使用 NoSQL/GraphQL/动态语言弱类型比较
- 存在差分校验（比对旧值）或反射式分发

## 触发信号

- 单值参数改数组后变批量查询绕过限速
- 差分校验信任了客户端提交的"旧值"
- 类型/形状变化改变鉴权或方法分发

## 发散问题

- 把标量换成数组/对象/null，逻辑会怎样变？
- 校验假设的类型和实际接受的类型一致吗？
- 旧值/元数据是否被无条件信任？

## 推荐动作

- 对关键参数做类型/形状单变量变换。
- 观察限速、鉴权、分派是否被翻转。
- 对差分校验测伪造旧值。

## 关联 Skills

- web2-vuln-classes
- triage-validation
- security-arsenal

## 停止条件

- 参数经严格类型与形状校验
- 变换不改变任何安全行为

## 检查要求

- 必须证明类型/形状变换实际绕过限速/授权或改变控制流，且可复现。

## 可晋升经验

- 弱类型/动态分派处优先做类型形状 fuzz：标量<->数组<->对象<->null。

## 源报告（on-demand）

- source_report_ids: `960244`, `49652`, `1130721`, `1095612`, `186194`, `1106652`, `386807`, `213789`, `240958`, `946728`, `387250`
- 用途：这些 ID 只作为本地案例库查询指针。只有当前证据已命中本卡触发信号，且需要真实攻击链形状、报告写作先例或相似案例时，才按需查询 gitignored 的 `distill/` 本地缓存；不要默认拉取全文，不把报告正文、目标域名、payload 或 PII 写入知识卡。
