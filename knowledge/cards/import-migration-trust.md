---
id: import-migration-trust
type: technique-card
related_skills:
  - web2-vuln-classes
  - bb-methodology
  - triage-validation
trigger_tags:
  - import
  - migration
  - restore
  - trust-boundary
risk: medium
maturity: draft
load_priority: low
deep_refs: []
source_refs:
  - type: corpus-report
    corpus: hackerone-disclosed-reports
    id: "446585"
  - type: corpus-report
    corpus: hackerone-disclosed-reports
    id: "689314"
  - type: corpus-report
    corpus: hackerone-disclosed-reports
    id: "767770"
  - type: corpus-report
    corpus: hackerone-disclosed-reports
    id: "534794"
  - type: corpus-report
    corpus: hackerone-disclosed-reports
    id: "508184"
  - type: corpus-report
    corpus: hackerone-disclosed-reports
    id: "1132378"
  - type: corpus-report
    corpus: hackerone-disclosed-reports
    id: "1439593"
  - type: corpus-report
    corpus: hackerone-disclosed-reports
    id: "826361"
---

# 导入/恢复/迁移类功能坍塌信任边界

## Quick Recall

- 触发：导入、恢复、迁移或备份流程把外部对象带入新的权限/租户上下文。
- 最小验证：用测试 fixture 追踪导入对象的 owner、来源和操作级校验。
- 证据门：必须证明导入后权限、身份绑定或敏感字段发生越界变化。
- 停止：每一步都有操作级校验，或继续验证需要真实数据和破坏性状态变化。

## 适用场景

- 存在数据导入、备份恢复、迁移、批量创建
- 存在策略/规则链传递能力
- 校验绑在流程步骤而非最终操作上

## 触发信号

- 导入的数据跳过了正常创建的校验
- 控制在流程入口做，绕过流程即绕过控制
- 策略链把授权能力传给间接主体

## 发散问题

- 导入/恢复的数据是否复用了正常写路径的校验？
- 控制绑在"流程"还是"操作"上？能否直达操作？
- 策略链会不会把能力传给不该有的主体？

## 推荐动作

- 对比导入路径与正常创建路径的校验差异。
- 尝试直达被流程包裹的最终操作。
- 追踪策略链的能力传递闭包。

## 关联 Skills

- web2-vuln-classes
- bb-methodology
- triage-validation

## 停止条件

- 导入/恢复复用统一的操作级校验
- 控制绑定在操作而非流程

## 检查要求

- 必须证明经导入/恢复/策略链获得正常路径被拒的状态或能力，且可复现。

## 可晋升经验

- 导入/恢复/迁移是高价值信任坍塌面；追问校验绑在流程还是操作。
