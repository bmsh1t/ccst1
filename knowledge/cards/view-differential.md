---
id: view-differential
type: technique-card
related_skills:
  - web2-vuln-classes
  - bb-methodology
  - security-arsenal
trigger_tags:
  - view-differential
  - validation-view
  - consumption-view
  - canonicalization
risk: medium
maturity: draft
load_priority: low
deep_refs: []
source_refs:
  - type: corpus-report
    corpus: hackerone-disclosed-reports
    id: "44513"
  - type: corpus-report
    corpus: hackerone-disclosed-reports
    id: "730779"
  - type: corpus-report
    corpus: hackerone-disclosed-reports
    id: "1086108"
  - type: corpus-report
    corpus: hackerone-disclosed-reports
    id: "2101076"
  - type: corpus-report
    corpus: hackerone-disclosed-reports
    id: "815085"
  - type: corpus-report
    corpus: hackerone-disclosed-reports
    id: "945990"
  - type: corpus-report
    corpus: hackerone-disclosed-reports
    id: "397792"
  - type: corpus-report
    corpus: hackerone-disclosed-reports
    id: "52042"
---

# 校验视图与执行视图的规范化/编码/截断差异

## Quick Recall

- 触发：校验、日志、缓存和实际执行对同一输入采用不同编码/截断/规范化视图。
- 最小验证：对测试输入只改变一个边界表示，比较校验结果与最终消费对象。
- 证据门：必须证明差异穿过安全判定并改变资源、权限或执行行为。
- 停止：两侧共用同一规范化结果，或差异不改变安全行为。

## 适用场景

- 存在"先校验再使用"的两段式处理，且两段由不同组件/库完成
- 输入会经历解码、Unicode 归一、大小写折叠、长度截断、去空白
- 代理与后端、校验器与存储层对同一字符串处理不同

## 触发信号

- 对畸形/多字节/百分号编码输入校验 fail-open 或行为分叉
- 长度限制在解码前测量，或存储层静默截断
- NUL、控制字符、重复条目、尾随点改变解析归属

## 发散问题

- 校验时看到的字节和执行时看到的字节是否逐字节相同？
- 谁先解码、谁后解码，中间是否有截断或归一？
- 同一输入在两个组件里会不会被解析成不同实体？

## 推荐动作

- 定位校验与消费两个点，分别观察它们对同一畸形输入的解读。
- 单变量注入编码/截断/归一差异，比较状态码与副作用。
- 用时序或错误信息发现逻辑分叉点。

## 关联 Skills

- web2-vuln-classes
- bb-methodology
- security-arsenal

## 停止条件

- 校验与消费共用同一规范化结果
- 差异存在但不改变任何安全判定或落地行为

## 检查要求

- 必须给出一份在校验视图合法、在执行视图产生越权/注入/绕过效果的可复现请求。

## 可晋升经验

- "检查的是不是你执行的那份"是通用发散母题，可迁移到路径、认证、限速、去重。
