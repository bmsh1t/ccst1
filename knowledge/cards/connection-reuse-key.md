---
id: connection-reuse-key
type: technique-card
related_skills:
  - web2-vuln-classes
  - web2-recon
  - triage-validation
trigger_tags:
  - connection-reuse
  - pool-key
  - tenant-key
  - keep-alive
risk: medium
maturity: draft
load_priority: low
deep_refs: []
source_refs:
  - type: corpus-report
    corpus: hackerone-disclosed-reports
    id: "1912778"
  - type: corpus-report
    corpus: hackerone-disclosed-reports
    id: "1552110"
  - type: corpus-report
    corpus: hackerone-disclosed-reports
    id: "1912782"
  - type: corpus-report
    corpus: hackerone-disclosed-reports
    id: "1912783"
  - type: corpus-report
    corpus: hackerone-disclosed-reports
    id: "1565624"
  - type: corpus-report
    corpus: hackerone-disclosed-reports
    id: "1526328"
  - type: corpus-report
    corpus: hackerone-disclosed-reports
    id: "1223565"
  - type: corpus-report
    corpus: hackerone-disclosed-reports
    id: "1555796"
---

# 连接/缓存复用键遗漏安全维度

## Quick Recall

- 触发：连接池、缓存、keep-alive 或复用键看起来遗漏租户、角色或认证上下文。
- 最小验证：用两个受控上下文请求同一资源，单变量改变主体并观察复用边界。
- 证据门：必须证明跨上下文共享了不应共享的响应、连接状态或权限结果。
- 停止：复用键包含完整安全维度，或无法制造跨上下文共享条目。

## 适用场景

- 存在连接池复用、keep-alive、上游连接重用
- 存在 CDN/反代/应用层缓存
- 复用/缓存键由部分请求属性构成

## 触发信号

- 连接复用键漏掉 auth 参数导致凭据混淆
- 缓存键归一化与取源不一致（poisoning/deception）
- 复用键漏掉安全选项导致 TLS/证书校验降级

## 发散问题

- 复用/缓存 key 是否包含所有影响安全的维度？
- 两个不同安全上下文的请求会共用同一连接/缓存条目吗？
- 归一化后的 key 与实际取源是否一致？

## 推荐动作

- 构造仅在安全维度上不同、在 key 上相同的两个请求。
- 观察是否发生凭据/响应串味或缓存投毒。
- 对缓存做键归一化差异探测（大小写/参数序/端口）。

## 关联 Skills

- web2-vuln-classes
- web2-recon
- triage-validation

## 停止条件

- 复用/缓存键包含完整安全维度
- 无法制造跨上下文共享条目

## 检查要求

- 必须证明跨安全上下文的凭据混淆、缓存投毒或降级，且可复现。

## 可晋升经验

- 遇到池化/缓存先问"key 里少了哪个安全维度"。
