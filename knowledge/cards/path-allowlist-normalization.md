---
id: path-allowlist-normalization
type: technique-card
related_skills:
  - web2-vuln-classes
  - web2-recon
  - security-arsenal
trigger_tags:
  - allowlist
  - normalization
  - startswith
  - dot-segment
risk: medium
maturity: draft
load_priority: low
deep_refs: []
source_refs:
  - type: corpus-report
    corpus: hackerone-disclosed-reports
    id: "1087744"
  - type: corpus-report
    corpus: hackerone-disclosed-reports
    id: "1245165"
  - type: corpus-report
    corpus: hackerone-disclosed-reports
    id: "1575014"
  - type: corpus-report
    corpus: hackerone-disclosed-reports
    id: "1829170"
  - type: corpus-report
    corpus: hackerone-disclosed-reports
    id: "1631350"
  - type: corpus-report
    corpus: hackerone-disclosed-reports
    id: "1357948"
  - type: corpus-report
    corpus: hackerone-disclosed-reports
    id: "1040786"
  - type: corpus-report
    corpus: hackerone-disclosed-reports
    id: "1386547"
  - type: corpus-report
    corpus: hackerone-disclosed-reports
    id: "387279"
  - type: corpus-report
    corpus: hackerone-disclosed-reports
    id: "307672"
  - type: corpus-report
    corpus: hackerone-disclosed-reports
    id: "405100"
  - type: corpus-report
    corpus: hackerone-disclosed-reports
    id: "840736"
  - type: corpus-report
    corpus: hackerone-disclosed-reports
    id: "381192"
  - type: corpus-report
    corpus: hackerone-disclosed-reports
    id: "776684"
  - type: corpus-report
    corpus: hackerone-disclosed-reports
    id: "1250730"
  - type: corpus-report
    corpus: hackerone-disclosed-reports
    id: "156615"
---

# 路径前缀/白名单归一化绕过（含 off-by-slash）

## Quick Recall

- 触发：路径 allowlist、startswith、dot-segment、编码或代理/后端规范化不一致。
- 最小验证：先记录允许/拒绝 baseline，每次只改变一个 slash、编码或路径段变量。
- 证据门：必须证明同一输入在校验与消费阶段到达不同资源或权限边界。
- 停止：统一规范化后精确锚定、无可控路径分量，或只出现普通 404/WAF 差异。

## 适用场景

- 路径/资源 URL 由前缀白名单或深链锚定限制
- 存在 Nginx alias/location、反代到后端的路径转发
- 前端拼接资源 URL（CSPT）

## 触发信号

- alias 与 location 尾斜杠错配（off-by-slash）
- 资源 ID 位置接受 . / .. 触发归一越权
- 代理归一化后的路径与后端解析不一致

## 发散问题

- 前缀锚定后还能不能用 ../ 跳出？
- 归一化在代理做还是后端做？两者一致吗？
- 把 . / .. 当作 ID 会触发路径拼接吗？

## 推荐动作

- 对前缀/深链单变量注入 ../、尾斜杠、编码点。
- 对比代理与后端对同一路径的归一结果。
- 对前端拼 URL 处测 CSPT。

## 关联 Skills

- web2-vuln-classes
- web2-recon
- security-arsenal

## 停止条件

- 路径经统一规范化后精确锚定且代理后端一致
- 无可控路径分量

## 检查要求

- 必须读到/触达前缀边界之外的资源，且可复现。

## 可晋升经验

- 前缀白名单几乎必测 off-by-slash 与代理/后端归一差。
