---
id: stale-derived-authz
type: technique-card
related_skills:
  - bb-methodology
  - web2-vuln-classes
  - triage-validation
trigger_tags:
  - stale-authz
  - role-cache
  - revoked-permission
  - deprovision
risk: medium
maturity: draft
load_priority: low
deep_refs: []
source_refs:
  - type: corpus-report
    corpus: hackerone-disclosed-reports
    id: "700831"
  - type: corpus-report
    corpus: hackerone-disclosed-reports
    id: "416983"
  - type: corpus-report
    corpus: hackerone-disclosed-reports
    id: "1285226"
  - type: corpus-report
    corpus: hackerone-disclosed-reports
    id: "1193321"
  - type: corpus-report
    corpus: hackerone-disclosed-reports
    id: "411337"
  - type: corpus-report
    corpus: hackerone-disclosed-reports
    id: "300179"
  - type: corpus-report
    corpus: hackerone-disclosed-reports
    id: "1959219"
  - type: corpus-report
    corpus: hackerone-disclosed-reports
    id: "1200700"
---

# 授权/凭证的派生态未随源变更及时失效

## Quick Recall

- 触发：角色撤销、成员移除或权限变更后仍存在旧 token、缓存或派生连接。
- 最小验证：用测试主体记录授权前后 baseline，在受控时间窗复用旧派生状态。
- 证据门：必须证明撤销后仍能访问具体资源/操作，并记录时间与主体差异。
- 停止：撤销即时传播到所有派生态，或无法构造低风险的先授权后撤销窗口。

## 适用场景

- 存在 signed token / capability / 预签名 URL / 长连接
- 权限来自父对象（组织/角色/分享）可被变更或撤销
- 存在派生存储、物化视图、缓存的权限快照

## 触发信号

- 撤权后旧 token/session/通道仍可访问旧权限
- 父级角色变更未级联撤销子级授权
- 长连接只在握手鉴权，令牌过期后通道仍存活

## 发散问题

- 签发出去的能力是否独立于实时授权？撤销如何传播？
- 父变更后派生数据/缓存/连接何时被重新校验？
- 存在"永久有效"的凭证态吗？

## 推荐动作

- 先获得能力，再撤销/降权/改父级，随后重放旧凭证。
- 对长连接在令牌过期后继续发消息，观察是否仍被授权。
- 检查派生存储是否保留降权前的越界数据。

## 关联 Skills

- bb-methodology
- web2-vuln-classes
- triage-validation

## 停止条件

- 撤销即时传播到所有派生态与连接
- 无法构造"先授权后撤销"的时间窗

## 检查要求

- 必须证明在权限已被撤销/降低后仍能行使旧权限，且可复现。

## 可晋升经验

- 凡是"签发即长期有效"的能力，都追问撤销传播路径。
