---
id: xs-leak-oracle
type: technique-card
related_skills:
  - web2-vuln-classes
  - triage-validation
  - security-arsenal
trigger_tags:
  - xs-leak
  - oracle
  - timing
  - resource-size
risk: medium
maturity: draft
load_priority: low
deep_refs: []
---

# XS-Leak / 可观测差异侧信道 oracle

## Quick Recall

- 触发：跨域请求无法直接读响应，但登录/未登录或对象状态产生稳定时间/大小/资源差异。
- 最小验证：用自有账号和受控页面做 baseline-vs-variant，重复少量采样确认信号稳定。
- 证据门：必须说明攻击者可观测量、状态差异和可推断信息，不以单次抖动定性。
- 停止：各状态无稳定差异，或 CORB/CORP/SameSite 等边界可靠阻断可观测量。

## 适用场景

- 存在认证态跨域资源、搜索/过滤/聚合接口
- 响应在不同状态下有可观测差异
- 存在可被 <script> 包含的 JSON/JSONP 端点

## 触发信号

- 跨域可观测长度/时序/缓存/报错随目标状态变化
- 聚合/过滤查询数量随隐藏数据变化
- 端点可 script 包含且数据经回调/构造器暴露

## 发散问题

- 哪一个可观测量随受害者私有状态变化？
- 这个差异是否稳定到可作为 oracle？
- 端点能否被跨域 script 包含读取？

## 推荐动作

- 锁定单一可观测量，构造 present/absent 二态对比。
- 验证差异稳定、可重复、可区分。
- 对 script 包含端点测回调/构造器覆盖读数。

## 关联 Skills

- web2-vuln-classes
- triage-validation
- security-arsenal

## 停止条件

- 各状态下可观测量无稳定差异
- 跨域读取被 CORB/CORP/SameSite 稳定阻断

## 检查要求

- 必须证明能可靠区分受害者私有状态或读到跨域数据，且可复现。

## 可晋升经验

- 把"任何可观测差异"都当潜在 oracle：长度/时序/缓存/报错/UI/包长。

## 源报告（on-demand）

- source_report_ids: `493176`, `491473`, `306733`, `1127455`, `1139541`, `159890`, `152696`, `1217114`
- 用途：这些 ID 只作为本地案例库查询指针。只有当前证据已命中本卡触发信号，且需要真实攻击链形状、报告写作先例或相似案例时，才按需查询 gitignored 的 `distill/` 本地缓存；不要默认拉取全文，不把报告正文、目标域名、payload 或 PII 写入知识卡。
