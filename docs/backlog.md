# Backlog

> 已识别、已裁决、等待时机的条目。死清单：每条只有出处和触发条件，没有状态机。
> 已裁决"不做"的条目不在这里（它们在当时的会话裁决里，不回来）。
> 动一条就移除一条；新增条目必须带出处。

## 工程

- **OOB marker 归因**（claude-bug-bounty 唯一幸存借鉴项，2026-09-08 对比审阅）
  `tools/oast_listen.py` 加 `payloads` 子命令：payload 内嵌唯一子域
  （如 `ssrf-{uid}.{oob}`）→ 回连 host 匹配归因到漏洞类+具体 payload。
  ~150 行。验收：发 payload 后 poll 能报出"哪个回连来自哪个 payload"。
- **intel_engine components 采集 bug**（2026-09 juice-shop 3001 靶场实测）
  components:[] 空解析——指纹已到位但组件未入 artifact。孤立 bug，碰
  intel lane 或顺路时修。

## 内容搬运

- **vuln-report 报告纪律**（四层记忆系统对比，2026-09 确认）
  0x01~0x05 思考链 / 攻击链总览 / 失败表格——实战报告价值最高的部分，
  搬进 report-writing skill 或 rules/reporting.md。内容整理，不是工程。
- **escalation 话术**（2026-09-14 skill/rule 审阅，原项目 reporting.md #10）
  报告被降级时的申诉模板（"requires only a free account" 等）。
  赏金谈判经济学，实战遇到降级再议。

## 定期复审

- **5 张 borderline 知识卡复审**（2026-09-14 三问审计，audit-2026-09-14-three-question.md）
  wordpress-surface-intelligence / public-package-artifact-intelligence /
  path-pattern-management-exposure / cdn-response-differential /
  custom-protocol-state-recovery。触发：pull 数据积累 30 天后（约 2026-10-14）。
  判据：`python3 tools/kb_review.py` 看 pulls。

## 低优先（记录在案）

- **vuln_memory L3 compaction 召回缺口**（四层记忆系统对比）
  长会话 target_memory 压缩时线索丢失风险；ccst 对应物是 checkpoint 交接。
- **/stop 叙事对齐**（四层记忆系统对比）
  会话结束叙事格式与 Session Summary 的一致性。
