# Backlog

> 已识别、已裁决、等待时机的条目。死清单：每条只有出处和触发条件，没有状态机。
> 已裁决"不做"的条目不在这里（它们在当时的会话裁决里，不回来）。
> 动一条就移除一条；新增条目必须带出处。

## 工程

（"intel_engine components 采集 bug"条目已裁决关闭，2026-09-15：
诊断不成立——`-tech-detect` 已在 httpx 调用中，`technology_inventory`
解析器对无 tech 字段的行为正确；真实情况是 httpx 默认 Wappalyzer 指纹
对无 Server 头的 SPA 不命中。版本化 advisory 查询需要精确版本与
PACKAGE_MAPPINGS 映射，两者都是设计边界：读锁文件/package.json.bak 提取
版本属于目标特定证据，由 AI 按发现驱动，不硬编码进采集管道。
3001 实战已按此路径闭环：AI 发现 /ftp/package.json.bak 可读 → 12 组件
+ KEV 落盘 intel.json。）

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
- **全量卡惰性复检**（判据升级，2026-09-14 借自 skill-based-architecture）
  pull 数只测可达性，测不了惰性。复审时每张卡过两问：
  (a) 正常路径上不找就能命中吗（不可达→退）；
  (b) 命中后下一个动作改变吗——现在读的文件/跑的检查/跳过的步
  （读完行为不变 = 惰性→退；"触发信号+停止条件+动作改变"形态 = 留）。
  与 pull 数据并用：pull>0 但惰性 → 退；pull=0 但激活 → 留。
  与 5 张 borderline 复审同一窗口执行。

## 低优先（记录在案）

- **fingerprint 机械记录**（2026-09-14 终审）
  Rotation 判定依据（progress fingerprint：hypothesis + surface + actor/state +
  observation kind + evidence reference）只在 prose 里，resolve 时不落盘——
  长跑压缩后 stall 判定靠回忆。修法约 20 行（resolve 时写入 action 记录）。
  触发条件：实战出现一次压缩后 stall 误判再上（imagined-pain 判据）；
  届时大概率是 checkpoint 投影加字段，不是新机制。

- **vuln_memory L3 compaction 召回缺口**（四层记忆系统对比）
  长会话 target_memory 压缩时线索丢失风险；ccst 对应物是 checkpoint 交接。
- **/stop 叙事对齐**（四层记忆系统对比）
  会话结束叙事格式与 Session Summary 的一致性。
