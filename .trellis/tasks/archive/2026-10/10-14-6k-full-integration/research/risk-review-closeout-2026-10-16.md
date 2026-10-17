# 六项风险审核收尾（2026-10-16）

## 范围与状态

沿用 `10-14-6k-full-integration`，状态仍为 `in_progress`，不创建/启动替代任务。
本轮审核只修订任务文档，未开始产品实现或 B6。原实施批准及 D1=A 保留；审核摘要后，
用户于 2026-10-16 以 `go` 确认本次协议并启动 B1 隔离实现，不代表验收或 B6 已完成。

当前：**本次设计/文档审核收尾通过**。五项设计消歧、独立复核及有界规划校验已完成；
不代表产品实现、V2/V1–V7、B6 或个人 runtime 处置完成。
[原六项风险报告](implementation-risk-review-2026-10-15.md) 保留历史结论，当前规范正文
只在 [设计 §4](../design.md)，验收只在 [B1/V2](../implement.md)，不在此复制第二套协议。

## 五项歧义的处置

| 问题 | 设计选择与理由 | 实现时必须证明 |
|---|---|---|
| receipt 后 restore | applied/restored 终态收据互斥；applied 后 restore 拒绝。显式恢复先持久化方向，正常 apply 在 manifest 及全组核对之后、receipt 之前固化 complete | receipt 后同向只核对/清理，反向拒绝且不改现场；两方向再次中断仍可继续；撤回已完成版本用新事务 |
| fsync 屏障及失败 | transaction 文件/目录先于 pending；decision、receipt 各有文件/目录屏障。unlink 后同步失败不假称 pending 仍存在 | 每个屏障单独注入错误；输出历史终态、当前版本、pending 实况及清理持久性，不把非零误说成未改过活动字节 |
| 跨进程路径身份 | before/after 硬链接见证固定合法 inode，内容 blob 独立；恢复不从 blob 重建 inode | owner 合法 replace/重试可认，同字节换 inode、metadata/父目录/见证变化拒绝；不许 hash-only 降级 |
| 新文件缺失 | 同目录 slot 与活动名间的原子 rename 同时表达位置和进度 | 尚未发布/已恢复有 slot；已发布有活动名；两处皆无或两处都有冲突，不能用独立 published 标记猜历史 |
| 旧 receipt 与 CAS | 完整材料绑定先验，历史分派早于当前协议、无 pending 和旧 CAS；包括 bootstrap | T1→T2→T1 不修改 T2；T2 pending 时历史成功不表示当前可读；restored 的旧 apply 不复活 |

前两项由终态/持久化专项探子检查，身份及 slot 由另一个专项探子独立论证；主会话
亲读现有 owner 与设计后作出取舍。落文后另派两名探子审协议及跨文档一致性：协议未发现
阻断问题；一致性审核发现异常矩阵遗漏和“本版批准”歧义，已补回第三种字节/旧文件删除/
准备阶段屏障用例，并把原批准明确标为 2026-10-15。此处审核不是产品实现通过的证明。

最小新增机械均归现有方法 owner：decision 仅固定该事务方向，witness/slot 仅作本地
身份与位置证据，不是方法发现目录、目标事实、第二数据库或通用事务框架。不能仅用
hash/before inode，因为前者接受同字节换 inode，后者拒绝 owner 自己的合法原子替换；
不能用另一个 published 布尔日志，因为更新它与改名之间仍有崩溃窗口。

新增明确限制：本地同文件系统、可硬链接/目录同步、活动父目录稳定且已存在；保留
mode/uid/gid，被改文件的 ACL/xattr 等本版不支持条件必须在 pending 前拒绝，不静默
丢弃。目录重建、恶意日志篡改、非协作 TOCTOU 和断电物理持久性不是本协议的保证。
这些限制及保留本地见证/slot 的成本已随本次协议补充确认，不能宣传为任意文件系统方案。

代码/机制依据（仅阅读，没有执行产品）：

- `tools/hot_method.py:16,94–101,149–156,195–211`：当前仍为 v1/hash 健康入口，不具备本次协议。
- `tools/artifact_io.py:16–34`：普通临时文件替换，没有父目录 fsync 或稳定的恢复 inode。
- `tools/distill_digest.py:250–256`：已有 create-only link 接缝，没有跨文件持久化保证。
- `tools/knowledge_promote.py:67–106,152–160`：目录锁可复用；字节补偿回滚不等于崩溃恢复。
- 本地 Linux `link(2)`、`rename(2)`、`inode(7)`、`fsync(2)`：链接共享 inode/metadata，
  同目录 rename 原子改变位置，ctime/nlink 会变，名称持久化需目录同步；不据此声称磁盘断电测试通过。

## 六项风险分别结账

1. **发布协议**：原先“没有独立审核”已过时。已补专项审核并明确五项设计选择；完整
   V2 仍是 apply/bootstrap × 四断点 × 两方向的 16 次独立恢复，加方向/slot/同步故障
   等异常矩阵。测试尚未执行，不能用一个成功检查或默认 60 秒预算代替。
2. **脏树保护**：持久恢复包已覆盖 575 份源码、79 份当前脏文件、15 份风险修订前任务
   文件及 Git 元数据，680 个成员，字节/权限回读已有成功记录。本轮开始再次核对全部
   79 份当前脏文件与恢复清单一致。旧 `before/` 的 221 项权限差异没有被掩盖；恢复用
   包内原 mode，不照搬旧目录权限。`guihua.md` 仅当前版可恢复，旧字节缺失/作者未知。
3. **个人 runtime**：误安装事实仍未恢复；技能列表不是充分归因证据。只读取证及逐文件
   恢复来源/方案需单独确认，不访问或使用它作验收依据。这是具名外部待办，不假称已修好。
4. **B6 排他**：范围是 C 受影响路径的全部读写消费者，不要求无关进程退出整台机器。
   未取得排他证据，不能切换、不擅自杀会话；历史批准和目录 flock 都不替代时点确认。
5. **效果与接线**：工程验收、宿主部署、在线效果分别报告。后续 lab 需另定授权范围、
   预算与已知结果；本轮无目标操作，不保证发现率/token/效率改善。
6. **2.3 延期**：四条短表场景和三篇手册仍在原台账具名保留，未激活，后续按 A 核对
   完整来源/准入，不计本批效果、不修改台账。

持久包（本轮不改写）：

```text
/root/.local/state/ccst-recovery/6k-full-integration/20261015T160219Z-XQES5z/recovery.tar.gz
sha256: adb8e25f2c23aa39c60610220b70db9ace6ffe5e4488b4159ee144976cbc05e3
```

## 本轮保护与最终校验

本轮编辑前独立快照：`/tmp/ccst-risk-closeout-20261016-euopioco/before/`，16 份任务
文件；同目录 `baseline.json` 保存本轮 Git/79 项当前脏文件的 hash/mode。不会用更早
baseline 的 `guihua.md` hash 回滚用户版本。隔离源码仍为 `/tmp/ccst-6k-accept-XQES5z/staging`。

实际命令（末次 exit 0，脚本计时 0.489 秒）：

```text
python3 -B /tmp/ccst-risk-closeout-20261016-euopioco/validate_risk_review.py
```

结果保存在同目录 `validation-result.json`；native 上下文及 task validator 输出也已
保存，未新增项目测试文件。首轮通过后，最终差异复核进一步明确“本事务记录匹配”
不排斥“其他事务 pending 的当前诊断”，因此对最新正文重跑了同一项有界检查。末次结果：

- task validator 无超限警告；两份 manifest 各 6 个完整正文及三件套均完整注入，
  无截断/路径降级。包装后的 implement/check 为 **130748 / 130740 bytes**，低于
  131072；余量仅 324 / 332 bytes，后续工件变化必须重渲染，不可盲目追加或提高全局上限。
- 45 条相对链接有效；62 个原始来源、54 个当前副本和 123 个对照文件 hash 一致。
- R1–R6、A1–A9、D1 正文及 task/manifests/来源台账未改；HEAD/index/原 tracked diff
  未变，79 份受保护文件 bytes/mode 未变。
- C/S/before 各 575 个源码 hash 一致，C/S mode 保留；旧 before 的 221 项 mode 差异
  仍明确报告。持久包 SHA256、0700/0600 保护及 680 个成员与既有 readback 的
  bytes/mode 全部一致；本轮只读比较，没有重新解包或还原 live 文件。
- 阅读图保留全部 canonical owner；文档中的两个 Bash 块仅 `bash -n` 语法检查，
  未执行其命令。检查器校验的是工件及保护边界，不是未来协议的行为实现。

本次只改六份任务文档：PRD 状态引用、设计协议、实施验收、阅读导航、原风险报告的
历史标记及本收尾报告。校验后只据实际结果回填本报告；未再修改注入正文或产品文件。

当前没有运行 V1–V7、产品 CLI、installer、个人 runtime 操作或 B6。即使本轮审核
收尾通过，整个集成任务也仍未完成，A1–A9 不因此勾选。
