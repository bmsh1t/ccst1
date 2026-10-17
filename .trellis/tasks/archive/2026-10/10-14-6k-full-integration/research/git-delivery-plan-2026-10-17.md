# B7：自包含 Git 交付补充设计与执行计划

## 授权与范围

2026-10-17，用户对“审核并单列必要前置改动，补齐新 checkout 读取，再提交/归档”明确回复
“同意”。沿用原任务，不创建替代任务。原 C 的 B6/A1–A9 验收保留；本节新增 Git 交付门。
不部署个人 runtime、不操作真实目标、不提交无关 advisory/metrics/degraded 或其他旧 WIP。

## 最小设计

- `hot_method` 仍是唯一 owner、同一 manifest/revision 日志，不引入 Git 特判或第二版本账本。
  catalog/read 显式验证已完成发布的内容：transaction/request/decision/receipt、全部引用blob、
  witness字节、origin、当前manifest/正文hash与路径安全，且必须是匹配manifest的applied终态。
- 只读验证用新checkout当次目录/文件身份防读中变化，不拿旧dev/ino/uid/gid/mode当可移植内容。
  旧身份仍保留在日志；witness必须存在、字节正确并与blob独立，不重建或改写历史记录。
- apply（包括当前版本前置校验、历史重试）和recover仍默认完整核对本地目录与见证身份；
  slot/alias/第三态、恢复方向、同步屏障完全不变。新checkout可读不等于可继续原checkout事务。
  本轮不新增adopt/rebind或允许新checkout写入的协议；不以读取成功声称恢复能力已迁移。
- pending始终阻止活动读取；损坏/缺失材料、symlink、非普通文件、读中变化、旧CAS仍拒绝。
  不在异常后fallback、不按.git存在与否降级；来源/审核声明限制保持。
- 产品只改 `tools/hot_method.py`；读取语义记入现有spec。活动方法、manifest、事务、见证、
  原有cleanup/Store字节不为本次修复修改；新验收脚本仅放W，不新增仓库测试设施。

## 前置提交分界

1. 单列已存在的cleanup闭包：`tools/target_store.py`、`tools/validation_runner.py` 的B1旧增量、
   `tools/report_generator.py`、`tools/validate.py`；保留既有Finding关联、回读证据与发布保护。
   不只摘helper来修import，须验证完整gate。相应tool-index的record-evidence说明及既有
   validation-evidence 的34行cleanup合同一并单列，不纳入runtime-autopilot的degraded旧增量。
2. 6k集成：纳入原有内置方法55文件和本批新增/修订后的完整56活动文件、真实origins及历史
   材料；明确不是全为本轮新增。hot_method旧内置/非排名基础、campaign旧控制器衔接纳入。
   runtime-protocol旧125行重写作为已验收整体单列，含重述/压缩，不虚称每行均为代码前置。
3. context_pack只取B1→当前任务增量，保留其旧advisory/metrics为未暂存；tool-index只取cleanup/
   observation/browser说明，排除advisory/metrics/degraded段。其余明确无关路径继续保留原状。
   CLAUDE仅取四处必要接线：scanner非前置、去固定管线、手动/自动共用core、协议索引；
   不纳入整份旧压缩重写，C现有CLAUDE字节不变，提交时按独立预览blob精确暂存。
4. 用独立临时Git index/checkout预览上述提交树，不改变C暂存区；只从该树运行验证，禁止
   依赖未纳入提交的C/S文件。具体分批及文件白名单经最终检查后一次展示确认，再实际提交。

## 执行与验证

- [x] 在W的新B7候选修复read/local identity分层，保留S/F冻结基线。
- [x] 从拟提交Git树检出新inode，使用它自己的代码和独立HOME/数据根运行catalog及完整read；
  manifest、方法、日志字节不改，来源及review状态如实返回。
- [x] 在新checkout拒绝旧事务recover和普通apply；原本地fixture的同字节换inode、父目录/
  witness/metadata变化、pending与恢复方向拒绝仍成立，不产生隐式写入。
- [x] 损坏/缺失blob、witness、receipt、origin/正文及symlink和旧CAS均有反例；只读不变字节。
- [x] 用合成Store执行cleanup缺失→拒绝、真实只读确认→允许、证据改变→拒绝/报告stale；
  相关既有Finding登记/报告/preflight回归。不发网络请求，不新增真实目标数据。
- [x] 检查候选diff、未纳入的旧WIP与C原样保留；兼容reader已发布并只读回读成功。
- [x] 两批代码按白名单提交；archive --no-commit并修正链接。add_session亦禁自动提交，日志独立成批。

验证按新增共享合同选窄矩阵，不以旧71项/59项记录替代新增行为，也不默认重跑全套。
实际结果、包装限制及持久材料见 [B7验收](b7-git-acceptance-2026-10-17.md)。
