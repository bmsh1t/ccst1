# F07/F08 研究记录：报告附件归属与完整性

## 基线与范围

2026-10-06，HEAD `b8b95e4`；F06 已收尾。本轮仅静态研究与原始审计对照，未运行复现或测试。
来源：`/tmp/ccst-audit-2026-10-02/AUDIT.md:72-84`；F07 对应完整性，F08 对应草稿归属。

## 发布与所有权

- `tools/report_generator.py:189-228`：当前 assessment/delivery/原始证据检查后，读取所选正文，
  复制相邻整个截图目录，再发布原样正文并登记。整目录遍历是跨草稿混入和无关坏文件阻塞的根因。
- `:113-136` 的 `_publish_bytes` 已提供同字节复用、冲突拒绝、无覆盖发布，应继续复用。
- `:360-378,406-427`：手工草稿共用 `drafts/poc_screenshots/`；工具挂图名称已有完整 SHA-256，
  正文输出 `![PoC N](poc_screenshots/<sha256><suffix>)`。不存在通用 Markdown 附件解析器。
- `commands/report.md:81-87` 的整目录复制说明需随实现更新；其它相对附件目前要求调用者保证可解析。

## Store 接入点与不变量

- `tools/target_store.py:1396-1445` 的 `register_report` 是报告统一登记入口，当前仅绑定正文。
  `tools/validate.py:1689-1693` 直接调用它，不能只在 report generator 检查附件。
- `target_store.py:1967-1987` 的 `_report_rows` 是 Finding/page 共享报告当前性入口；
  `:1989-2008` 的历史 delivery event `current_binding` 由报告 stale 决定；`:1457-1463`
  在新增 delivery event 前拒绝 stale 报告。
- `:1414` 的原 command material 必须保持兼容；不可因添加附件字段让既有命令重试冲突。
- `:1054-1108` 已有文件摘要/状态检查，但路径先 resolve；受管发布副本须单独拒绝 symlink，
  不得通过完好原件掩盖副本缺失。解析正文的字节须与其已捕获摘要相同。
- 大文件 hash 留在写事务外；不能声称 SQLite 能事务化外部文件。不得新增嵌套 mutation lock。
- 保留历史报告和交付事件。不要修改技术证据/closure 或将轻量历史 reported count 改成交付健康。
- 只靠工具已有内容寻址引用即可设计无 schema 方案；任意旧文件名没有原始摘要，不能以当前
  文件自动补造完整性信用。2026-10-06 用户已确认仅处理工具生成的截图引用，不扩展任意 Markdown/HTML。

## 可复用测试与验收

- `tests/test_finding_index.py:318` `_primary_report_fixture` 已建立可交付 Finding；
  `:1035-1051` 有真实 manual attach/publish 流程；无需新增框架或构造另一套 Store fixture。
- `:1193` 无图片引用却因邻接 dangling 目录失败的旧测试与新隔离要求冲突：应按新行为修正，
  并用真实受管引用保留危险目录拒绝覆盖。
- 新增 A/B 精确附件集合、无关目录垃圾、被引用来源无效、出版副本缺失/变更、直接登记、
  历史事件保留/新事件拒绝、同 revision 下重新读取、注册前中断重试/注册后不自动修复。
- 保留 `:476,775,807,822,924` 的中断、无覆盖、历史和原样正文回归；
  `tests/test_target_store.py:556-587` 已有显式 delivery event 历史用例。
- fixture 图片只要求非空 bytes；图像解码或媒体类型检查不属于本任务。

## 主代理已复核的关键原文

已点验发布器复制循环、手工 SHA-256 文件名与 Markdown 输出、Store 登记及报告/交付当前性、
`commands/report.md` 的现有兼容说明。完整架构契约与父子任务基础文档由主代理亲读。
