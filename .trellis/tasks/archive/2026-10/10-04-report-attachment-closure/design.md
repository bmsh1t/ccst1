# F07/F08 技术设计：受管截图闭包

## Owner 与数据流

```text
手工草稿原始 bytes + 既有内容寻址截图
  -> report_generator 选择所选正文声明的受管引用
  -> 校验源文件 -> _publish_bytes 无覆盖发布附件和原样正文
  -> TargetStore.register_report 验证正文及受管发布副本 -> 原报告/收据事务
  -> Finding/page 当前报告健康 -> INDEX/SUMMARY 与 delivery event 当前性
```

不增加数据库表、artifact 关联或 API 参数。不可变正文的已登记 SHA-256 承诺受管文件名，
文件名中的完整 SHA-256 再承诺图片字节；这是现有身份的闭包，不是另一个附件 manifest。
引用识别由 `tools/target_store.py` 中一个小的纯 helper 定义，发布器沿已有 Store import 复用，
不得让 Store 反向依赖 publisher、CLI 或 Markdown 渲染层。文件获取复用现有安全读/摘要模式；
不改全局 `_artifact` 身份字典或 `_command` 的幂等协议。

## 已批准的受管引用协议

- 支持工具生成的独立行行内图片：`![说明](poc_screenshots/<64位小写SHA-256><可选扩展名>)`。
  说明不参与身份；LF/CRLF、非 ASCII 说明和重复引用可用，输出正文不做规范化。
- 路径是正文旁 `poc_screenshots/` 下的单个文件名。只接受完整内容摘要和安全单文件后缀；
  拒绝目录穿越、绝对路径、反斜杠、URL query/fragment、百分号转义或其他需要解释的路径形式。
  不增加媒体扩展名白名单，也不解码图片；无扩展名的既有工具图片继续可用。
- 只识别上述工具输出面，不实现一般 Markdown。 fenced/缩进代码、行内代码、转义图片标记、
  普通正文中的目录名称和外部 URL 不属于受管声明。对明显的受管独立图片声明，路径或摘要
  格式错误必须报错，不能静默当作没有附件。
- 任意内联排版、引用式图片和 HTML 不获本批托管保证；其他普通相对链接保持调用者负责。
  既有非内容寻址截图没有可验证的原始摘要，不能自动纳入信任或迁移。
- 以 bytes 识别 ASCII 协议，避免把 Store 既有非空非 UTF-8 artifact 一概改为非法；publisher
  的非空 UTF-8 正文要求保持不变。解析数据必须校对已捕获的正文摘要，不能混用两次不同读取。

## 发布选择与文件边界

引用列表确定性去重，仅逐一访问声明的文件，不枚举 `poc_screenshots/`。零引用时不探测、
创建或验证该目录。因此其他草稿的坏文件不会阻断当前报告。

被引用源文件和发布副本必须位于各自正文的受管目录，无路径组件 symlink，最终对象为非空
普通文件，字节摘要与文件名一致。采用非阻塞、no-follow 打开和读取前后身份检查，避免 FIFO
挂起和路径替换。Store 继续校验目标归属；发布器允许已有 `--body-file` 输入位置，不扩大
其源文件读取范围。校验文件名不能替代对真实路径、文件类型和字节的校验。

保留 `_publish_bytes` 的同字节复用和不同字节冲突语义，附件先于正文完整落盘，最后登记。
失败可留下完整但未登记的文件供同字节重试，不删除原件、不覆写历史。发现已登记报告 stale
时在复制前拒绝，不能从原件或草稿自动补齐损坏的发布副本。

## Store 健康与写入边界

- `register_report` 在现有写事务外取得正文与所有受管附件的字节/摘要/文件身份快照，
  解析所用正文必须匹配既有 `artifact_value`。所有直接生产调用者共享此检查。
- 保留 `(report_id, finding_id, assessment_id, delivery_id, artifact_value)` command material，
  不新增持久化关系，不改变旧收据 digest。健康同字节重试保持幂等；损坏时仍在命中旧收据前拒绝。
- `_report_rows` 在既有同连接查询获取中复核受管附件。沿用现有 `artifact_available`、
  `artifact_authorized` 表达整个当前交付物的可用/授权状态，`stale` 同时依赖正文和附件健康；
  正文 artifact 的 availability/provenance 事件仍有效。不增加附件独立 provenance events。
- 附件失败局限于对应报告；捕获明确的文件/格式/Store 错误后置其不可用，保留报告行。
  没有跨查询健康缓存；下一次读取重新核对字节，即使 Store revision 没变。
- `record_delivery_event` 继续经报告当前性拒绝损坏材料；历史事件仅派生为
  `current_binding=false`，不删除。报告附件损坏不得改变 assessment、delivery decision 的
  技术/目的地判断，也不修改 `finding_summary` 的历史存在性统计。
- 在报告登记或交付事件的既有 mutate 内、插入前，用预检捕获的文件身份做轻量复核
  （dev/inode/size/mtime_ns/ctime_ns 与安全路径）。注册正文已有的 artifact 事件在同一写连接
  复核；不把大文件哈希移入写事务，不包裹第二个 mutation lock。沿既有 statement 顺序
  保持 assessment/delivery 的提交时检查，不扩成通用 transaction/authorization 重构。
- 这只能拒绝所观察到的预检到写入漂移，不宣称 SQLite 对外部文件提供事务；提交之后的
  文件变化由下一次完整读取再次发现。文件恢复到原始字节后，可恢复当前性，不改历史。

## 改动面与兼容性

产品代码限于 `tools/report_generator.py` 和 `tools/target_store.py`；回归复用
`tests/test_finding_index.py` 与 `tests/test_target_store.py` 的现有 fixture。
`tools/validate.py` 只作调用兼容核对，不改写其正文规范化行为。

同步 `commands/report.md`、`.trellis/spec/backend/contracts/validation-evidence.md` 和
`.trellis/spec/backend/contracts/transactional-target-state.md` 的原有报告段落。
明确托管语法、选择规则、aggregate 健康、历史无摘要材料边界与真实提交的区分。

## 风险与回滚

独立行工具协议是明确范围，不是通用 Markdown 解析保证。若实现需要任意格式识别、新表、
补写历史摘要、覆盖旧正文或扩展 transaction owner，停止并回到规划。
回滚本批代码及契约即可，无 schema 回滚或真实数据清理。回滚会恢复旧的附件健康缺口，
不得把回滚后的旧查询解释为已经验证附件完整。
