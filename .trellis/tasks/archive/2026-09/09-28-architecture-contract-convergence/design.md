# 设计

## 问题与落点

基线 AST 检查发现五组循环。现有延迟 import 仅避开加载异常，没有建立单向职责。

| 环 | 新的职责边界 |
|---|---|
| request_diff ↔ validation_runner | wire vocabulary 属于已有 contracts；parser/runner 共用，无执行器反向 import |
| decision_scaffold ↔ validate | decision schema/七问定义属于同一 contracts；CLI 依赖骨架，骨架不加载 CLI |
| runtime_state → browser_mcp_import → action_queue → runtime_state | readiness 移至已有 browser_evidence 只读模块；importer 仅发布，runtime 只消费证据读取 |
| autopilot_state → resume → checkpoint → autopilot_state | Resume 的目标查询/会话解析移至 resume_read；CLI/pickup 编排留 resume；状态层只依赖查询 |
| target_paths ↔ scope_context | URL 所属/列表解析归 scope_context，底层类型/键/锁仍归 target_paths；迁移所有消费者，不用延迟反向委托维持环 |

共享 contracts 只含常量/纯函数，不新建业务 owner。保留仍有调用的 Resume 读取导出只作为同一函数引用；Scope 公共导入位置统一迁移，不复制算法。

## 文件发布

初查发现九个同形 JSON writer；逐项核对后将 36 个模块中的 40 个普通文件发布实现
统一到 tools/artifact_io.py（JSON、文本、JSONL、流式 inventory）：
同目录独立 NamedTemporaryFile → UTF-8 内容 → flush/fsync → replace → finally 清理。
JSON helper 固定 indent=2 和末尾换行；默认 ensure_ascii=False，原 ASCII/排序格式由明确选项保留。
OAST markers 的 indent=1/无末尾换行用文本原语保持。Recon URL 流保留逐行 hash 和过滤计数。
Runner 直接调用共享发布，不再通过 Action Queue 的私有 writer。
不添加后端、回调注册、配置框架或第三方依赖。

有意的机械行为改善：param_discovery 的固定临时文件改成独立 0600 临时文件并 fsync；
distill_digest 与两处 migration 激活 receipt 补文件 fsync；这些 receipt 也改用独立临时文件；js_reader 的共享 writer 可创建缺失父目录；清理覆盖
KeyboardInterrupt。没有新增目录 fsync 或跨文件事务承诺。
私密文件、Scope CAS、Store fence、独占 snapshot、多文件 manifest 的特殊发布保留各自协议，不能降低权限或耐久要求。

## 共享准入

Action Queue 内的证据引用定位/归属/非空校验被 Runner、Checkpoint、Autopilot 共用，
迁到 target_paths.target_owned_nonempty_evidence_ref，算法与拒绝边界不变。
敏感观察文本 regex/500 字符校验迁到 contracts，Runner 与 Case 共用；保留原异常文本。

## 保持与验证

模块移动保留函数体/常量，除去反向 import；导入改动逐项可核对。原子发布以真实文件字节、0600、写入/同步/replace 失败检查旧字节和清理。
新增 tools import 图无环检查，防止把延迟 import 当作结构解法；现有 Scope、Runner、记忆、Closure、浏览器、Store 测试证明业务契约。
不拆 autopilot_state 的高耦合投影族，也不为每个短小相似函数创建 util。是否合并按相同责任/语义决定，不以文件长度或重复文本百分比决定。
