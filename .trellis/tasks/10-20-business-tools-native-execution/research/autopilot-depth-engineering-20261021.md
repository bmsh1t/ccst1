# Autopilot 深度优化：工程验收

用户已授权实施与新的隔离靶场复测。沿用当前任务；不触碰项目 tests、个人 runtime、旧目标/报告或方法正文。

## 修改与边界

- 普通和 round 模式都消费动作后状态；仅 round 先登记终态心跳。handoff 保存连续性，实际用户/范围/预算边界、真实阻塞或证据支持的无值得继续问题才是停止依据；continue 不构成无限续跑命令。
- 当前问题展开完整方法，新身份按 `rules/dig-scope-workflow.md` §4.2.3 重判业务对象。报告影响区分实际观察与推断。
- 文档统一原生采集、真实时间/exit、准确 CLI 与失败阶段说明，保留执行/登记分离。
- Store v18 追加未绑定 Finding 处置；无观察、assessment、任何 Action 或 Coverage review 才能撤回/重开。前驱 CAS、幂等与原历史保留，replacement 仅另一 active Finding。
- 活动查询过滤先于分页，counts.total 是历史量，page.total 是活动量。Runner/Resume/Pack/Surface/Coverage 同步消费；新链接在事务内拒绝 withdrawn。

## 验收

运行 `python3 .trellis/tasks/10-20-business-tools-native-execution/research/check_autopilot_depth_20261021.py`：
69 assertions，2.32 秒，exit 0；结果 `/tmp/ccst-depth-fix-check-9ghs9c2_/result.json`。
临时源码副本中运行生产 CLI，验证撤回/重开、历史回放不改当前状态、错误前驱/绑定拒绝、活动分页及全/短消费者、Runner 原件旁路、并发单写、写故障回滚。
旧 HEAD 实际创建 v17 Store，再用新 CLI 私有备份升级，原 claim/history 保留。文档 curl 片段对本地 HTTP 成功/失败各执行一次，核对十六进制 trace 真实请求、body 与退出码；SQLite integrity/FK 和修改 Python AST 通过。

前三次未完成检查分别因临时副本缺 registry、私有 HOME 下 Git ownership、curl trace 折行匹配错误；均修验证脚本，未为这些问题改生产代码。

两路只读独立审核：Store/迁移/消费者无阻断项；提示/证据审核发现 `rules/dig-scope.md` 不存在，已改正确文件并同步 spec。6 个 CLI --help 参数匹配。主代理最终 `git diff --check` 通过。

## 尚未证明

工程检查不能证明模型深度改善；后续同 `claude-opus-4-8` 普通 `/autopilot` 新靶场结果单独记录。
两入口合计 15624 bytes，基线已 14959 bytes；旧 spec 的 11 KiB 预算既有漂移，本轮不声称通过该预算，也未读改运行相关项目 tests。
未安装依赖、修改个人配置、迁移真实 Store、外部提交或推送；v18 能力在旧目标上仍需明确备份升级。
