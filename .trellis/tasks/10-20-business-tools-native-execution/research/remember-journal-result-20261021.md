# remember journal 已知缺口修复

2026-10-21，用户要求先补已知缺口。实战影响限于 Store 保存成功而 journal 失败后的操作
日志缺口；权威经验仍可召回。此次完成恢复行为，不重开知识归并或完整底座优化。

## 最终行为

- remember 的 Store 重放也检查 journal；缺失时补写，正常重试不重复经验或绑定日志。
- 日志使用可选 target/store/command 绑定，无新数据库/永久收据。ts/session 保留原行，
  同 ID 的其他日志内容改变为显式冲突；JSON 往返不会因 Python tuple→list 误报冲突。
- 追加与已有 GC/reset 日志处理共用稳定 sidecar flock；轮换算法和 reset 的过滤语义不变。
- 短写只撤自己未完整的尾部；完整写后 ack/fsync 故障重试识别已有行并同步，不再追加。
- 已提交后失败返回 partial/exit 2，保留原经验收据及生成/显式 command ID，提示按原解析
  输入和同 ID 恢复；不重跑网络动作。
- 保留旧无绑定行字节；首次补绑定明确无法推断旧行归属。判重仅保障保留 live/数字备份，
  不保留已显式清理的历史绑定。坏日志不能假报已经补齐。

## 验证与独立核验

命令：`python3 -B .trellis/tasks/10-20-business-tools-native-execution/research/remember-journal-check-20261021.py`

最终 exit 0，**61 项断言，1.290 秒**。固定 `6c2bd414476b042d050181d5d0246998af5daf8d`
临时源码副本只叠加五个本轮生产源码；真实 Store/CLI 接线使用合成数据、假故障。
覆盖正常/失败重试、原经验 revision、短写、完整写后报错/fsync、内容冲突、旧 schema、
坏行、数字备份/清理、跨 target/store、同命令并发与普通 append/GC，以及 reset 的
合成 journal block。首轮通过行为检查但临时目录 cleanup 因 cwd 尚在副本内失败；修正
fixture cleanup 后通过。独立核验指出的 JSON tuple 往返边界已修复并纳入最终检查。

两路 default 单轮只读 scouts 分别检查 journal/schema owner 与 CLI/GC/reset 接线；
未发现剩余阻塞问题。主线程亲自实施、最终验证及 diff 检查；`git diff --check` 通过。
验证脚本/本记录保存在已有任务 research，不修改项目 tests/。

未接触真实目标/日志/私有数据，不安装、联网、推送或归档。宿主运行、真实模型能力、
能力对照和 token 成本仍未验收；此项修复不声称全框架完美适配。
