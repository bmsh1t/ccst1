# 第四批核查证据

基线：`7c3556d`；2026-09-28；单主会话。只读产品源码，写入任务记录和临时 fixture。

## Owner 与能力边界

| 链路 | 出处 | 当前契约 |
|---|---|---|
| Scanner 摘要生产 | `tools/vuln_scanner.sh:399-729` | 整数 lane 计数、execution_kind、continuation、原始材料索引 |
| 失败/完成发布 | `tools/vuln_scanner.sh:1569-1647` | partial 保留候选，不发 completion marker；summary 最后发布 |
| 摘要消费 | `tools/autopilot_state_read.py:204-265`、`tools/autopilot_state.py:1653,1691` | path/status/lanes 进入普通与 bounded state |
| residual/review | `tools/autopilot_gate.py:161-222` | 候选/采样/剩余输入必须保留复核 token，不自动 tested |
| 部署文件规则 | `tools/runtime_doctor.py:95-158,309-357` | compare/sync 共用 repo file 枚举；只管理 repo-owned Skill roots |
| 安装复制 | `install.sh:44-101` | shared/nested Skills、disabled commands、agents；存在已复现筛选差异 |

完整 manual-review 原文仍在 summary 指向的 target-owned 文件中；此次没有证据支持改写
scanner 执行链、重新设计 state owner、统一所有 JSON reader 或新增部署服务。

## 实跑复现

```bash
PYTHONPATH=. python3 .trellis/tasks/09-28-scanner-summary-deployment-contract/research/reproduce_contract_gaps.py
```

退出码 0，全部基线缺陷断言通过；执行时间工具返回约 0.02 秒。
脚本只运行临时 summary 的 reader/gate，以及从 install.sh 原文截取的文件复制循环；
未执行 scanner、完整安装器、网络访问、个人 HOME/runtime 或数据库迁移。

### F1：Scanner 输入损坏的处理分叉

| 输入 | 当前输出 | 已证实影响 |
|---|---|---|
| 合法 3/2/1 | valid，1 residual | 正常控制组 |
| 空 lane 字典 | valid，0 residual | 合法空控制组 |
| lane_coverage=[] | missing，0 residual | 已存在的错误容器伪装成无摘要 |
| 1.9/1.1/0.8 | valid，0 residual | int 截断产生假完整计数，丢掉复核残余 |
| input_total=Infinity | OverflowError | 未按损坏摘要产生 partial |
| 非 UTF-8 字节 | UnicodeDecodeError | 未进入其他坏 JSON 的 partial 路径 |

同一问题有两个计数转换点：reader `:230-251` 与 gate `:171-191`。
只修 reader 会让直接 state API 保留不同规则；两者需复用同一 Scanner 判定。
复现证明的是 malformed 输入的信息损失/错误形态，不证明真实执行输出过小数，也不证明
真实目标已经误耗尽。原始文件在读取前后字节相同。

### F2：安装复制后被 Doctor 判为 EXTRA

| Kind | 输入 | 临时复制后 |
|---|---|---|
| commands | autopilot.md | ok |
| commands | local.patch.md / local.PATCH.md | extra / extra |
| agents | autopilot.md | ok |
| agents | local.patch.md / local.PATCH.md | 未复制 / extra |

规则来自 Doctor 的 lowercase 后缀判断；安装器两段 shell 筛选不一致。
最小修复是对齐两个现有循环并用 parity 回归约束，不是部署管理器/新配置。
现有 tests/test_install_script.py 覆盖普通安装 clean、禁用命令、完整资源和升级重放，
但没有放入上述补丁样本；tests/test_runtime_doctor.py:340 仅覆盖小写 agent patch。

## 风险与不扩围

- Recon gate 也有相似计数逻辑，但其缺字段/blocking 规则不同，本轮不连带改动。
- 旧摘要 absent lane_coverage 保留原兼容；不能把显式错误容器与缺字段合并处理。
- Doctor 的 managed-root、disabled、sync/prune，以及 cp fallback additive 规则已有测试，
  不因局部筛选修复重写它们。
- 以上是本轮研究证据，不是尚未实施的新代码验收；第三批的 68 项通过不能移用。
