# 6k 完整接入：二次方案复审（2026-10-15）

## 结论与范围

本次回应“再次审核确认一遍方案”，不是实施批准。确认了 **2 项 P1、3 项 P2、1 项 P3**
方案缺陷，已修订设计、实施顺序及验收说明；没有实现产品功能或宣称 V1–V7 通过。
R1–R6、A1–A9、D1=A 不变：完整接入、唯一调查主控和活动方法正文，复用当前 Store/
记忆/执行/报告 owner；不改 schema、不建平行系统或项目测试设施。

实际仓库 C 为 `/root/tool/ccst(rename-_Ya66f2)/ccst3/ccst`。任务仍为
`.trellis/tasks/10-14-6k-full-integration`，状态 `planning`，没有设置当前任务指针。
本记录是 [历史方案审核](final-plan-review-2026-10-15.md) 与
[规划收尾记录](planning-closeout-2026-10-15.md) 之后的新发现；旧报告原文及当时结果保留。
最新合同以 [设计](../design.md) 和 [实施计划](../implement.md) 为准。

复审前 14 个任务文件与 79 个任务外脏文件的快照在
`/tmp/ccst3-plan-review2-20261015-xk3jxw58/baseline.json`、`before/`。
以下规划旧行号指该 before 镜像；源码行号指本轮未改的 C 源码。

## 已确认发现及处置

### R2-01 · P1：正文/入口提前改变，直到 B6 才更新版本

复审前 `implement.md:49–76,124–126` 已在 B2/B3 改活动正文及入口，却只推迟 manifest
bootstrap。`tools/hot_method.py:144–168` 会立刻把新字节视为 changed；
`skills/src-hunting/SKILL.md:91–96` 禁用不健康方法；
`tools/autopilot_bootstrap.py:857–873` 对 critical drift 停止启动。

**修订**：B1–B5 全部在隔离开发副本 S，验收在 F，C 保持原状。B6 先验收，再停用 C
读者/入口消费者及写者，核对 before，发布兼容代码，执行 C 自己的新 bootstrap，最后
发布入口/Rules/critical 清单；回读一致后才解除维护。F receipt 不是 C 发布收据。
整库切换不冒称原子事务；中断保持维护关闭，以逐路径守卫恢复，不回滚目标数据。

### R2-02 · P1：JSON “raw” 和 fingerprint 不提供原始捕获基线

`tools/browser_mcp_import.py:132–146` 用替换字符读文本后解析；`:417–419` 将结果重新
序列化为 `network.raw.json`；`:423,524` 的 fingerprint 来自公共 `requests.json`。
HAR 等附件则已有私有原件 metadata，见 `:248–256,454–465,536`。旧设计 §6 把这些
JSON 字节当原件，无法发现首次登记前 raw 已被改变，更不能恢复解码丢失的原字节。

**修订**：仅窄改 importer，让实际选中导出（含 HAR fallback）的同一份捕获 bytes
用于规范化与私有归档；summary 发布前绑定 `network_source` 的 path/sha256/bytes/format。
适配器从已核对的同一 bytes 严格解析，不以替换字符掩盖坏 UTF-8/JSON；V5 覆盖首次
登记前及之后的原件改变。历史 HAR 可复用已有 digest；缺捕获基线的旧 JSON 保留为
显式不可验证材料，需留存原始导出及新 capture 身份，不反向补造历史完整性。
identity/去重/清理算法保留；digest 不等于来源真实性或抗同时篡改认证。

### R2-03 · P2：一律验证当前 claim 会阻断历史登记与补证

`TargetStore.start_attempt`（`tools/target_store.py:1688–1708`）在首次调用核对 claim；
`_command:1336–1355` 在 mutation 前返回完全相同的历史收据。
`record_execution:1953–1996` 绑定原 attempt/predecessor，且检查 observation **集合**，
不是要求每一步都匹配 Action；`transition_action:1633–1636` 允许已有 operation 后释放
claim。`execution:3996–4014` 可展开原关联，但 attempt 没有原始 command actor 列。

**修订**：无 predecessor 原样调用 start，保留精确重试；有 predecessor 读原 execution，
核对 attempt/source/start，复用原 action/token，不重新 start/reclaim。不添加 blanket
current-claim preflight，也不虚构原 actor。补证 actor 可与首次登记不同，但该次重试
须保留自己的 actor；若输入关联须与原关联一致。V4 增加 claim 已释放/改派后的恢复。

### R2-04 · P3：kind 与 lane 的拼写/职责混用

复审前 `design.md:252,275` 混用 `native-observation` 与 `native_observation`。
现有 `tools/validation_runner.py:504` 按 lane 分派；
`tools/structured_findings.py:43–55` 读取 lane/result，不是仅看 kind。

**修订**：envelope/summary 固定 `kind="native-observation"`，summary 另有
`lane="native_observation"`。同步按 lane 分派并校验配对；候选消费显式排除该对。
未知/错配/缺损不落入旧 Finding 分支；合法旧 lane 仍按原合同处理。V5 增加错配断言。

### R2-05 · P2：参数指向 F，但执行的脚本和测试仍来自 C

复审前 `implement.md:159–176` 调用 C 的 tools/install/doctor。
`install.sh:6,43–44` 由自身路径选择源码；`tests/test_install_script.py:13,116–134`
由测试文件位置选根。`tools/context_pack.py:18,83–88` 在 import 时加载 registry，
`tools/knowledge_registry.py:286–298` 还允许 fallback；单传 repo-root 不能证明隔离。

**修订**：以显式逐文件白名单和 hash 从真实候选 S 构造 F，包含已有脏增量及实际依赖，
不是只拷 HEAD。所有脚本、installer、doctor、pytest 从 F 执行；断言核心项目模块
`__file__` 在 F，缺资产失败而不借 C 补足。排除 runtime/目标数据、私有材料、`.env`、
模型及越界符号链接。V7 验证代码来源与错误缺项路径。

### R2-06 · P2：只有 installer 的 HOME 隔离，其他环境仍可越界

`tools/hot_method.py:104–114,137–146` 会消费 `CCST_CLOWN_SNAPSHOT`；
`tools/target_store.py:812–824` 会探测 `HUNT_MEMORY_DIR`；
`tools/runtime_doctor.py:33–41` 读取 runtime override。旧命令只给 installer 临时 HOME，
不足以约束其他命令和 pytest 子进程。

**修订**：整组统一 `run_fixture`，`env -i` 加临时 HOME/XDG/TMPDIR/runtime/memory 根，
清除默认快照/认证/代理/PYTHONPATH，禁用用户 Python site 和 pytest 自动插件。
特殊用例只注入临时 override；cd 失败即退出，不能退回 C。保留独立 I/O/网络哨兵，
不把白名单环境称为操作系统沙箱。V7 增加污染环境和隔离缺项断言。

## 审阅依据与尚未证明边界

- 两个独立只读探子分别提供观察/恢复和切换/验收发现；主会话按关键源码位置复核并亲读
  架构、规划及交接原文。方法发布专项探子因服务限流未完成，不能称为该面的独立背书；
  主会话另核对了现有 hot_method、普通文件 publisher 和知识发布锁，未新增已证实阻塞项。
- 修订后另一次切换/隔离独立只读核对未发现新问题；该轮观察合同探子再次因限流无结果，
  不计为通过，相关修订仍由主会话对源码及差异作最终核对。没有重试产品命令来替代审阅。
- 六项修订限于任务内 PRD 状态、design、implement、能力矩阵、加载图及本报告；两个
  JSONL、来源/差分台账、历史报告、产品代码和已有脏工作树不属于本轮编辑。
- 白盒缺损原文未恢复，2.3 延期方法未证明效果，非 HTTP Store 生命周期不补，在线能力
  未实测。新 capture 绑定与 v2 方法发布都是待实现合同，不是本轮已完成能力。
- 个人 `/root/.claude` 的历史误安装仍没有可证明的恢复；本轮未触碰，也不纳入后续
  checkout 实施批准。安装/同步/提交/模型下载/真实目标操作仍不在本轮授权内。
- 本轮只做规划一致性、原文/来源绑定、注入预算及保护范围检查；产品 V1–V7 不执行，
  A1–A9 不勾选。修订后仍需用户另一次明确批准最终规划，才启动原任务。

## 最终规划窄检查：已执行并通过

在 C 运行以下临时检查，exit 0，检查器记录耗时 0.186 秒：

```bash
python3 -B /tmp/ccst3-plan-review2-20261015-xk3jxw58/validate_planning.py
```

| 检查 | 实际结果 |
|---|---|
| 原生 `task.py validate` | exit 0，无超大上下文警告 |
| implement renderer + wrapper | 6 个 manifest 正文及 PRD/design/implement 完整包含，124,571 bytes，无截断或仅路径退化 |
| check renderer + wrapper | 同上，124,563 bytes；两者均低于 131,072-byte 上限，未改全局限额 |
| 相对文件链接 | 33 条按所在 Markdown 目录解析，全部存在 |
| A 来源与当前副本 | 62 项原 hash、54 份当前副本 hash、62 个归档规划绑定及 MD/JSON ID 全部匹配 |
| B 差分台账 | 123 个不同对照源文件的登记 hash 匹配，不代表效果验证 |
| 需求与范围 | R1–R6/A1–A9/D1=A 原文未变；task/JSONL/来源及差分台账/历史报告未改；仅 6 个规划文件有差异 |
| 既有工作保护 | 79 个任务外脏文件 hash、NUL 分隔 Git 状态和 tracked diff 均与本次 baseline 一致 |
| 实施命令 | 两个 Bash 代码块 `bash -n` 通过，无 C-bound 验收命令；未执行其中的产品命令 |

临时目录保留 `validation-result.json`、`task-validator.txt`、两份 `*-context.txt` 和
`planning.diff`。任务目录受 Git ignore，差异审阅使用本轮逐文件 before 快照，不仅依赖
`git diff`。检查后仅把实际结果追加于本节，没有修改已检验的设计、实施计划或上下文。

六项已确认的方案问题已完成静态修订和规划核验，可提交本版最终审阅；不据此宣称
产品已接通、V1–V7 已通过或个人 runtime 已部署/恢复。任务继续保持 `planning`。
