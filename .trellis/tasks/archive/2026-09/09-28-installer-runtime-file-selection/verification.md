# 安装文件筛选一致性：验收与提交计划

状态：实现、定向验收和规范同步完成，工作提交 8227cd2 已完成，进入收尾归档。
分支：`fix/installer-runtime-file-selection`；基线：`45fdf1e`。
前置 Scanner 工作为 `e755065`，已在 `45fdf1e` 归档；不重新运行其 67 项验收冒充本任务验证。

## 实现与维护边界

- `install.sh` 的 commands/agents 两个现有循环使用同一大小写字符匹配，排除 `.patch.md`。
- 保留既有 `*.md` 枚举，普通/近似名称文件仍安装；筛选发生在 disabled command 路由之前。
- 仅用已有 shell case，不新增外部命令、依赖、配置、库存服务或 Bash 版本要求。
- Doctor 产品逻辑未变，它继续拥有 compare/sync/prune 的源枚举规则；跨语言等价由现有回归约束。
- 不把安装改成 prune：已有 runtime 补丁仍显示 EXTRA，只由显式 Doctor prune 清理。

## 实跑验证

```bash
python3 -m pytest -q tests/test_install_script.py tests/test_runtime_doctor.py
```

退出码 0：**31 passed in 7.25s**，无 skip；完整输出：`research/final-check.log`。
测试使用临时 checkout/HOME/PATH，未执行个人 runtime 安装、真实扫描、网络探测或部署。

| 要求 | 证据 |
|---|---|
| AC1：大小写补丁不安装，普通文件不误过滤 | 既有升级测试加入两个 kind × 小写/全大写/混合大小写 patch，以及普通和 patch-notes 文件；每轮验证复制与源字节 |
| AC2：既有能力与用户状态保持 | disabled command、完整嵌套资源、外部 Skill、用户设置、私有材料、Store binding 和保存经验均沿用原断言 |
| AC3：两条安装路径可验证 | 系统 rsync 可用；隔离 PATH 分别选择 rsync 和 cp，各执行初装、升级及重复安装；cp 的 additive 行为与显式 prune 保持原样 |
| Doctor 不隐藏历史误安装 | 扩展现有 patch 回归为 2 kind × 3 spellings；旧副本仍为 EXTRA，显式 prune 不改源文件 |

按验证预算，通过后不运行全仓、构建、个人 runtime doctor 或重复测试。

## 差异与保护审查

- 已读完整相关 diff：产品仅修改 `install.sh` 两个筛选点；无额外 fallback、宽泛异常、状态写入、
  重复 owner 或无关整理。回归复用原升级/重放流程，没有新建平行安装测试框架。
- `.trellis/spec/backend/contracts/runtime-autopilot.md` 的现有七段契约已同步大小写、近似名称、
  原文件保留、旧副本显式 prune 与 rsync/cp 验收语义；无新增模板副本。
- `git diff --check` 通过。
- `sha256sum -c /tmp/fact-contract-baseline.vmDsm7/worktree.sha256` 两项均 OK。
  两份旧日志的暂存二进制 patch 与 `staged-before.patch` 经 `cmp` 一致；不调用改写它们的 session 记录工具。

## 提交计划

一个工作提交：`fix: align installer patch file filtering`。

- `install.sh`
- `tests/test_install_script.py`
- `tests/test_runtime_doctor.py`
- `.trellis/spec/backend/contracts/runtime-autopilot.md`
- `.trellis/tasks/09-28-installer-runtime-file-selection/` 的任务与验收记录
- `.trellis/tasks/09-28-scanner-summary-deployment-contract/` 的父任务进度记录

排除 `.trellis/workspace/Codex/index.md` 和 `.trellis/workspace/Codex/journal-1.md`；
获批后按精确路径提交，不使用裸 `git commit` 吞入旧暂存日志。当前尚未提交安装器修改。
提交后再归档安装器与父任务；不合并、不 push、不部署。

## 交付与归档

用户回复“提交”后已完成 `8227cd2 fix: align installer patch file filtering`。按既定收尾计划归档本任务与父任务；不调用会改写旧暂存日志的 add_session.py，归档提交同样限定精确路径。
