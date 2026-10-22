# Autopilot 新目标启动修复

2026-10-22，基线 `f98398a`，实际 checkout：`ccst3/ccst`。
本轮继续既有修复，不创建或归档 Trellis 任务。

## 回归与修复

此前隔离复现：基线的全新目标在状态读取时因 Store 未初始化失败。工作区已有的
`autopilot_state.py` / `surface_projection.py` 修补让空目标返回 `handoff`，但不建库，
后续 loop-check 和 Round prepare 仍因 Store 缺失失败；显式 init 后可以继续。
历史 Store-only 收敛将读者改为依赖已有 Store，却未将启动初始化前移。
这与后来新调查的选择变化共同造成启动缺口；不能归因于最近一次纯文档精简。
删除旧 `if not has_recon: return run_recon` 的精确历史提交本轮未确认。

- 共享 Bootstrap 在参数、Scope/Auth/context、关键 runtime 检查之后，状态读取之前，
  调用现有 `initialize_target_store`；普通和 Round 入口共同受益。
- 显式/continuation 认证使用已有 `AuthSession.from_sources(env={}, ...)` 校验。
  列表先校验内容，选定子目标后校验 target 绑定；错误不建库、不公开凭据。
- Shared Automation 明确：无既有工作及可用材料的新/空目标默认 Recon，有可用材料可直接调查；
  旧目标缺 inventory 不强制重跑。Round 仍先 prepare、claim，再执行。
- `handoff` 的机器提示回指共享启动/结束合同，不再给出相反的“无需 Recon/可直接停”提示。
  Python selector 仍投影已有 owner 工作，不自行运行 Recon。
- 同步入口、Recon 模块、架构、lane 与两份开发规范，区分显式启动与只读状态查询。

## 针对性验收

```bash
python3 -B .trellis/workspace/Codex/research/10-22-autopilot-cold-start/check_startup.py
```

最终结果见 [result.json](result.json)：13 组检查通过，记录运行约 2.21 秒。
使用真实 Bootstrap、Store、loop guard、Round、continuation、runtime compare；
临时 runtime 含真实对应资源字节及归属 receipt，不跳过 drift 检查。
临时源码中的两个旧修补文件替换为基线字节，证明本轮修复独立成立。

覆盖新普通目标及 seed/quick 保留、Round 启动/幂等恢复、旧目标 Store 身份/revision/goal/
experience/Action/Scope/fence 保留、只读查询不建库、无效参数/Scope/context/auth、列表及
子目标绑定、匿名 continuation、legacy/preview/fenced-missing/damaged 拒绝、实际 runtime drift。
额外检查入口的 Recon/材料例外、claim 顺序、动态行/frontmatter/manifest/loop 身份。
独立只读复核发现列表与域名认证绑定混淆，已修复并加入正反案例。

子进程只加载白名单临时源码，清除 ambient 项目环境；audit hook 禁止网络、子进程及
真实仓库数据、tests、个人 Claude/Codex 目录读取，最终没有上述访问尝试。
准备夹具时出现的 context 参数格式和缺 runtime receipt 两项问题已修正；未绕过准入检查。

## 保留与边界

真实工作区以下既有改动未修改、未纳入本轮提交：

- `tools/autopilot_state.py`：`6cb58e7ff7a61a1e060ef8bd4ca62c912d9d6f103807d88d65368aca45e4dd9e`
- `tools/surface_projection.py`：`ac0a1b8c38c3d05c2f7aa015a607333185421e69c2103078404f448063243982`

未读取/修改/运行项目 `tests/`，未执行真实 Claude、Recon、付费模型或目标请求，
未同步个人宿主、迁移真实数据或 push。新目标 Recon 默认只完成入口合同验收，
尚无真实 Claude 执行轨迹；既有宿主不会因本地提交自动更新。

后续涉及初始化/恢复的改动，验收至少应实际贯通“新目标启动 → 首次消费/写回所需 owner”，
并复核旧目标与拒绝路径；文案、参数或预先建库的夹具不能单独证明新目标可启动。
