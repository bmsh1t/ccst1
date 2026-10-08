# F01–F05 当前验收映射

2026-10-08，基线 `a31535d`。两个 default/fork-none 只读探子核对测试与 owner；主线程完整阅读
F01/F02 六份原始规划、F03–F05 PRD、架构，并抽查关键原文。未运行测试、collection、产品命令或网络。

## F01：认证来源替换

- 工作提交 `4646762`；`AuthSession.export_to_env` 在 `tools/auth_session.py:394` 清理八键后应用选定 overlay。
- `tests/test_auth_session.py:43,90,106,127,154`：18 种导出组合、默认 environ、12 个真实 Bash helper 组合、来源优先级、绑定冲突。假凭据，无 HTTP。
- `tests/test_validation_runner.py:657` mock 实际 runner 检查 auth-file/raw-header 优先级；`:524` 直接检查越界 redirect；`:574` 两个 `127.0.0.1:0` listener 检查不允许的 origin 去头、显式允许的 origin 只重放 session 头。
- listener 不可创建会 skip（`:592,613`），不能视为完成。finally 关闭服务；Bash helper 每次 timeout 10 秒。
- `request_once(..., repo_root=BASE_DIR)` 在 `tools/validation_runner.py:619–635` 读取 Scope；`tools/scope_source.py:43–57` 还可能发现原 repo 的 Store/profile。必须在固定提交源码副本运行，不读取实际工作区状态。
- `urllib.request.build_opener` 读取环境 proxy；白名单环境清除代理并显式 NO_PROXY loopback。Shell 使用 `os.defpath` 找 Python，记录系统 Python，不假定任意 venv 等价。
- 原任务 `implement.md:29–36` 有历史 **37 passed**，并非缺少所有历史证据；journal 无条目只是记录缺口。本轮仍需新验收。

## F02：锁继承与清理

- 工作提交 `14f0261`；`tools/runtime_phase_exec.py:29–55` include_fd/pass_fds；`tools/runtime_state.py:249–256` 继承路径 close 而不显式 unlock。
- `tests/test_runtime_phase_execution.py:164,191,206,335,340,344,350`：direct/hunt、recon/scan、0/17/124、busy、信号、超时、leader 先退出、spawn failure、argv/env/cwd/流输出。
- `:212–280` 独立 Linux subreaper 核心回归：只杀 wrapper，存活 child 保持 wait；重复启动 75、不改 marker；finally 回收 child 后锁可重取。内部软期限 20 秒，外层 35 秒。
- `tests/test_runtime_state.py:338,376,400`：父上下文退出仍持锁、有效 FD 与 timeout/signal-handler 接线、异常 marker。
- 临时脚本替代真实 recon/scanner；仅自建进程。普通 signal 测试将 zombie 视为不再运行，不能声称全部孙进程已 waitpid；严格回收由 SIGKILL reaper 证明。
- 要求 Linux /proc、flock、signals、prctl。组级预算 120 秒，防止挤占内部清理余量；失败需核对本次测试残留，不批量杀其他进程。
- 原任务 `implement.md:33–39` 有历史 **34 passed** 和提交记录；两处旧 FD 预期已更新，没有必需新增的回归。

## F03：部分执行与显式恢复

- 工作提交 `b460f05`；`tools/validation_runner.py:433,457,503` 发布真实 partial/unknown 并从已存材料登记；`tools/target_store.py:1388` 放行 partial 同 family 的 control。
- `tests/test_validation_runner.py:2873` 原 summary 重载和 blocked 前后去重，HTTP/raw/attempt 不变；responses=0/1 保留 unknown/partial，不伪造 subject/Finding 证据，不得完成 Action。
- `tests/test_target_store.py:880,913` 覆盖 outcome/endpoint/family、所有 attempt 登记、actor/token/version；原 subject 绑定、坏材料、unknown predecessor、partial 不确认与完整执行节点保留。

## F04：完成提交时的证据授权

- 工作提交 `704009c`；`tools/target_store.py:992` 事务前验证，`:1077–1083` writer 内重读所有 artifact 最新事件；`:757` BEGIN IMMEDIATE。
- `tests/test_target_store.py:2040` subject/control × availability/provenance 竞态，保留独立 invalidation、claim/version/raw，拒绝时无 completion/receipt；恢复后可重试及去重。
- `:2109` 断言 proof hash 只在 writer 前发生；`:2147` 无关事件不阻挡。保留 stale/unbound/损坏、回滚、CAS、非 execution work、完整 operation 和 native claim 节点。
- 不承诺对任意外部文件写入原子，也不扩大到已有 metadata 引用的 hash 行为。

## F05：当前授权与 actor coverage

- 工作提交 `70871aa`；`tools/current_truth.py:63–121` 捕获完整 invalid_event_ids，`tools/evidence_ledger.py:333–367,407–430` 先处理 succession/最新结果，再判授权，避免旧 covered 复活。
- `tests/test_evidence_ledger.py:245,299,335,209` 覆盖 changed/missing/unavailable/revoked/control、空/回溯 successor、独立记录、历史 v2/result、method/actor。
- `tests/test_current_truth.py:184,233,335` 覆盖截断/不可定位损坏、单快照及下一读重查、已有 truth 不二次读取。
- `tests/test_context_pack.py:776` / `tests/test_checkpoint.py:1878` 通过真实 seam 证明 raw 损坏后 pending/gap、历史不丢、Store binding/actions 不变；不为每个消费者复制 owner 的完整矩阵。

## 隔离与选择

F03–F05 共 29 个函数节点静态存在，精确列表在 `implement.md`。所选 runner 请求 fake，目标和证据是 tmp_path；仅 CAS 节点有两条线程，无真实 HTTP/process。Context Pack 只读副本的知识注册表。
所选节点无 skip/xfail；仅导入的 HTTPServer/multiprocessing 不等于执行它们。C 的 Store 节点不命中 D 的报告选择器，不重复运行。

当前缺口是新验收和记录，不是缺少产品实现。未经最终计划批准不运行这些命令；源码测试、历史计数和当前通过结果分别记录。
