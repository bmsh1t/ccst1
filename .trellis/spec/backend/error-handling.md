# 错误处理规范

## 分层策略

错误处理按“入口解析 -> 核心逻辑 -> 持久化/外部工具 -> CLI 出口”分层：

- **入口解析**：用户参数错误应在执行任何目标动作前返回稳定、可展示的错误。
  `tools/autopilot_args.py` 把未知 flag、冲突 cadence 和无效 auth file 转为结构化
  `errors`，`autopilot_bootstrap` 据此停止。
- **核心逻辑**：可被其他模块调用的函数使用 `ValueError` 或领域异常表达非法状态，不能
  `print()` 后继续。`RuntimePhaseBusy` 是目标 phase 锁冲突的领域异常范例。
- **交互边界**：`tools/validate.py` 的 prompt 读到 EOF 必须抛
  `ValidationInputUnavailable`，不能把默认值当作肯定 gate；non-TTY 只能走显式
  `--decision-json` machine path。machine binding 预检使用
  `find_finding(..., migrate_legacy=False)` 只读 legacy payload；所有 binding 通过前不得触发迁移。
- **持久化**：写入失败必须清理临时文件并继续向上抛出，不能返回成功。原子 writer 在
  `except` 中只做清理，不吞掉原始异常。
- **CLI 出口**：`main(argv)` 捕获预期的 `KeyError`/`ValueError`，错误写 stderr，返回稳定
  非零码；`if __name__ == "__main__"` 使用 `raise SystemExit(main())`。

## 可恢复错误

以下情况允许就近降级，但必须符合数据含义：

- 可选 recon/browser/source artifact 不存在：返回空投影或 unavailable，交给状态层决定
  下一步，不能把缺失当作 tested-clean。
- bootstrap 发现 inventory summary 或 surface projection missing/stale/invalid：返回结构化
  `needs_sync`/`prepare_surface_context`，保持零 target-write，不能为“兜底”加载大型 body 或
  执行 ranking。recon 成功后的 surface finalizer 是明确的 best-effort 派生；失败必须保留 raw
  recon、输出 warning，并让后续显式 refresh 恢复。
- bootstrap 读取损坏的 canonical state 时返回 `stop_state_error` 和有界错误类型/原因；不得
  输出 traceback、覆盖损坏文件或继续目标动作。已有历史 probe summary 读取失败必须保持 partial，不能伪装为空。
- bootstrap 的 runtime compare 遇到 `OSError`/`ValueError` 时返回 `stop_runtime_error`；参数
  gate 仍优先，错误不得触发 target state 读取或自动 runtime sync。
- 可选 `distill/corpus/` 缺失时，case resolver 返回结构化 `unavailable`，普通
  `/kb`/知识路由继续；启用来源解析后发现 stale/invalid corpus、坏 offset/hash 或 dangling
  ref 时必须返回不可用结果，不能返回部分 payload 或伪可信摘要。
- append-only 日志单行损坏：跳过该行并在 stderr 输出文件/行号 warning。
- 非主链 telemetry、session summary 或 queue 同步失败：保留主结果，输出 warning 或
  `sync.status=skipped`。`HuntJournal.log_session_summary()` 是 best-effort 范例。
- capability profile 探测失败：返回 advisory unknown profile，不能阻断 target state；
  runtime drift 和参数错误仍是 blocking gate。
- subprocess cleanup 的 `communicate()`、process-group lookup、SIGTERM 或 SIGKILL
  异常必须保留 bounded stderr 诊断并返回失败语义；不得把空 stdout/stderr 当作
  `finished=true`，也不得静默跳过强制终止路径。

## 不可恢复错误

- 无效 target、非法状态迁移、缺少必需文件、schema owner 无法写入、知识 registry 不可
  解析等错误必须 fail-fast。
- 显式 Surface/index refresh 遇到 external sort 失败、坏 index 行、输入构建 race 或 manifest
  不匹配必须 fail-fast 且不得发布新 manifest/projection；不能退回首 N URL、stale cache 或
  materialized 全量 set 来伪装成功。
- `validate.py` 的 non-TTY 无 `--decision-json`、decision target/finding/endpoint/vuln class
  不绑定、四 gate/Q1-Q7/CVSS/evidence/report 任一缺失或 evidence ref 不可定位，均是写入前
  的参数/契约错误：stderr 输出恢复动作、返回 `2`，且不得创建 report、summary、ledger、queue、
  runtime 或 canonical finding mutation。
- 已存在的 action queue 若为坏 JSON、非 object、错误 schema 或 `actions` 非 list，owner 和 CLI
  必须 fail-fast 并在错误中包含 queue 路径；只有文件缺失可以投影为空 queue。
- 不允许 broad `except Exception: pass`。只有明确标注的 best-effort 派生、清理或日志
  路径可捕获 broad exception，并且必须保留可诊断结果。
- canonical state 损坏不能无提示地伪装成空状态。现有少数 legacy loader 的空回落属于
  已记录 P2 技术债务，不是新代码模板。
- 正式卡 governance log 有坏 JSON、重复 `event_id` 或非法 replay 时，audit 和后续 append
  都必须 fail-fast；诊断包含行号/card/event。修复使用新的补偿事件，不静默跳过后继续改写
  lifecycle。

## CLI 约定

- stdout 用于机器可消费结果或最终摘要；stderr 用于 progress、warning 和错误。
- 成功返回 `0`；没有可执行对象但不是数据损坏时可返回 `1`；参数/状态契约错误通常返回
  `2`。具体工具必须在测试中固定自己的语义，不能让调用方靠字符串猜测。
- 支持 `--json` 的 CLI 应保持字段稳定，错误同样结构化；Claude-facing bootstrap 尤其不能
  输出半结构化混合文本。
- `autopilot_state.py --projection-only` 只允许缩小 loop-check/closure 的序列化结果，必须保留
  schema、目标身份和命令消费者实际读取的完整字段；不带该参数的 full JSON/text 诊断入口
  必须继续可用，canonical state 损坏仍返回结构化 error，不能因投影缩小而变成空结果。
- `python3 tools/validate.py --target <target> --finding-id <id> --decision-json <file> --json`
  是唯一 non-TTY validation signature。decision 先完整验证，再经既有
  `finding_index` owner 写回；不得接受 stdin EOF、自然语言确认或直接 `findings.json` edit
  作为替代输入。
- `python3 tools/action_queue.py ...` 遇到 queue read/write 的 `OSError`/`ValueError` 时写 stderr
  并返回 `2`；不得把损坏 queue 当作没有 action 后继续 checkpoint 或 handoff。
- `target_case_state.py` 与 `coverage_matrix.py` 仅在状态文件缺失时返回空投影；已有文件损坏时
  owner 抛出带路径错误，CLI 写 stderr 并返回 `2`。checkpoint 不得吞掉损坏 case state 后继续。
- `surface.py`、`surface_index.py` 和 `observation_inventory.py` 的 schema/cursor/race/owner
  错误写 stderr 并返回 `2`。page cursor 的 target/revision/filter 不一致是明确错误，调用方从
  新 snapshot 重启，不能猜 offset 后继续。
- case resolver 的 `available|unavailable|stale|invalid|ok|not-found` 是机器契约；调用方按
  `status` 分支，不匹配 `reason` 文本。完整案例只允许显式单 ID `--full`，失败结果的
  `payload` 保持为空。
- 错误消息必须包含失败对象和可执行恢复动作，例如目标、candidate ID、文件路径或允许的
 状态集合；不要只输出 `failed`。
- Evidence runner 在任何网络 I/O 或 Action Queue 写入前必须校验绝对 HTTP(S) URL 属于当前
  canonical target；请求 cap 只限制采样量，若已完成所需样本，恰好耗尽 cap 仍按该 lane 的
  `tested`/`complete_no_hit` 或 `candidate` 语义收束，不能误降级为 `partial`。

## 直接执行与导入

项目工具既会作为 package 导入，也会直接执行。跨 `tools` 导入按现有模式处理：

```python
try:
    from tools.target_paths import target_storage_key
except ImportError:  # 兼容 python3 tools/example.py
    from target_paths import target_storage_key
```

只捕获 `ImportError`/`ModuleNotFoundError`，不能用 broad exception 隐藏模块自身初始化错误。

## 测试矩阵

- 合法输入 -> 预期输出和退出码。
- 缺参数/未知参数/非法状态 -> 无副作用、非零退出码、可操作错误。
- 缺失可选 artifact -> advisory/empty，不误报完成。
- JSON 损坏/半写 -> reader 行为明确，旧可读状态不被破坏。
- 写入中断 -> 临时文件被清理，原文件仍可读。
- best-effort 同步失败 -> 主结果保留且 warning/status 可见。
- non-TTY validate 缺/坏 decision -> exit `2`、所有 target-owned state 保持未创建或字节不变。
- legacy finding 上的 machine binding 失败 -> exit `2`，且 legacy payload 不迁移、event/report/
  summary/ledger/queue/runtime 不创建。
- action queue 损坏/非法 shape -> owner 抛带路径错误、CLI exit `2`；replace 失败 -> 旧字节不变、
  同目录临时文件清理。
- validation case state / coverage matrix 损坏或非法 shape -> owner 抛带路径错误、CLI exit `2`；
  replace 失败 -> 旧字节不变、同目录临时文件清理；checkpoint 遇到损坏 case state 显式失败。
- Surface/inventory 派生：missing/stale/corrupt summary/projection -> 不消费；atomic failure/race ->
  旧字节保留或无新 manifest；cursor snapshot 变化 -> fail-fast；recon finalizer failure -> raw
  artifact 保留且可由显式 refresh 重建。
