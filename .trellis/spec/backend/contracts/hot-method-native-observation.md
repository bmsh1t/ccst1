# 方法版本与无裁决原生观察

## 1. Scope / Trigger

修改 `hot_method`、Context Pack 方法目录、`record-observation` 或浏览器原件适配时读取。
本文取代旧 hot-method 的 focus/max-methods 选择合同；不改 TargetStore/schema、Finding、
cleanup 或共享知识审核 owner。方法准入唯一正文仍是
`knowledge/methods/clown/references/hunt-iter.md`，工具不代替主会话语义审核。

## 2. Signatures

```text
hot_method.py --repo-root ROOT --catalog --diagnostics --json
hot_method.py --repo-root ROOT --read RELATIVE --expected-manifest HASH --json
hot_method.py --repo-root ROOT --origin SOURCE_ID --json
hot_method.py --repo-root ROOT --apply INPUT --expected-manifest HASH [--bootstrap] --json
hot_method.py --repo-root ROOT --recover ID --mode complete|restore --json
```

Python owner：`build_hot_method_projection(repo_root=BASE_DIR, *, focus="", environ=None,
include_catalog=False, diagnostics=False)`；`read_methods(repo_root, paths, *,
expected_manifest, environ=None)`；`apply_update(repo_root, update, *,
expected_manifest=None, bootstrap=False, environ=None)`；`recover_update(repo_root,
transaction_id, *, mode="complete", environ=None)`。

`validation_runner.py record-observation` 调用 `record_native_observation(*, repo_root,
target, attempt_id, evidence=None, browser_capture_ref=None, execution=None,
expected_operation=None, action_id=None, claim_token=None, command_actor="validation-runner")`。
完整 CLI/envelope 位于 [evidence-runners](../../../../docs/evidence-runners.md#native-observation-registration)，
不要让 `record-evidence --finding-id` 变成可选 Finding 的同一分支。

## 3. Contracts

- catalog 完整、未排名；focus 不过滤方法，`bodies_read=False` 不冒称已读。`--read` 在同一
  knowledge 目录共享锁内捕获 manifest、选定正文及 context 依赖并验证实际 bytes/hash。
  v1 只读；v2 的 `CCST_CLOWN_SNAPSHOT` 仅选 origin-only，不允许外部根 apply/recover。
- v2 catalog/read 返回 `revision_validation=published_content`：核对匹配当前 manifest 的
  applied transaction/request/decision/receipt、引用 blob、origin 与独立 witness 字节。
  新 checkout 用当次目录/文件身份防读中变化，不绑定日志中的旧 dev/ino/uid/gid/mode；
  历史身份仍须形状合法。不会重建 witness、改日志或因 `.git`/异常自动降级。
- `ccst-hot-method/2` 区分 origins 原始 hash 与活动条目 `sha256`，`revision_ref` 绑定收据。
  普通 A 仅改 method/index；bootstrap 仅用于已批准的首次 v1→v2 工程接入。
  来源仅支持 `origin|private`；reviewer 是声明，不是认证。保留
  `private_source_unavailable`、`recorded_declaration_not_authenticated` 和来源缺损。
- 文件 owner 持独占锁：独立 create-only blobs、before/after inode 见证、新路径 slot →
  transaction → pending → 正文 → manifest → decision → receipt → 清 pending，各阶段 fsync。
  blob 不能硬链接成活动文件；见证不是不可变字节备份。目录/文件身份、mode、uid/gid 与
  hash 在 apply/recover 均须匹配（含当前版本前置及历史重试）；不支持的文件系统、ACL/xattr
  或 ownership 保留失败须在 pending 前拒绝。只读不强制这些写入用 metadata 限制。
  发布要求协调相关消费者/写者；锁不是对非协作进程的隔离。
- 同 ID/材料历史分派先于当前协议/CAS，历史 outcome 与当前健康分开；同 ID 换材料冲突。
  manifest 发布不是终态：decision 前仍可显式 restore；decision 固定方向，终态不可反转。
  checkout 的恢复身份不可移植；新 checkout 可读不等于可 apply/recover 原事务。本版不提供
  adopt/rebind；不能复制 F 收据作为 C 发布证明。
- 新观察严格为 schema=1、`kind=native-observation`；summary 的
  `lane=native_observation,result=""` 不产生 Finding、技术阴性或 Action 解决。
  使用真实 source/started_at、逐步 method/URL/family/observed_at 和有序原件；命令 actor
  不等于 HTTP actor，未知副作用仍 unknown/null。零 runs 仅限 unknown，不伪造 `:0`。
- 原件/summary create-only，registration receipt 独立；文件发布与 Store 登记不是同一事务。
  首次/无前驱走 `start_attempt` 的原 claim 与历史重试；有前驱复用原 attempt/source/start/
  action/token，不重新认领。补证发送完整有序快照，重试仍绑定原 predecessor。
- browser importer 一次捕获所选 export bytes，解析与 `network_source` 共用该版本。
  低层 `browser_evidence` fresh 校验路径/hash/长度，不联网、不写 Store、不反向导入 runner。
  旧 HAR 可用既有基线；旧 JSON 无基线不得补造历史 hash。缺响应保留 partial，登记失败
  只重试登记，不能重放浏览器动作。原始证据、目标私有事实不复制进共享方法正文。

## 4. Validation & Error Matrix

| 条件 | 必须观察到的结果 |
|---|---|
| pending / read CAS 不符 / 必需日志、blob、origin、witness 损坏或 symlink | 读取拒绝；无隐式修复 |
| 新 checkout 的旧事务 recover/普通 apply；本地第三态 inode 或 metadata | 可见拒绝，不自动重新绑定或覆盖 |
| applied 后 restore；restored 后 complete | terminal 拒绝，旧 receipt 不变 |
| pending unlink 后目录 fsync 失败 | 非零、cleanup durability unconfirmed；pending 可能已无，显式同向 recover |
| 历史成功但另一事务 pending | 返回历史结果和当前 pending，不能说当前可读 |
| 方法 changed/missing/来源缺损 | 保留诊断，不变技术阴性，不阻断独立 Store/冷卡事实恢复 |
| 观察坏 kind/lane、时间、原件或关联 | 显式错误，不落入 Finding 或静默 skipped |
| 观察 partial/unknown 或登记失败 | CLI 退出 1；输入错误退出 2；保留原件及准确登记重试入口 |
| 旧 JSON 无捕获基线 | `unverifiable_capture`；保留发现材料，不追认原件或自动重放 |

## 5. Good / Base / Bad Cases

- Good：真实受审 A apply 后另起进程 read，新完整正文、旧版本与真实来源/reviewer 可追溯。
- Good：Git 新 checkout 完整读取终态内容，仍保留 reviewer 声明及 private source 不可用诊断。
- Base：无 Finding 的 partial 观察保存真实 step，后续同 attempt 完整快照补证，旧记录保留。
- Bad：目录指针当正文已读、机械 accepted 当人审、空结果当技术否定、故障后自动重执行。

## 6. Tests Required

按受改合同选择针对性验证，不默认重跑全套。方法发布核心变化必须覆盖 complete/restore、
decision/receipt 后拒绝、身份/同步故障、两写者 CAS、历史重试和新进程 captured read。
读取分层变化另从拟提交树检出新 inode：完整 catalog/read、旧事务写入拒绝、日志/原件/
witness 缺损及硬链接 blob 反例，核对调用前后持久状态不变。
观察适配验证真实 Store operation/step、无 Finding、claim 改派后的精确重试、原前驱补证、
partial/unknown、原件变化与零网络重放；既有 Finding/cleanup 路径保持原合同。
相关已有回归：`tests/test_validation_runner.py`、`tests/test_browser_analysis_fidelity.py`、
`tests/test_target_store.py::test_unknown_external_effect_can_be_supplemented_without_reexecution`。
本次完整临时验收矩阵与回执见
[实施记录](../../../tasks/10-14-6k-full-integration/research/implementation-progress-2026-10-16.md)、
[A6](../../../tasks/10-14-6k-full-integration/research/a6-acceptance-2026-10-17.md) 和
[B6](../../../tasks/10-14-6k-full-integration/research/b6-cutover-2026-10-17.md)；不新增项目测试设施。

## 7. Wrong vs Correct

Wrong：hash 健康检查后另开可变文件；把复制的见证当原恢复身份；失败后删 pending。
Correct：读取锁内捕获的已验证内容；写入仍用本 checkout 的真实身份；检查 decision/receipt，
只用返回的显式 recover 同向完成。外层包装超时同样不代表未发布，先留存输出/调用记录。

Wrong：改已发布 summary 或只传新增 step 补证；用登记时间、当前 claim 替代原执行身份。
Correct：保留旧材料，以原 attempt/真实时间/完整快照/原 predecessor 建新登记版本。
