# Enable On-Demand Intel Advisory Expansion

## Goal

让 `intel-review.json` 继续承担默认上下文的有界索引，但不再成为 AI 的能力上限。
AI 必须能够根据组件、版本、目标主机、严重度、适用性或其他现有证据筛选并分页读取
`intel.json` 中被省略的 advisory，然后通过现有 Action Queue 记录 reviewed/deferred/
dismissed 或可执行 applicability 验证。

## Confirmed Facts

- `intel.json` 是完整 advisory 事实 owner，当前可能达到数百 MB；不能删除、重写或把完整内容注入默认上下文。
- `intel-review.json` 已按 component@version 分组、保留代表项并记录 `omitted_count`，但没有省略 group 的可选索引，也没有 query/page/cursor 入口。
- `intel_continuation.py` 在 sidecar 有效时只消费 representatives；没有省略项时仍可能直接返回 `complete`。
- Action Queue 已提供原子写入、稳定去重、最终状态和结构化 metadata；本任务不新增数据库、事件总线或 writer 抽象。
- 当前工作树包含用户已有未提交文件；本任务只修改本任务列出的代码、文档和测试。

## Requirements

1. 保持默认路径有界：sidecar 的 group、代表项、gap、metadata 和启动 compact state 仍受固定字节/条数限制。
2. sidecar 必须暴露有界的省略 group 索引（group key、组件/版本、数量、排序提示和重新激活条件），不能因为固定 group 上限隐藏 group 的存在。
3. 增加只读 advisory query API/CLI，支持 component、version、host、severity、applicability、KEV 等已有字段过滤，结果稳定排序、固定单页上限、无重复游标并返回 owner binding/下一页信息。
4. query 只能读取并投影 raw owner；不得修改 `intel.json`、sidecar、Queue 或 Finding，也不得把不可信的 advisory 直接变成 finding。
5. continuation 在 representatives 处理完后，若存在未完成的 omitted group，必须返回可解释的 `review_intel_group` handoff，而不是错误 `complete`；已有 high-value representative 仍优先。
6. group review 必须能通过现有 Action Queue 的 target-owned metadata 记录最终 reviewed/deferred/dismissed 或后续验证，重复刷新不得生成重复 active work；group closure 绑定 owner fingerprint 和 group key，raw owner 更新后可重新激活。
7. non-sidecar/legacy artifact 继续兼容，损坏 canonical JSON 仍 fail-fast；不能用 fallback 把 invalid 当成空结果。
8. Autopilot bootstrap、state 描述和 `/intel` 文档必须能路由到 query/分页入口，但不把所有 advisory 预加载到 prompt。

## Acceptance Criteria

- [x] 单一组件含 20+ advisory 时，默认 sidecar 仍有界，同时显示该 group 的 omitted count 和可选展开入口。
- [x] 多组件 sidecar 的排序稳定，不会因某一组件 advisory 数量大而隐藏其他组件的 group 索引。
- [x] 相同 raw owner、过滤条件和 cursor 的 query 输出字节/顺序稳定；分页无重复、无漏项，超过单页上限可继续请求。
- [x] query 只读且 raw `intel.json`/`intel-review.json` 字节不变；owner binding 变化时旧 cursor 不被静默复用。
- [x] representatives 有最终 disposition 后，omitted group 返回 `review_intel_group`；group 被现有 Queue 记录最终 review 后，continuation 才能继续其他 lane 或 complete。
- [x] route/host-bound advisory、stale/not_affected 过滤和 legacy artifact 行为保持既有测试语义。
- [x] 相关 focused tests、Python 编译检查、`git diff --check` 通过；不处理 `hunt.md` runtime drift。

## Out Of Scope

- 不把所有 advisory 自动 materialize 成 Queue action。
- 不新增数据库、事件总线、Mutation Coordinator 或新的持久化 writer。
- 不重写 raw Intel、改变 advisory source 查询逻辑或扩大网络请求。
- 不拆分 `autopilot_state.py`，不治理其他已明确暂缓的 P2。

## Open Questions

无。单页大小、游标格式和 group action 名称由现有 bounded projection、Action Queue 和 CLI 约定选择，并以回归测试固定。
