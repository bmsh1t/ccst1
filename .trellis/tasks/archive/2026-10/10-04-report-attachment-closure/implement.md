# F07/F08 实施计划

## 批次与顺序

1. [x] 用户批准最终摘要后激活现有子任务，读取 backend 开发规范与上下文清单。
   不创建新任务，不启动父任务或 F09；主线程负责最终方案、代码修改和验证。
2. [x] 在现有 fixture 上增加最小回归：A/B 草稿隔离、无关坏文件、受管链接协议、发布副本
   missing/changed 的 Store/index/event 闭包。先确认旧实现的失败确实对应 F07/F08。
3. [x] 在 `target_store.py` 定义一份 bytes 级受管引用识别 helper，排除代码/普通文本/外链，
   拒绝畸形受管声明；保留无引用和非 UTF-8 直接 artifact 的兼容面。
4. [x] 在 `report_generator.py` 用引用集合替换共享目录枚举，校验选中源文件，复用 `_publish_bytes`；
   保留正文逐字节、无覆盖、先附件后正文和已登记 stale 先拒绝的顺序。
5. [x] 在 Store 报告登记、报告当前性及交付事件入口闭合受管附件健康。摘要/文件快照在写事务前
   获取，mutate 内只做当前元数据与轻量文件身份复核；保持 command material、schema 和收据。
6. [x] 补足边界回归：直接 Store 登记、畸形路径/symlink/FIFO、同 revision 重读、历史事件保留、
   原件/技术判断不变、损坏不自动修复、中断同字节重试及预检后文件漂移。
   按 R1 修正“无引用也因旁边坏目录失败”的旧测试，另保留真实引用的危险目录拒绝用例。
7. [x] 同步命令说明和两份 owner 契约，执行下方定向检查。独立复核完整 diff 与真实入口，
   不把 publisher 层成功当作 Store 直接登记已覆盖。
8. [x] 检查任务验收，记录实际实现、验证和复核结果。
9. [x] 用户以“go on”确认提交计划，完成工作提交并归档本任务；归档记录和 journal
   分别单独提交，journal 引用工作提交；不推送，不自动开展 F09。

## 验收矩阵

| 要求 | 最小场景 | 结果证据 |
|---|---|---|
| R1 / AC1-2 | A/B 同目录；重复引用；无引用坏目录；有引用加无关坏成员 | 仅 B 的精确去重文件集合，原稿/原图不变，无无关读取 |
| R4 / AC2-3,7 | LF/CRLF、Unicode 标签、fenced/缩进/行内代码、外链、无后缀、畸形受管路径 | 支持工具原格式；不识别展示文本；声明错误显式拒绝 |
| R2 / AC3-5 | 缺失、改字节、空、symlink/非普通文件、登记/交付预检后漂移 | 发布/直接登记/新交付拒绝；无新报告、收据、revision 或部分元数据 |
| R2 / AC4 | 已有报告和历史交付后删改副本，再次查询/索引 | 同 revision 发现损坏；报告 stale，当前索引移除；历史保留，技术判断不受影响 |
| R3 / AC6-7 | 注册/索引中断；已登记损坏；健康重放；无附件直接报告 | 同字节中断可恢复；不补写损坏发布物；稳定 inode/收据/revision，API 与 schema 不变 |

## 定向验证结果（2026-10-06）

新增用例沿现有临时目录和隔离 Store fixture 组织，不另起测试框架。实际执行顺序如下。

### 实现前复现

```bash
python3 -m pytest -q tests/test_finding_index.py \
  -k 'report_attachment_publication_selects or report_attachment_damage_invalidates' --tb=short
```

结果：3 个预期失败，分别暴露共享目录混入其他草稿图片，以及发布副本缺失/变更未使报告失效。

### 首轮实现后

```bash
python3 -m pytest -q tests/test_finding_index.py tests/test_target_store.py tests/test_validate_target_mode.py \
  -k 'attachment or screenshot or attach_images or report or delivery_event or finding_authorization'
git -c safe.directory="$PWD" diff --check
```

结果：**130 passed**，随后 `git diff --check` 通过。涵盖 Store 报告契约、发布消费链及直接
validate 路径。这是后述两处复核修复之前的结果。

### 复核修复后

```bash
python3 -m pytest -q tests/test_finding_index.py tests/test_target_store.py \
  -k 'report_attachment_registered_retry or report_attachment_direct_replay or report_attachment_retry or report_registration or explicit_report_retry_does_not_repair or report_attachment_damage_invalidates'
git -c safe.directory="$PWD" diff --check
```

结果：**13 passed**，包含针对两处修复新增的 4 个参数化场景；随后 `git diff --check` 通过。
两批检查不是一次“134 项全通过”。最终独立复核没有要求进一步代码改动，因此未重复运行 pytest。
未运行全仓测试、构建、lint、typecheck、真实目标或网络验证；未执行安装、迁移或推送。

## 实施与复核记录

- F08 根因：发布器以共享目录成员而非所选正文决定附件集合。现在 publisher 与 Store
  共用 `report_attachment_refs(bytes)`；无引用不访问目录，精确引用去重后才读取和发布。
- F07 根因：报告登记与读取只核验正文。现在正文 digest 绑定受管文件名，文件名 digest
  绑定附件字节；安全读取拒绝 symlink、FIFO、空文件、摘要错误及观察到的文件漂移。
  Store 的登记、完整查询和新交付入口共享检查，原件、历史事件及技术判断不被改写。
- 首轮独立产品复核发现：已登记重试仍复制附件，可能补回健康预检之后删除的副本。
  已将所有正文/附件发布限定在未登记分支；已登记重试只检查发布副本，不依赖草稿截图。
  `test_report_attachment_registered_retry_never_republishes_files` 的 2 个场景覆盖源图缺失和
  预检后副本删除，并断言没有调用发布函数。
- 首轮独立产品复核还发现：直接登记重放可能绕过只在 mutate 内执行的正文事件检查。
  已在 `_command` 之前拒绝已登记 stale 报告，同时保留事务内复核，不改变 command material。
  `test_report_attachment_direct_replay_rejects_revoked_body` 的 2 个场景覆盖 availability/provenance
  撤销、旧收据保留，以及显式恢复后的幂等重放。
- 独立测试复核未发现重要验收缺口。最终由两个新的一次性只读探子分别核对上述修复和回归，
  均未发现阻塞项；它们未运行测试或修改文件。主线程复查最终产品、测试及契约 diff。
- `commands/report.md` 与两份 owner 契约已同步受管语法、当前健康、重试和文件/事务边界。
  没有新增 schema、持久化附件清单、owner、缓存或依赖，也没有扩展任意 Markdown/HTML 支持。

### 验收证据定位

以下测试均位于 `tests/test_finding_index.py` 或 `tests/test_target_store.py`。

| 条件 | 证据 |
|---|---|
| AC1 | `test_report_attachment_publication_selects_only_current_draft`：精确集合、重复引用、原件不变 |
| AC2 | 上述用例的 junk 场景；`test_report_publication_ignores_unreferenced_dangling_screenshot_directory`；`test_report_attachment_refs_only_interpret_the_managed_tool_protocol` |
| AC3 | `test_report_attachment_publication_rejects_invalid_selected_source`；`test_report_attachment_direct_registration_rejects_invalid_files`；`test_report_attachment_refs_reject_malformed_managed_paths` |
| AC4 | `test_report_attachment_damage_invalidates_report_and_delivery`：同 revision 发现损坏、索引剔除、历史保留、新交付拒绝、技术判断不变 |
| AC5 | `test_report_attachment_precommit_file_drift_is_rejected`；`test_report_attachment_hashes_stay_outside_write_transactions`；`test_report_attachment_delivery_rechecks_body_events_before_commit` |
| AC6 | `test_report_attachment_retry_preserves_published_files_and_receipts`；最终两处修复的新回归；既有 `test_explicit_report_retry_does_not_repair_registered_artifact` |
| AC7 | `test_report_attachment_free_direct_reports_preserve_existing_artifact_contract`；协议/原样正文用例；首轮包含直接 validate 报告用例；diff 核对 schema、command material 和无迁移 |
| AC8 | 两批定向检查及 diff check；命令说明、两份契约和独立复核 |

## 风险停止点与回滚

- 不得通过覆写正文、扫描整目录、原件 fallback、自动补摘要或新增持久化附件 manifest 解题。
- 不改技术 closure、轻量历史计数、真实目标状态、Store schema 或无附件历史 command digest。
- 不在写事务内哈希大文件，不嵌套现有 mutation lock，不声称文件与数据库跨介质原子。
- 验证只用临时目录与隔离 Store；发现真实目标/网络依赖时修正测试隔离，而非放宽断言。
- 回滚仅恢复本批两个产品文件、相关测试和契约；不执行数据迁移或删除历史报告。

## 收尾记录（2026-10-06）

- 用户已确认七文件提交计划。工作提交为 `fd02dc84cf829d418192354f72088c19ba20ed0b`，
  `fix: bind report attachment ownership and integrity`；提交前暂存 diff 检查通过。
- AC1–AC8 已满足，实现、定向验证与独立复核完成。提交阶段没有产品代码变化，未重跑 pytest；
  沿用上文明确区分的 130 项首轮结果和最后修复后的 13 项结果，不扩大验证声明。
- 本任务直接在 `main` 完成、没有 PR；使用 `archive --skip-branch-validation --no-commit`
  归档到 `.trellis/tasks/archive/2026-10/10-04-report-attachment-closure`，状态为 `completed`，
  保留真实分支元数据，不修改 `.trellis/` 忽略规则。
- 本记录随归档单独提交，随后 journal 单独记录并引用工作提交；不推送、不自动启动 F09，
  不处理其他历史任务、真实目标状态或全局安装。
