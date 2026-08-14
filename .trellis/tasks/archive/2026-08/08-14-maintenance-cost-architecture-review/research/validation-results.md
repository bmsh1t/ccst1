# 验证结果

日期：2026-08-14

## 静态治理门禁

| 命令 | 结果 | 结论 |
|---|---|---|
| `python3 tools/runtime_doctor.py --fail-on-drift` | exit 1；overall drift 1；critical 0；advisory 1 | 仅 `/root/.claude/commands/hunt.md` 与仓库不同；本轮不治理 |
| `python3 tools/knowledge_audit.py --strict` | PASS；63 capabilities、61 documents、0 errors、0 warnings | Registry/文档治理有效 |
| `python3 tools/capability_governance.py --strict` | PASS；57/57 active cards、12 Skills、15 collision advisories | collision 是路由重叠提示，不是治理错误 |
| `git diff --check`（报告前） | PASS | 起始用户 diff 无 whitespace error |
| Trellis task validation | PASS；inline manifests 0 entries | 任务结构和 inline context 合法 |
| 四份 research Markdown `git diff --no-index --check` | PASS | 报告无 whitespace error |

未运行任何 `runtime_doctor --sync` 命令。

## 聚焦回归

命令对以下 8 个测试文件使用单一 `-k` 选择：

- `test_vuln_scanner_script.py`；
- `test_auth_session.py`；
- `test_target_case_state.py`；
- `test_target_profile.py`；
- `test_request_guard_tool.py`；
- `test_validation_runner.py`；
- `test_context_pack.py`；
- `test_autopilot_inline_contract.py`。

结果：**21 passed, 302 deselected in 2.03s**。

覆盖含义：

- executable upload 默认审批和显式批准路径；
- explicit auth file 缺失、跨来源/跨 CLI target 拒绝；
- target profile 与 request guard 的损坏输入、replace 失败和重试收敛；
- Ledger/Finding/Queue 三个 owner 分步失败后的同 operation replay；
- Finding canonical write 与 mutation event append 之间失败后的修复；
- collision 正向、负向、稳定顺序、selected/deferred 预算与 reason；
- inline 主控制器和 Legacy exact-resume 文档边界。

## 既有完整回归证据

上一批 upload/auth/profile 修复任务记录 **3390 passed**，并通过 scanner shell syntax 和
`git diff --check`；证据在
`.trellis/tasks/archive/2026-08/08-14-executable-upload-approval-gate/prd.md:88-98`。该完整测试发生在
`17e58b2` request-guard 修复前，因此本轮不把它用于证明 request guard；当前 21 项聚焦选择包含
request-guard 的三项 persistence 回归。

本轮是只读增量复核，没有重跑全量测试。现有完整证据加当前目标验证足以证明所引用契约；重复
运行全套不会提高维护成本结论的可信度。

## Legacy session 最小复现

使用 `/tmp` 创建 synthetic `agent_session.json`，原始内容为
`working_memory=SAMPLE, step_count=7`，再写入半截 JSON `{`：

```json
{"step_count_after_corruption": 0, "working_memory_after_corruption": ""}
{"persisted_step_count": 0, "persisted_working_memory": ""}
```

复现未访问网络或真实目标。它证明 `agent.py:1458-1489` 的 catch-all load + direct overwrite 会把
显式 Legacy exact-resume 历史静默重建为空，而不只是静态代码气味。

## 安全与环境

- 未读取 `.env`、`.private/`、真实凭据、真实目标产物或用户未跟踪文档正文。
- 未运行 scanner、浏览器、外部网络请求、包安装或真实目标动作。
- 未修改生产代码、测试、runtime 模板或用户已有工作树文件。
- 报告完成后的 Git 快照与起始快照一致。
