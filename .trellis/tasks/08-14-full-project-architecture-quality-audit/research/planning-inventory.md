# 规划期仓库盘点

日期：2026-08-14

## 已确认产品边界

- 当前产品主入口是 Claude slash command/inline workflow；`agent.py`、`brain.py` 和
  `tools/hunt.py --agent` 是 legacy local-agent 入口。
- 完整主链为 scope/recon -> surface/context -> hypothesis/action -> validation/evidence ->
  finding/queue/checkpoint -> report/memory。
- 项目约定工具拥有稳定 schema、identity、replay 和落盘；AI 拥有假设、价值判断和最终升级/降级。
- runtime 产物和目标状态目录不是源码，审核测试不得依赖本机真实目标数据。

## 关键代码面

- Runtime/entry：`commands/`、`agent.py`、`brain.py`、`tools/hunt.py`、`tools/runtime_state.py`、
  `tools/autopilot_state.py`。
- State/evidence：`tools/target_case_state.py`、`tools/evidence_ledger.py`、
  `tools/action_queue.py`、`tools/checkpoint.py`。
- Knowledge：`tools/context_pack.py`、`tools/knowledge_registry.py`、
  `tools/knowledge_candidates.py`、`tools/knowledge_lifecycle.py`、
  `tools/knowledge_value_review.py`、`tools/capability_governance.py`。
- Integration/security：`tools/credential_store.py`、`tools/browser_mcp_import.py`、
  `tools/spray_contract.py`、shell orchestrators 和 scanner wrappers。

## 当前基线事实

- `HEAD`：`c2aca24 feat: explain knowledge card recall`。
- `main` 相对 `ccst1/main` ahead 1。
- 当前有 27 项未提交改动；用户决定以工作树为主、`HEAD` 为归因对照。
- 已知线索：`hunt.md` runtime drift advisory、trigger collision advisory、多 owner 最终一致性、
  协调器耦合和 legacy 双入口。它们尚不是本审核的预设 findings。

## 规划结论

- 保持单一综合任务，按工作流分段审核并统一交叉验证。
- 不使用子代理；主会话直接读取奠基文档和即将引用的代码证据。
- 不修改生产代码，不读取秘密内容，不运行真实目标或外部网络测试。
