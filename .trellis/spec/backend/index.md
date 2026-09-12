# 后端开发规范

> 本目录记录当前仓库已经采用的目录、持久化、错误处理、日志和质量约定。

---

## 使用方式

开始修改 `tools/`、`memory/`、runtime 状态或测试前，先读取与改动相关的规范。规范描述
当前实现和已知技术债务，不把尚未落地的理想方案当成有效契约。

---

## Guidelines Index

| 规范 | 内容 | 状态 |
|-------|-------------|--------|
| [目录结构](./directory-structure.md) | Claude 命令、工具、状态、知识和测试的职责边界 | 已完成 |
| [持久化与状态](./database-guidelines.md) | JSON/JSONL schema、身份、原子写和迁移 | 已完成 |
| [错误处理](./error-handling.md) | 入口、核心逻辑、持久化和 CLI 出口 | 已完成 |
| [质量规范](./quality-guidelines.md) | 所有 backend 改动都读取：通用质量、AI/工具边界和专题索引 | 已完成 |
| [Runtime 与 Autopilot](./contracts/runtime-autopilot.md) | 修改 Claude CLI、启动、打包、长任务或子进程执行时读取 | 已完成 |
| [Recon 与 Surface](./contracts/recon-surface.md) | 修改 Recon、scanner 语料、coverage、Surface 或知识路由时读取 | 已完成 |
| [Browser 与 JavaScript](./contracts/browser-js.md) | 修改会话内 Playwright/Chrome DevTools MCP 证据、增量发现或 JS 分析时读取 | 已完成 |
| [Validation 与 Evidence](./contracts/validation-evidence.md) | 修改主动验证、证据门禁或 validation runner 时读取 | 已完成 |
| [Lifecycle 与 State](./contracts/lifecycle-state.md) | 修改身份、checkpoint、case、observation 或 Action Queue 时读取 | 已完成 |
| [外部集成](./contracts/integrations.md) | 修改 OAST、solver、spray、EBurst 或动态 token adapter 时读取 | 已完成 |
| [ScopeContext](./scope-context.md) | 多资产 Scope 解析、排除、分类和续跑身份 | 已完成 |
| [日志规范](./logging-guidelines.md) | stdout/stderr、JSONL、轮换和敏感信息 | 已完成 |

---

## 开发前检查

1. 确认目标状态的唯一 owner 和读写入口。
2. 搜索已有 identity/schema/normalizer，避免复制。
3. 明确缺失、损坏、中断和重复执行路径。
4. 新行为增加 focused regression；跨层契约扩大时增加 staging/localhost 测试。
5. 不读取或覆盖真实目标状态和用户未跟踪的 `.claude/`。

---

## 质量检查

- `git diff --check`
- 相关 focused tests
- `test "$(wc -l < .trellis/spec/backend/quality-guidelines.md)" -le 250`
- `! rg -n '^## (Scenario|场景)' .trellis/spec/backend/quality-guidelines.md`
- `test "$(rg -o './contracts/[^)]+' .trellis/spec/backend/quality-guidelines.md | wc -l)" -eq 6`
- `python3 -m pytest -q`（全量）
- 知识变更额外运行 `python3 tools/knowledge_audit.py --strict`
- Claude runtime 变更额外运行 `python3 tools/runtime_doctor.py --fail-on-drift`
