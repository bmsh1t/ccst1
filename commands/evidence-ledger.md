---
description: 查看当前目标 Store 中的执行证据、闭合状态与角色差异矩阵。用法：/evidence-ledger <target>
---

# /evidence-ledger

读取当前目标 Store 的执行观察。选择测试顺序、解释结果和决定后续行动由 AI 完成；摘要不创建行动或技术裁决。

## 只读查询

```bash
python3 tools/evidence_ledger.py summary --target <target>
python3 tools/evidence_ledger.py summary --target <target> --endpoint /api/accounts/42/export --vuln-class IDOR --json
```

当前事实来自 `state/<target-key>/metadata.sqlite3`。需要指定数据根时加 `--repo-root <repo-root>`。
未初始化、preview、缺库或坏库会非零退出；不会读旧 JSONL 补值或创建空库。
新目标使用明确的 `target_store.py init --store --target <target>`；有旧领域数据的目标使用显式导入。

## 登记已执行材料

`evidence_ledger.py record` 和 `--from-probe` 已退役。Probe 通过 Store 保存自己的 attempt 与 observation。
原生工具、浏览器或多步执行的材料通过统一 Runner 登记到已存在的 Finding：

```bash
python3 tools/validation_runner.py record-evidence \
  --repo-root <repo-root> --target <target> --finding-id <finding-id> \
  --evidence-json <native-evidence.json>
```

材料 JSON 必须包含明确的 `attempt_id`、带时区的 `generated_at`、`source`、`result`、
`observed_difference` 和 `runs`；每步给出实际 URL、method、actor 及目标内 request/response 引用。
完整格式见 `docs/evidence-runners.md#native-evidence-registration`。
登记不发请求；同一 attempt 的相同材料可重试，真实重跑必须用新 attempt。登记失败保留原始材料。
行动关联须显式传 `--action-id`、`--claim-token` 和 `--actor`；不会根据 URL 猜测并完成队列工作。

副作用由实际操作事实说明。确有状态改变时使用 `--state-changing --redline-checked`；
HTTP method 本身不决定副作用。部分执行、截断或未确认红线的副作用记录保留可查，不能授权已测闭合。
观察结果与技术裁决分开；Finding 的 confirmed/refuted/inconclusive 由后续显式 `/validate` 写入。

## Actor Matrix

`IDOR` / `Authz` / `GraphQL` / `CSRF` 的适用矩阵展示实际尚缺的 actor/object/replay 条件：

```text
anonymous / none / unauth_denied
owner / own_object / baseline
peer / other_object_same_org / id_swap
low_role / own_object / role_diff
cross_tenant / cross_tenant_object / tenant_diff
owner / own_object / token_missing
owner / own_object / origin_diff
```

后两项用于 CSRF。公开页面可匿名访问不等于受保护资源已经完成 Authz 验证。
相同 endpoint 的不同 method、actor、对象范围及实验身份不互相覆盖；开放 family 的证据可以保存，
但不会凭未知类别自动关闭标准 Coverage。

## 输出与恢复

摘要给出来源 Store/revision、记录数量、最近观察、闭合单元、角色差异和证据损坏诊断。
最近窗口不限制当前闭合计算。损坏材料保留历史行，同时压制相应授权。
`/context-pack` 与 `/checkpoint` 读取同一事实源，展示缺口和展开入口；AI 自己决定是否显式创建行动。
旧 `memory/evidence/<target-key>/ledger.jsonl` 只由历史检查或迁移工具读取，不是当前运行后端。
