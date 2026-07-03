---
description: 记录和检查当前目标的 endpoint 级测试账本与角色差异矩阵。用法：/evidence-ledger <target>
---

# /evidence-ledger

检查或记录 Evidence Ledger。

这个命令不是扫描器，也不是新的并行工作流。它服务于 `/context-pack`、
`/hunt`、`/autopilot`、`/checkpoint`：把“测过什么角色、什么对象、什么 replay
变体、结果是什么”结构化记录下来，防止只测单账号成功路径就收工。

## 默认只读

先运行 summary：

```bash
python3 tools/evidence_ledger.py summary --target <target>
```

可按 endpoint 聚焦：

```bash
python3 tools/evidence_ledger.py summary --target <target> --endpoint /api/accounts/42/export --vuln-class IDOR
```

默认读取：

```text
memory/evidence/<target>/ledger.jsonl
```

如果文件不存在，不要当成“已覆盖”；这表示 actor/object/replay 覆盖还没有结构化记录。

## 显式记录

只有实际完成某个低风险验证后，才 record：

```bash
python3 tools/evidence_ledger.py record \
  --target target.com \
  --endpoint /api/accounts/42/export \
  --method GET \
  --vuln-class IDOR \
  --actor peer \
  --object-scope same_org_other \
  --variant id_swap \
  --result tested_clean \
  --source browser \
  --browser-observed \
  --replayed \
  --evidence-ref recon/target.com/browser/xhr_endpoints.txt:1
```

状态改变动作必须先过红线检查。HTTP method 本身不是红线：POST 常用于只读查询、
搜索、GraphQL query 和浏览器观察到的 API replay。只有具体动作会写入/删除/
改变真实业务状态时，才需要按红线处理，例如 PUT/PATCH/DELETE、GraphQL mutation、
admin action、payment action、upload canary、OTP/MFA 尝试、SAML 伪造提交等。
这类动作只有使用测试资源、可回滚、低频且符合 `rules/red-lines.md` 时，才可以
记录为已测试：

```bash
python3 tools/evidence_ledger.py record \
  --target target.com \
  --endpoint /api/accounts/42/role \
  --method PATCH \
  --vuln-class Authz \
  --actor low_role \
  --object-scope own \
  --variant role_diff \
  --result blocked_redline \
  --notes "真实角色修改有破坏性，保持 Lead，需测试组织授权"
```

如果安全完成了状态改变类验证，必须加：

```text
--redline-checked
```

## Actor Matrix

对于 `IDOR` / `Authz` / `GraphQL` / `CSRF`，默认矩阵关注：

```text
anonymous / none / unauth_denied
owner / own_object / baseline
peer / other_object_same_org / id_swap
low_role / own_object / role_diff
cross_tenant / cross_tenant_object / tenant_diff
```

CSRF 还会关注：

```text
owner / own_object / token_missing
owner / own_object / origin_diff
```

## 输出解释

```text
EVIDENCE LEDGER
- Entries:
- Red-line unchecked state-changing records:
- Recent entries:
- Actor matrix gaps:
- Record commands:
```

`Actor matrix gaps` 非空时，不能声称该 endpoint 的 authz/IDOR/业务逻辑路径已经完整覆盖。

## 和其他层的关系

- `/context-pack`：执行前把 actor gap 放进上下文。
- `/checkpoint`：结束前把 actor gap 变成 next action。
- `/retrospect`：只沉淀可复用经验，不把所有 ledger 行写进知识库。
- `coverage_matrix`：负责 endpoint × vuln_class；Evidence Ledger 负责 actor/object/replay。
