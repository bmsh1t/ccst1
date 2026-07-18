---
id: k8s-control-plane-boundaries
type: technique-card
related_skills:
  - web2-recon
  - web2-vuln-classes
  - triage-validation
  - security-arsenal
trigger_tags:
  - kubernetes
  - kubelet
  - rbac
  - kubernetes-service-account
  - nodes-proxy
risk: high
maturity: draft
load_priority: low
deep_refs: []
source_refs: []
---

# Kubernetes API、Kubelet 与 ServiceAccount 边界

## Quick Recall

- 触发：Kubernetes API、kubelet、service-account token、RBAC、namespace、pod/node 或
  `nodes/proxy` 信号。
- kubelet `10255` 主要是历史只读信息面；`10250` 才涉及认证 kubelet API 和 exec/run 等高影响路径。
- namespace/API 返回 200 只证明某个 read/list；使用 SelfSubjectRulesReview / SelfSubjectAccessReview
  确认当前身份对具体 verb/resource/subresource 的权限。
- `nodes/proxy` 可能形成 API server -> kubelet 的连接器，但必须证明当前 identity 拥有该 subresource 权限。
- Bound/Projected service-account token 必须检查 audience、expiry、namespace、service account 与实际权限。

## 能力定位

本卡是精简边界卡，只连接 Web/配置泄露、workload identity 与 Kubernetes 控制面证据。它不维护 CVE、
容器逃逸或大规模集群枚举清单，也不把单个 API 200 推导为 cluster-admin。

## 触发信号

- 响应、source/config、容器环境出现 API server、kubelet 端口、namespace、pod/node 或 RBAC 对象。
- 暴露 service-account token、CA、namespace mount、`KUBERNETES_SERVICE_HOST` 或 projected volume 配置。
- 当前身份能调用 authorization API、列举特定资源或访问 `nodes/proxy`、pods/log/exec 等 subresource。
- edge/proxy/SSRF 能到达 cluster internal endpoint，但尚未证明身份和操作权限。

## 思路分支

- Endpoint：区分 API server、kubelet 10255/10250、metrics、dashboard 和普通应用端口。
- Identity：记录 token issuer、audience、expiry、namespace、service account 和 caller group。
- RBAC：按 verb/resource/subresource/namespace/resourceName 建模，不以角色名称或 API 200 代替权限。
- Connector：SSRF/proxy -> API server -> `nodes/proxy` -> kubelet，需要每一跳身份和 allow 证据。
- Impact：优先无副作用 get/list/authorization review；exec、secret read、create/update/delete 需单独门控。

## 技巧家族 / Payload 家族

```bash
kubectl auth can-i --list --token TOKEN --server API_SERVER
kubectl auth can-i get pods/log --namespace NAMESPACE --token TOKEN --server API_SERVER
```

- API 自省族：SelfSubjectRulesReview、SelfSubjectAccessReview，优先于猜测 ClusterRole 名称。
- subresource 族：pods/log、pods/exec、pods/portforward、nodes/proxy；分别验证，不把父资源权限外推。
- token 族：legacy secret token 与 bound/projected token 的 audience/expiry/rotation 差异。
- endpoint 族：10255 只读信息、10250 authn/authz、API server proxy 的来源和身份传播差异。

## 补充 Checklist

- 当前请求到的是 API server、kubelet 还是代理后的路径？
- token 的 issuer/audience/expiry/namespace/service account 是否与 endpoint 匹配？
- allow 是否绑定 namespace、resourceName、verb 或 subresource？
- list/watch、get secret、impersonate、bind/escalate、nodes/proxy 是否分别记录？
- 是否只在自有 namespace/测试 resource 上验证状态影响并保留 read-back？

## 最小验证

1. 保存 endpoint/TLS/响应字段 baseline，确认组件身份，不由端口号单独下结论。
2. 对当前 token 做本地 claim decode，再用 SelfSubjectRulesReview/AccessReview 或 `kubectl auth can-i`
   确认具体 verb/resource/subresource。
3. 先验证单个只读、自有 namespace 资源；记录 allow/deny 与 resource scope。
4. 只有 `nodes/proxy` 等 connector 的每跳权限成立时，才规划后续 kubelet 验证。
5. 非预期敏感数据或受控状态动作齐全后进入 Candidate；其余保持身份/权限 Lead。

## 常见误判 / 死路

- `/api`、`/version`、namespace 列表或 10255 信息面不等于集群管理员权限。
- role/clusterrole 名称、通配 policy 文本不等于当前 token 实际绑定和条件成立。
- service-account token 存在不等于长期有效；audience/expiry 不匹配时可能完全不可用。
- 可读 pod metadata 不等于可读 secret、exec 或 node；subresource 权限不能互相外推。

## 关联 Skills

- `web2-recon`
- `web2-vuln-classes`
- `triage-validation`
- `security-arsenal`

## 晋升到 Skill / Queue 的条件

- 只有组件/端口/token 格式时保留为 recon/identity lead。
- identity 与具体 RBAC allow 齐全时，交给 `cloud-control-plane-pivots` 组织最小资源验证。
- 非预期 resource/subresource 影响可复现后，进入 `triage-validation`。

## 可晋升经验

- 多目标复现的 token audience、RBAC subresource 或 API server->kubelet 连接器边界。
