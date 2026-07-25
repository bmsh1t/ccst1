---
id: wordpress-surface-intelligence
type: technique-card
related_skills:
  - web2-recon
  - web2-vuln-classes
  - triage-validation
trigger_tags:
  - wordpress
  - wp-json
  - wp-content
  - wp-admin
  - admin-ajax
  - xmlrpc
  - wordpress-plugin
  - wordpress-theme
risk: low
maturity: draft
load_priority: low
deep_refs: []
source_refs: []
---

# WordPress Surface 与版本情报

## Quick Recall

- 触发：明确 WordPress 指纹、`wp-json`、`wp-content`、插件/主题路径、`admin-ajax.php`、
  `xmlrpc.php` 或精确插件/主题版本。
- WPScan 是按需 inventory 工具：仅在目标价值和版本/覆盖缺口值得时运行，使用 `--enumerate p,t`；
  不加入用户枚举、密码字典或 password-attack 参数。
- `WPSCAN_API_TOKEN` 只在运行时环境中读取；raw JSON 保存到
  `recon/<target-key>/intel/wpscan.json`，不把 token 写入证据或知识库。
- WPScan 命中、文件存在或 HTTP 200 不证明插件已启用、版本受影响或漏洞可利用。

## 能力定位

本卡给 `web2-recon` 和漏洞验证提供 WordPress 特定的 inventory、版本和权限边界检查。它复用
现有 `/intel`、Action Queue 和 Finding 生命周期，不创建 WordPress 专用状态、解析器或自动漏洞执行。

## 触发信号

- httpx/Wappalyzer/响应头、HTML generator、`wp-includes` 或 `wp-content` 明确识别 WordPress。
- `wp-json` route、插件/主题 asset、源码或浏览器请求泄露 slug、版本或 REST namespace。
- 目标业务关键，或已识别的插件/主题与现有 Intel 覆盖之间存在版本或历史漏洞缺口。

## 按需 Inventory

```bash
wpscan --url "<target-url>" --format json --output "recon/<target-key>/intel/wpscan.json" \
  --no-banner --no-update --enumerate p,t --detection-mode mixed --max-threads 2 \
  --request-timeout 10 --connect-timeout 5 --api-token "$WPSCAN_API_TOKEN"
```

- 先确认 URL 属于当前目标；子域、端口和子目录安装保持原始观测路径。
- `p,t` 只用于插件与主题 inventory；不加 `u`、`-U`、`-P`、`--password-attack` 或 XML-RPC 密码测试。
- 读取 core、plugin、theme、main theme、version、`fixed_in` 和 CVE/GHSA/reference；再由 AI 选择少量
  高价值组件进入现有 `/intel` 或 Action Queue。

## 优先验证面

- REST：route 的 `permission_callback` 是否存在，匿名与低权限是否在对象、租户、私有字段或写操作上不同。
- AJAX：`admin-ajax.php` 的 `nopriv` action、nonce、当前用户 capability 和对象 ownership 是否分别校验。
- Nonce：nonce 主要绑定请求完整性/时间窗口，不替代用户角色、capability、对象或租户授权。
- XML-RPC：区分公开方法、认证门、multicall 行为和实际数据/状态影响；可达性不等于漏洞。
- Multisite：site/blog、network admin、super-admin、media/upload 和跨站对象边界分别比较。

## 最小验证

1. 先证明插件/主题已启用或由真实请求消费，记录精确版本与对应 URL/path。
2. 对 advisory 的 affected/fixed range 做版本判断，再确认目标路由或 action 真实可达。
3. 保持同一请求形状，只替换一个 actor、对象、权限或状态变量；保存 raw baseline 和差异。
4. 只有非预期数据、授权边界穿透或可复现状态影响才升级 Candidate；否则保持 Lead/Signal 并记录缺口。

## 常见误判 / 停止条件

- 历史 `wp-content/plugins/<slug>/` 静态文件可能来自缓存、备份或未启用残留，不证明运行态组件。
- `wp-json`、XML-RPC、REST index、nonce 生成和单一匿名 200 都是攻击面信息，不是授权绕过。
- 没有精确版本、启用/消费证据、受影响范围或可达路由时，不测试该历史 CVE。
- 同一插件/主题在多个路径出现时先合并证据，不对每个静态副本重复扫描。

## 关联 Skills

- `web2-recon`
- `web2-vuln-classes`
- `triage-validation`

## 晋升到 Skill / Queue 的条件

- 已有启用组件、版本范围和可达 route/action 时，创建一个现有 Action Queue 补证据动作。
- 有稳定的匿名/角色/对象/租户差异或可回读状态影响时，进入现有 Candidate 与 `/validate` 流程。

## 可晋升经验

- 多目标重复出现且由证据证明的插件 inventory、版本判断、REST/AJAX/XML-RPC 权限模式。
