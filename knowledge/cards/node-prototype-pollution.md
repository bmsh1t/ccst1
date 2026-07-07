---
id: node-prototype-pollution
type: technique-card
related_skills:
  - web2-vuln-classes
  - bb-methodology
  - triage-validation
trigger_tags:
  - node
  - prototype-pollution
  - json-merge
  - template-sink
  - vm
  - express
  - same-realm
  - monkey-patch
risk: medium-to-high
maturity: draft
load_priority: medium
deep_refs:
  - knowledge/cards/controlled-rce-impact.md
  - knowledge/playbooks/controlled-rce-validation.md
---

# Node Prototype Pollution / VM Sink 链

## Quick Recall

- Prototype pollution 不是固定打 `__proto__`；关键是目标是否存在对象 merge / clone /
  path set / query parser / config update，再看污染值是否进入权限、模板、渲染、VM 或配置 sink。
- 先从 source/JS/package/error 证据判断 Node/Express、`qs`、`lodash.merge`、`flat`、
  `deep-extend`、模板引擎、`vm`、`vm2`、`happy-dom`、`jsdom` 等。
- 最小验证优先使用唯一 inert marker 和响应差异，避免污染全局状态、角色字段或持久配置。
- 有污染 primitive 不等于 RCE；必须找到可触达 gadget / sink，例如权限字段、模板选项、
  parser setting、render config、VM eval 开关。
- JS runtime 边界也别只盯 `__proto__`：如果校验逻辑和攻击者代码共处同一 realm，可变原语/内建方法被 monkeypatch 后，也可能把“安全检查”直接翻成无效。
- 深挖时读取 `deep_refs` 中的 Node/prototype 深度参考，提取污染路径、gadget 思路和 sink
  建模，不照搬 RCE payload 或持久状态污染流程。

## 能力定位

本卡给 `web2-vuln-classes` 补充 Node/Express/JS 对象污染与 gadget 链思路。它用于
从源代码、前端 bundle、错误栈、package metadata 和 JSON/API 行为中识别可验证的
prototype pollution / VM sink 方向，不替代 RCE 受控影响证明。

## 触发信号

- 技术栈显示 Node.js、Express、Next.js API routes、NestJS、Koa、Hapi、Fastify。
- `package.json` / lockfile / source / error 中出现 `lodash.merge`、`merge`、`deep-extend`、
  `flat`、`qs`、`dot-prop`、`set-value`、`vm2`、`pug`、`ejs`、`handlebars`、
  `happy-dom`、`jsdom`。
- API 接收 JSON object、nested query、config/settings/profile/preferences/theme/filter、
  webhook body、workflow definition、template/render payload。
- source-intel 显示 `merge`, `defaultsDeep`, `Object.assign`, deep set, path assignment,
  recursive clone, `vm.runInContext`, template compile, SSR/render worker。
- 响应里出现对象属性默认值、role/permission/config/options/theme 字段随请求变化。

## 思路分支

- Pollution source：用户可控 JSON/query/body/cookie/config 是否进入 deep merge / path set。
- Persistence boundary：污染只影响单请求、当前用户配置、服务进程全局，还是持久存储。
- Gadget search：污染后的属性是否被模板、权限、序列化、渲染、HTTP client、parser 或 VM 读取。
- Auth impact：污染是否能改变自有账号的 role/permission/feature flag，而不是直接攻击真实账号。
- Template / VM impact：污染是否能打开 eval/render/script 选项，若涉及执行转 `controlled-rce-impact`。
- Cleanup boundary：若污染持久化，是否只在测试资源内发生，是否可清理和证明恢复。

## 技巧家族 / Payload 家族

- Key shapes：`__proto__`、`constructor.prototype`、dot path、bracket path、nested JSON、
  query parser nested object。
- Wire payload：用代理、请求日志或原始 JSON 文本确认线上请求真的包含污染 key；
  用 JS 对象字面量构造 `__proto__` 时可能被运行时当成原型 setter，导致 `JSON.stringify`
  后字段消失。
- Safe marker：使用唯一、无业务语义的 marker 字段观察响应、日志或只读回显。
- Config gadget：`options`、`settings`、`defaults`、`headers`、`view options`、template options。
- Auth gadget：`isAdmin`、`role`、`permissions`、`scope` 等只能作为自有/测试账号的假设验证，
  不能直接作用真实用户。
- Template/VM gadget：Pug/Jade AST、EJS/Handlebars options、`vm`/`vm2`/DOM renderer settings；
  命中后转受控 RCE 验证。

示例是候选形态，不是固定字典；只有 Node 栈证据、merge/path-set 输入和可观测 sink 支持时才测试。

## 补充 Checklist

- 是否有 source/lockfile/package/error 证据支持 Node 相关库或对象合并路径？
- 输入是否真的进入 deep merge/path set，而不是普通 JSON parse 后直接读取？
- 实际发出的请求体是否保留污染 key、必要绑定字段和当前会话上下文，例如 `sessionId`、
  CSRF、tenant/account id 等目标要求字段？
- marker 是否能在同请求、同 session、跨请求或其他对象上被观察到？
- 是否找到实际 sink，而不是只证明理论污染？
- 若 sink 是权限字段，是否只在自有/测试账号上验证？
- 若 sink 是模板/VM/RCE，是否转 `controlled-rce-impact` 并保留最小影响证明？

## 最小验证

- 优先 source / local reproduction / dependency advisory / sink grep，避免直接 live 试错。
- live 验证只使用一个唯一 inert marker，单请求、低频、测试资源内完成。
- 先证明 marker 影响一个非敏感、可观察字段，再寻找 sink；不要一开始污染 `isAdmin` 或执行相关字段。
- 对权限方向，用自有/测试账号比较 baseline 与 marker 后的只读权限差异。
- 对 RCE/VM 方向，只证明到 primitive/sink 可达；执行证明交给 `controlled-rce-impact`。
- 如果污染可能持久化或影响全局进程，先停为 Lead，要求测试资源、清理计划或本地复现。

## 常见误判 / 死路

- 能提交 `__proto__` 字段不等于发生污染；很多框架会丢弃或深拷贝。
- 单次响应 echo 了 payload 不等于污染成功；需要观察继承属性或 sink 行为。
- 依赖版本有 CVE 不等于目标可达；必须证明 vulnerable code path 被调用。
- 污染 `isAdmin` 没效果不代表无漏洞；可能缺少对应 gadget。
- VM/sandbox escape 需要实际脚本执行入口；只有 `vm2` 依赖不等于可利用。

## 关联 Skills

- `web2-vuln-classes`
- `bb-methodology`
- `triage-validation`
- `security-arsenal`

## 晋升到 Skill / Queue 的条件

- 只有 Node/依赖线索时，保持为 Lead，先做 source/package/sink 证据补强。
- 有明确 endpoint/input/merge-path/sink next question 时，写入 `tools/action_queue.py`，
  类型可标记为 `node-prototype-pollution`.
- 出现稳定 marker -> sink 差异时，交给当前 vuln lane 深入；涉及执行时转
  `controlled-rce-impact`。

## 可晋升经验

- 某类 Node 框架或包组合稳定出现污染 source 和 gadget。
- 某类 JSON schema / config API 容易暴露 merge/path-set 行为。
- 某类无 sink 的污染 primitive 多次低价值，应沉淀为 dead-end 条件。

## 源报告（on-demand）

- source_report_ids: `276031`, `2208860`, `188086`, `470519`, `470547`, `861744`, `187542`, `1668723`
- 用途：这些 ID 只作为本地案例库查询指针。只有当前证据已命中本卡触发信号，且需要真实攻击链形状、报告写作先例或相似案例时，才按需查询 gitignored 的 `distill/` 本地缓存；不要默认拉取全文，不把报告正文、目标域名、payload 或 PII 写入知识卡。
