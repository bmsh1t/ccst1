---
id: server-side-template-injection
type: technique-card
related_skills:
  - web2-vuln-classes
  - triage-validation
trigger_tags:
  - ssti
  - template-injection
  - jinja
  - twig
  - erb
  - freemarker
risk: high
maturity: draft
load_priority: medium
deep_refs:
  - knowledge/payloads/command-execution-probes.md
  - knowledge/playbooks/controlled-rce-validation.md
  - /root/tool/ccst/ctf-skills/ctf-web/server-side-exec.md
---

# SSTI / 服务端模板注入

## Quick Recall

- SSTI 先证明服务端模板求值 primitive，再判断是否能升级到文件读取、对象访问或受控命令执行。
- 入口常在邮件模板、预览、报表、CMS 富文本、错误页、通知、PDF/HTML 转换、主题/页面配置。
- 算术 marker、字符串拼接、模板错误、上下文变量和引擎指纹是早期信号，不等于 RCE。
- 命中模板求值后，再读取 `controlled-rce-impact` 做最小影响证明；不默认 reverse shell、webshell 或持久化。
- 示例表达式只作为候选形态，不是固定字典；Jinja/Twig/Freemarker/Velocity/Smarty/ERB 等引擎语法和 sandbox 差异很大。

## 能力定位

本卡给 `web2-vuln-classes` 提供 SSTI 输入面、指纹和升级路径。它负责发散和补漏，
受控执行证明仍交给 `controlled-rce-impact` 和检查层。

## 触发信号

- 用户输入被保存后出现在邮件、通知、PDF、HTML 预览、报表、后台审核或错误页面。
- 响应出现模板引擎错误、变量未定义、sandbox、render、template、Jinja/Twig/Freemarker/Velocity/Smarty/ERB 等线索。
- `{{...}}`、`${...}`、`<%=...%>` 等表达式产生可复现差异。
- 源码/JS/source-intel 显示 render template、mail merge、CMS block、theme render 或 document generator。

## 思路分支

- Reflected SSTI：输入立即进入服务端模板渲染。
- Stored SSTI：输入先保存，再由后台、邮件、预览、导出或异步 worker 渲染。
- Blind SSTI：不回显结果，但错误、延迟、OAST 或二阶页面出现差异。
- Code-context SSTI：输入落在已有字符串、标签、语句块或表达式上下文里，先闭合当前上下文再放入最小 marker。
- Sandbox escape：先识别引擎和上下文对象，再判断是否存在安全绕过。
- Chain：模板求值 -> file-read / config key / controlled command -> 业务影响证明。

## 技巧家族 / Payload 家族

- Primitive probe：算术、字符串拼接、变量解析、注释闭合、模板错误触发。
- Fingerprint probe：不同引擎的分隔符、运算符、过滤器、对象访问语法差异，例如 `{{...}}`、`${...}`、`<%= ... %>` 都只是候选形态。
- Context probe：读取无敏感上下文变量、模板路径、引擎版本或安全模式状态。
- Execution probe：只有 primitive 和 sink 明确后，按 `command-execution-probes` 做受控证明。
- 这些 probe shapes 用于单变量 fingerprint，不是固定字典；命中后先收敛到对应引擎和渲染上下文，避免跨引擎 payload spray。

## 补充 Checklist

- 是否区分客户端模板注入和服务端模板注入？
- 是否记录 store step 与 trigger step？
- 是否检查了邮件/通知/导出/PDF/后台审核这类二阶渲染？
- 是否确认模板结果由服务器生成，而不是前端框架渲染？
- 是否在升级 RCE 前证明了引擎、上下文和 sandbox 状态？

## 最小验证

- 建立正常输入 baseline。
- 单变量插入短 marker，比较渲染结果、错误类型、响应长度或二阶页面变化。
- 命中后优先证明引擎指纹和上下文边界；需要命令执行时转 `controlled-rce-impact`。
- Candidate 前需要 replay、baseline、trigger 位置、引擎证据和影响说明。

## 常见误判 / 死路

- 前端模板渲染、Markdown、字符串插值或日志格式化不等于 SSTI。
- 单次 500 不等于可控模板执行。
- 算术表达式被 WAF 或前端替换也可能产生假信号。
- sandbox 内只读变量访问未必有高影响，需要寻找业务连接器。

## 关联 Skills

- `web2-vuln-classes`
- `triage-validation`
- `bb-methodology`

## 晋升到 Skill / Queue 的条件

- 只有模板语法线索时，作为 Lead 做 baseline。
- 有 endpoint/input/trigger/marker 差异时，写入 action queue，类型 `server-side-template-injection`。
- 已证明命令、文件或敏感上下文影响时，转 `controlled-rce-impact` 和 `triage-validation`。

## 可晋升经验

- 某类业务功能反复出现二阶模板渲染。
- 某类引擎低风险指纹 probe 稳定有效。
- 某类 sandbox 误判或低价值结果应沉淀为 dead-end。
