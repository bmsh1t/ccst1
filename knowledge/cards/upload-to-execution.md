---
id: upload-to-execution
type: technique-card
related_skills:
  - web2-vuln-classes
  - web2-recon
  - triage-validation
trigger_tags:
  - upload
  - file-parser
  - webshell
  - upload-execution
  - parser-chain
risk: high
maturity: draft
load_priority: medium
deep_refs:
  - knowledge/cards/upload-parser.md
  - knowledge/payloads/controlled-shell-primitives.md
  - knowledge/playbooks/controlled-rce-validation.md
---

# 上传到执行链

## Quick Recall

- 上传漏洞不只看扩展名绕过；关键是上传后文件是否被执行、解析、转换、预览、包含或由高权限上下文读取。
- 默认先证明处理链和路径控制，不默认上传持久 webshell。
- webshell / script execution 属于高风险受控影响证明，需要当前轮明确授权、测试资源和清理计划。
- 最小证据优先：上传路径、访问路径、解析器行为、权限边界、一次性 marker 或无害执行差异。
- 未保存原始 upload/read-back 请求与响应时，只能作为 lead，不能升级为稳定能力或结论。
- 深挖时优先使用本卡和 `upload-parser` 中已蒸馏的 polyglot、
  MIME/扩展/metadata/解析链思路；历史外部来源只在审计文档中追溯，不把 webshell 上传变成默认动作。

## 能力定位

本卡补充 `upload-parser` 的高阶分支：当上传/导入/解析链可能通向执行时，
将 webshell、polyglot、wrapper、解析器差异等高风险技巧转译为受控影响证明。

## 触发信号

- 上传目录可 Web 访问，或文件 URL 可被直接请求。
- 支持 PHP/JSP/ASP/模板/脚本扩展、大小写扩展、双扩展、服务端 include、插件/主题上传。
- 图片、SVG、PDF、Office、ZIP、HTML、Markdown、模板文件进入转换器、预览器、渲染器或后台任务。
- 响应、错误或 source 显示服务端根据扩展名、MIME、magic bytes、文件名或 metadata 分派处理器。

## 思路分支

- 存储路径 proof：证明攻击者可控文件进入服务端可预测位置，并区分默认上传目录与 filename/path 影响后的目标目录。
- 访问路径 proof：证明上传文件可被直接访问、预览、下载、分享或后台读取。
- 解析器 proof：证明服务端处理文件内容、metadata、外部引用、压缩包条目或模板语法。
- 执行 proof：在明确授权下用一次性、可清理、无持久化方式证明服务器端执行。
- Chain proof：上传 -> 解析器 SSRF/XXE/LFI/SSTI -> controlled RCE 或内部影响。

## 候选形态 / Probe 家族

- 以下形态是按证据选择的候选形态，不是固定字典；每次只改一个维度，命中或明确无差异即停止。
- 扩展/声明 MIME/magic bytes 差异：双扩展、大小写、后缀解析、multipart part `Content-Type` 与实际内容不一致。
- 文件名/目录选择差异：路径分隔符、编码 parent segment、后端 normalize 行为只作为候选形态；必须同时验证原上传目录和目标目录的 read-back 差异。
- Polyglot：合法图片/ZIP/PDF/SVG/HTML 与服务端解析差异。
- Server config 邻近风险：`.htaccess`、`web.config`、模板/主题/插件目录。
- Metadata 触发：EXIF、XMP、文件名、压缩包条目、Office XML 外部引用。
- Controlled shell primitive：只在 deep ref 条件满足时读取，不写入默认流程。

## 补充 Checklist

- 上传后文件是否可直接访问？
- 文件是否被其他用户、管理员、异步任务或转换器读取？
- 下载/预览/分享是否和上传权限边界不同？
- 文件名、路径、metadata、MIME、magic bytes 是否参与服务端逻辑？
- 是否有清理接口、过期机制或可删除上传物？

## 最小验证

- 先上传无害 marker 文件，确认存储、访问、权限和清理链路。
- 若验证 filename 影响存储目录，先对默认上传目录 read-back 建 baseline，再对目标目录 read-back；上传响应“成功”本身不是目录选择证据。
- 对解析器方向，使用最小无害样本证明解析行为，不使用压缩炸弹、超大文件或资源耗尽样本。
- 对执行方向，优先证明一次性短输出或 OAST token，不持久化 webshell。
- 如果创建测试文件，记录路径、请求、时间、清理方式和清理结果，并保存原始上传请求/响应与 read-back 请求/响应。

## 常见误判 / 死路

- 能上传不等于能执行。
- 能访问上传文件不等于服务端解析执行。
- MIME 绕过如果最终只作为静态文件下载，通常不是执行链。
- 预览器报错不等于 RCE；需要证明解析器能力或安全影响。

## 关联 Skills

- `web2-vuln-classes`
- `web2-recon`
- `triage-validation`

## 晋升到 Skill / Queue 的条件

- 只有上传面时，先走 `upload-parser`。
- 出现可访问路径、解析器行为或执行迹象时，写入 action queue，类型 `upload-to-execution`。
- 需要 webshell / script execution / RCE proof 时，转 `controlled-rce-impact` 和 playbook。

## 可晋升经验

- 某类上传组件、CMS、富文本编辑器或转换器反复出现执行链。
- 某类文件格式的解析器链在目标技术栈中稳定产生高价值影响。
