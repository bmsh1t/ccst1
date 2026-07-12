---
id: upload-parser
type: technique-card
related_skills:
  - web2-recon
  - web2-vuln-classes
  - security-arsenal
  - triage-validation
trigger_tags:
  - upload
  - import
  - parser
  - converter
risk: medium-to-high
maturity: draft
load_priority: high
deep_refs: []
---

# 上传 / 导入 / 解析器链

## Quick Recall

- 触发：上传/导入后存在扫描、转换、预览、下载、分享或异步处理链。
- 最小验证：使用无害小样本追踪存储、处理和读取路径，再做下载/预览权限对照。
- 证据门：必须记录实际处理器、权限边界和影响；不把扩展名差异直接升级为漏洞。
- 停止：无法触发处理链，或需要恶意文件、资源耗尽及真实用户影响才能继续。

## 适用场景

- 目标支持文件上传、导入、转换、预览、解析、压缩包处理、图片处理、PDF/HTML 渲染
- 文件内容、文件名、metadata、MIME 或外部引用参与后端处理
- 上传后文件可被其他用户、管理员、异步任务或转换器访问

## 触发信号

- 参数或路径出现 upload、import、convert、preview、avatar、attachment、document、export
- 响应中出现 processor、converter、thumbnail、ocr、metadata、scan、virus、render
- 支持 SVG、PDF、DOCX、XLSX、ZIP、图片、HTML、Markdown、CSV 等复杂格式
- 上传后有下载、预览、分享、管理员审核或异步处理链路
- 文件名或 metadata 被拼进存储路径；引用解析正则的 file 段未做规范化，可出现 parent segment、覆盖或软链穿透风险

## 发散问题

- 服务端信任扩展名、MIME、magic bytes 还是实际内容？
- 文件名、路径、路径分隔符、编码 parent segment、metadata、EXIF、压缩包条目是否参与后端逻辑？
- 上传后的文件是否在不同权限上下文中被读取或渲染？
- 转换器是否会访问外部 URL 或本地文件？
- 上传、预览、下载、分享是否使用同一鉴权边界？

## 推荐动作

- 先确认上传后处理链：存储、扫描、转换、预览、下载、分享。
- 用最小无害样本验证解析路径，不上传炸弹、超大文件或资源耗尽样本。
- 对下载/预览权限做 role diff。
- 对 URL fetch、XXE、SSRF、路径穿越等二阶方向，只在证据命中时按 `rules/playbook-router.md` 路由。

## 关联 Skills

- `web2-recon`
- `web2-vuln-classes`
- `security-arsenal`
- `triage-validation`

## 停止条件

- 无法控制文件内容、文件名或 metadata
- 上传后不可触发任何处理链
- 继续验证需要破坏性文件、资源耗尽或真实用户影响
- 服务端稳定隔离上传、预览和下载权限

## 检查要求

- 禁止压缩炸弹、超大文件、解析器资源耗尽测试。
- 禁止上传会影响真实用户或管理员的恶意内容。
- Candidate 前必须证明处理链、权限边界和实际影响。

## 可晋升经验

- 某类文件格式在目标技术栈中反复触发高价值处理链
- 某类上传后预览/下载权限反复和上传权限不一致
- 某类解析器方向多次因红线只能记录为 Lead

## 源报告（on-demand）

- source_report_ids: `730239`, `822262`, `1115864`, `1131465`, `191884`, `1377748`, `243156`, `375083`
- 用途：这些 ID 只作为本地案例库查询指针。只有当前证据已命中本卡触发信号，且需要真实攻击链形状、报告写作先例或相似案例时，才按需查询 gitignored 的 `distill/` 本地缓存；不要默认拉取全文，不把报告正文、目标域名、payload 或 PII 写入知识卡。
