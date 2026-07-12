---
id: render-pipeline-ssrf
type: technique-card
related_skills:
  - web2-vuln-classes
  - security-arsenal
  - triage-validation
trigger_tags:
  - render-pipeline
  - pdf
  - screenshot
  - wkhtmltopdf
  - ssrf
risk: high
maturity: draft
load_priority: low
deep_refs: []
---

# 渲染/转换/导出管线作为 SSRF/RCE 攻击面

## Quick Recall

- 触发：PDF、截图、HTML 转换器或导出服务接收 URL/文件并在后端渲染。
- 最小验证：先用自有 callback/无害文件确认管线，再只改变一个协议或重定向变量。
- 证据门：记录服务端请求/文件访问和实际回显或影响；不把渲染成功直接当 RCE。
- 停止：管线不发起网络/文件访问，或 scheme、重定向和本地读取均稳定隔离。

## 适用场景

- 存在导出/PDF/报表/截图/媒体转码/文档渲染功能
- 后端组件会主动加载外部资源或回调 URL
- 存在 k8s webhook、中继、代理等可控回调端

## 触发信号

- 渲染器解析外部资源引用（img/link/include/concat）
- 导出/PDF 渲染跟随重定向或解析内部主机
- 302 POST->GET 降级 / # 截断可打到 GET-only 内部端点

## 发散问题

- 这个管线在服务端到底会去访问什么？
- 渲染器支持哪些危险 scheme / include 语义？
- 重定向/降级能否改变最终内部目标？

## 推荐动作

- 先证明管线会发起服务端请求（低频 OAST 观察）。
- 单变量切换 scheme/重定向/降级，观察内部可达性。
- 对媒体/文档管线测 concat/include 等二阶读取。

## 关联 Skills

- web2-vuln-classes
- security-arsenal
- triage-validation

## 停止条件

- 管线不发起服务端网络/文件访问
- 所有 scheme/重定向被稳定拦截

## 检查要求

- 必须证明经渲染管线访问到内部资源/文件或达成执行，且低风险可复现。

## 可晋升经验

- 把"导出/渲染/转码"当作一类高信号 SSRF 入口，而非普通 fetch。

## 源报告（on-demand）

- source_report_ids: `885975`, `2262382`, `312543`, `530974`, `843256`, `941178`, `776017`, `809248`
- 用途：这些 ID 只作为本地案例库查询指针。只有当前证据已命中本卡触发信号，且需要真实攻击链形状、报告写作先例或相似案例时，才按需查询 gitignored 的 `distill/` 本地缓存；不要默认拉取全文，不把报告正文、目标域名、payload 或 PII 写入知识卡。
