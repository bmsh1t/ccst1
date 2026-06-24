# SQLi 隐藏输入面

## 适用场景

- 常规 query/body 参数没有 SQLi 信号，但目标存在复杂 API、日志、风控、搜索、权限或资源查询逻辑。
- recon、JS、浏览器 XHR 或 source-intel 显示同一业务有多个 sibling endpoint。
- 目标有代理/WAF/CDN、真实 IP 识别、审计日志、访问统计、黑白名单、风控或后台管理功能。
- `/autopilot --deep` 中 SQLi lane 不能只停在 `?id=`、`q=`、`search=` 等显式参数。

## 触发信号

- 请求头被后端信任或记录：`X-Forwarded-For`、`X-Real-IP`、`Forwarded`、`Client-IP`、`User-Agent`、`Referer`、`X-Original-URL`。
- URL path segment 可能承载资源名、slug、租户、地区、分类、权限路径或 CMS 路由。
- A 接口有高信号参数，B 接口同业务但前端未传这些参数。
- JS/source 暴露了内部、admin、config、export、search、report、audit、stats 等 endpoint。
- 单引号、双单引号、括号或编码后的等价扰动导致状态码、长度、错误、排序或响应结构稳定变化。

## 发散问题

- 后端是否把 header 中的 IP、UA、Referer 写入日志表或用于风控 SQL 查询？
- 路由中间件是否把 path segment 抠出来做资源、权限、分类、租户或 CMS 查询？
- A 接口的参数是否能横向“喂”给 B 接口，触发后端公共查询函数里的隐藏参数分支？
- JS/source 里出现但 UI 不传的参数，是否仍被后端读取？
- 响应差异是数据库语法/布尔/类型差异，还是只是路由/WAF/缓存差异？

## 推荐动作

- Header lane：对低风险、只读请求做成对扰动，比对 baseline、单引号、双单引号或等价编码后的状态、长度、错误和时间。
- Path lane：逐段测试 path segment，不只测 URL 尾部参数；每次只改变一个 segment。
- Hidden-param lane：从已知接口提取参数集，将同业务 sibling endpoint 追加相同参数，再对单个参数做成对扰动。
- 对所有疑似信号先做 2-3 次稳定性复测，再决定是否交给 `sqlmap -r` 或 `ghauri`。
- 优先记录最小证据：请求、响应差异、受影响输入面、DBMS 指纹或稳定布尔差异。

## 关联 Skills

- `web2-vuln-classes`
- `web2-recon`
- `bb-methodology`
- `triage-validation`

## 停止条件

- 单引号/双单引号/括号扰动只产生 WAF、路由 404、缓存 miss 或不稳定网络抖动。
- Header/path/hidden 参数无法稳定影响响应，且没有错误、布尔、时间或排序差异。
- 继续验证需要破坏性写入、批量请求、高延迟 time-based 枚举或真实数据修改。
- 只有一次性报错，无法复现或无法关联到数据库查询。

## 检查要求

- 不要只凭 500 或报错文本升级为 Candidate，必须有稳定对照。
- time-based 只能作为最后确认路径，必须有 control 请求，不能用高并发或长时间 sleep。
- 如果输入面位于日志、审计、风控等二阶路径，必须记录 store step 和 trigger step。
- 报告前必须说明攻击者可控输入、查询影响、可复现差异和实际业务影响。

## 可晋升经验

- 某类 header 在特定框架、网关或业务系统中反复进入 SQL 查询。
- 某类 path segment 命名与数据库资源查询强相关。
- 某类参数集可以跨 sibling endpoint 复用并触发隐藏后端分支。
