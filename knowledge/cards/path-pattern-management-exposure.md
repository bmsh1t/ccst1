---
id: path-pattern-management-exposure
type: technique-card
related_skills:
  - web2-recon
  - web2-vuln-classes
  - bb-methodology
  - bug-bounty
  - triage-validation
trigger_tags:
  - management-path
  - admin-path
  - monitoring
  - naming-pattern
  - spring-actuator
risk: medium
maturity: draft
load_priority: medium
deep_refs: []
---

# 命名规律 / 结构化记录反哺发现

## Quick Recall

- 触发：路径、子域、静态资源或结构化记录显示管理/监控/配置命名规律。
- 最小验证：从目标自身材料生成有界词表，只验证最像的兄弟路径和只读入口。
- 证据门：记录可达性、认证要求、敏感字段或配置影响；secret 只保留最小证据。
- Spring Actuator/management 路径返回 200 时，必须确认 content-type、响应结构或 heapdump 等真实
  endpoint 形态，排除登录页、Whitelabel、SPA fallback 和统一错误页。
- 停止：候选接近无边界爆破，或需要默认凭据、云资源枚举、真实数据/运维动作。

## 能力定位

本卡用于 recon、路径发现或管理面暴露测试中，补充目标命名规律、有界词表、局部递归和结构化记录反哺二次发现的联想方向。输出候选假设、发散问题和最小验证提示，供当前 recon 或暴露面验证流程选择使用。

## 核心原则

- 高风险停止条件、凭据/云资源/生产运维面的红线始终优先。
- 标准发现链路是目标命名规律 -> 有界词表 -> 局部递归 -> 结构化记录/真实路径反哺二次 recon。
- 目标特定词表通常优于通用目录字典；结构化记录、接口统计、访问日志、配置字段常能暴露更高价值路径、参数和 secret 候选。
- `/autopilot` 默认不执行口令爆破、批量默认凭据尝试、导入云管平台、接管服务器、读取真实数据或触发支付/运维动作。口令测试可形成 credential lead，并在满足 `rules/red-lines.md` 条件时进入受控 `/spray` / `credential-attack`。

## 方法模型

- 命名形态归纳：从任何已知目录、文件名、API 前缀、参数名、子域、静态资源或业务短码观察字符集、长度、前后缀、分隔符和位置规律，生成有界目标词表，而不是直接套通用字典。
- 命中后局部递归：发现高信号兄弟路径、相邻模块、相似前缀或同业务目录后，在该局部上下文继续寻找接口、记录、配置、静态资源和管理/监控入口。
- 结构化源优先：同一信息如果同时存在 HTML、JSON、API、raw log、导出文件或统计接口，优先读取结构化/原始源，避免 HTML 截断、分页、懒加载或刷新不完整。
- 真实记录反哺字典：从访问记录、接口统计、日志、配置、sitemap、source map、bundle manifest、错误报告等真实记录中提取路径和参数，再做二次目录/API 发现。
- Secret-like 字段降级处理：`accesskey` 等字段只进入最小证据、归属判断和验证计划，不直接扩大到资源接管。
- Response-shape gate：管理路径的 status 只表示路由可达；title、content-type、JSON key、链接结构、
  文件 magic 和相邻 endpoint 一致性共同证明真实组件，不由 200/401/403 单点判断暴露。

## 候选形态示例

这些只是联想种子，不是固定字典；只有目标路径、静态资源、JS/source、
结构化记录、标题、状态码或命名规律支持时才优先尝试。

- 环境/版本：`dev`、`test`、`stg`、`uat`、`prod`、`v1`、`v2`、`old`、`new`、`legacy`。
- 后台/内部：`admin`、`manage`、`console`、`internal`、`ops`、`operator`、`portal`、`dashboard`。
- 监控/任务：`metrics`、`health`、`logs`、`trace`、`job`、`task`、`scheduler`、`datasource`、`connection`、`monitor`。
- Spring 管理面：`/actuator`、`/manage/actuator`、`/management/actuator`、`env`、`mappings`、
  `configprops`、`heapdump`、Jolokia；这些是目标有 Spring 证据时的候选形态，不是固定扫描清单。
- 兄弟命名：`app01/app02`、`api1/api2`、`data/manage-data`、`web/web-admin`、短码 + 数字或环境后缀。
- 结构化源：`manifest.json`、`routes.json`、`asset-manifest.json`、`sitemap.xml`、统计 JSON、访问记录、导出 JSON、raw log。

## 默认不执行的动作

- 不把具体账号口令、Burp Battering ram、云管平台导入、服务器接管、支付集群接管写成默认流程。
- 不把具体工具选择绑定为强制工具；核心是“目标特定词表 + 局部递归 + 只读记录反哺”。
- 不把口令测试归入本卡自动执行；需要时只把登录面、命名规律、默认品牌和错误信号提供给 `/spray` / `credential-attack` 受控流程。

## 适用场景

- 目标 URL、目录、文件名、API 前缀、参数名、子域、静态资源或业务模块名存在可归纳命名规律。
- 常规目录字典效果一般，但目标自身路径、JS、历史 URL、访问日志、统计接口、配置页、错误报告或 source map 暴露了更贴近业务的词。
- 发现任何管理、监控、日志、统计、配置、健康检查、连接池、任务调度、内部工具或运营后台入口。
- 只读接口、访问记录、配置页、健康检查、URL 统计、日志索引、manifest 或 raw data 可能泄露内部路径、接口、配置字段或 access key。

## 触发信号

- 某个节点命中后，相邻路径像是短字符串、业务缩写、环境编号、部门代码、版本号、地区、租户或模块名组合。
- 返回 200/301/302/401/403 的页面、接口或静态资源显示 monitor、admin、console、metrics、log、trace、config、health、stats、job、task、datasource 等关键词。
- Spring/Java 指纹、`X-Application-Context`、Whitelabel、Actuator link JSON、Jolokia JSON 或 heapdump
  content-type/magic 提示真实管理组件。
- 登录页使用默认品牌、缺少验证码/锁定提示、错误信息稳定；这可以形成受控口令测试 lead，是否进入 credential lane 由当前 Skill / `/autopilot` 按 `rules/red-lines.md` 判断。
- 只读结构化数据、访问记录、配置字段或日志里出现 `accesskey`、`secretKey`、`ak`、`sk`、`token`、`bucket`、`endpoint`、`region`、内部 API 路径。

## 发散问题

- 当前路径命名是不是能生成更小的目标特定字典，而不是直接跑通用大字典？
- 命中的兄弟路径是否共享同一套部署、静态资源、登录方式、API 前缀、配置源或内部工具？
- 管理/监控/日志/统计/配置类入口是否无需认证、弱认证、默认凭据、只读可访问，或暴露访问记录/配置字段？
- 真实记录里的长 URL、结构化接口、内部路径是否能反向构造新的 recon 字典？
- 疑似云密钥或 access key 是否能在不接管资源、不读取真实数据的前提下做最小有效性确认？

## 推荐动作

- 先从目标自身提取词表：路径分段、目录前缀/后缀、短码模式、文件名、API 前缀、参数名、JS 路由、历史 URL、结构化记录。
- 对命名规律做有界生成：限制长度、字符集和候选数量，优先验证最像目标风格的兄弟目录。
- 管理/监控/日志/统计/配置入口只先做安全识别：标题、版本、认证要求、只读页面、结构化数据、配置字段；口令测试作为受控 `/spray` 或 `credential-attack` 后续动作。
- 对 Actuator 先比较不存在路径、`/actuator` root 和单个只读 endpoint；只有 actuator-shaped JSON、
  endpoint link、heapdump 文件形态或目标特定管理数据才算真实暴露，HTML 登录/错误页保持 Signal。
- 发现访问记录、统计接口、JSON/API/raw log/导出类结构化源时，优先提取路径和参数作为二次 recon 字典，不直接访问状态改变接口。
- 发现 access key/secret/token 时，只记录来源、字段名、上下文和最小有效性验证计划；需要云资源枚举、导入第三方工具或接管资源时先停为 Candidate/blocked。

## 关联 Skills

- `web2-recon`
- `web2-vuln-classes`
- `bb-methodology`
- `bug-bounty`
- `triage-validation`

## 停止条件

- 目录规律产生的候选数量过大，已经接近无边界爆破或触发限速/WAF/告警风险。
- 入口需要口令爆破、默认凭据检查或真实账号尝试时，当前发现 lane 停止并转受控 `/spray` / `credential-attack`；验证码绕过、账号锁定规避或大规模猜测按红线处理。
- 真实记录里的 URL 指向写入、删除、支付、订单、消息发送、部署或其他状态改变动作。
- 疑似云密钥验证需要列举真实资源、读取客户数据、导入云管平台、接管服务器或执行运维动作。

## 检查要求

- 不把“存在登录页”直接当作漏洞；Candidate 需要可达性、认证缺陷、敏感信息泄露或配置影响证据。
- 不把 Actuator/Jolokia 路径 200 直接当作管理面暴露；必须排除 Whitelabel、认证跳转、SPA fallback、
  反向代理统一页和普通 health 文案。
- 默认凭据检查必须低频、有限、可说明依据；如需扩大为口令爆破，必须切换到受控 `/spray` / `credential-attack` 流程。
- Secret 候选只保留最小证据，避免保存完整密钥、批量导出资源或扩大影响。
- 任何云、支付、生产服务器、CI/CD、部署和运维面操作必须先按 `rules/red-lines.md` 降级或停止。

## 可晋升经验

- 某类目录短码、业务前缀、文件名、API 前缀、参数名、子域或环境编号能稳定生成高命中目标词表。
- 某类结构化记录或只读接口经常泄露二次 recon 字典或 secret 字段。
- 某类真实记录字段能把“目录 fuzz”转化为高价值 API、配置和 secret 检查路线。
