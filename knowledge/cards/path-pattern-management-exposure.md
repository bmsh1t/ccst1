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
- 最小验证：从同一目标的可追溯样本归纳命名画像，生成有界候选，并用随机 miss 和响应差异
  验证最像的兄弟 surface。
- 证据门：记录可达性、认证要求、敏感字段或配置影响；secret 只保留最小证据。
- 路由 Oracle：404、405/`Allow`、响应形态或错误族差异只证明可能存在不同处理分支，不能
  单独证明权限缺陷或漏洞。
- Spring Actuator/management 路径返回 200 时，必须确认 content-type、响应结构或 heapdump 等真实
  endpoint 形态，排除登录页、Whitelabel、SPA fallback 和统一错误页。
- 停止：候选接近无边界爆破，或需要默认凭据、云资源枚举、真实数据/运维动作。

## 能力定位

本卡用于 recon、路径发现或管理面暴露测试中，补充目标命名规律、有界词表、局部递归和结构化记录反哺二次发现的联想方向。输出候选假设、发散问题和最小验证提示，供当前 recon 或暴露面验证流程选择使用。

## 核心原则

- 高风险停止条件、凭据/云资源/生产运维面的红线始终优先。
- 标准发现链路是目标命名规律 -> 有界词表 -> 局部递归 -> 结构化记录/真实路径反哺二次 recon。
- `check` 只验证已知清单；`discover` 根据目标自己的语法提出尚未观察到的有限假设。两者都必须
  经过协议层事实验证，生成结果不能直接进入资产或漏洞结论。
- 孤立字符串容易诱发模型为缩写或业务含义编故事；优先使用同一目标、同一产品或同一前缀下的
  邻居样本归纳结构。只有单一样本时，解释必须保持为待验证假设。
- 目标特定词表通常优于通用目录字典；结构化记录、接口统计、访问日志、配置字段常能暴露更高价值路径、参数和 secret 候选。
- `/autopilot` 默认不执行口令爆破、批量默认凭据尝试、导入云管平台、接管服务器、读取真实数据或触发支付/运维动作。口令测试可形成 credential lead，并在满足 `rules/red-lines.md` 条件时进入受控 `/spray` / `credential-attack`。

## 方法模型

- 命名画像：从已知目录、文件名、API 前缀、参数名、子域、静态资源或业务短码观察分隔符、
  大小写、固定前缀、版本、实体/动作别名、环境、地域、编号和位置规律；只记录证据实际支持的
  槽位，不补齐一张看似完整但未经观察的模板。
- 证据绑定生成：每个候选保留 `seed_refs`、转换规则、推导理由和来源强弱。明确的大小写、
  分隔符、编号或已观察槽位使用确定性转换；实体、动作和业务别名由 AI 结合目标上下文提出。
  模型自报的数字置信度不是存在概率，不能用于晋升。
- 命中后局部递归：发现高信号兄弟路径、相邻模块、相似前缀或同业务目录后，在该局部上下文继续寻找接口、记录、配置、静态资源和管理/监控入口。
- 结构化源优先：同一信息如果同时存在 HTML、JSON、API、raw log、导出文件或统计接口，优先读取结构化/原始源，避免 HTML 截断、分页、懒加载或刷新不完整。
- 真实记录反哺字典：从访问记录、接口统计、日志、配置、sitemap、source map、bundle manifest、错误报告等真实记录中提取路径和参数，再做二次目录/API 发现。
- Secret-like 字段降级处理：`accesskey` 等字段只进入最小证据、归属判断和验证计划，不直接扩大到资源接管。
- Response-shape gate：管理路径的 status 只表示路由可达；title、content-type、JSON key、链接结构、
  文件 magic 和相邻 endpoint 一致性共同证明真实组件，不由 200/401/403 单点判断暴露。
- 反馈收敛：候选与随机 miss 同质时降低该转换优先级；稳定的不同错误族、方法差异或同词根
  多点信号才支持下一轮有界扩写。每轮根据新证据重新决定继续或停止，单轮有界不是全局能力上限。

## 候选形态示例

这些维度用于拆解目标语法，不是固定字典；只有目标路径、静态资源、JS/source、结构化记录、
标题、响应差异或邻居样本支持时才生成对应候选。

- 语法槽位：分隔符、大小写、单复数、固定前后缀、版本位置、扩展名和路径层级。
- 语义槽位：目标实际出现的实体、动作、业务短码和同族别名；不从孤立缩写反推确定含义。
- 部署槽位：环境、地域、可用区、灾备和编号/补零风格；只替换已被邻居样本证明存在的槽位。
- 结构模板：`<prefix>/<version>/<entity><separator><action>`、
  `<service><separator><region><separator><cluster>` 等仅表达槽位关系，不提供固定候选值。
- Spring 管理面：`/actuator`、`/manage/actuator`、`/management/actuator`、`env`、`mappings`、
  `configprops`、`heapdump`、Jolokia；这些是目标有 Spring 证据时的候选形态，不是固定扫描清单。
- 结构化源：`manifest.json`、`routes.json`、`asset-manifest.json`、`sitemap.xml`、统计 JSON、访问记录、导出 JSON、raw log。

## 目标方言闭环

1. 收集同目标真实种子，并保留 browser、JS/source、schema、历史 URL、DNS 或结构化记录引用。
2. 归纳已观察到的语法与结构槽位；单一样本只产生假设，多邻居样本用于校正含义和位置。
3. 生成与一个具体 request/template 和认证上下文绑定的有限候选，去重后再执行。
4. 用同方法、同认证语义的随机 miss 对照 status、length、words、lines、content-type、redirect、
   404/405/`Allow` 和错误族；SPA/soft-404、登录跳转、网关/WAF 页面单独聚类。
5. 把稳定差异写为 Signal/lead，把同质范围写为 dead-end；只有新证据支持时再开始下一轮。

画像和候选只是本轮证据附件，不拥有 finding、queue、coverage 或 target memory 状态。

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
- 哪些命名结论由多个同目标样本支持，哪些只是对孤立字符串的语义猜测？
- 当前候选使用了什么结构或语义转换，能否逐条回到种子证据？
- 命中的兄弟路径是否共享同一套部署、静态资源、登录方式、API 前缀、配置源或内部工具？
- 管理/监控/日志/统计/配置类入口是否无需认证、弱认证、默认凭据、只读可访问，或暴露访问记录/配置字段？
- 真实记录里的长 URL、结构化接口、内部路径是否能反向构造新的 recon 字典？
- 疑似云密钥或 access key 是否能在不接管资源、不读取真实数据的前提下做最小有效性确认？

## 推荐动作

- 先从目标自身提取词表：路径分段、目录前缀/后缀、短码模式、文件名、API 前缀、参数名、JS 路由、历史 URL、结构化记录。
- 对命名规律做有界生成：先记录 seed、槽位、转换和理由，再限制长度、字符集和单轮候选数量；
  优先验证最像目标风格的兄弟 surface，不用模型自报置信度代替证据排序。
- 先建立随机 miss/soft-404 control，再复核差异响应；405/`Allow` 或不同错误族只形成路由
  Signal，转入具体漏洞 lane 后重新满足该 lane 的证据门。
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
- 不把生成候选、DNS 解析、收到 HTTP 响应或单一 200/401/403/405 当作发现结论；必须排除
  wildcard、soft-404、SPA fallback、登录跳转、统一网关页和 WAF 响应。
- 不把 Actuator/Jolokia 路径 200 直接当作管理面暴露；必须排除 Whitelabel、认证跳转、SPA fallback、
  反向代理统一页和普通 health 文案。
- 默认凭据检查必须低频、有限、可说明依据；如需扩大为口令爆破，必须切换到受控 `/spray` / `credential-attack` 流程。
- Secret 候选只保留最小证据，避免保存完整密钥、批量导出资源或扩大影响。
- 任何云、支付、生产服务器、CI/CD、部署和运维面操作必须先按 `rules/red-lines.md` 降级或停止。

## 可晋升经验

- 某类目录短码、业务前缀、文件名、API 前缀、参数名、子域或环境编号能稳定生成高命中目标词表。
- 某类结构化记录或只读接口经常泄露二次 recon 字典或 secret 字段。
- 某类真实记录字段能把“目录 fuzz”转化为高价值 API、配置和 secret 检查路线。
