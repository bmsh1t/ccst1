# 缺参信号 / 隐藏参数发现

## 能力定位

本卡用于 recon 或 Web2 漏洞验证中出现缺参、空参、类型错误、schema/validator/binder 错误时，补充隐藏参数发现、目标词表构造和低风险响应差异验证的联想方向。输出候选假设、发散问题和最小验证提示，供当前 recon 或漏洞验证流程选择使用。

## 核心原则

- 缺参/校验错误只能作为信号，不是漏洞结论；命中后仍需最小影响验证和红线检查。
- 标准验证链路是错误信号 baseline -> 目标特定参数词表 -> 低频收敛 -> 单参数响应形态差异 -> 最小影响验证。
- 后端错误、校验提示、响应长度/结构变化能反推出隐藏输入面；目标自身词表通常优于通用参数字典。
- 自动化默认不批量枚举真实 PII、凭据、联系方式、地址、token 或业务数据，不保存完整真实数据集，不把某个具体参数名、接口名、框架路径或工具绑定为必选。

## 方法模型

- 错误信号路由：`missing parameter`、`parameter is null`、`required parameter`、schema/validator/binder 错误、400/422 参数错误等，都可作为“后端还在读取未知参数”的入口信号。
- 目标词表构造：从 JS、source、API 文档、schema、浏览器 XHR、历史 URL、表单、GraphQL 变量、错误字段、sibling endpoint、路径分段、静态资源和业务文案中提取候选参数名。
- 分组/差异收敛：用低频分组探测、二分收敛或响应差异聚类减少请求量；具体工具只是实现细节，不是能力边界。
- 响应形态验证：命中候选后比较 status、length、字段集合、错误码、空/非空结构、排序/分页/过滤变化，而不是直接认定漏洞。
- 最小影响停点：如果隐藏参数进入对象选择、授权边界或敏感数据面，停止在字段级/结构级最小证据，转 Candidate/blocked。

## 候选形态示例

这些只是联想种子，不是固定字典；只有缺参错误、schema、JS/source、
浏览器流量、历史请求或业务语义支持时才优先尝试。

- 身份/对象：`userId`、`accountId`、`orgId`、`tenantId`、`memberId`、`projectId`、`orderId`、`reportId`。
- 范围/角色：`scope`、`role`、`permission`、`owner`、`group`、`department`、`region`、`channel`。
- 筛选/状态：`status`、`type`、`category`、`source`、`keyword`、`dateRange`、`startTime`、`endTime`。
- 调试/内部：`debug`、`preview`、`internal`、`includeDeleted`、`includeHidden`、`isAdmin`、`mode`。
- 分页/排序：`page`、`size`、`limit`、`offset`、`sort`、`order`、`fields`、`include`。

## 默认不执行的动作

- 不把具体参数名、接口名、路径绕法或框架字典作为固定流程。
- 不批量遍历真实 PII、凭据、联系方式、地址或业务数据。
- 不把 Burp、Excel、Arjun 等工具固定为必用；核心是“目标词表 + 差异收敛 + 最小验证”。

## 适用场景

- 任意 Web/API/移动端/后台/数据平台接口返回缺参、空参、类型错误、校验失败、schema mismatch、binder/validator 错误或类似参数提示。
- 页面、接口、历史记录、source、浏览器流量、文档、schema、静态资源或 sibling endpoint 暴露了更贴近业务的候选词。
- 常规参数字典没有命中，但目标自身材料能构造更高信号的参数词表。
- 某个 endpoint 可达但缺少认证、租户、对象、筛选、分页、查询或业务上下文参数。

## 触发信号

- 响应明确提示缺少参数、参数为空、类型不匹配、绑定失败或校验失败，但没有给出完整参数名，或只给出业务字段片段。
- 添加某个参数后状态码、响应长度、错误结构、字段集合或空结果形态出现稳定变化。
- 文档/schema/source/历史请求/浏览器流量显示接口结构，但多数接口仍缺少认证、租户、对象或参数上下文。
- JS 路由、bundle 字符串、表单字段、GraphQL 变量名、source-intel route 名称、路径分段或业务文案与目标 endpoint 的语义重合。

## 发散问题

- 缺参错误来自业务 controller、网关、WAF，还是后端框架参数绑定？
- 参数名是否来自目标自身材料，例如 JS/source/schema/浏览器 XHR/历史 URL/路径分段/表单/GraphQL/sibling endpoint？
- 添加参数后改变的是授权边界、对象选择、分页/筛选条件，还是普通展示差异？
- 该参数是否能把“匿名可达 / 低权限可达”的 endpoint 变成读取其他主体数据的路径？
- 是否存在无需批量枚举也能证明的最小影响，例如只读元数据、当前账号对象、测试账号对象或响应结构差异？

## 推荐动作

- 先固定 baseline：原请求、缺参响应、认证状态、响应长度、关键 header 和错误体。
- 构造目标特定参数词表：从 JS/source/schema/API docs/浏览器 XHR/历史 URL/表单/GraphQL/sibling endpoint/路径分段/业务文案中提取单词、驼峰、下划线、短横线和缩写变体；优先目标词表，不优先大通用字典。
- 使用低频、可限速的参数发现策略；分组探测、二分收敛、响应差异聚类等只是降噪方法，不代表可以无边界大流量。
- 每次只验证一个候选参数或一组由工具收敛出的候选，比较 status、length、字段集合、错误码和空/非空结构。
- 若出现数据访问迹象，停止在最小证据：证明隐藏参数影响对象选择或授权边界即可，记录 Candidate/blocked，不做批量枚举或真实数据采集。

## 关联 Skills

- `web2-recon`
- `web2-vuln-classes`
- `bb-methodology`
- `bug-bounty`
- `triage-validation`

## 停止条件

- 差异只来自 WAF、缓存、路由 404、随机错误页或不稳定网络抖动。
- 候选参数只能改变错误文案，不能稳定改变响应结构、对象选择、认证/授权状态或业务结果。
- 继续验证需要批量遍历用户、PII、凭据、联系方式、地址、token、订单或其他真实敏感数据。
- 继续验证需要高频请求、压力测试、破坏性状态改变、绕过验证码/OTP/账号锁定或测试真实第三方账号。

## 检查要求

- 不把“parameter is null”本身升级为 Candidate；它只是隐藏参数发现的入口信号。
- Candidate 前必须有 baseline-vs-candidate 稳定对照、最小请求、参数来源和影响解释。
- 如果响应疑似包含敏感数据，只保留必要字段级证据和截图/摘要；不要导出、枚举或保存完整真实数据集。
- 记录到目标层时使用 `Evidence -> Hypothesis -> Next action -> Stop condition`，并明确停止条件。

## 可晋升经验

- 某类框架、网关、schema、文档或校验器经常暴露“缺参但可达”的接口。
- 某类目标材料词表构造方式能稳定优于通用参数字典。
- 某类缺参信号反复导向 IDOR、Authz、SQLi hidden-param 或业务筛选绕过。
