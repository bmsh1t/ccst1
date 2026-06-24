# 缺参信号 / 隐藏参数发现

## 适用场景

- SPA、后台、数据平台或移动端 API 出现空白页、隐藏路由、JS 暴露路径或 API 文档线索。
- endpoint 返回 `missing parameter`、`parameter is null`、`required parameter`、`parameter required`、400/422 参数错误或类似后端校验提示。
- Swagger/OpenAPI/Spring Boot API docs、`/v3/api-docs`、`/api-docs`、`/swagger.json` 等暴露接口结构，但请求缺少关键参数。
- 常规字典没有命中隐藏参数，目标自身 JS、source、历史请求、浏览器 XHR 或 sibling endpoint 暴露了更贴近业务的词表。

## 触发信号

- 响应明确提示缺少参数，但没有给出完整参数名或只给出业务字段，例如 `selectUser`、`search`、`query`、`filter`、`code`。
- 添加某个参数后状态码、响应长度、错误结构、字段集合或空结果形态出现稳定变化。
- API docs 经过路径绕过、版本路径、网关路径或 Spring Boot 风格路径后可读，但多数接口仍缺少认证、租户或参数上下文。
- JS 路由、bundle 字符串、表单字段、GraphQL 变量名、source-intel route 名称与目标 endpoint 的业务语义重合。

## 发散问题

- 缺参错误来自业务 controller、网关、WAF，还是后端框架参数绑定？
- 参数名是否来自同一 SPA 的 JS 词、接口路径分段、API docs schema、历史 URL 或 sibling endpoint？
- 添加参数后改变的是授权边界、对象选择、分页/筛选条件，还是普通展示差异？
- 该参数是否能把“匿名可达 / 低权限可达”的 endpoint 变成读取其他主体数据的路径？
- 是否存在无需批量枚举也能证明的最小影响，例如只读元数据、当前账号对象、测试账号对象或响应结构差异？

## 推荐动作

- 先固定 baseline：原请求、缺参响应、认证状态、响应长度、关键 header 和错误体。
- 构造目标特定参数词表：JS/source/API docs/浏览器 XHR/历史 URL/sibling endpoint 的单词、驼峰、下划线和路径分段；优先目标词表，不优先大通用字典。
- 使用低频、可限速的参数发现策略；Arjun 这类分组探测只作为降噪工具，不代表可以无边界大流量。
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
- 继续验证需要批量遍历用户、手机号、身份证、密码、地址、token、订单或其他真实敏感数据。
- 继续验证需要高频请求、压力测试、破坏性状态改变、绕过验证码/OTP/账号锁定或测试真实第三方账号。

## 检查要求

- 不把“parameter is null”本身升级为 Candidate；它只是隐藏参数发现的入口信号。
- Candidate 前必须有 baseline-vs-candidate 稳定对照、最小请求、参数来源和影响解释。
- 如果响应疑似包含敏感数据，只保留必要字段级证据和截图/摘要；不要导出、枚举或保存完整真实数据集。
- 记录到目标层时使用 `Evidence -> Hypothesis -> Next action -> Stop condition`，并明确停止条件。

## 可晋升经验

- 某类框架、网关或 API docs 路径经常暴露“缺参但可达”的接口。
- 某类 JS 词表构造方式能稳定优于通用参数字典。
- 某类缺参信号反复导向 IDOR、Authz、SQLi hidden-param 或业务筛选绕过。
