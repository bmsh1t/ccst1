---
id: view-differential
type: technique-card
related_skills:
  - web2-vuln-classes
  - bb-methodology
  - security-arsenal
trigger_tags:
  - view-differential
  - validation-view
  - consumption-view
  - canonicalization
risk: medium
maturity: draft
load_priority: low
deep_refs: []
source_refs:
  - type: corpus-report
    corpus: hackerone-disclosed-reports
    id: "44513"
  - type: corpus-report
    corpus: hackerone-disclosed-reports
    id: "730779"
  - type: corpus-report
    corpus: hackerone-disclosed-reports
    id: "1086108"
  - type: corpus-report
    corpus: hackerone-disclosed-reports
    id: "2101076"
  - type: corpus-report
    corpus: hackerone-disclosed-reports
    id: "815085"
  - type: corpus-report
    corpus: hackerone-disclosed-reports
    id: "945990"
  - type: corpus-report
    corpus: hackerone-disclosed-reports
    id: "397792"
  - type: corpus-report
    corpus: hackerone-disclosed-reports
    id: "52042"
---

# 校验视图与执行视图的规范化/编码/截断差异

## Quick Recall

- 触发：校验、日志、缓存和实际执行对同一输入采用不同编码/截断/规范化视图。
- JSON 边界按 `raw bytes -> validation object -> serialized/stored form -> consumption object -> final impact` 逐层对照；不要只比较入口响应。
- `Validate-Proxy` 关注校验后继续转发原始输入，`Validate-Store` 关注同一持久化值被不同读取方解释成不同对象。
- 最小验证：对测试输入只改变一个边界表示，比较校验、存储/转发、消费和 read-back；具体解析器行为必须绑定库版本、配置和 Content-Type。
- 证据门：必须证明差异穿过安全判定并改变资源、权限或执行行为。
- 停止：两侧共用同一规范化结果，或差异不改变安全行为。

## 适用场景

- 存在"先校验再使用"的两段式处理，且两段由不同组件/库完成
- 输入会经历解码、Unicode 归一、大小写折叠、长度截断、去空白
- 代理与后端、校验器与存储层对同一字符串处理不同
- JSON 被校验后以原始文本转发，或被存储后由 API、worker、管理端、支付服务分别读取

## 触发信号

- 对畸形/多字节/百分号编码输入校验 fail-open 或行为分叉
- 长度限制在解码前测量，或存储层静默截断
- NUL、控制字符、重复条目、尾随点改变解析归属
- JSON 重复 key、未配对 surrogate、注释、尾随字符、大整数/指数或 parse/serialize round-trip 在不同组件中产生不同值
- 角色、租户、数量、金额、状态等高价值字段跨 API、队列或存储 read-back 后发生规范化碰撞

## 发散问题

- 校验时看到的字节和执行时看到的字节是否逐字节相同？
- 谁先解码、谁后解码，中间是否有截断或归一？
- 同一输入在两个组件里会不会被解析成不同实体？
- 解析后的对象是否被重新序列化，还是校验后继续转发原始 JSON？
- 持久化的是原始文本、解析对象还是规范化结果；后续读取方是否使用相同解析器和配置？

## JSON 差异家族

- 字段选择：重复 key 在不同解析器中可能首值优先、末值优先、保留全部或直接拒绝。
- 字符规范化：未配对 surrogate、反斜杠、回车和非法字符可能被保留、拒绝、替换或截断；截断不能只凭库名推断。
- 宽松语法：注释、替代引号、尾随字符和 Content-Type 分派可能改变实际进入的 parser 或字段集合。
- Round-trip：内存访问值、重新序列化文本和再次解析结果可能不一致。
- 数值表示：大整数、指数、小数精度、`NaN`、`Infinity` 可能被拒绝、舍入、饱和、归零或改写类型。

这些都是候选形态，不是固定测试字典。库行为必须在目标对应版本和配置下本地复现；可能触发原生 parser 崩溃的畸形输入只做本地 fixture，不对真实服务批量发送。

### Validate-Store 实战例子

- 发现一个可写入的角色/身份值，同时存在权限 API 和管理 API 两个读取方时，比较它们是否消费同一份存储数据。
- 在自有测试账号上，从目标 schema/请求中派生角色或身份值，只给该值追加一个异常字符，例如 `{"role":"<TARGET_ROLE>\\ud888"}`；文章中的 `superadmin` 只是示例，不是固定字典。
- 观察存储 read-back、权限 API 和管理 API 是否分别保留完整值、拒绝或规范化为原角色值；只有规范化后的值让原本被拒绝的测试账号访问自有测试管理资源，才记录为权限影响，单纯编码差异保持 Signal。
- 使用目标派生的正常值、单个不同后缀和拒绝未配对字符作为对照，确认不是固定角色、缓存或错误页差异。
- 身份矩阵不能默认只有已登录账号：若匿名入口能写入或影响该存储值，并且权限/管理入口接受匿名上下文，则同样比较 anonymous baseline 与 variant；匿名 Candidate 必须证明原本拒绝的匿名请求实际获得了测试管理资源或操作。
- 若匿名不能影响存储值，或管理入口始终要求有效 session，解析差异不能单独推出匿名管理权限；转回已认证角色/租户边界或记录为 Lead。

## 推荐动作

- 定位校验与消费两个点，分别观察它们对同一畸形输入的解读。
- 单变量注入编码/截断/归一差异，比较状态码与副作用。
- 用时序或错误信息发现逻辑分叉点。
- 保存原始请求 bytes、校验结果、转发/存储表示、消费 read-back 和最终业务状态；缺少中间视图时明确记录证据缺口。
- 对角色/租户碰撞转 `auth-access`，数量/金额/支付状态转 `business-logic-state-machines`，签名字节与消费对象不一致转 `signature-scope-mismatch`，单纯标量/数组/对象翻转转 `type-confusion-controlflow`。

## 关联 Skills

- web2-vuln-classes
- bb-methodology
- security-arsenal

## 停止条件

- 校验与消费共用同一规范化结果
- 差异存在但不改变任何安全判定或落地行为
- 严格 parser 在进入业务逻辑前拒绝重复 key、非法字符、不可表示数字或尾随内容

## 检查要求

- 必须给出一份可复现请求，并证明 validation、stored/forwarded、consumption 至少两个视图不同，且最终造成具体权限、资源、金额或业务状态影响。

## 常见误判 / 死路

- 单次 `400`、`500`、长度差异、parser error 或存储成功只说明输入路径存在，不证明安全判定改变。
- 文章、文档或历史版本声称某库会首值优先、截断或归零，只能形成验证假设；没有当前版本/config 的 A/B 结果不能定性。
- JSON Schema 在解析之后运行，不能单独消除解析前差异；但入口已经严格拒绝异常输入时不应继续尝试下游影响。
- `Validate-Store` 必须证明持久化值由另一消费方重新解释并改变权限或状态；只看到转义形式不同不够。

## 可晋升经验

- "检查的是不是你执行的那份"是通用发散母题，可迁移到路径、认证、限速、去重。
