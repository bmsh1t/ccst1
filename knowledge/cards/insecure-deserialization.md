---
id: insecure-deserialization
type: technique-card
related_skills:
  - web2-vuln-classes
  - triage-validation
trigger_tags:
  - deserialization
  - signed-object
  - viewstate
  - rememberme
risk: high
maturity: draft
load_priority: medium
deep_refs:
  - knowledge/payloads/command-execution-probes.md
  - knowledge/playbooks/controlled-rce-validation.md
  - /root/tool/ccst/ctf-skills/ctf-web/server-side-deser.md
---

# 反序列化 / Signed Object

## Quick Recall

- 先识别格式和完整性保护：Java/PHP/Python/.NET/Node serialized blob、remember-me、session、state、ViewState、导入/导出对象。
- 反序列化错误、类名、类型栈、OAST callback、签名校验差异都是 sink 线索，不等于 RCE。
- 有签名/加密时先测试 tamper 是否被拒绝，再考虑弱密钥、key reuse、算法或框架配置。
- URLDNS/OAST 类 probe 可证明 Java 反序列化触发，但命令 gadget 需要单独证据和受控验证。
- 反序列化也可能导致 role/tenant/state tamper，不只 RCE；按业务影响选最小证明。

## 能力定位

本卡给 `web2-vuln-classes` 提供 serialized object 的识别、完整性判断和利用分支。
它不默认武器化 gadget chain，RCE 影响证明交给 `controlled-rce-impact`。

## 触发信号

- Cookie、rememberMe、session、state、payload、object、data、ViewState、import/export 文件呈现序列化特征。
- Java `rO0AB` / `AC ED 00 05`，PHP `O:<len>:"Class"`，Python pickle `gAS` / `80 04`，.NET ViewState/LosFormatter 等。
- 响应或日志出现 ClassCast、InvalidClass、unserialize、pickle、BinaryFormatter、ObjectInputStream、MAC validation failed。
- 框架或依赖版本存在历史 gadget/签名配置问题。

## 思路分支

- Format recognition：base64、gzip、URL-safe、hex、签名分段、加密外壳。
- Integrity test：单字节 tamper、重放、过期、跨账号复制、签名错误差异。
- State tamper：对象字段可改时，优先测试 role、tenant、feature flag、price/quantity 等业务状态边界。
- Sink proof：类型错误、OAST callback、URLDNS、反序列化日志，证明服务端真的反序列化。
- RCE chain：只有 sink、框架、gadget、低风险 probe 都明确时，转受控影响证明。

## 技巧家族 / Payload 家族

- 识别形态：base64/gzip/URL 编码、magic bytes、语言序列化头、ViewState 分段。
- 完整性形态：签名/MAC、加密、时间戳、nonce、用户绑定、key rotation、算法降级。
- 低风险 sink probe：类型破坏、类名错误、URLDNS/OAST、无副作用 callback。
- 业务 tamper：布尔/枚举/ID/金额/角色字段只在自有或测试对象上验证。

## 补充 Checklist

- 是否记录原始 blob、解码层级、签名段和绑定用户？
- 是否区分“可解码”和“服务端会反序列化”？
- Tamper 失败是完整性保护成功，还是格式/编码错误？
- 是否检查跨账号 replay、旧 token、remember-me 与 session 绑定差异？
- 是否在命令 gadget 前确认框架、版本、classpath/gadget 可用性？

## 最小验证

- 保存合法 blob baseline，做单字节 tamper 或无害字段变化，比较拒绝方式。
- 对 unsigned object，只改自有/测试对象中的低影响字段，证明服务端接受和业务边界。
- 对 blind sink，用一次性 OAST token 或类型错误证明触发，不直接上命令 gadget。
- Candidate 前需要格式证据、完整性结论、可 replay 请求和明确业务/RCE 影响路径。

## 常见误判 / 死路

- Base64 JSON 不等于反序列化漏洞。
- 看到 serialized magic bytes 不代表可篡改；签名和用户绑定可能完整。
- OAST callback 只证明 sink，不证明命令执行。
- Gadget 工具失败不代表没有漏洞；也可能是 classpath、签名或触发路径不匹配。

## 关联 Skills

- `web2-vuln-classes`
- `triage-validation`
- `bb-methodology`

## 晋升到 Skill / Queue 的条件

- 只有格式线索时，作为 Lead 做识别和完整性测试。
- 有 endpoint/blob/tamper/sink 差异时，写入 action queue，类型 `insecure-deserialization`。
- 有业务状态篡改或 RCE primitive 时，转 `triage-validation`；RCE 按 `controlled-rce-impact` 证明。

## 可晋升经验

- 某类框架/组件的序列化格式和默认保护方式。
- 某类 remember-me/session/state 边界常见的弱绑定模式。
- 某类 OAST/sink 误判和 gadget 失败原因。
