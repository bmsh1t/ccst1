---
id: js-runtime-signature-reconstruction
type: technique-card
related_skills:
  - web2-recon
trigger_tags:
  - js-reverse
  - client-signature
  - request-initiator
  - runtime-hook
  - first-divergence
risk: low
maturity: draft
load_priority: low
deep_refs: []
source_refs: []
---

# 动态 JS 请求签名链重建

## Quick Recall

- 只在已经观察到目标请求、脚本、initiator/call stack、运行时参数或明确的加密参数信号时启用。
- 顺序固定为 `Observe -> Capture -> Rebuild -> Patch -> DeepDive`；不要先模拟整个浏览器。
- 每次只补一个有证据的环境缺口，以 first divergence 是否前移判断补丁价值。
- 稳定本地复现只是后续签名、认证、业务或请求差异验证的输入，不是漏洞结论。

## 能力定位

本卡帮助 `web2-recon` 把浏览器中不透明的参数生成链压缩为可复核的请求形状、调用链、样本输入输出和环境依赖。它不承诺专用逆向工具，不创建新的 finding 或运行时状态。

## 触发信号

- 已定位请求 initiator、调用栈、脚本 URL/hash 或生成签名/密文的函数候选。
- 浏览器请求含动态 signature、nonce、加密参数或设备环境字段，静态阅读无法解释其来源。
- 运行时 hook、断点或采样已显示输入、输出或首次异常位置。
- 同一受控输入在浏览器与本地实现之间出现稳定 first divergence。

## 流程

1. **Observe**：保存一次正常请求 baseline、initiator、脚本 URL/hash、入口函数候选及必要认证状态。
2. **Capture**：按 capability profile 选择现有 browser/DevTools 能力，只采样目标函数边界、关键参数和调用顺序。
3. **Rebuild**：在入口、输入、顺序和依赖均有证据后，用本地最小实现复现同一受控样本。
4. **Patch**：从首个不同值向上追踪，每轮只补一个时间、编码、Web API、全局对象或调用顺序缺口，并记录差异是否前移。
5. **DeepDive**：本地输出稳定后，才按需做 AST、去混淆或安全语义分析，并把请求交给现有验证路线。

## 证据要求

- 原始请求形状、脚本 URL/hash、initiator/call chain 和采样时间。
- 至少一组受控 sample input/output，以及浏览器与本地输出的逐阶段对照。
- 每个环境补丁的观测依据、修改内容、first divergence 和复现命令或步骤。
- 输出写回现有 Lead/Candidate：证据路径、重建状态、下游假设、next action 和 stop condition。

## 最小验证

1. 用同一输入重复浏览器采样，先确认输出是确定的，或识别时间/随机数/会话依赖。
2. 本地实现只覆盖已观察的调用路径；逐阶段比较类型、字节、编码和调用顺序。
3. 连续样本稳定一致后，再改变一个自有输入，验证重建不是对单一样本硬编码。
4. 将重建请求交给现有签名范围、认证、对象或业务差异验证，单独保存 raw request/response。

## 常见误判 / 死路

- 裸 `signature`、`encryption` 或 `hook` 没有目标请求和 JS/browser 上下文时，不进入本路线。
- 页面能发出请求不代表已理解签名链；单个输出相同也可能只是常量或缓存。
- 无观测依据地补齐大量 DOM、navigator 或 Node polyfill，会隐藏真正的首个差异。
- 脚本/hash、入口或输入已变化时，旧重建结果只算历史线索。

## 停止条件

- 找不到目标请求、initiator、脚本或可重复样本。
- first divergence 连续两轮没有前移，且没有新的运行时证据支持继续补环境。
- 输出由服务端、硬件或不可观测会话状态生成，本地重建不能回答当前验证问题。
- 已获得稳定请求形状并进入现有下游验证，不继续为完整逆向而扩张范围。

## 推荐动作

- 将稳定请求交给 `web2-vuln-classes` 或 `triage-validation` 做单变量 replay 与影响证明。
- 若差异属于验签字节与消费字节不一致，再加载 `knowledge/cards/signature-scope-mismatch.md`。
- 将跨目标有效的定位或补环境技巧写为带证据链接的 knowledge candidate，不保存目标 token、密钥或响应正文。
