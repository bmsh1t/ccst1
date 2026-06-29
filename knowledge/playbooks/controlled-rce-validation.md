---
id: controlled-rce-validation
type: workflow-card
related_cards:
  - knowledge/cards/controlled-rce-impact.md
  - knowledge/cards/upload-to-execution.md
  - knowledge/cards/ssrf-internal-impact.md
related_skills:
  - web2-vuln-classes
  - triage-validation
trigger_tags:
  - rce
  - impact-proof
  - controlled-exploit
risk: high
maturity: draft
load_priority: low
---

# 受控 RCE 验证 Playbook

## Quick Recall

- 先证明 primitive，再证明影响；不要一开始就上 shell。
- 每一步都要能停止、复现、解释和清理。
- 影响证明围绕执行身份、边界、应用上下文、内部可达性和业务风险。
- 验证完成后进入 `/validate`，报告里写清红线、最小证据和清理情况。

## 流程

1. **Scope / Red-line review**
   - 目标、路径、账号、测试资源、时间窗口和授权边界明确。
   - 排除持久化、破坏性写入、真实数据批量读取、服务扰动。

2. **Primitive proof**
   - 用最小请求证明输入能影响命令/代码执行。
   - 记录 baseline、payload 请求、响应/OAST、控制请求。

3. **Execution context**
   - 只收集必要上下文：执行用户、主机/容器、工作目录、运行时。
   - 不默认读取全量 env、配置、密钥或用户数据。

4. **Impact proof**
   - 选择一个低风险业务影响：应用配置风险、内部服务状态级可达、后台任务能力、受限文件只读证明、上传执行边界。
   - 只取最小非敏感证据。

5. **Cleanup**
   - 删除测试文件、关闭监听器、撤销临时资源。
   - 记录清理命令、结果和残留风险。

6. **Triage / Validation**
   - 进入 `triage-validation`。
   - 输出 replay、影响、权限边界、红线说明、清理说明。

## 停止条件

- 需要破坏性写入、持久化、横向移动、真实数据导出或高压请求。
- 无法证明执行发生在目标服务端。
- 低风险 primitive 已足够证明影响，不需要继续扩大。
- 目标进入 WAF/guard cooldown，转 cached evidence / source / browser / checkpoint。
