# Skills 层

Skills 是按需加载的执行契约。Claude Code CLI 主会话根据当前目标、阶段和证据保留路线选择权，Skill 提供所选路径的输入、观察、检查和写回协议。

## 职责分层

| 角色 | Skill | 只负责 |
|---|---|---|
| 跨阶段协调 | `bug-bounty` | 阶段选择与交接，不复制专项方法或知识卡映射 |
| 假设策略 | `bb-methodology` | 下一假设、继续、转向、停止与重开条件 |
| 暴露面发现 | `web2-recon` | 选择产生新证据的发现动作 |
| Web/API 边界判断 | `web2-vuln-classes` | 当前类别的判断分支和证据要求 |
| 凭据验证准备 | `credential-attack` | 来源、模式与准备判断，执行交给现有命令 |
| 显式专项工作 | `cicd-security`、`mobile-pentest`、`web3-audit`、`meme-coin-audit` | 明确领域目标下的判断与交接 |
| 验证裁决 | `triage-validation` | 证据是否成立、缺什么、降级或撤回 |
| 报告表达 | `report-writing` | 已验证结果的格式、措辞和交付 |
| 共享契约入口 | `security-arsenal` | 按需指向公共执行契约，不作为主路线 |

这些是职责关系，不是每轮必须依次执行的流水线。简单任务直接使用对应 Skill，
只有跨阶段工作或假设选择不清晰时才加载协调或策略 Skill。

## 路由模式

职责与路由模式是两个维度。`tools/skill_catalog.py` 是 Skill ID、路径、
`route_mode` 和主路线维度的唯一注册表：

| 模式 | 含义 |
|---|---|
| `primary` | 可成为 Context Pack 的主推荐，并供 Action Queue 校验路由 |
| `direct-only` | 用于显式专项工作，不进入自动主推荐 |
| `reference-only` | 支持当前工作，不拥有主路线 |
| `report-only` | 只处理已验证结果的报告表达 |

安装仍保留全部现有 Skill 目录。`direct-only` 不表示未安装，也不改变当前主会话的控制权。

## 公共边界

- `skills/runtime-protocol.md` 持有加载、Shared Knowledge Recall、状态连续性和写回协议。
- `rules/` 持有动作安全与全局检查；红线优先，覆盖基线不要求所有方向机械实测。
- `knowledge/` 持有按需经验、反例和技术细节，不拥有当前目标状态。
- `tools/` 负责确定性执行和各自状态；Skill 不能创建第二个 controller 或状态机。

## 修改落点

- 改假设策略：修改 `bb-methodology`；改阶段交接：修改 `bug-bounty`。
- 改领域判断：修改对应专项 Skill；改经验或反例：修改已有知识卡。
- 改召回选择：修改 `tools/context_pack.py`，卡片路径继续来自知识 registry。
- 改验证裁决：修改 `triage-validation` 及相关执行 owner；改报告格式：只修改 `report-writing`。
- 改公共契约：修改对应协议或 Rules，消费者保留触发入口，不复制正文。
