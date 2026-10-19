# 单一原生 Skill 与完整内部模块

`src-hunter/SKILL.md` 是本项目唯一宿主可发现的原生入口，以 6k 原版 S01 的业务/代码意图、
范围与取材、按特征选法、证明/输出和白盒组织为主体，融入 CCST 的竞争解释、条件反证与
工程能力。主会话选择问题、实验和转向；模块提供完整方法，不是固定顺序或穷举清单。

## 职责分层

| 角色 | 当前阅读位置 | 只负责 |
|---|---|---|
| 调查核心 | [src-hunter](src-hunter/SKILL.md) | 全局业务模型、竞争解释、实验选择、继续/转向/停止与交接 |
| 暴露面发现 | [web2-recon](src-hunter/modules/web2-recon.md) | 选择产生新证据的发现动作 |
| Web/API 方法知识 | `knowledge/playbooks/web2-evidence-contracts.md` | 完整方法、证据门和反例；按问题直接读，不是第二个 Skill |
| 源码专项 | [whitebox-audit](src-hunter/modules/whitebox-audit.md) | 入口/guard/sink、实际源码字节与部署条件 |
| 凭据验证准备 | [credential-attack](src-hunter/modules/credential-attack.md) | 来源、模式与准备判断；review 不等 live |
| 显式专项工作 | [CI/CD](src-hunter/modules/cicd-security.md)、[mobile](src-hunter/modules/mobile-pentest.md)、[Web3](src-hunter/modules/web3-audit.md)、[token](src-hunter/modules/meme-coin-audit.md) | 明确领域目标下的判断与交接 |
| 验证裁决 | [triage-validation](src-hunter/modules/triage-validation.md) | 证据是否成立、缺什么、降级或撤回 |
| 报告表达 | [report-writing](src-hunter/modules/report-writing.md) | 已验证结果的格式、措辞和交付 |
| 共享契约索引 | `docs/tool-index.md` | 指向执行 owner，不持有全局调查循环 |

九专项是完整内部 Markdown，不含原生 frontmatter，也不叫 `SKILL.md`。简单问题直接读对应
模块，仍由同一调查核心统筹；同会话无需角色切换或填写交接表，真实委派才传递原件与回执。

## 原生发现与加载

平台仅从 `src-hunter/SKILL.md` 的 frontmatter 发现本项目入口，模块由核心中的相对链接按需加载。
`tools/skill_catalog.py` 运行注册表已退役；Queue/Store 不验证 Skill 文件、路由或预设维度。
实验的 `active_dimension` 与 Runner 实测 `tested_dimensions` 仍由各自 owner 保存。

安装递归复制该包和共享 Markdown；不注册旧名 wrapper、软链或来源参考 Skill。
完整 6k 方法唯一活动根仍为 `knowledge/methods/clown/`，经版本化完整 reader 展开；安装目录
不是方法根，CLAUDE/rules/tools/knowledge 来自指定 checkout，不提供独立自包含安装包。
历史 `related_skills` 原字节与审核回执保留，由 `tools/skill_reference_contract.py` 精确解析到
当前 core/模块；导航兼容不恢复旧入口，不重新背书模块内容，也不参与自动路线选择。

## 公共边界

- `skills/runtime-protocol.md` 持有加载、Shared Knowledge Recall、状态连续性和写回协议。
- `rules/` 持有动作安全与全局检查；红线优先，覆盖基线不要求所有方向机械实测。
- `knowledge/` 持有按需经验、反例和技术细节，不拥有当前目标状态。
- `tools/` 负责确定性执行和各自状态；Skill 不能创建第二个 controller 或状态机。

## 修改落点

- 改全局调查策略/交接：修改 `src-hunter/SKILL.md`；Recon/专项不复制全局循环。
- 改领域判断：修改对应内部模块；改经验或反例：修改已有知识卡并遵守审核绑定。
- 改召回目录或引用投影：修改 `tools/context_pack.py`，卡片路径继续来自知识 registry；Context Pack 提供有界目录和引用，卡片选择由 AI 按当前信息缺口完成。
- 改验证裁决：修改 triage-validation 模块及相关执行 owner；改报告格式：修改 report-writing 模块。
- 改公共契约：修改对应协议或 Rules，消费者保留触发入口，不复制正文。
