## 跨源能力处置

| 能力面 | C 当前 owner / 事实 | A 增量与差分 | B 可借鉴 | 最终处置 |
|---|---|---|---|---|
| 主调查控制器 | 主会话 + `skills/src-hunting`；手动和 Autopilot 共用 | 6k 的完整迭代、短表、种子闭环和证据选择 | 多专家分层与分工声明 | 接入原生 core；专家只对局部问题提议，不移 controller/gates/branch state |
| 完整方法读取 | `knowledge/capabilities.yaml` 管卡目录；`tools/hot_method.py` 管方法来源/健康；Context Pack 尚未完整展示方法目录 | 62 个来源逐项有去向；按问题展开相关完整方法及规则依赖，不把治理原件全部当活动方法 | 更广的 playbook 目录，但发现/回链需真实验证 | 保留唯一正文和 manifest；补 hash 绑定的一致正文读取与完整目录，不强制 top-k |
| 方法维护 | 已审共享卡由 knowledge registry/promotion/review owner 管理 | 6k 三问门槛和无需等“放”的当轮迭代 | B 的 adapter/envelope 只是机制候选，不证明执行 | 用户已选 A：主控复核后维护活动方法；全版本回溯；治理改动/共享发布仍人审；不冒充 review receipt |
| 治理与范围 | C Scope/Auth、red-lines、Trellis 和规则 owner | 多宿主路径、范围继续和报告准入需适配 | B route contract/registry 是自有控制体系 | 映射到现有 owner；上游禁令/桌面路径不覆盖 C，也不引入 B 双路由 |
| 条件事实和记忆 | TargetStore、Experience、handoff、Resume、knowledge recall | 增量依赖当前事实、跨轮恢复和重要节点写回 | B graph/ledger 不可直接照搬 | 保留现有 owner；campaign seed file 显式恢复，手法差分与私有 target 事实分离 |
| 未裁决原生观察 | Store 可持无 Finding observation；Validation Runner CLI 当前 Finding-specific | 需要真实原件登记为无 verdict observation | B outcome/handoff 字段有表达价值但 schema 不一致 | 新增独立 `record-observation` lane，禁止构造 Finding/Candidate；不改 Store schema |
| 浏览器与多步证据 | importer 的 network.raw.json 是重序列化结果，network_fingerprint 绑定 requests 投影；HAR 私有副本已有 digest；Recon surface 另属 discovery | JSON 缺原始导出基线；surface 丢时序/完整 response；重复 identity 可返回旧 partial | B adapters 强调 handoff 槽位 | 窄补同 bytes 捕获/归档及 network_source 绑定，再从已核对原件建 steps；旧 JSON 无基线显式不可验证；保真实顺序/方法/时间/缺失，partial 补充同 attempt/完整快照，不重放 |
| 执行、安全与恢复 | Scope/Auth、runner、attempt/operation、cleanup 与未知效果恢复 | 调查 cadence 不能覆盖当前约束/禁止重放 | B orchestration 与 branch/状态文件重复 | 保留 C 所有执行权限和责任 owner；方法建议不给操作授权；证据补登不执行 |
| 报告和交付 | C Finding/assessment/delivery/report owner 分离 | 6k 迭代门槛引用其源 report 等级正文 | B report_gate 自有结构 | 不用方法入库门槛充当 Finding 或发布裁决 |
| 专项与新方法 | 当前原生 specialists 与 method正文；Web3 非 HTTP 有明确边界 | A 完整方法源；白盒 Phase0 原文损坏 | B 19 专家声明、4 场景行+3手册 | 专项与 A 正文完整接入；Mobile retired API 卡修正链接；4+3 个 B 增量暂缓到来源/效果复核 |
| 效率/能力测量 | 有既有测试/AB/eval资产 | 静态接入不能证明模型能力增加 | B 声称的工具/评估资产未由此验证 | 不新增 benchmark；不声称在线效果/效率提升；后续用已有测试或另行批准的能力测量 |

源文件与 SHA256 分别见 [A 来源台账](source-disposition-matrix.json) 和 [B 差分台账](v23-delta-inventory.json)。除已明确的同名文件比对、入口声明、链接/Schema 形状之外，B 其余工具、MCP、lane 和专家正文没有宣称经完整审计；C 的对照入口不构成能力等价证明。
