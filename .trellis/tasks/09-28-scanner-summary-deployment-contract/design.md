# 设计：两个独立切口，不引入统一框架

## 边界和归属

Scanner 生产链保留 `vuln_scanner.sh -> summary.json`；partial run 仍只保留 candidate/raw，
不伪造 completion marker。消费链为 `autopilot_state_read -> scanner_summary ->
autopilot_gate -> Closure/review`，把 Scanner 计数判定收敛在已有 reader 模块的纯函数，
reader 与直接 state 的 gate 都使用它。完整原文仍由 summary path 指向，不创建状态 owner。

Runtime Doctor 已定义 Markdown 排除语义；安装器仅对齐其既有 shell 文件筛选。
不用新 inventory service/配置/依赖；跨语言等价由临时副本 parity 回归约束。

## 子任务顺序

1. Scanner 摘要输入契约：影响损坏输入诊断与未完成工作可见性，优先处理。
2. 安装文件筛选：独立交付，单独验证和提交；不与 Scanner 产品提交混合。

## 兼容与风险

- 不把候选、跳过、采样改成 tested；不改原 review token 和 Closure hash 规则。
- 区分 lane_coverage 缺失（旧版可选字段）与字段存在但类型错误；空字典为合法空集合。
- Scanner 小数/非有限计数不再被接受或异常漏出；整数及可解析整数文本保持现有支持。
- 禁用命令、managed Skill root、外部 Skill 和 cp fallback 的已声明 additive 语义保持原样。
- 核查只证明已覆盖的局部契约，不宣称全局部署安全、Scanner 全面正确或真实误闭合已发生。

## 操作边界

最终方案获批后，在当前已提交 HEAD 上创建首个子任务分支并激活该子任务。第二个子任务
执行前重新确认实际基线/分支元数据，不自动合并旧基线分支。每个工作提交另行确认；
可以独立回滚两个代码提交，无迁移。研究和验收记录由父任务汇总。
