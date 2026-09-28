# 设计：在现有 reader 内集中 Scanner 计数规则

## 数据流与最小边界

在 `tools/autopilot_state_read.py` 增加一个 Scanner 专用纯函数处理三项计数及有效标志，
由 `_load_scanner_summary_projection()` 与 `autopilot_gate._scanner_lane_residuals()` 复用。
不新建模块、类、配置、状态或 reader 框架；gate 仍负责终态/residual/review 决策。

reader 的文件边界捕获 UnicodeError，显式区分字段缺失与错误 lane 容器。
已有 path/status/lanes 形状保留；异常输入显示 partial。计数函数只接受非布尔整数或
可解析的整数文本，不通过 int(float) 截断事实，也不让 OverflowError 漏出。
无效输入的有效 remaining 可继续用于诊断，但 accounting_valid 必须保持 False，
再次被 gate 检查时不能因投影后的零值被升级成有效闭合依据。

## 依赖与兼容

- gate 可导入现有 reader 的纯函数；reader 当前不依赖 gate/autopilot_state。
  实施时验证双导入路径，不将上层状态模块反向导入。
- direct state 的 gate 校验不能删除，避免仅文件路径安全而直接 API 仍截断计数。
- 旧版 absent lane_coverage 仍走原 missing 兼容；显式 []/null/string 为坏容器。
- 本轮不抽取 Recon 的相似代码；其不同的缺字段和 blocking 规则属于另一契约。
- 正常 Scanner writer 仍输出相同 JSON；来源、complete/partial、候选深度及 review/hash 不变。

## 验证与回滚

真实临时 summary -> reader -> gate 验证损坏信息不丢失，并覆盖直接 state 的 gate。
至少一条真实 Store 的 bounded state/Closure 路径验证错误不破坏当前恢复视图，
以及读取不改 raw/Store。失败先定位当前改动，不修无关 reader。
只回滚本子任务独立产品提交；无需数据迁移。

## 已批准的范围修订

原计划只处理 reader/gate，但真实调用链在 Coverage 的可选 policy reader 先读取相同源。
Surface 的 manual-review reader 也有相同编码边界缺口。仅在这两处既有 except 增加
UnicodeError，不改变它们已存在的坏 JSON 语义；公开健康仍由 Scanner reader 保留。
这不是抽通用 parser 或新状态 owner。用户最新 `go` 已批准实施两处边界补充。

## 第二次验收的归属修订（已批准）

Finding claim 枚举通过 root `*.json` 纳入了 Scanner 专属 summary。复用
`ROOT_CLAIM_EXCLUDED_FILES` 添加 `summary.json`，在解码前排除非 claim 产物；分类函数的所有
调用者共享这一规则。不改 `_load_json_value`，避免影响历史 Finding 读取并掩盖其他损坏。
坏 summary 仍由 Scanner reader 公开 partial/path；独立 claim 原文、候选身份和 Store binding 不变。
