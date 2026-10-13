# C5 G3 能力关口就绪复核

日期：2026-10-13。状态：**not started / not ready for execution**。

本复核只确认 G3 是否具备启动条件，不运行模型、不下载依赖、不创建题库/测试文件、不改变默认组合。

## 已具备

- C0 `capability-evaluation/2` 统计合同已登记；分层符号翻转精确检验、lineage 排除、Wilson
  描述性区间、零退化门和停止规则已固定。
- 离线实现验证已通过：协议聚焦检查 `24 passed`，基线+协议集合 `68 passed`。
- v1 的不可达功效缺陷已记录并由 v2 设计修正；v1 结果不混入 v2。
- C5 G2 owner continuity review 已提交为 `b65b47f`，工程 owner/恢复边界与 G3 能力轴分开。

## 启动阻塞

| 阻塞项 | 当前事实 | 不能替代的证据 |
|---|---|---|
| 案例与真值 | 尚无八族完整的开发/留出案例、独立 lineage、真值原件和受控错误变体 | 现有目录、静态测试或旧 161 例草稿 |
| 各臂材料 | A/B/C/D/E/F/K 及三个 B 消融的完整源码、Skill、知识、索引、权限 manifest 尚未按 v2 study 冻结 | 单个工程 checkpoint 或 hot-method hash |
| 预登记回执 | 尚无独立保存的 registration hash/首槽前 receipt | 本地 `seal` 成功或文档时间 |
| 模型运行 | F2 已记录不批准下载/运行本地 encoder/reranker；A–F/K 真实运行也未批准 | CLI help、fake provider、合成结果 |
| 内容准入 | C2 候选仍按既定边界后置，不能在 G3 中隐式晋升或把单模型结果泛化 | 单次盲答、目录命中或候选草稿 |

## 判定

G3 保持 `not_started`，不是失败，也不是通过。当前 `release_decision=not_ready`、
`default_selection=not_selected` 不变。没有新的产品代码缺口需要修复；继续追加工程微切片
不会补足能力证据。

## 唯一可执行的后续入口

只有在单独批准能力批次后，才按新 study 依次执行：

1. 登记八族案例、真值、mutant 和开发/留出隔离；
2. 冻结各臂 manifest、模型/权限/版本和独立 preregistration receipt；
3. 先用开发集选择候选，再用锁定候选运行 heldout A 对照；
4. 保存所有失败分母和 hard/保护门结果，最后才进行默认评审。

在该批准和完整材料出现前，不启动 C0 A–F/K、C2 盲答/晋升、C7 语义模型或真实发布切换。
