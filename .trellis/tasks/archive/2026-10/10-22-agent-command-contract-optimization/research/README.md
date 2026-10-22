# Agent / command 合同优化验收

日期：2026-10-22。仓库 `ccst3/ccst`，基线 `2ce0171`，分支
`refactor/10-11-capability-architecture`。用户审阅 PLAN 后回复“开始”，本轮保持批准范围。

## 结果与证据

`check_entry_contracts.py` 在临时目录复制限定生产源码和发现资产，使用合成
provider 调用真实 API，并在清理后的环境运行真实 CLI。最终执行约一秒、exit 0，
结构化结果见 [result.json](result.json)。项目 `tests/` 未读取或执行。

- 三专项的六份 frontmatter（含 description/tools/model）与 usage 命令保持；
  输出字段未丢失。Web3 十类、Token 八行、Chain 七行迁入已有完整 module；
  原十二条 CHAIN_REQUIRED 示例仍在。
- 21 个 Markdown 链接/anchors 有效。现有资产发现保持 10 agents / 37 commands，
  三模块递归发现与 critical runtime manifest 有效。
- 79 个保护文件与基线字节一致，含完整 6k rules/知识库、主 Skill/协议、Autopilot
  核心和 Store。Surface 保留 pool/browser 等选项，仅删除按候选数量推荐 Chain。
- API/CLI 行业传递与五次查询配额、行业/legacy cache 命中、失配失败回退、partial
  不混旧快照、完整成功零结果、坏行业/cache 类型均符合合同。
- cached/live/unavailable/no-mcp 重建保留精确旧全文章节，覆盖 CRLF、H3、嵌套 fence、
  H1/H2 及空标题边界。独立 `.readings.md` bytes/mtime 保持，含空格自定义路径链接正确。
- no-mcp 的 cache/client/inventory 禁止调用断言通过；摘要读取/编码/发布失败保留旧字节。
  非 UTF-8 的真实 CLI 返回 2，无成功路径；`find-gaps --help` 有 `--limit`、无 `--all`。

三名干净 default 探子只读独立复核，主代理完成最终取舍与修正：补回 Web3
预期学习/可逆成本、authority transition 与 actor/replay 范围；Token 入口接受缺源码信息；
旧阅读章节正确结束于空 H1/H2；移除无效 target 必然报错的新文档承诺。
发布收据、按需读取、记忆 locator 与负经验参数未发现剩余合同矛盾。
完整 diff 审阅与 `git diff --check` 通过。

## 改动与测量范围

默认 single-step 验证消费已有报告收据，deferred 或显式新 eligible delivery 才作者入口；
纯查看不强制 refresh 或无增量认知写回，实际结束仍满足 Coverage/Closure。
专项方法只有现有 module 一份完整正文，原生 description 入口继续保留。
披露查询支持行业匹配，并保全人工全文阅读。记忆/导航示例与现有 owner 接口一致。

本轮受影响的 agent/command 正文从 111,279 bytes 变为 102,385 bytes，减少 8,894
bytes（约 8%）。完整方法移到模块后按需读取，不能据此推断实际模型费用或测试深度改善。

## 未检查与已知边界

未运行项目全套测试、真实宿主安装/description 调用、模型或靶场测试，未测 token、
费用或漏洞产出。未访问真实目标、个人/全局 runtime、正式知识审核或上游服务；未安装
依赖、push 或归档旧任务。验收源副本的安装资产发现不代表真实宿主调用验收。
任务 context 校验通过，但 Recon/Validation 两份现有大 spec 超过 32KB 自动注入
上限；本轮直接读取相关合同并审阅完整差异，未扩大范围拆分这些 spec。

每目标仍只存最后一次完整行业快照，切回旧行业可能重新查询。人工编辑要求单写者，
无并发编辑锁；cache 与摘要独立原子发布，没有跨文件事务，摘要发布失败不回滚已写
成功 cache。非 HTTP 合约只保留分析材料，尚不进入 Store Finding 生命周期。
