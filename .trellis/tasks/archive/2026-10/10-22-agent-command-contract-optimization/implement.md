# Implementation

用户在最终计划后回复“开始”，已同意任务创建与该范围实施。

1. 配置 context、绑定当前 Codex session、激活本任务；不改变旧 Claude 任务。
2. 主代理完整读取将改代码，修正 disclosure 行业/缓存和阅读保全、Surface 推荐。
3. 迁移 Chain/Web3/Token 的全部独有方法，再薄化 command/agent；保持六个入口
   description、权限、模型与输出字段。
4. 同步验证/发布收据、纯读取/增量写回、记忆示例与导航的活动调用者。
5. 更新 owner specs，加入 isolated assert-based focused check；不进入项目 tests。
6. 运行一轮约60秒 focused check：隔离生产副本、stub provider、真实 CLI/API、
   cache bytes/mtime、引用/方法/接口保全、Surface 纯函数和临时安装资产清单。
7. 默认配置探子只读核验全 diff；主代理采纳 in-scope 发现并最终复核、commit。

验证产物位于本任务 `research/`。不以缩短 bytes 推断实际模型能力或费用改善。
出现 attributable 失败后只修本轮原因，代码/环境变化后才重跑；不扩大到全套检查。
