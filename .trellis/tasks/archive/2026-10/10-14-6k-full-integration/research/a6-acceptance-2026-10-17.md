# A6 真实方法维护隔离验收（2026-10-17）

> 历史检查点：下文状态仅指 A6 当时；最终提交与归档见 [B7](b7-git-acceptance-2026-10-17.md)。

## 当前状态与边界

**A6 的 F 隔离行为验收已通过；C 的 B6 尚未执行。** 原任务仍为 `in_progress`。
此前收尾所述“A6 缺来源”是当时时点；本记录补充其后的公开来源审核与实际 owner 回执。
不把 F 完成勾成 C 完整生效；PRD 的全局 A1–A9 仍待 B6 收束。

```text
C = /root/tool/ccst(rename-_Ya66f2)/ccst3/ccst
W = /tmp/ccst-6k-accept-XQES5z
A6 子 checkout = W/repo/.6k-a6-1792204519563802950
回执目录 = W/results/a6-1792204519563802950
主控 session = 01a14797-1316-7843-a8a8-b0103026e05a
```

仅子 checkout 的既有 `knowledge/methods/clown/skills/src-hunter/知识库/deserialization-test.md`
及其 manifest 经 A 发布变化。方法增加 54 行，保留全部旧字节及 CRLF；没有第二份活动方法、
新短表行、治理变更、产品代码变更或仓库测试。S/主 F 的 638 文件冻结候选与原持久包未改。
公开来源抓取、临时候选、审核与验收材料位于 W；C 只更新本任务文档，不动受保护产品路径。

## 主控来源审核

- James Cao 的 [2026-03-21 公开报告](https://jameskaois.com/posts/case-study-pre-authentication-rce-in-koacook-order-online-system-cve-2025-55182/)
  与 [已合并修复 PR](https://github.com/KoaCook/order-online-website/pull/2) 给出既有应用本地
  Flight 反序列化命令执行的作者叙述；PR 提供可核对的完整多行 PoC。博客代码块抓取有重复，
  不将其修整后冒充原文。主控对照准入原文的“命令跑起来”，不是依靠标题或 CVSS 标签。
- 环境为 localhost，不是互联网生产入侵；不是本会话自挖 Finding。正文与 PoC 作为来源
  报告准入，不声称已独立复现、认证作者或核实截图。图片 fetch 的 OCR 不算图像原件或
  已验证输出，未采用其中具体 uid/密钥值。PR 合并不证明漏洞复现或修复完整性。
- 两份完整抓取 JSON 原字节私下保留、绑定 SHA256；这是完整抓取正文，不是原网站 HTML/
  HTTP 证据或全部截图下载。临时签名图链不进入方法或公共收据；公开稳定出处可保留。
- 主控亲读同一捕获版本的两份准入规则、旧模块和短表。全活动知识库独立查重没有同构
  Flight/thenable 方法；旧 Node 段是函数字符串/IIFE，短表第 85 行是污染写入到模板 gadget。
- 三问通过：同形态产品可识别服务端对象图恢复；新增认法是继承属性读取、伪造内部 Chunk
  receiver、嵌套 getter 与 thenable 自动调用，不是通用命令串或特定业务路径；只补旧模块。
  不混淆读取继承属性与修改全局原型，不把函数值、500/blank/digest 或反射标记当执行。
- 不采纳来源中普遍中间件绕过、sandbox escape、持久化或横向移动的过宽结论；没有发送
  PoC、访问该业务应用、认证会话、读取真实目标资料、下载模型或使用个人 runtime。

## 真实行为与证据绑定

```text
python3 -B W/run_fixture.py -- python3 -B W/acceptance/accept_a6_method.py
日志：W/results/a6-method-2026-10-17.log
结果：W/results/a6-1792204519563802950/summary.json（passed）
```

一项窄验收约 2.3 秒完成，没有重跑 B1 矩阵、全套或已知既有失败。

1. 逐项核对主 F 的冻结 638 文件 bytes/hash/mode。新子 checkout 从保留的真实 before
   575 文件复制新 inode；禁止复制 `.history`，非方法代码来自冻结候选。
2. 使用真实 62 origins 和原工程 payload，经子 checkout 自己的 `hot_method` bootstrap；
   生成自己的事务、见证与收据。隔离网络哨兵实际触发，C/S/真实 `.claude` 不可见。
3. 子 owner 捕获当前准入条文、旧方法和短表；真实主控 review 绑定正文 hash 和两份来源。
   普通 A apply 只更新既有 method 与 manifest，成功返回 `applied`、清理屏障 confirmed。
4. 另起进程 read（namespace PID 5 → 6）返回新完整正文、真实 manifest/revision_ref/reviewer；
   全部旧/新正文及 manifest blob、bootstrap 历史、transaction/decision/receipt 绑定可核对。
5. 规则/短表/62 origins 不变；子 checkout 其他候选文件和主 F 全部 638 项仍匹配。
   没有创建 Store、Finding、证据执行或共享知识发布。

现有 source 协议仅支持 `origin|private`。两份材料本身公开，使用 `private` 只是现有非-origin
保管/传输分支，不能伪造为原 62 origins 或宣称新增 public 协议。来源正文 SHA 与 locator
字符串 hash（`content_ref`）含义不同。reader 如实返回 `private_source_unavailable` 和
`recorded_declaration_not_authenticated`，即使原材料仍在；本次没有隐藏、升级这两个状态。

| 对象 | SHA256 |
|---|---|
| 冻结 638 候选 inventory | `fdd06f1230e4ee65a17511a178e9ac221fbb0b7c2c3f31c36699203b8e756208` |
| 验收脚本 | `6cd8a51edd656e24e541d0f9bedb9193f61f4b3d7c050c6c1fe38b6d471b939d` |
| 子 owner | `f69fc8d9b7bd988a7fd7c8d519a59acc54f239eff618af36b3207f927e37fe80` |
| 方法 before | `864302d8f30cc036e344ec22b88e2ed3c811d84be938abb9687eb51cebe171c0` |
| 方法 after | `4332b12f1baf732bd8ad72b71f316c4c3c5ec43b5e2c42d371e2d1f81044e84f` |
| manifest before | `ce595c6608fb3c7f5968418862d7ae30dd672eac1be4177ff8a2a290e88f69ef` |
| manifest after | `bc1cd02623b3d7ce8b3535a1e928bb8fd21b00582d469e184c98830aea250155` |
| A receipt | `b623f7b0343b4f094c54ee71ddbecc386d06bdda7db79d751a31391311ad42ee` |
| 公开报告抓取 | `a9f3a045ae8f4b2f187426ea02e569c7b4c3a8681c090349d0db313daa274e09` |
| PR 抓取 | `e0c7e5c41e69f5b06bf064f7bf28bcfada221fa45127cf59f911b526d8d2366d` |

两项独立只读审阅均无发现：一项核对本次方法增量/来源/门槛/隐私，另一项逐字节核对
真实 origins、见证/blob 身份分离、收据链、新进程正文和冻结 F。它们不代替主控准入或
已执行验收，也不构成公开漏洞独立复现。

02:40:11 UTC 的 `W/results/a6-final-static.json` 复核 C 的 575 源码、79 受保护脏路径
bytes/mode、HEAD、index、完整 status 与 staged/unstaged binary patch 均未变；S/主 F
各 638 候选文件也未变。这是时点字节保护，不是排他证明。更新后的实际上下文 wrapper
为 implement 130747 B、check 130739 B，各 6 条 manifest 与三件规划全文保留，无截断。

## 恢复与下一步

补充包只保存本次 A 增量、完整来源抓取、真实回执和任务状态。原 before 恢复包与
`20261017T021639Z-candidate-XQES5z/candidate.tar.gz` 不覆盖；补充包不是重冻的 638 文件
候选，须与原候选配套。固定 W 路径需显式重建，inode 见证仅用于审计，不能移植作 C 收据。
持久包路径、hash、成员与回读状态以 [独立归档回执](a6-durable-package.json) 为准。

B6 的候选是原 B1–B5 基础加本次已审 A 增量：C 排他确认且 before 守卫匹配后，先发布代码，
用 C 自己的 before bootstrap，再用新事务 ID 应用 A6 增量，最后发布原生入口并回读。
不得复制 F 的活动 manifest/日志/见证假装 C 完成。此次不需要更改 A 权限或放宽健康检查。
个人 runtime 部署、提交、同步与真实目标操作仍未授权。

用户“继续”不是排他确认；目前已再次投递明确问题，尚未收到有效确认，不执行 B6。

## 后续状态（B6 完成后追加）

上述“尚未确认/B6 未执行”为历史时点。用户随后明确回复“确认,继续”，确认相关读写
消费者和写者停用；C 已使用自己的 bootstrap 与 A6 事务完成发布和真实回读。
最终结果、两次包装失败/向前恢复、权限保护及恢复材料见 [B6 回执](b6-cutover-2026-10-17.md)。
个人 runtime、提交及真实目标操作仍未授权；本记录原有来源/能力限制不变。
