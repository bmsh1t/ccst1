# 普通 Autopilot 深度优化：一次复测与后续修正

本轮单样本显示业务调查有扩展：普通账号/购物篮、注册角色赋值、FTP、JWT 和浏览器
XSS 均在首批报告后继续。误建 Finding 成功撤回，不再复活。仍未展开匹配的完整方法，
动作后状态刷新没有按合同落实，最终用局部账号 cleanup 失败解释全目标收尾；报告影响、
身份材料及事件时间仍有缺口。因此不能称已经稳定适配 6k，也不能从这一次判断原生 6k
与适配层谁更深。耗时和报告数只描述样本，不作为测试深度或正确性的替代指标。

## 设置与基线

用户已授权优化、本地提交及新隔离靶场。严格沿用普通 `/autopilot` 和指定模型，没有
增加 deep/quick、最低分钟数、漏洞路线或 lane 数。未读取/修改/运行项目 tests，未安装
依赖、push、归档、改个人 runtime/配置、旧目标/报告或原始方法正文。

| 项目 | 原诊断样本 | 本次唯一复测 |
| --- | --- | --- |
| 固定源码 | 73e0113 | 67eb3ede5d80ab26a63249e0ecb3725c844d52b7 |
| 模型/入口 | claude-opus-4-8，普通 /autopilot | 同模型、同入口 |
| 实验根 | /root/ccst-runs/ccst-depth-20261021-5htrnssg | /root/ccst-runs/ccst-depth-optimized-20261021-ui5vbj3q |
| 时长 | 417.807 秒（6分58秒） | 856.618 秒（14分17秒），exit 0 |
| 工具调用 | 69；浏览器0 | 148；Bash134、浏览器14 |
| Skill工具调用 | 1，完整注入 | 0，通过 cat 完整读取正文 |
| 对应方法正文 | 未展开 | 未展开 injection/idor/authbypass/oauth-jwt/xss |
| 模型裁决/已发布报告 | 3/3 | 9/8；非独立重新复现次数 |
| 新身份/业务 | 管理员只读 Users | 普通账号、购物篮、注册admin、投诉等；对照仍有缺口 |
| 动作后状态 | 仅开场/末尾 | 末尾3次closure、1次loop-check，仍不满足每动作消费 |
| 停止投影 | handoff，非exhausted | handoff，209未测单元，非exhausted |

复测于 2026-10-21 **13:40:01.758534→13:54:18.376447 UTC** 运行。收尾上限
14:30:01.758534，硬截止14:40:01.758534，均未触发。新 Juice Shop、新 Store、独立
HOME/runtime/UUID、bwrap 隔离，同镜像 sha256:9f0f27a4451494f6442351e8f3cd8eca7b00ddb6d473fa7ab28c7373f255c2a4，
同506文件白名单，无应用服务端源码或旧答案。实际 MCP new_page about:blank 预检成功，
Bootstrap clean/continue。模型名称来自参数/服务自报，未独立认证服务后端身份。
CLI自报149 turns、duration_ms=853563、费用约$10.49；不等于独立账单。

## 审计与保全

以下路径相对本次实验根。只读审计使用过滤后的可见 text/tool_use/tool_result，
`visible N` 指派生条目的原流 line 字段；未读取或输出隐藏 thinking。

- audit/visible-trace.private.jsonl：297可见事件。
- audit/tool-calls.private.json：148调用、参数与真实结果。
- audit/result.private.json、process.json：最终可见答复/CLI统计与起止记录。
- audit/final-store.sqlite3：SQLite backup API 冻结副本。
- audit/frozen-verification.json、source-integrity.json、cleanup.json、process-cleanup.json。

冻结计数：10 Findings（9 active、1 withdrawn）、9 assessments、8 reports、11 attempts/
operations、21 observations、1 experience、0 Actions。62登记artifact存在且大小/hash匹配，
SQLite integrity=ok、FK错误0，506源码无变化。误建 F-002-sqli-search 撤回后 replacement
指向 F-002b-sqli-search，原历史仍保留。普通模式没有round claim；0 Actions本身不算违规。
INDEX等级已正常保留，但解析正确不代表语义定级正确。例如F-002b仅证明用户数据读取，
按现有唯一报告规则属于“注入出了他主体的数”门槛；尚无接管/业务变更证据支撑critical。
本次没有独立验收所有报告的6k定级。

三路早先live审核因服务token限流失败，无结论；本次两个独立只读证据审核均完成，
主代理按其line/原件引用抽查可见浏览器执行、登记字段与最终停止说明。只读核验留存
原件不是重新执行利用。被测Store和报告保持原样，不补改证据来修饰样本。

## 核心结论及边界

| Finding / 账本等级 | 留存原件支持的结论 | 缺口与定位 |
| --- | --- | --- |
| F-001，critical | 匿名正常登录401；OR恒真/注释载荷200，取得管理角色JWT；同一JWT读取22用户 | 不证明全部管理员写删；visible4239→4240，登记5036→5037；operation:2e39cac1f2f68e2174a5e226ac1dc55349e35758680d5c54b247238c0fe71fc8 steps0/1/2 |
| F-002b，critical | 匿名基线3商品；UNION响应80行，23行匹配用户字段投影 | 32位hex不能独立认定MD5；未验证口令恢复、登录或任意表写入；visible5843→5844、5919→5920；operation:2f476e09deb16a4acc875b90c49a095214c6bc3f146c50db95d7ccc324e22cd3 steps0/1 |
| F-003，high | 匿名memories返回10条，嵌套5个不同User及敏感字段，6嵌套记录token非空 | 未认钥，不证明token冒充或10个不同用户；visible2710→2711、5059→5060；operation:a83f3f7f1f92dad06604a7de6d3055c186d6a168d0bd59bd36f49708af20531e step0 |
| F-004，medium | 本轮注册/登录同一customer；该token读到owner不同且有商品的购物篮 | “own-basket”对照200/data:null，不证明本人归属，可能误用user ID；visible2894→2895、2917→2918、4239→4240；operation:824d59102c9565dff5cf5cf97ad42371e521d6088ead5597d9cff52ba4d72e4f steps0/1 |
| F-005，confirmed/eligible，未发布 | 匿名注册role=admin，随后同账号登录并用所得token读取Users | 缺同接口普通角色拒绝对照；cleanup pending；visible12947→12948、13104→13105；operation:d7a11149acbb9fc38d3734b6a4b0295c3c277b864c1d90985d11757611d978af steps0/1/2 |
| F-006，medium | 匿名目录及两个文件200；909bytes机密文档、3246bytes正确KDBX签名/v3.1 | 不证明凭据库明文已解密；visible19814→19817、19872→19873；operation:71e7d5a525229b7910731fad59d4ffdf282ca42297b6d4f5e3b72d5e910b2b91 steps0/1/2 |
| F-007，critical | 无token401；不同于SQLi会话的alg=none空签名JWT请求200/24用户 | 未独立whoami或其它管理操作；variant=token_missing与实际伪造token不符；visible21773→21774、21913→21914；operation:38b799d08e00495e974006d1cc99988191f4a589aa42c929335f3dadfaf65124 steps0/1 |
| F-008，medium | 浏览器原导航有alert；第二载荷回读iframe执行标记 | HTTP原件后补首页，非同次导航；浏览器匿名身份未独立核实；visible23167→23168、25253→25254、25274→25275；operation:cca1ceac43f186178af39cb4bb7a44fb85fcca25cf43d6cb1c0737affec0d311 step0 |
| F-009，high | 从本轮customer登录原件取token，投诉集合200含他人owner/正文；匿名401 | 无对象ID替换，variant=id_swap分类失真；本人投诉对照未核得；visible28763→28764；operation:af8449e8670378b6d0e59be35827d47a62490912e6fdeeba0253ea8d4fa8f31e steps0/1 |

所有本轮观察identity_status=none、identity_v2/dimensions为空，Case actor/session/object
没有登记。URL identity artifact只绑定请求地址，不是主体身份凭证。上表身份结论来自
原始curl请求头/JWT/响应及同源token取用关系；不会因为标签存在就声称完整closure证据。

报告具体夸大：F-001第8行写全站写删，F-002b第10行推其它表写入，F-003第10行推
deluxeToken冒充。XSS执行成立，但localStorage token取得未实测。原唯一报告格式确实
要求“进后台只证明能看，危害仍写能改能删”，是直接冲突源，不能只在Autopilot叠提示。

## 时间、来源与执行摩擦

7条observed_at晚于operation登记：两cleanup为13:59:30/14:00:10（登记13:44:56/
13:45:09），FTP三步为13:51:30（登记13:48:12），投诉两步为13:53:20（登记13:52:04）。
这些手填时间不能充当精确执行证明。登录baseline/注入登录/GET Users原先统一标了
state-changing；注册链也把所有步骤套顶层事实，使cleanup引用包含非mutation。
两cleanup材料复用同一真实read-back，却另造attempt/未来时间；不会据此认定成功恢复。

XSS登记：visible26084→26085留存浏览器首页response但缺request；26255→26256/
26315→26316暴露缺项；26572→26573另行curl首页替代request/response。执行证明来自
浏览器dialog/DOM回执，不能把后补HTTP原件当同次导航，也未证明两份body字节相同。

明确CLI拒绝5次：endpoint不匹配1，cleanup发布2，缺observed_difference1，XSS缺request1。
管道/后续命令掩盖非零，外层is_error=false不是零失败。另有shell `=== not found` 和
浏览器alert造成暂时拒绝。未把预期HTTP401或500统一计为工具故障。

## 停止依据与回收

visible33355最终把“无法删除测试admin、Users PUT/DELETE JWT decoder401”作为停止
新增写/上传的依据，同时列出未测上传/XXE、会员逻辑、订单/支付等。这足以约束相应
操作，尚不足证明全目标不存在值得继续的独立业务。首次cleanup失败visible14000→14001
后仍有66工具调用，包含FTP/JWT/XSS/投诉及其它清理尝试，反而证明局部失败不阻断所有
后续调查。末尾closure/loop-check仍只保存handoff，不证明所有只读业务已经完成。

测试账号24/customer与25/admin留在本实验数据库；应用级cleanup未成功。模型将
浏览器导航至about:blank，最后一页关闭失败。外层于13:55:51正常停止本实验容器，
OOMKilled=false；session PID及本实验runtime进程均消失。隔离回收完成不等于账号恢复。

## 本次复测后修正及定向验收

以下修改发生在固定67eb3ed复测**之后**，未再做live测试：

- 唯一报告格式改为实际操作/可信权限内省支撑影响；角色、菜单、只读请求不推写删，
  未验证链明确标注，hash/加密库/token不推口令恢复或接管。/report引用该唯一owner。
- Autopilot在选定问题首个请求前读/apply完整对应方法；局部writer/cleanup失败需
  评估独立业务路径，不增加controller或模型行为回执。
- record-evidence保留可选逐步observed_at/state_changing/redline_checked；summary/CLI
  事实仅作默认，旧省略字段身份及历史pair语义保持。类型、timezone、step≥attempt start、
  no-future、mutation redline与cleanup有效只读在attempt/witness发布前拒绝。
  cleanup比较真实anchor observed_at；无Finding观察复用同一no-future边界。
- 文档补混合实验、完整cleanup、浏览器fragment来源/partial和身份/对象对照说明。
  不自动解析HTTP业务含义，不由method推副作用，不重写旧报告/Store。

`python3 .trellis/tasks/10-20-business-tools-native-execution/research/check_native_step_facts_20261021.py`
最终通过74项断言，4.599秒，exit0；结果 `/tmp/ccst-native-step-check-5f35ftip/result.json`。
临时源码/独立HOME，真实生产CLI/Store；旧67eb3ed实现实际登记后用新CLI重试，身份/
operation不变。覆盖混合步骤、null、时间精度/offset、cleanup实际顺序/重试、future/naive/
早于attempt/非法bool/缺redline/非只读cleanup零发布拒绝，以及历史pair/no-verdict。
首轮74项5.062秒通过；随后将分支内事实选择移到现有native分支以便阅读，重验同一
定向检查通过。既有69项工程验收不重复运行，本次不运行项目tests或全套。
两路最终差异审核均因服务stream disconnect失败，没有审核结论；主代理亲读最终生产diff、
round共享入口、证据/cleanup示例与owner检查，git diff --check通过。没有宣称独立最终审核通过。
两入口合计15957 bytes（本轮前15624，原诊断14959）；既有11KiB预算漂移保留，未声称通过。

剩余：未验证这组后续提示能被模型稳定遵守；仍需原生6k对照/多样本才可判断整体适配。
生成时间的机械门禁不能证明模型填的过去时间真实，身份/报告影响仍依赖原件语义核验。
未修饰本轮结果、重跑到满意或加入静态严重度裁判。旧Store使用新候选处置需显式备份
升级v18，仅未绑定候选能撤回；并非通用裁决撤销。
