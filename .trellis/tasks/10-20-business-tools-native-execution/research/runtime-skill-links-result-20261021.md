# Runtime Skill 链接兼容修复

用户报告 Bootstrap 因 chrome-devtools-cli 目录链接失败，并要求判断是否影响 Skill。
根因来自 2026-10-19 的 `76d16e6`：单入口迁移增加 `_skill_entries` 完整身份检查，
却在读取身份前无条件拒绝目录链接，扩大到正常第三方共享 Skill。

## 影响与修复

`autopilot_bootstrap.py` 的 `compare_runtime` 发生 ValueError 后直接返回
`stop_runtime_error`，不进入目标工作；因此间接阻断该流程后的 Skill 使用。
宿主原生 Skill 加载不经过此函数，不能据此认定原生加载本身失败。

另一窗口的基础放行补丁已提交 `e56d335`，本轮保留该提交及其 runtime/source 接线，
把按链接目录名跳过收口为只读身份检查：

- runtime 正常第三方目录链接、SKILL.md 文件链接允许共存。
- frontmatter/逻辑目录识别改名、嵌套 CCST 已知身份，仍明确拒绝重复或退役入口。
- 没有入口的资源链接不因目录名误拒；目录循环终止，不无限遍历。
- `_safe_path/_file_hash` 写入、删除和所有权边界不放宽，source 仍禁止链接。
- 只改 runtime_doctor 入口发现 owner 与规范，不改个人宿主安装或原生 loader。

## 验证

`python3 -B .trellis/tasks/10-20-business-tools-native-execution/research/runtime-skill-links-check-20261021.py`

最终 exit 0，**23 项断言，0.513 秒**。固定 `1e0c06b` 临时生产源码副本仅叠加
runtime_doctor；候选 Skill/manifest、runtime、shared 目录全部为合成数据。
覆盖真实 compare/sync、Bootstrap 经过真实 compare（仅下游状态/依赖采集隔离）、
目录/文件链接、嵌套资源、循环、改名/嵌套旧身份、source strict/受管写入拒绝，
以及外部字节/链接/receipt 不变。首轮 fixture 缺合成 registry，补齐后通过。

三轮 default 单次只读核验分别检查历史/影响链、基础补丁盲区和最终窄 diff。
最终核验无新增问题；主线程亲自实施和验证。未读/运行项目 tests/，未访问真实
~/.claude/~/.codex Skill/config、目标或审核材料，不联网、不安装、不推送、不归档。
真实个人 Bootstrap 需重新调用确认，隔离验证不代替实际宿主加载验收。
