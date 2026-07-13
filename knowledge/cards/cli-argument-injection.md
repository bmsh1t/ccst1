---
id: cli-argument-injection
type: technique-card
related_skills:
  - web2-vuln-classes
  - cicd-security
  - security-arsenal
trigger_tags:
  - cli-wrapper
  - flag-injection
  - terminal-escape
risk: medium-to-high
maturity: draft
load_priority: low
deep_refs: []
source_refs:
  - type: corpus-report
    corpus: hackerone-disclosed-reports
    id: "658013"
  - type: corpus-report
    corpus: hackerone-disclosed-reports
    id: "653125"
  - type: corpus-report
    corpus: hackerone-disclosed-reports
    id: "682442"
  - type: corpus-report
    corpus: hackerone-disclosed-reports
    id: "587854"
  - type: corpus-report
    corpus: hackerone-disclosed-reports
    id: "733072"
  - type: corpus-report
    corpus: hackerone-disclosed-reports
    id: "1070247"
  - type: corpus-report
    corpus: hackerone-disclosed-reports
    id: "651518"
  - type: corpus-report
    corpus: hackerone-disclosed-reports
    id: "1154034"
---

# CLI 包装器的参数/flag 注入与终端转义注入

## Quick Recall

- 触发：服务端把用户输入拼入 CLI、flag、shell wrapper 或终端输出路径。
- 最小验证：用无害参数和数组式边界做单变量 replay，确认是否进入选项位或解释层。
- 证据门：必须证明参数改变了受控命令/文件行为；只出现错误文案不算注入。
- 停止：参数被 `--`/白名单/数组传参隔离，或继续验证会执行破坏性命令。

## 适用场景

- 后端拼接命令行调用外部工具（git/ffmpeg/curl/包管理器）
- 用户值出现在参数位置且可能以 - 开头
- 不可信数据被回显到终端/日志

## 触发信号

- -- 前缀或 - 开头的值被 CLI 当作 flag
- ref/path/scheme 值改变工具行为
- 输出含未过滤的终端转义序列

## 发散问题

- 这个值能否以 - 开头变成选项？有无 -- 终止符？
- 工具的哪些 flag 能改变文件/网络/执行行为？
- 回显路径是否会解释转义序列？

## 推荐动作

- 单变量注入 - 开头的候选，观察工具行为变化。
- 检查是否缺少 -- 参数终止或白名单。
- 对终端回显测无害转义序列。

## 关联 Skills

- web2-vuln-classes
- cicd-security
- security-arsenal

## 停止条件

- 参数经 -- 终止或数组式传参且值不落在选项位
- scheme/工具行为被白名单严格限制

## 检查要求

- 必须证明注入的 flag/转义改变了工具或终端行为并有影响，且无破坏性复现。

## 可晋升经验

- 拼命令行先找参数注入面：能否以 - 开头、有无 --、黑名单还是白名单。
