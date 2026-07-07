---
id: path-traversal-file-read
type: technique-card
related_skills:
  - web2-vuln-classes
  - triage-validation
trigger_tags:
  - path-traversal
  - directory-traversal
  - lfi
  - file-read
risk: medium
maturity: draft
load_priority: medium
deep_refs: []
---

# 路径遍历 / LFI / 文件读取

## Quick Recall

- 路径遍历的入口是“用户输入影响文件定位”：参数、路径段、文件名、下载/预览/模板/本地化/主题/附件/导出。
- 先用正常文件 baseline，再比较 traversal 形态的状态码、长度、文件特征、错误和 MIME。
- Linux、Windows、Java、PHP、Nginx alias、Apache/Tomcat/IIS 的路径规范化不同，要按技术栈变形。
- 示例路径和 wrapper 只是候选形态，不是固定字典；命中后优先证明最小读取和业务影响。
- 文件读取常作为链路种子：源码/配置/路由/签名密钥/依赖版本，而不是默认批量读取敏感数据。

## 能力定位

本卡给 `web2-vuln-classes` 补充文件选择器识别、路径解析差异和 file-read 链路思路。
它提供技巧和 checklist，不替代红线、覆盖 gate 或 `triage-validation`。

## 触发信号

- 参数或路径出现 file、path、download、view、include、template、page、image、doc、export、filename、attachment、theme、locale、backup。
- 错误信息出现 no such file、permission denied、base path、canonical path、realpath、WEB-INF、open_basedir。
- 静态文件、下载、预览、报表、模板渲染、图片处理或 archive extraction 使用用户可控文件名。
- 源码/JS 暴露文件路径、模板名、资源 ID 到本地路径的映射。

## 思路分支

- Direct traversal：参数直接拼接到文件路径。
- Encoded traversal：单编码、双编码、混合 slash/backslash、Unicode/overlong、路径分号等绕过。
- Suffix/prefix bypass：服务端追加扩展名、前缀目录或安全 base path 时的截断/规范化差异。
- Wrapper/read filter：PHP `php://filter`、Java `WEB-INF`、Windows drive/UNC、Tomcat/IIS 特定路径。
- Archive traversal：ZIP/TAR 条目名穿越；默认只证明风险信号，不在真实目标写覆盖文件。
- Chain：file-read -> source/config -> route/dependency/signing secret -> authz/RCE/SSRF 假设。

## 技巧家族 / Payload 家族

- 路径形态：`../`、`..\\`、嵌套点段、绝对路径、混合分隔符、URL 编码和双编码。
- 平台形态：Linux 常见只读文件、Windows 系统文件、Java `WEB-INF/web.xml`、PHP wrapper、IIS 8.3。
- 业务形态：已存在静态资源名、下载 token 对应文件名、导出模板名、语言包/主题名。
- 对照形态：合法文件、同目录不存在文件、越界存在文件、越界不存在文件四组响应差异。

## 补充 Checklist

- 是否有正常可读文件作为 baseline？
- 是否确认读取发生在服务端，而不是浏览器缓存或前端路由？
- 是否测试了路径参数、路径段、文件名、archive entry 和二阶预览/转换？
- 是否检查了后缀拼接、MIME 校验、下载 header 和错误栈？
- 命中后是否记录了最小必要证据，而不是继续扩大读取范围？

## 最小验证

- 用合法文件和不存在文件建立响应差异。
- 单变量替换为 traversal 形态，比较状态、长度、MIME、错误和文件特征。
- 若读取源码/配置能证明影响，只记录必要片段、键名或路径，不保存真实凭证正文。
- Candidate 前需要 replay 请求、baseline 对照、读取边界、影响解释和敏感数据处理说明。

## 常见误判 / 死路

- 404/500 差异可能是路由层差异，不一定是文件系统访问。
- CDN/静态服务 rewrite 可能产生类似路径差异。
- 下载 IDOR 与路径遍历可能重叠，需要区分对象权限和文件路径控制。
- 读到公开静态文件通常只是 Signal，除非能越界读取非公开资源。

## 关联 Skills

- `web2-vuln-classes`
- `triage-validation`
- `bb-methodology`

## 晋升到 Skill / Queue 的条件

- 只有命名信号时，作为 Lead 补 baseline。
- 有可控文件选择器和稳定差异时，写入 action queue，类型 `path-traversal-file-read`。
- 读到源码、配置、私有文件或可链到 token/RCE/authz 时，转 `triage-validation`。

## 可晋升经验

- 某类框架或代理的路径规范化差异。
- 某类下载/预览功能常见的文件选择器命名。
- 某类 wrapper 或平台路径在授权测试中稳定、低风险地证明 file-read。
