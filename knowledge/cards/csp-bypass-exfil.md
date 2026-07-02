# CSP 绕过与无脚本数据外带

## 适用场景

- 目标部署 CSP 但仍有 HTML/属性注入点
- 页面存在可复用 nonce、模板占位符、内联 SVG
- 可注入 CSS 或无脚本标签

## 触发信号

- nonce 可被复用或从模板占位符泄露
- CSP 仅对 text/html 生效，SVG/其他类型漏网
- 拦截器枚举不全（漏 CSS background 等向量）

## 发散问题

- CSP 覆盖了所有响应类型和注入上下文吗？
- 有没有可复用的 nonce 或 script-gadget？
- 不执行脚本能否用 CSS/表单外带数据？

## 推荐动作

- 枚举 CSP 未覆盖的响应类型与向量。
- 尝试 nonce 复用 / gadget 组合。
- 用无脚本通道逐步外带小片段做 PoC。

## 关联 Skills

- web2-vuln-classes
- security-arsenal
- triage-validation

## 停止条件

- CSP 严格且覆盖全部类型，无 gadget、nonce 一次性
- 无可注入上下文

## 检查要求

- 必须在 CSP 生效下证明脚本执行或敏感数据外带，且可复现。

## 可晋升经验

- 把 CSP 当作可绕清单：类型覆盖、nonce 复用、gadget、无脚本外带四条线。
