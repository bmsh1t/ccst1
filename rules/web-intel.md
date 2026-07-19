# Web Intel 规则

Web Search、Grok、smart-search、浏览器和其他 provider 只负责发现或核对来源；
`tools/web_intel_artifact.py` 是 Web Intel 的唯一持久化 owner。它不创建 finding，
不写 coverage/action 状态，也不把搜索摘要当成漏洞结论。

## 触发条件

- 官方 OSV/GHSA/NVD 全部无结果、部分失败或不可用。
- 已识别产品、CMS、插件、库或网络服务存在未知别名、近期版本或明确的最新情报需求。
- 现有 advisory 需要补充厂商正文、修复版本、受影响范围或 PoC 参考。

没有上述条件时不为每个组件固定搜索；端口号本身也不能触发 CVE 查询。

## 记录契约

先核对正文，再提交 JSON。`body_verified=false` 的结果只保留 discovery lead，不能进入
Intel merge。转载同一公告的 URL 使用同一个 `independent_source_group`，不能伪造多源确认。

```json
{
  "target": "TARGET",
  "subject": "COMPONENT@VERSION",
  "intent": "component_advisory",
  "query": "COMPONENT VERSION vulnerability advisory",
  "provider": "PROVIDER",
  "status": "ok",
  "results": [{
    "url": "https://HOST/advisory",
    "source_tier": "A",
    "independent_source_group": "ORIGIN_GROUP",
    "body_verified": true,
    "claims": [{
      "identifiers": ["CVE-YYYY-NNNN"],
      "component": {"name": "COMPONENT", "version": "VERSION"},
      "applicability": "affected",
      "severity": "HIGH",
      "summary": "BODY_VERIFIED_SUMMARY"
    }]
  }]
}
```

写入后运行 `/intel`，再让 `/autopilot` 重新读取状态。精确版本不匹配时，适用性降为
`unknown`；来源不可用写 `status=blocked` 并交接，不得写成 `not_affected` 或 clean。

## 续跑顺序

```text
inventory -> /intel -> collect_web_intel（仅在 gap 时）
         -> /intel -> test_advisory_applicability
         -> action_queue -> evidence/disposition
```

验证只使用最小、可回放、低影响的 reachability/version 证据。action queue、finding、
evidence ledger 和 coverage matrix 继续使用各自 owner；Web Intel 不建立第二套状态机。
