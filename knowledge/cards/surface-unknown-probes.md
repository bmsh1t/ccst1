---
id: surface-unknown-probes
type: checklist-card
related_skills:
  - src-hunting
trigger_tags:
  - surface-review
  - discovery-unknowns
risk: low
maturity: draft
load_priority: medium
deep_refs: []
surface_advisory:
  multipart_request:
    questions:
      - Which captured field carries the test-owned file and which consumer reads it?
      - What read-back evidence distinguishes storage from interpretation or execution?
    action: inspect_one_saved_upload_and_readback
    why: Establish the observed storage and consumer boundary before considering another upload.
    hint: Inspect the saved request and one existing test-owned read-back; a successful upload alone proves no cross-object impact.
    stop_conditions:
      - Stop if the object is not test-owned or the consumer is unknown.
      - Before any new write, establish scope, reversibility and final-state verification.
  structured_request:
    questions:
      - Which captured body field selects the object, operation, actor or tenant?
      - What existing control response would isolate one changed variable?
    action: compare_one_saved_structured_request_with_control
    why: Locate the smallest unresolved input or identity boundary in existing evidence.
    hint: JSON is a serialization fact, not proof of GraphQL, authorization failure or side effects.
    stop_conditions:
      - Stop when no comparable control or request context exists.
      - Stop after one evidence pair distinguishes the current explanations.
  parameterized_surface:
    questions:
      - Which parameter location and value were actually observed rather than inferred from a URL name?
      - What ownership or identity context is missing for a controlled comparison?
    action: inspect_one_saved_parameter_and_response
    why: Establish an actual input-to-object relationship before proposing a mutation.
    hint: Read only the necessary existing sample; a parameter name or numeric ID does not establish access semantics.
    stop_conditions:
      - Stop if the parameter has no observed consumer or response binding.
      - Stop before enumerating other users or objects to manufacture a control.
  request_shape_hint:
    questions:
      - Which actual method, response shape and identity context are supported by raw bytes rather than importer defaults?
      - Which single missing response fact separates the leading explanations?
    action: inspect_one_captured_request_response_pair
    why: Reuse captured facts before choosing another request.
    hint: Request-shape method and MIME values may be defaults or guesses; inspect raw bytes, and determine effects from observed behavior.
    stop_conditions:
      - Stop if the captured request cannot be bound to its raw response.
      - Keep a missing baseline or identity context explicit rather than guessing it.
  scanner_signal:
    questions:
      - Which raw response fact supports the scanner label?
      - Which baseline distinguishes that fact from a generic error, login wall or public content?
    action: inspect_one_scanner_signal_and_baseline
    why: Separate a scanner lead from finding-grade evidence without automatic replay.
    hint: Start with saved bytes; live confirmation requires an AI-selected scoped request and its existing executor.
    stop_conditions:
      - Stop if the raw evidence or baseline is missing or damaged.
      - A label or status code alone cannot establish impact or close coverage.
  unobserved_request:
    questions:
      - What actual method, request shape and raw response exist for this discovered URL?
      - Which existing page, source reference or capture explains the endpoint's consumer?
    action: inspect_one_existing_endpoint_reference
    why: Resolve the missing request shape before proposing any live probe.
    hint: Do not fill unknown methods with GET; if no material exists, retain unknown and let AI choose the next bounded observation.
    stop_conditions:
      - Stop if no existing material establishes the request or target ownership.
      - New network work needs an explicit scope, identity and side-effect decision.
---

# 发现面上的未知问题与最小观察

## Quick Recall

- 触发：发现期 review window 尚缺请求形态、对照或对象关系。
- 最小验证：按已观察的形态读取一份现有材料，不自动发送请求。
- 证据门：原始请求与响应引用、身份和条件；URL 词语不是漏洞证据。
- 停止：缺材料时保留 unknown，不把建议当作已执行或覆盖结论。

## 触发信号

- multipart、结构化 body、参数名、真实捕获请求或 scanner 线索提供不同的事实缺口。
- 形态可重叠；脚本只显示一个启发式标签，不排序价值、不判断漏洞或副作用。浏览器导入的 method/MIME 可能是默认值或 body 推断，只作 hint，不当作原始请求事实。

## 推荐动作

- frontmatter 的 `surface_advisory` 是只读投影的问题材料，由现有 registry 提供本卡身份与路径。
- 先从已存证据消除未知。需要现场请求时，由 AI 明确假设、对照、Scope、Auth、预算与停止条件，交给原执行 owner。
- 涉及状态变化时先确定可回滚对象与最终回读；动作执行和回收确认分别绑定 Store 观察。

## 检查要求

- 保留分类依据、知识来源和证据引用。建议本身不证明原始字节健康或可重放。
- HTTP 方法不代表副作用；未知方法、身份、对象关系和影响均保持 unknown。
- 不选择 Skill，不写 Queue，不扫描全索引，不刷新缓存，不生成 Finding。

## 常见误判与停止条件

- 没有可区分的观察、受控对象或可用材料时停止当前建议，不扩大为固定流程。
- 卡片缺失或结构损坏应显示 unavailable，不用代码中的另一套问题集顶替。
