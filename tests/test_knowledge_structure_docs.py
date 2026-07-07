"""Regression tests for the knowledge-base card structure contract."""

from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]


def _read(relative_path: str) -> str:
    return (REPO_ROOT / relative_path).read_text(encoding="utf-8")


def test_knowledge_card_template_is_experience_compression_library():
    text = _read("knowledge/card-template.md")

    assert "知识库是经验压缩库，不只是联想种子" in text
    assert "## 能力定位" in text
    assert "## 触发信号" in text
    assert "## 思路分支" in text
    assert "## 技巧家族 / Payload 家族" in text
    assert "## 补充 Checklist" in text
    assert "## 最小验证" in text
    assert "## 常见误判 / 死路" in text
    assert "## 晋升到 Skill / Queue 的条件" in text
    assert "示例可以具体" in text
    assert "不是固定字典" in text


def test_knowledge_readme_and_index_define_dual_role():
    readme = _read("knowledge/README.md")
    index = _read("knowledge/index.md")

    assert "经验压缩库" in readme
    assert "payload 家族" in readme
    assert "补充 checklist" in readme
    assert "推荐知识卡结构" in readme
    assert "能力定位" in readme
    assert "晋升到 Skill / Queue 的条件" in readme

    assert "经验压缩库" in index
    assert "payload 家族" in index
    assert "bypass 思维" in index
    assert "Technique family" in index
    assert "Checklist gap" in index
    assert "action queue" in index


def test_kb_and_retrospect_use_new_promotion_shape():
    kb = _read("commands/kb.md")
    retrospect = _read("commands/retrospect.md")
    promotion = _read("knowledge/promotion-rules.md")

    assert "Technique family" in kb
    assert "Checklist gap" in kb
    assert "技巧家族 / Payload 家族" in kb
    assert "WAF 绕过" in kb
    assert "SQLi 绕过" in kb

    assert "Thought branches" in retrospect
    assert "Technique / payload / bypass family" in retrospect
    assert "False positives / dead ends" in retrospect
    assert "Promote to Skill / Queue when" in retrospect

    assert "Thought branches" in promotion
    assert "Technique / payload / bypass family" in promotion
    assert "Checklist gap" in promotion
    assert "Promote to Skill / Queue when" in promotion


def test_promotion_rules_define_capability_layer_placement():
    promotion = _read("knowledge/promotion-rules.md")
    context_loading = _read("rules/context-loading.md")
    readme = _read("knowledge/README.md")

    assert "经验进知识库" in promotion
    assert "判断进 rubric" in promotion
    assert "路由进 context_pack" in promotion
    assert "下一步进 checkpoint" in promotion
    assert "重复动作进工具" in promotion
    assert "结果进 ledger" in promotion

    assert "tools/evidence_rubric.py" in promotion
    assert "tools/context_pack.py" in promotion
    assert "tools/checkpoint.py" in promotion
    assert "Evidence Ledger" in readme
    assert "能力增强必须按 `knowledge/promotion-rules.md` 的落位规则分层" in context_loading


def test_capability_promotion_keeps_ai_as_reasoning_layer():
    promotion = _read("knowledge/promotion-rules.md")
    quality = _read(".trellis/spec/backend/quality-guidelines.md")

    assert "工具化不是限制 AI" in promotion
    assert "AI 的优势必须保留" in promotion
    assert "假设" in promotion
    assert "攻击链" in promotion
    assert "baseline" in promotion
    assert "variant" in promotion
    assert "下一步建议" in promotion
    assert "停止条件" in promotion

    assert "工具化必须增强 AI" in quality
    assert "AI 负责假设生成" in quality
    assert "工具负责稳定 replay" in quality
    assert "不能只输出 pass/fail" in quality


def test_auth_access_card_covers_method_path_header_access_control():
    card = _read("knowledge/cards/auth-access.md")

    assert "Method-based access" in card
    assert "GET /admin-roles" in card
    assert "X-HTTP-Method-Override" in card
    assert "X-Original-URL" in card
    assert "Referer-based access" in card
    assert "raw replay" in card
    assert "浏览器 `fetch` 不能设置 `Referer`" in card


def test_sqli_article_card_uses_v2_structure_and_payload_pack():
    card = _read("knowledge/cards/sqli-hidden-surfaces.md")
    payload_pack = _read("knowledge/payloads/sqli-low-risk-probes.md")
    index = _read("knowledge/index.md")

    assert "id: sqli-hidden-surfaces" in card
    assert "type: technique-card" in card
    assert "trigger_tags:" in card
    assert "hidden-input" in card
    assert "deep_refs:" in card
    assert "knowledge/payloads/sqli-low-risk-probes.md" in card
    assert "/root/tool/ccst/ctf-skills" not in card
    assert "已蒸馏的 Header" in card
    assert "## Quick Recall" in card
    assert "Header 示例是候选形态，不是固定字典" in card
    assert "sibling 参数迁移" in card
    assert "XML entity" in card
    assert "parser 解码" in payload_pack
    assert "## 技巧家族 / Payload 家族" in card
    assert "## 补充 Checklist" in card
    assert "## 最小验证" in card
    assert "## 晋升到 Skill / Queue 的条件" in card
    assert "sqli-hidden-surface" in card

    assert "id: sqli-low-risk-probes" in payload_pack
    assert "type: payload-pack" in payload_pack
    assert "Probe 目标是制造稳定差异，不是直接扩大利用" in payload_pack
    assert "不属于默认低风险 probe" in payload_pack
    assert "WAF/路由/缓存差异排除说明" in payload_pack

    assert "## 深度附录 / Payload Packs" in index
    assert "knowledge/payloads/sqli-low-risk-probes.md" in index


def test_controlled_exploitation_cards_define_impact_proof_layer():
    rce = _read("knowledge/cards/controlled-rce-impact.md")
    upload = _read("knowledge/cards/upload-to-execution.md")
    ssrf = _read("knowledge/cards/ssrf-internal-impact.md")
    command_probes = _read("knowledge/payloads/command-execution-probes.md")
    shell_primitives = _read("knowledge/payloads/controlled-shell-primitives.md")
    playbook = _read("knowledge/playbooks/controlled-rce-validation.md")
    index = _read("knowledge/index.md")

    assert "id: controlled-rce-impact" in rce
    assert "RCE、命令注入、SSTI、反序列化、上传执行不是禁用能力" in rce
    assert "Controlled Exploitation / Impact Proof" in rce
    assert "不默认执行 reverse shell、webshell、持久化" in rce
    assert "controlled-rce-impact" in rce
    assert "/root/tool/ccst/ctf-skills" not in rce
    assert "knowledge/payloads/command-execution-probes.md" in rce
    assert "knowledge/playbooks/controlled-rce-validation.md" in rce
    assert "不照搬拿 flag / 持久 shell / 批量读取流程" in rce

    assert "id: upload-to-execution" in upload
    assert "webshell / script execution 属于高风险受控影响证明" in upload
    assert "Controlled shell primitive" in upload
    assert "/root/tool/ccst/ctf-skills" not in upload
    assert "knowledge/cards/upload-parser.md" in upload
    assert "不把 webshell 上传变成默认动作" in upload

    assert "id: ssrf-internal-impact" in ssrf
    assert "SSRF callback 只是入口信号" in ssrf
    assert "默认不做大范围端口扫描" in ssrf
    assert "/root/tool/ccst/ctf-skills" not in ssrf
    assert "knowledge/cards/ssrf-url-fetch.md" in ssrf
    assert "不照搬内网扫描或凭证抓取流程" in ssrf

    assert "id: command-execution-probes" in command_probes
    assert "默认不写文件、不读敏感文件" in command_probes
    assert "id: controlled-shell-primitives" in shell_primitives
    assert "webshell / reverse shell 是高风险影响证明能力" in shell_primitives
    assert "不把 CTF “拿 flag”流程照搬到真实目标" in shell_primitives

    assert "id: controlled-rce-validation" in playbook
    assert "先证明 primitive，再证明影响" in playbook
    assert "Cleanup" in playbook

    assert "knowledge/cards/controlled-rce-impact.md" in index
    assert "knowledge/cards/upload-to-execution.md" in index
    assert "knowledge/cards/ssrf-internal-impact.md" in index
    assert "knowledge/payloads/controlled-shell-primitives.md" in index
    assert "knowledge/playbooks/controlled-rce-validation.md" in index
    assert "## 外部材料蒸馏记录" in index
    assert "不再挂载本机" in index
    assert "/root/tool/ccst/ctf-skills" not in index


def test_auth_sso_and_node_cards_are_indexed_with_deep_refs():
    auth_recovery = _read("knowledge/cards/auth-credential-recovery-flows.md")
    auth_sso = _read("knowledge/cards/auth-sso-token-edge-cases.md")
    node = _read("knowledge/cards/node-prototype-pollution.md")
    index = _read("knowledge/index.md")

    assert "id: auth-credential-recovery-flows" in auth_recovery
    assert "reset token" in auth_recovery
    assert "hidden `username`" in auth_recovery
    assert "口令/OTP/remember-me 测试不是绝对禁用" in auth_recovery
    assert "Host/XFH" in auth_recovery

    assert "id: auth-sso-token-edge-cases" in auth_sso
    assert "JWT/JWE/JWKS/OIDC/SAML" in auth_sso
    assert "state/nonce/PKCE" in auth_sso
    assert "account-linking" in auth_sso
    assert "Claim tamper" in auth_sso
    assert "decode-only" in auth_sso
    assert "/root/tool/ccst/ctf-skills" not in auth_sso
    assert "历史 CTF 来源只在审计文档中追溯" in auth_sso
    assert "不照搬凭证收割" in auth_sso

    assert "id: node-prototype-pollution" in node
    assert "Prototype pollution 不是固定打 `__proto__`" in node
    assert "merge / clone" in node
    assert "inert marker" in node
    assert "Wire payload" in node
    assert "JSON.stringify" in node
    assert "sessionId" in node
    assert "/root/tool/ccst/ctf-skills" not in node
    assert "knowledge/cards/controlled-rce-impact.md" in node
    assert "不照搬 RCE payload" in node

    assert "knowledge/cards/auth-credential-recovery-flows.md" in index
    assert "knowledge/cards/auth-sso-token-edge-cases.md" in index
    assert "knowledge/cards/node-prototype-pollution.md" in index
    assert "docs/ctf-web-distillation-audit.md" in index
    assert "/root/tool/ccst/ctf-skills" not in index


def test_parser_file_read_and_deser_cards_are_indexed():
    xxe = _read("knowledge/cards/xxe-xml-parser.md")
    traversal = _read("knowledge/cards/path-traversal-file-read.md")
    ssti = _read("knowledge/cards/server-side-template-injection.md")
    deser = _read("knowledge/cards/insecure-deserialization.md")
    index = _read("knowledge/index.md")

    assert "id: xxe-xml-parser" in xxe
    assert "SOAP/XML API" in xxe
    assert "XInclude" in xxe
    assert "OAST callback" in xxe

    assert "id: path-traversal-file-read" in traversal
    assert "文件选择器" in traversal
    assert "php://filter" in traversal
    assert "批量读取敏感数据" in traversal

    assert "id: server-side-template-injection" in ssti
    assert "模板求值 primitive" in ssti
    assert "controlled-rce-impact" in ssti
    assert "ERB" in ssti
    assert "不是固定字典" in ssti

    assert "id: insecure-deserialization" in deser
    assert "URLDNS/OAST" in deser
    assert "signed object" in deser
    assert "不默认武器化 gadget chain" in deser

    assert "knowledge/cards/xxe-xml-parser.md" in index
    assert "knowledge/cards/path-traversal-file-read.md" in index
    assert "knowledge/cards/server-side-template-injection.md" in index
    assert "knowledge/cards/insecure-deserialization.md" in index
    assert "knowledge/cards/insecure-deserialization.md" in index


def test_remaining_web2_category_cards_are_indexed():
    api_testing = _read("knowledge/cards/api-testing-workflow.md")
    business_logic = _read("knowledge/cards/business-logic-state-machines.md")
    nosql = _read("knowledge/cards/nosql-query-injection.md")
    xss = _read("knowledge/cards/xss-client-injection.md")
    browser = _read("knowledge/cards/browser-client-boundaries.md")
    proxy = _read("knowledge/cards/proxy-cache-boundaries.md")
    websocket = _read("knowledge/cards/websocket-realtime-api.md")
    info = _read("knowledge/cards/information-disclosure-source-config.md")
    llm = _read("knowledge/cards/web-llm-tool-chains.md")
    index = _read("knowledge/index.md")

    assert "id: api-testing-workflow" in api_testing
    assert "endpoint + method + auth + object + content-type matrix" in api_testing
    assert "isAdmin:true" in api_testing
    assert "sopa:true" in api_testing
    assert "不是固定字典" in api_testing

    assert "id: business-logic-state-machines" in business_logic
    assert "客户端信任" in business_logic
    assert "price=1" in business_logic
    assert "状态机" in business_logic
    assert "不是固定字典" in business_logic

    assert "id: nosql-query-injection" in nosql
    assert "operator" in nosql
    assert "$ne" in nosql

    assert "id: xss-client-injection" in xss
    assert "Reflected XSS" in xss
    assert "Stored XSS" in xss
    assert "真实浏览器执行证据" in xss
    assert "不是固定字典" in xss
    assert "script-src-elem" in xss
    assert "report-uri" in xss
    assert "CSP header 注入" in xss

    assert "id: browser-client-boundaries" in browser
    assert "CORS" in browser
    assert "CSRF" in browser
    assert "DOM" in browser
    assert "auto-submit" in browser
    assert "CSRF token matrix" in browser
    assert "method swap" in browser
    assert "cross-session token" in browser
    assert "Duplicate-cookie token" in browser
    assert "Cookie injection / response splitting" in browser
    assert "SameSite bypass matrix" in browser
    assert "Lax method-override" in browser
    assert "Strict on-site gadget" in browser
    assert "Sibling-domain" in browser
    assert "Cookie-refresh" in browser
    assert "same-site 与 same-origin" in browser
    assert "Referer validation matrix" in browser
    assert "Referer missing" in browser
    assert "Referer substring" in browser
    assert "Referrer-Policy: unsafe-url" in browser
    assert "no-referrer" in browser
    assert "Origin: null" in browser
    assert "sandboxed iframe" in browser
    assert "Trusted insecure protocol" in browser
    assert "trusted origin 上执行 JS" in browser
    assert "Trusted-origin gadget" in browser
    assert "JSON.stringify(targetUrl)" in browser
    assert "document.write" in browser
    assert "CSRF token 不等于 clickjacking 防护" in browser
    assert "真实第三方 top origin" in browser
    assert "third-party cookie" in browser
    assert "button coordinate alignment" in browser
    assert "Prefilled-form clickjacking" in browser
    assert "URL 参数预填" in browser
    assert "submitted state" in browser
    assert "Frame-buster bypass" in browser
    assert "sandbox=\"allow-forms\"" in browser
    assert "不要随手加 `allow-scripts`" in browser
    assert "DOM-XSS connector" in browser
    assert "Iframe offset" in browser
    assert "browser execution" in browser
    assert "Multistep clickjacking" in browser
    assert "iframe state transition" in browser
    assert "step1 coordinate" in browser
    assert "DOM open redirect" in browser
    assert "location.href" in browser
    assert "Cookie manipulation" in browser or "Cookie" in browser
    assert "Cookie-to-XSS" in browser
    assert "写入页面和消费页面" in browser
    assert "&'><script>print()</script>" in browser
    assert "DOM clobbering" in browser
    assert "property-chain" in browser
    assert "HTMLCollection" in browser
    assert "sanitizer-bypass" in browser
    assert "node.attributes" in browser
    assert "input name=attributes" in browser
    assert "tail item" in browser

    assert "id: proxy-cache-boundaries" in proxy
    assert "Request smuggling" in proxy
    assert "Cache poisoning" in proxy
    assert "Host header" in proxy
    assert "Host: localhost" in proxy
    assert "victim 实际访问的 cache key" in proxy
    assert "Victim cache key 不只看 URL 和 `Vary`" in proxy
    assert "Resource-import poisoning" in proxy
    assert "Unkeyed cookie" in proxy
    assert "Multiple-header redirect" in proxy
    assert "Targeted UA" in proxy
    assert "Request-shape" in proxy
    assert "cache-buster oracle" in proxy
    assert "Cache key implementation flaws" in proxy
    assert "Unkeyed query" in proxy
    assert "Unkeyed parameter" in proxy
    assert "Parameter cloaking" in proxy
    assert "Fat GET" in proxy
    assert "URL normalization" in proxy
    assert "parser discrepancy" in proxy
    assert "Coordinated poisoning" in proxy
    assert "Cache key injection" in proxy
    assert "Internal cache poisoning" in proxy
    assert "Multi-entry" in proxy
    assert "Smuggling-to-cache poisoning" in proxy
    assert "host-controlled redirect connector" in proxy
    assert "Smuggled redirect cache-poisoning" in proxy
    assert "miss -> 302 Location -> hit" in proxy
    assert "Smuggling-to-cache deception" in proxy
    assert "incomplete-header absorber" in proxy
    assert "Smuggled private-page cache-deception" in proxy
    assert "Smuggling-to-WCD" in proxy
    assert "H2 response queue poisoning" in proxy
    assert "Raw H2.TE" in proxy
    assert "forbidden header" in proxy
    assert "Response-queue hunting" in proxy
    assert "404 sentinel" in proxy
    assert "H2.CL resource delivery" in proxy
    assert "Raw H2.CL" in proxy
    assert "content-length: 0" in proxy
    assert "victim 浏览器导入 JS 前" in proxy
    assert "H2 CRLF header injection" in proxy
    assert "H2 CRLF-to-TE" in proxy
    assert "H2 request splitting" in proxy
    assert "H2 request-splitting" in proxy
    assert "GET /x HTTP/1.1" in proxy
    assert "Search-history capture" in proxy
    assert "完整 Cookie line" in proxy
    assert "cache key oracle" in proxy
    assert "victim key collision" in proxy
    assert "HTTP/2" in proxy
    assert "Internal fragment" in proxy
    assert "Web cache deception 不等于 poisoning" in proxy
    assert "Delimiter deception" in proxy
    assert "Normalization deception" in proxy
    assert "Exact-match deception" in proxy
    assert "WCD path-mapping" in proxy
    assert "WCD-to-CSRF" in proxy
    assert "no-cookie/raw read" in proxy
    assert "TE header 混淆" in proxy
    assert "TE.CL 形态" in proxy
    assert "TE.TE / TE obfuscation" in proxy
    assert "Backend-pool probe" in proxy
    assert "Differential response" in proxy
    assert "differential 404" in proxy
    assert "Smuggling front-end bypass" in proxy
    assert "Front-end control bypass" in proxy
    assert "Header-conflict absorber" in proxy
    assert "Chunk-size accounting" in proxy
    assert "Smuggling victim delivery" in proxy
    assert "Smuggled reflected-XSS delivery" in proxy
    assert "victim-facing 影响" in proxy
    assert "GGET" in proxy
    assert "GPOST" in proxy
    assert "Path mapping deception" in proxy

    assert "id: websocket-realtime-api" in websocket
    assert "CSWSH" in websocket
    assert "消息级权限" in websocket
    assert "raw frame" in websocket
    assert "UI 表单带 `encode=true`" in websocket
    assert "CSWSH exfil" in websocket
    assert "X-Forwarded-For" in websocket
    assert "handshake header mutation" in websocket

    assert "id: information-disclosure-source-config" in info
    assert "source map" in info
    assert "最小必要证据" in info
    assert "完整组件版本" in info

    assert "id: web-llm-tool-chains" in llm
    assert "prompt injection" in llm
    assert "工具调用" in llm
    assert "tool_calls" in llm
    assert "Backend/error disclosure" in llm
    assert "internal host:port" in llm
    assert "connection refused" in llm

    assert "knowledge/cards/api-testing-workflow.md" in index
    assert "knowledge/cards/business-logic-state-machines.md" in index
    assert "knowledge/cards/nosql-query-injection.md" in index
    assert "knowledge/cards/xss-client-injection.md" in index
    assert "knowledge/cards/browser-client-boundaries.md" in index
    assert "knowledge/cards/proxy-cache-boundaries.md" in index
    assert "knowledge/cards/websocket-realtime-api.md" in index
    assert "knowledge/cards/information-disclosure-source-config.md" in index
    assert "knowledge/cards/web-llm-tool-chains.md" in index
