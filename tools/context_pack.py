#!/usr/bin/env python3
"""为 Claude CLI 装配当前目标的最小高信号上下文包。

Context Pack 是只读导航层：它收敛 Claude 本轮应该加载的目标、Skill、
知识卡和检查规则，同时给出发散假设与相邻角度。它不扫描目标、不写目标
记忆、不自动修改知识库或 Skill。
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from urllib.parse import urlparse

BASE_DIR = Path(__file__).resolve().parents[1]
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

try:
    from memory.target_profile import default_memory_dir
    from tools.coverage_matrix import find_high_value_gaps, load_matrix
    from tools.evidence_ledger import build_summary as build_evidence_summary
    from tools.surface import load_surface_context, rank_surface
    from tools.target_paths import canonical_target_value, target_storage_key
except ImportError:  # pragma: no cover - direct tools/ execution
    from memory.target_profile import default_memory_dir
    from coverage_matrix import find_high_value_gaps, load_matrix  # type: ignore
    from evidence_ledger import build_summary as build_evidence_summary  # type: ignore
    from surface import load_surface_context, rank_surface  # type: ignore
    from target_paths import canonical_target_value, target_storage_key  # type: ignore


SKILL_PATHS = {
    "bb-methodology": "skills/bb-methodology/SKILL.md",
    "bug-bounty": "skills/bug-bounty/SKILL.md",
    "triage-validation": "skills/triage-validation/SKILL.md",
    "web2-recon": "skills/web2-recon/SKILL.md",
    "web2-vuln-classes": "skills/web2-vuln-classes/SKILL.md",
}

KNOWN_SKILL_OR_FOCUS = {
    *SKILL_PATHS.keys(),
    "api",
    "api-testing",
    "api-test",
    "business-logic",
    "logic-flaw",
    "state-machine",
    "workflow-validation",
    "client-side-controls",
    "password-reset",
    "forgot-password",
    "account-recovery",
    "username-enumeration",
    "credential-attack",
    "brute-force",
    "lockout",
    "idor",
    "api-idor",
    "auth",
    "auth-hidden",
    "authz",
    "access-control",
    "method-based-access-control",
    "referer-based-access-control",
    "url-based-access-control",
    "role-bypass",
    "hidden-login",
    "login-bypass",
    "ato",
    "missing-param",
    "parameter-null",
    "param-discovery",
    "api-docs",
    "path-pattern",
    "management-exposure",
    "admin-panel",
    "monitoring-console",
    "structured-record",
    "raw-log",
    "config-exposure",
    "secret-leak",
    "graphql",
    "sqli",
    "sql-injection",
    "hidden-param",
    "nosql",
    "nosql-injection",
    "xxe",
    "xml",
    "xml-parser",
    "xinclude",
    "path-traversal",
    "directory-traversal",
    "lfi",
    "file-read",
    "local-file-inclusion",
    "ssrf",
    "url-fetch",
    "webhook",
    "upload",
    "import",
    "parser",
    "race",
    "ssti",
    "template-injection",
    "template-engine",
    "render-template",
    "code-context",
    "erb",
    "ruby-template",
    "tornado-template",
    "mako-template",
    "handlebars-template",
    "deserialization",
    "deserialize",
    "signed-object",
    "viewstate",
    "host-header",
    "host-header-attack",
    "proxy-trust",
    "request-smuggling",
    "http-smuggling",
    "cache-poisoning",
    "web-cache-poisoning",
    "cache-deception",
    "web-cache-deception",
    "cors",
    "csrf",
    "xsrf",
    "xss",
    "reflected-xss",
    "stored-xss",
    "client-xss",
    "csp",
    "content-security-policy",
    "sandbox-escape",
    "dangling-markup",
    "open-redirect",
    "client-side-redirect",
    "cookie-manipulation",
    "dom-clobbering",
    "clickjacking",
    "dom",
    "dom-xss",
    "websocket",
    "cswsh",
    "information-disclosure",
    "info-disclosure",
    "web-llm",
    "llm",
    "essential-skills",
    "candidate",
    "validate",
    "validation",
    "coverage",
    "dead-end",
}

WEB2_VULN_FOCUS_RE = re.compile(
    r"\b("
    r"api[-_ ]?testing|api[-_ ]?test|business[-_ ]?logic|logic[-_ ]?flaws?|state[-_ ]?machine|workflow[-_ ]?validation|client[-_ ]?side[-_ ]?controls|"
    r"password[-_ ]?reset|forgot[-_ ]?password|account[-_ ]?recovery|username[-_ ]?enum(?:eration)?|credential[-_ ]?attack|brute[-_ ]?force|lockout|stay[-_ ]?logged[-_ ]?in|"
    r"api[-_ ]?idor|idor|authz?|access[-_ ]?control|method[-_ ]?based[-_ ]?access|referer[-_ ]?based[-_ ]?access|url[-_ ]?based[-_ ]?access|role[-_ ]?bypass|auth[-_ ]?hidden|hidden[-_ ]?login|login[-_ ]?bypass|ato|"
    r"jwt|jwe|jwks?|jku|kid|oauth|oidc|saml|sso|pkce|token[-_ ]?binding|account[-_ ]?linking|"
    r"graphql|sqli|sql[-_ ]?injection|hidden[-_ ]?param|nosql|no[-_ ]?sql[-_ ]?injection|"
    r"server[-_ ]?side[-_ ]?param(?:eter)?[-_ ]?pollution|http[-_ ]?param(?:eter)?[-_ ]?pollution|param(?:eter)?[-_ ]?pollution|hpp|mass[-_ ]?assignment|over[-_ ]?posting|overposting|"
    r"xxe|xml[-_ ]?parser|xinclude|"
    r"path[-_ ]?traversal|directory[-_ ]?traversal|lfi|local[-_ ]?file[-_ ]?inclusion|file[-_ ]?read|"
    r"ssrf|ssrf[-_ ]?internal|url[-_ ]?fetch|server[-_ ]?side[-_ ]?(?:fetch|request)|webhook|callback|oembed|"
    r"upload|upload[-_ ]?execution|web[-_ ]?shell|import|parser|"
    r"race|rce|command[-_ ]?injection|ssti|template[-_ ]?injection|template[-_ ]?engine|render[-_ ]?template|erb|ruby[-_ ]?template|tornado[-_ ]?template|mako[-_ ]?template|handlebars[-_ ]?template|mustache[-_ ]?template|nunjucks[-_ ]?template|liquid[-_ ]?template|pug[-_ ]?template|jade[-_ ]?template|ejs[-_ ]?template|deserialization|deserialize|signed[-_ ]?object|viewstate|"
    r"host[-_ ]?header|proxy[-_ ]?trust|request[-_ ]?smuggling|http[-_ ]?smuggling|cache[-_ ]?poisoning|cache[-_ ]?deception|"
    r"cors|csrf|xsrf|xss|reflected[-_ ]?xss|stored[-_ ]?xss|client[-_ ]?xss|csp|content[-_ ]?security[-_ ]?policy|sandbox[-_ ]?escape|dangling[-_ ]?markup|open[-_ ]?redirect|client[-_ ]?side[-_ ]?redirect|cookie[-_ ]?manipulation|dom[-_ ]?clobbering|clickjacking|dom[-_ ]?xss|dom|websocket|cswsh|"
    r"signature[-_ ]?scope|view[-_ ]?differential|allowlist|whitelist|sanitizer|connection[-_ ]?string|runtime[-_ ]?primitive|stale[-_ ]?authz|connection[-_ ]?reuse|redirect[-_ ]?header|xs[-_ ]?leak|cli[-_ ]?argument|non[-_ ]?parameterizable|type[-_ ]?confusion|second[-_ ]?order|payment[-_ ]?logic|postmessage|render[-_ ]?pipeline|information[-_ ]?disclosure|info[-_ ]?disclosure|web[-_ ]?llm|llm|essential[-_ ]?skills|"
    r"node\.js|nodejs|express|prototype[-_ ]?pollution|proto[-_ ]?pollution|__proto__|constructor\.prototype|"
    r"missing[-_ ]?param(?:eter)?|parameter[-_ ]?null|param[-_ ]?discovery|"
    r"path[-_ ]?pattern|management[-_ ]?exposure|admin[-_ ]?panel"
    r")\b",
    re.I,
)

SSTI_DIRECT_RE = re.compile(
    r"\b(ssti|server[-_ ]?side[-_ ]?template[-_ ]?injection|template[-_ ]?injection|jinja|twig|freemarker|velocity|smarty|erb|ruby[-_ ]?template)\b",
    re.I,
)
SSTI_CONTEXT_ENGINE_RE = re.compile(
    r"\b(?:tornado|mako|handlebars|mustache|nunjucks|liquid|pug|jade|ejs)\b.{0,80}\b(?:template|render|expression|helper|sandbox|code[-_ ]?context)\b"
    r"|\b(?:template|render|expression|helper|sandbox|code[-_ ]?context)\b.{0,80}\b(?:tornado|mako|handlebars|mustache|nunjucks|liquid|pug|jade|ejs)\b",
    re.I,
)
SSTI_TOKEN_RE = re.compile(f"{SSTI_DIRECT_RE.pattern}|{SSTI_CONTEXT_ENGINE_RE.pattern}", re.I)

SSRF_FETCH_CONTEXT_RE = re.compile(
    r"\b("
    r"ssrf|server[-_ ]?side[-_ ]?(?:fetch|request)|url[-_ ]?fetch|fetch_url|remote_url|"
    r"webhook|callback|oembed|url[-_ ]?parser|url[-_ ]?param(?:eter)?|stock[-_ ]?api|stockapi"
    r")\b",
    re.I,
)

SSRF_INTERNAL_TARGET_RE = re.compile(
    r"\b("
    r"ssrf[-_ ]?internal|localhost|loopback|127(?:\.\d{1,3}){3}|0\.0\.0\.0|"
    r"169\.254\.169\.254|metadata(?:[-_ ]?service)?|metadata\.google\.internal|"
    r"internal[-_ ]?(?:service|system|host|network|admin|api|endpoint|interface)|"
    r"intranet|admin[-_ ]?interface|admin[-_ ]?console|management[-_ ]?interface|"
    r"private[-_ ]?ip|link[-_ ]?local|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|"
    r"172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}"
    r")\b|(?<!\w)::1(?!\w)",
    re.I,
)

SSRF_EXPLICIT_INTERNAL_RE = re.compile(
    r"\b(ssrf[-_ ]?internal|internal[-_ ]?service|metadata[-_ ]?service|url[-_ ]?parser|"
    r"169\.254\.169\.254|metadata\.google\.internal)\b",
    re.I,
)

API_BUSINESS_CONTEXT_RE = re.compile(
    r"\b(api|endpoint|rest|xhr|openapi|swagger)\b",
    re.I,
)

BUSINESS_STATE_TARGET_RE = re.compile(
    r"\b(price|pricing|cart|checkout|order|purchase|buy|payment|billing|coupon|"
    r"wallet|quantity|stock|discount|refund|place[-_ ]?order)\b",
    re.I,
)

BUSINESS_STATE_MUTATION_RE = re.compile(
    r"\b(post|put|patch|delete|method[-_ ]?matrix|method[-_ ]?override|mutation|"
    r"write|update|modify|buy|purchase|checkout|place[-_ ]?order)\b",
    re.I,
)

BUSINESS_STATE_EXPLICIT_RE = re.compile(
    r"\b(price[-_ ]?tamper|price[-_ ]?(?:override|change|update|patch|edit|manipulation)|"
    r"pricing[-_ ]?api|mass[-_ ]?assignment|client[-_ ]?side[-_ ]?controls|"
    r"business[-_ ]?logic|state[-_ ]?machine|workflow[-_ ]?validation)\b",
    re.I,
)

API_PARAMETER_POLLUTION_RE = re.compile(
    r"\b("
    r"server[-_ ]?side[-_ ]?param(?:eter)?[-_ ]?pollution|"
    r"http[-_ ]?param(?:eter)?[-_ ]?pollution|"
    r"param(?:eter)?[-_ ]?pollution|hpp|"
    r"duplicate[-_ ]?(?:query|param(?:eter)?|body|key)|"
    r"(?:query|body|json)[-_ ]?duplicate|"
    r"backend[-_ ]?(?:request|url)[-_ ]?(?:construction|build(?:ing)?|concat(?:enation)?|truncation)|"
    r"query[-_ ]?string[-_ ]?injection|fragment[-_ ]?truncation"
    r")\b",
    re.I,
)

API_MASS_ASSIGNMENT_RE = re.compile(
    r"\b(mass[-_ ]?assignment|over[-_ ]?posting|overposting)\b",
    re.I,
)

API_PARAMETER_FIELD_RE = re.compile(
    r"\b(isadmin|is_admin|role|roles|plan|status|verified|approved|approval|limit|quota|"
    r"scope|scopes|permission|permissions|feature|features|internal|admin)\b",
    re.I,
)

API_PARSER_DIFF_RE = re.compile(
    r"\b(content[-_ ]?type|media[-_ ]?type|parser|parse|method[-_ ]?override|"
    r"x[-_ ]?http[-_ ]?method[-_ ]?override)\b",
    re.I,
)

BROWSER_CLIENT_BOUNDARY_RE = re.compile(
    r"\b("
    r"cors|csrf|xsrf|same[-_ ]?site|origin|referer|clickjacking|"
    r"frame[-_ ]?ancestors|x[-_ ]?frame[-_ ]?options|dom[-_ ]?xss|dom[-_ ]?based|"
    r"postmessage|message[-_ ]?event|hashchange|window\.name|open[-_ ]?redirect|"
    r"client[-_ ]?side[-_ ]?redirect|cookie[-_ ]?manipulation|dom[-_ ]?clobbering|"
    r"access[-_ ]?control[-_ ]?allow[-_ ]?(?:origin|credentials)|"
    r"credentialed[-_ ]?read|trusted[-_ ]?origin|null[-_ ]?origin"
    r")\b",
    re.I,
)

WEBSOCKET_REALTIME_RE = re.compile(
    r"\b(websocket|web[-_ ]?socket|socket\.io|stomp|graphql[-_ ]?subscription|"
    r"cswsh|cross[-_ ]?site[-_ ]?websocket[-_ ]?hijacking)\b",
    re.I,
)

RACE_CONDITION_RE = re.compile(r"\b(race|concurrent|parallel)\b", re.I)
COMMAND_INJECTION_RE = re.compile(
    r"\b(?:os[-_ ]?command[-_ ]?injection|operating[-_ ]?system[-_ ]?command[-_ ]?injection|"
    r"command[-_ ]?injection|cmdi|shell[-_ ]?injection)\b",
    re.I,
)

CARD_PATHS = {
    "api-idor": "knowledge/cards/api-idor.md",
    "auth-access": "knowledge/cards/auth-access.md",
    "auth-hidden-switches": "knowledge/cards/auth-hidden-switches.md",
    "auth-sso-token-edge-cases": "knowledge/cards/auth-sso-token-edge-cases.md",
    "auth-credential-recovery-flows": "knowledge/cards/auth-credential-recovery-flows.md",
    "api-testing-workflow": "knowledge/cards/api-testing-workflow.md",
    "business-logic-state-machines": "knowledge/cards/business-logic-state-machines.md",
    "missing-parameter-discovery": "knowledge/cards/missing-parameter-discovery.md",
    "path-pattern-management-exposure": "knowledge/cards/path-pattern-management-exposure.md",
    "ssrf-url-fetch": "knowledge/cards/ssrf-url-fetch.md",
    "ssrf-internal-impact": "knowledge/cards/ssrf-internal-impact.md",
    "graphql": "knowledge/cards/graphql.md",
    "sqli-hidden-surfaces": "knowledge/cards/sqli-hidden-surfaces.md",
    "nosql-query-injection": "knowledge/cards/nosql-query-injection.md",
    "xxe-xml-parser": "knowledge/cards/xxe-xml-parser.md",
    "path-traversal-file-read": "knowledge/cards/path-traversal-file-read.md",
    "server-side-template-injection": "knowledge/cards/server-side-template-injection.md",
    "insecure-deserialization": "knowledge/cards/insecure-deserialization.md",
    "xss-client-injection": "knowledge/cards/xss-client-injection.md",
    "browser-client-boundaries": "knowledge/cards/browser-client-boundaries.md",
    "proxy-cache-boundaries": "knowledge/cards/proxy-cache-boundaries.md",
    "websocket-realtime-api": "knowledge/cards/websocket-realtime-api.md",
    "information-disclosure-source-config": "knowledge/cards/information-disclosure-source-config.md",
    "web-llm-tool-chains": "knowledge/cards/web-llm-tool-chains.md",
    "upload-parser": "knowledge/cards/upload-parser.md",
    "upload-to-execution": "knowledge/cards/upload-to-execution.md",
    "controlled-rce-impact": "knowledge/cards/controlled-rce-impact.md",
    "node-prototype-pollution": "knowledge/cards/node-prototype-pollution.md",
    "signature-scope-mismatch": "knowledge/cards/signature-scope-mismatch.md",
    "view-differential": "knowledge/cards/view-differential.md",
    "path-allowlist-normalization": "knowledge/cards/path-allowlist-normalization.md",
    "connection-string-injection": "knowledge/cards/connection-string-injection.md",
    "import-migration-trust": "knowledge/cards/import-migration-trust.md",
    "stale-derived-authz": "knowledge/cards/stale-derived-authz.md",
    "connection-reuse-key": "knowledge/cards/connection-reuse-key.md",
    "redirect-header-leak": "knowledge/cards/redirect-header-leak.md",
    "xs-leak-oracle": "knowledge/cards/xs-leak-oracle.md",
    "cli-argument-injection": "knowledge/cards/cli-argument-injection.md",
    "type-confusion-controlflow": "knowledge/cards/type-confusion-controlflow.md",
    "second-order-sink": "knowledge/cards/second-order-sink.md",
    "render-pipeline-ssrf": "knowledge/cards/render-pipeline-ssrf.md",
    "race-conditions": "knowledge/cards/race-conditions.md",
    "coverage-prompts": "knowledge/cards/coverage-prompts.md",
    "dead-ends": "knowledge/cards/dead-ends.md",
}

CAPABILITY_REGISTRY_PATH = "knowledge/capabilities.yaml"


def _load_capability_registry(repo_root: Path | str = BASE_DIR) -> dict[str, dict[str, str]]:
    """读取知识能力注册表的受控 YAML 子集。

    这里不引入 PyYAML；registry 当前只使用简单 scalar 字段和 list 字段。
    context-pack 只需要 card file -> layer/load/purpose 这些轻量元信息。
    """
    repo = Path(repo_root)
    path = repo / CAPABILITY_REGISTRY_PATH
    if not path.is_file():
        path = BASE_DIR / CAPABILITY_REGISTRY_PATH
    if not path.is_file():
        return {}

    items: list[dict[str, str]] = []
    current: dict[str, str] | None = None
    in_capabilities = False
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if line == "capabilities:":
            in_capabilities = True
            continue
        if not in_capabilities:
            continue
        if line.startswith("  - id: "):
            if current:
                items.append(current)
            current = {"id": line.split(":", 1)[1].strip().strip('"')}
            continue
        if current is not None and line.startswith("    ") and ":" in line and not line.lstrip().startswith("- "):
            key, value = line.strip().split(":", 1)
            current[key] = value.strip().strip('"')
    if current:
        items.append(current)

    return {
        item["file"]: item
        for item in items
        if item.get("kind") == "card" and item.get("file")
    }


def _card_capability(path: str, repo_root: Path | str = BASE_DIR) -> dict[str, str]:
    registry = _load_capability_registry(repo_root)
    item = registry.get(path, {})
    return {
        "file": path,
        "id": item.get("id") or Path(path).stem,
        "layer": item.get("layer") or "unregistered",
        "load": item.get("load") or "unknown",
        "purpose": item.get("purpose") or "unknown",
    }


def _card_capabilities(paths: list[str], repo_root: Path | str = BASE_DIR) -> list[dict[str, str]]:
    return [_card_capability(path, repo_root) for path in paths]


def _budget_knowledge_cards(
    paths: list[str],
    repo_root: Path | str = BASE_DIR,
    *,
    max_cards: int = 2,
    max_case_router: int = 1,
) -> tuple[list[str], list[str]]:
    """按 registry 做保守预算。

    只限制 case-router 涌入：core/core、core/reference 等既有组合不变。
    被挤出的卡进入 deferred，供 AI 明确需要时回捞，而不是 silent drop。
    """
    selected: list[str] = []
    deferred: list[str] = []
    case_router_count = 0
    for path in _dedupe(paths):
        meta = _card_capability(path, repo_root)
        if meta["layer"] == "case-router" and case_router_count >= max_case_router:
            deferred.append(path)
            continue
        if len(selected) < max_cards:
            selected.append(path)
            if meta["layer"] == "case-router":
                case_router_count += 1
        else:
            deferred.append(path)
    return selected, deferred

REFERENCE_PATHS = {
    "bypass-patterns": "skills/security-arsenal/references/bypass-patterns.md",
    "payload-families": "skills/security-arsenal/references/payload-families.md",
    "sink-and-grep-patterns": "skills/security-arsenal/references/sink-and-grep-patterns.md",
    "recon-tool-usage": "skills/security-arsenal/references/recon-tool-usage.md",
}

DISTILLED_TOKEN_TO_CARDS = (
    (re.compile(r"\b(signature[-_ ]?scope[-_ ]?mismatch|signed bytes|consumption object|xsw|duplicate assertion)\b", re.I), ("signature-scope-mismatch",)),
    (re.compile(r"\b(oauth[-_ ]?sso[-_ ]?trust|email trust|audience confusion|redirect_uri trust)\b", re.I), ("auth-sso-token-edge-cases",)),
    (re.compile(r"\b(view[-_ ]?differential|validation view|consumption view|verified view|executed view|canonicalization gap)\b", re.I), ("view-differential",)),
    (re.compile(r"\b(h2 crlf|h2 request[-_ ]?splitting|pseudo-header injection|response queue poisoning|non[-_ ]?url crlf)\b", re.I), ("proxy-cache-boundaries",)),
    (re.compile(r"\b(allowlist|whitelist|path normalization|prefix check|starts?with|weak string|dot[-_ ]?segment|url normalization)\b", re.I), ("path-allowlist-normalization",)),
    (re.compile(r"\b(sanitizer|dompurify|mxss|mutation[-_ ]?xss|parser[-_ ]?xss|html parser|second decode)\b", re.I), ("xss-client-injection",)),
    (re.compile(r"\b(csp bypass|bypass exfil|no[-_ ]?script exfil|script-src exfil|report-uri exfil)\b", re.I), ("xss-client-injection",)),
    (re.compile(r"\b(connection string|dsn|jdbc|mongodb uri|database uri|driver option|protocol handler)\b", re.I), ("connection-string-injection",)),
    (re.compile(r"\b(runtime primitive|primitive override|monkey[-_ ]?patch|same realm|override fetch|override json|stringify override)\b", re.I), ("node-prototype-pollution",)),
    (re.compile(r"\b(import migration|migration trust|restore trust|backup import|bulk import|tenant import)\b", re.I), ("import-migration-trust",)),
    (re.compile(r"\b(stale[-_ ]?derived[-_ ]?authz|derived authz|revoked permission cache|deprovision|role cache|credential derivative)\b", re.I), ("stale-derived-authz",)),
    (re.compile(r"\b(connection reuse|reuse key|pool key|tenant key|keep-alive boundary|backend connection reuse)\b", re.I), ("connection-reuse-key",)),
    (re.compile(r"\b(redirect header|header leak|authorization header leak|sensitive header redirect|cross-origin redirect header|header stripping)\b", re.I), ("redirect-header-leak",)),
    (re.compile(r"\b(xs[-_ ]?leak|cross[-_ ]?site leak|timing oracle|image size oracle|resource timing oracle|window length oracle)\b", re.I), ("xs-leak-oracle",)),
    (re.compile(r"\b(cli argument|argument injection|flag injection|option injection|terminal escape|shell wrapper)\b", re.I), ("cli-argument-injection",)),
    (re.compile(r"\b(non[-_ ]?parameterizable|order by identifier|group by identifier|column name injection|table name injection|placeholder name)\b", re.I), ("sqli-hidden-surfaces",)),
    (re.compile(r"\b(type confusion|shape confusion|string boolean|array object|duplicate json|control[-_ ]?flow|reserved key)\b", re.I), ("type-confusion-controlflow",)),
    (re.compile(r"\b(invisible unicode|unicode tag|tag characters|hidden unicode prompt)\b", re.I), ("web-llm-tool-chains",)),
    (re.compile(r"\b(second[-_ ]?order|delayed sink|async sink|stored render|later processing|deferred template)\b", re.I), ("second-order-sink",)),
    (re.compile(r"\b(payment logic|rounding bypass|gateway state|recipient mismatch|refund logic|billing logic|price mismatch)\b", re.I), ("business-logic-state-machines",)),
    (re.compile(r"\b(postmessage trust|message event origin|targetorigin trust|window\.name trust|origin trust)\b", re.I), ("browser-client-boundaries",)),
    (re.compile(r"\b(render pipeline|pdf render|screenshot service|server-side browser|wkhtmltopdf|chromium export|html to pdf|docx render)\b", re.I), ("render-pipeline-ssrf",)),
)

TOKEN_TO_CARDS = (
    (
        re.compile(
            r"\b(api[-_ ]?testing|api[-_ ]?test|rest[-_ ]?api|soap[-_ ]?api|mobile[-_ ]?api|openapi|swagger)\b",
            re.I,
        ),
        ("api-testing-workflow", "api-idor"),
    ),
    (
        re.compile(
            r"\b(business[-_ ]?logic|logic[-_ ]?flaws?|state[-_ ]?machine|workflow[-_ ]?validation|client[-_ ]?side[-_ ]?controls|price[-_ ]?tamper|coupon|cart|checkout|exceptional[-_ ]?input|dual[-_ ]?use[-_ ]?endpoint)\b",
            re.I,
        ),
        ("business-logic-state-machines",),
    ),
    (
        re.compile(
            r"\b(password[-_ ]?reset|forgot[-_ ]?password|account[-_ ]?recovery|reset[-_ ]?token|username[-_ ]?enum(?:eration)?|credential[-_ ]?attack|brute[-_ ]?force|lockout|stay[-_ ]?logged[-_ ]?in|remember[-_ ]?me|mfa|2fa|otp)\b",
            re.I,
        ),
        ("auth-credential-recovery-flows", "auth-access"),
    ),
    (
        re.compile(
            r"\b(access[-_ ]?control|method[-_ ]?based[-_ ]?access|referer[-_ ]?based[-_ ]?access|url[-_ ]?based[-_ ]?access|role[-_ ]?bypass|admin[-_ ]?roles?|x[-_ ]?original[-_ ]?url|x[-_ ]?rewrite[-_ ]?url|x[-_ ]?http[-_ ]?method[-_ ]?override)\b",
            re.I,
        ),
        ("auth-access", "api-idor"),
    ),
    (
        re.compile(
            r"\b(missing[-_ ]?param(?:eter)?|parameter[-_ ]?null|parameter is null|required[-_ ]?param(?:eter)?|schema[-_ ]?error|validator[-_ ]?error|binder[-_ ]?error|param[-_ ]?discovery|api[-_ ]?docs|swagger|openapi)\b",
            re.I,
        ),
        ("missing-parameter-discovery",),
    ),
    (
        API_PARAMETER_POLLUTION_RE,
        ("api-testing-workflow", "missing-parameter-discovery"),
    ),
    (
        API_MASS_ASSIGNMENT_RE,
        ("api-testing-workflow", "business-logic-state-machines"),
    ),
    (
        re.compile(
            r"\b(path[-_ ]?pattern|directory[-_ ]?fuzz(?:ing)?|target[-_ ]?wordlist|sibling[-_ ]?path|structured[-_ ]?record|raw[-_ ]?log|admin[-_ ]?panel|management[-_ ]?exposure|management[-_ ]?console|monitoring[-_ ]?console|metrics|health|config[-_ ]?(?:exposure|page|endpoint|dump|leak)|configuration|stats|trace|datasource|accesskey|secretkey|secret[-_ ]?leak)\b",
            re.I,
        ),
        ("path-pattern-management-exposure",),
    ),
    (
        re.compile(r"\b(graphql|gql|mutation|subscription|introspection|global[_-]?id)\b", re.I),
        ("graphql",),
    ),
    (
        re.compile(
            r"\b(sqli|sql[-_ ]?injection|hidden[-_ ]?param|x[-_ ]?forwarded[-_ ]?for|x[-_ ]?real[-_ ]?ip|path[-_ ]?segment)\b",
            re.I,
        ),
        ("sqli-hidden-surfaces",),
    ),
    (
        re.compile(
            r"\b(nosql|no[-_ ]?sql[-_ ]?injection|mongo(?:db)?|bson|operator[-_ ]?injection)\b|\$(?:ne|regex|where|gt|nin)",
            re.I,
        ),
        ("nosql-query-injection",),
    ),
    (
        re.compile(
            r"\b(xxe|xml[-_ ]?parser|xinclude|doctype|external[-_ ]?entit(?:y|ies)|soapaction|samlresponse|svg|docx|xlsx|rss|atom)\b",
            re.I,
        ),
        ("xxe-xml-parser",),
    ),
    (
        re.compile(
            r"\b(path[-_ ]?traversal|directory[-_ ]?traversal|lfi|local[-_ ]?file[-_ ]?inclusion|file[-_ ]?read|file[-_ ]?download|php://filter|web-inf|etc/passwd)\b",
            re.I,
        ),
        ("path-traversal-file-read",),
    ),
    (SSTI_TOKEN_RE, ("server-side-template-injection", "controlled-rce-impact")),
    (
        re.compile(
            r"\b(deserialization|deserialize|serialized|signed[-_ ]?object|rememberme|remember[-_ ]?me|viewstate|ysoserial|pickle|java[-_ ]?serialized|php[-_ ]?serialize)\b",
            re.I,
        ),
        ("insecure-deserialization", "controlled-rce-impact"),
    ),
    (
        re.compile(
            r"\b(cors|csrf|xsrf|same[-_ ]?site|origin|referer|clickjacking|frame[-_ ]?ancestors|x[-_ ]?frame[-_ ]?options|dom[-_ ]?xss|dom[-_ ]?based|postmessage|message[-_ ]?event|hashchange|window\\.name|open[-_ ]?redirect|client[-_ ]?side[-_ ]?redirect|cookie[-_ ]?manipulation|dom[-_ ]?clobbering)\b",
            re.I,
        ),
        ("browser-client-boundaries",),
    ),
    (
        re.compile(
            r"\b(reflected[-_ ]?xss|stored[-_ ]?xss|client[-_ ]?xss|cross[-_ ]?site[-_ ]?scripting)\b|(?<!dom[-_])\bxss\b",
            re.I,
        ),
        ("xss-client-injection",),
    ),
    (
        re.compile(
            r"\b(csp|content[-_ ]?security[-_ ]?policy|script[-_ ]?src[-_ ]?elem|sandbox[-_ ]?escape|dangling[-_ ]?markup|angularjs[-_ ]?sandbox)\b",
            re.I,
        ),
        ("xss-client-injection", "browser-client-boundaries"),
    ),
    (
        re.compile(
            r"\b(host[-_ ]?header|x[-_ ]?forwarded[-_ ]?host|forwarded|proxy[-_ ]?trust|request[-_ ]?smuggling|http[-_ ]?smuggling|transfer[-_ ]?encoding|content[-_ ]?length|cache[-_ ]?poisoning|cache[-_ ]?deception|unkeyed|x[-_ ]?cache|age|vary|cdn)\b",
            re.I,
        ),
        ("proxy-cache-boundaries",),
    ),
    (
        re.compile(r"\b(websocket|web[-_ ]?socket|socket\\.io|stomp|graphql[-_ ]?subscription|cswsh|cross[-_ ]?site[-_ ]?websocket[-_ ]?hijacking)\b", re.I),
        ("websocket-realtime-api",),
    ),
    (
        re.compile(
            r"\b(information[-_ ]?disclosure|info[-_ ]?disclosure|debug|stack[-_ ]?trace|source[-_ ]?map|\\.map|backup|\\.bak|git[-_ ]?leak|directory[-_ ]?listing|robots\\.txt|security\\.txt|version[-_ ]?leak|error[-_ ]?leak)\b",
            re.I,
        ),
        ("information-disclosure-source-config",),
    ),
    (
        re.compile(
            r"\b(web[-_ ]?llm|llm|prompt[-_ ]?injection|indirect[-_ ]?prompt|rag|agent[-_ ]?tool|tool[-_ ]?call|model[-_ ]?context)\b",
            re.I,
        ),
        ("web-llm-tool-chains",),
    ),
    (
        re.compile(
            r"\b(rce|remote[-_ ]?code[-_ ]?execution|command[-_ ]?injection|cmdi|ssti|deserialization|deserialize|template[-_ ]?injection|shell[-_ ]?primitive)\b",
            re.I,
        ),
        ("controlled-rce-impact",),
    ),
    (
        re.compile(r"\b(upload[-_ ]?execution|web[-_ ]?shell|script[-_ ]?execution|polyglot)\b", re.I),
        ("upload-to-execution", "controlled-rce-impact"),
    ),
    (
        re.compile(r"\b(upload|import|file[-_ ]?parser|parse[-_ ]?file|preview|convert|csv|pdf|xlsx|avatar|attachment)\b", re.I),
        ("upload-parser",),
    ),
    (
        re.compile(
            r"\b(ssrf[-_ ]?internal|internal[-_ ]?service|metadata[-_ ]?service|metadata\.google\.internal|url[-_ ]?parser|169\.254\.169\.254)\b",
            re.I,
        ),
        ("ssrf-internal-impact", "ssrf-url-fetch"),
    ),
    (
        re.compile(r"\b(ssrf|url[-_ ]?fetch|webhook|callback|oembed|fetch_url|remote_url)\b", re.I),
        ("ssrf-url-fetch",),
    ),
    (
        re.compile(r"\b(race|concurrent|parallel|quota|otp|totp|payment|billing|refund|coupon|wallet|cart|checkout)\b", re.I),
        ("race-conditions",),
    ),
    (
        re.compile(r"\b(auth|authz|rbac|role|session|sso|oauth|oidc|admin|member|workspace)\b", re.I),
        ("auth-access", "api-idor"),
    ),
    (
        re.compile(
            r"\b(auth[-_ ]?hidden|hidden[-_ ]?login|login[-_ ]?bypass|account[-_ ]?takeover|ato|username[-_ ]?enum|soap|ldap)\b",
            re.I,
        ),
        ("auth-hidden-switches", "auth-access"),
    ),
    (
        re.compile(
            r"\b(jwt|jwe|jwks?|jku|kid|oidc|oauth|saml|sso|relaystate|samlresponse|acs|pkce|nonce|token[-_ ]?binding|account[-_ ]?linking)\b",
            re.I,
        ),
        ("auth-sso-token-edge-cases", "auth-access"),
    ),
    (
        re.compile(
            r"\b(node\.js|nodejs|express|next\.js|nestjs|koa|hapi|fastify|prototype[-_ ]?pollution|proto[-_ ]?pollution|__proto__|constructor\.prototype|lodash|qs|flat|deep[-_ ]?extend|dot[-_ ]?prop|set[-_ ]?value|vm2?|happy[-_ ]?dom|jsdom)\b",
            re.I,
        ),
        ("node-prototype-pollution",),
    ),
    (
        re.compile(r"\b(idor|tenant|org|organization|accounts|user_id|account_id|org_id|tenant_id|order_id|invoice|export|download|report|object)\b", re.I),
        ("api-idor", "auth-access"),
    ),
)


def _read_json_object(path: Path) -> dict:
    if not path.is_file():
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return payload if isinstance(payload, dict) else {}


def _read_json_any(path: Path) -> object:
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def _read_lines(path: Path, limit: int = 50) -> list[str]:
    if not path.is_file():
        return []
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []
    return _dedupe([line.strip() for line in lines if line.strip()])[:limit]


def _read_jsonl_objects(path: Path, limit: int = 50) -> list[dict]:
    if not path.is_file():
        return []
    items: list[dict] = []
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []
    for line in lines:
        value = line.strip()
        if not value:
            continue
        try:
            item = json.loads(value)
        except json.JSONDecodeError:
            continue
        if isinstance(item, dict):
            items.append(item)
        if len(items) >= limit:
            break
    return items


def _dedupe(items: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for item in items:
        value = str(item or "").strip()
        if not value or value in seen:
            continue
        seen.add(value)
        out.append(value)
    return out


def _display(path: Path, repo_root: Path) -> str:
    try:
        return str(path.relative_to(repo_root))
    except ValueError:
        return str(path)


def _entry_text(item: object) -> str:
    if isinstance(item, dict):
        return str(item.get("text") or item.get("summary") or item.get("title") or "").strip()
    return str(item or "").strip()


def _json_list(items: object) -> list[dict]:
    out: list[dict] = []
    if not isinstance(items, list):
        return out
    for item in items:
        if isinstance(item, str):
            try:
                item = json.loads(item)
            except json.JSONDecodeError:
                item = {"title": item}
        if isinstance(item, dict):
            out.append(item)
    return out


def _looks_like_target(value: str) -> bool:
    value = value.strip()
    if not value:
        return False
    if value in KNOWN_SKILL_OR_FOCUS:
        return False
    if "://" in value:
        return True
    if "/" in value and not value.startswith("/"):
        return True
    if ":" in value and not value.startswith("http"):
        return True
    return "." in value


def _resolve_cli_args(args: argparse.Namespace, repo_root: Path) -> tuple[str, str]:
    positional = list(args.args or [])
    target = args.target or ""
    focus_parts: list[str] = []

    if target:
        focus_parts.extend(positional)
    elif positional and _looks_like_target(positional[0]):
        target = positional[0]
        focus_parts.extend(positional[1:])
    else:
        focus_parts.extend(positional)

    if args.focus:
        focus_parts.append(args.focus)

    if not target:
        active = _read_json_object(repo_root / "memory" / "goals" / "active.json")
        target = str(active.get("target") or "").strip()
    if not target:
        raise SystemExit(
            "No target resolved. Use --target target.com or set active target with "
            "`python3 tools/target_memory.py set <target>`."
        )

    return canonical_target_value(target), " ".join(focus_parts).strip()


def _load_goal_memory(repo_root: Path, target: str) -> dict:
    target_key = target_storage_key(target)
    active_path = repo_root / "memory" / "goals" / "active.json"
    target_path = repo_root / "memory" / "goals" / "targets" / f"{target_key}.json"
    active = _read_json_object(active_path)
    target_memory = _read_json_object(target_path)
    active_target = canonical_target_value(str(active.get("target") or ""))
    return {
        "active": active if active_target == target else {},
        "raw_active": active,
        "target": target_memory,
        "active_matches": bool(active_target and active_target == target),
        "active_path": _display(active_path, repo_root),
        "target_path": _display(target_path, repo_root),
    }


def _load_findings(repo_root: Path, target_key: str) -> list[dict]:
    payload = _read_json_any(repo_root / "findings" / target_key / "findings.json")
    if isinstance(payload, dict):
        payload = payload.get("findings", [])
    if not isinstance(payload, list):
        return []
    return [item for item in payload if isinstance(item, dict)]


def _artifact_path(path: Path, repo_root: Path) -> str:
    return _display(path, repo_root) if path.is_file() else ""


def _load_local_intel(repo_root: Path, target_key: str) -> dict:
    """读取小型浏览器/JS/source 证据索引；不触发扫描或浏览器动作。"""
    browser_dir = repo_root / "recon" / target_key / "browser"
    js_dir = repo_root / "findings" / target_key / "js_intel"
    source_dir = repo_root / "findings" / target_key / "source_intel"

    forms_payload = _read_json_any(browser_dir / "forms.json")
    forms = []
    if isinstance(forms_payload, dict) and isinstance(forms_payload.get("forms"), list):
        forms = [item for item in forms_payload["forms"] if isinstance(item, dict)]

    page_js_map = _read_json_object(browser_dir / "page_js_map.json")
    pages = page_js_map.get("pages") if isinstance(page_js_map.get("pages"), dict) else {}
    js_index = page_js_map.get("js_index") if isinstance(page_js_map.get("js_index"), dict) else {}

    js_payload = _read_json_object(js_dir / "hypotheses.json")
    js_endpoints = [
        item for item in js_payload.get("endpoints", [])
        if isinstance(item, dict) and item.get("path")
    ]
    js_leads = js_payload.get("attack_surface_leads", js_payload.get("ranked_leads", []))
    js_leads = [item for item in js_leads if isinstance(item, dict)]
    js_graphql = [
        item for item in js_payload.get("graphql_operations", [])
        if isinstance(item, dict)
    ]

    source_routes_payload = _read_json_object(source_dir / "routes.json")
    source_routes = [
        item for item in source_routes_payload.get("routes", [])
        if isinstance(item, dict) and item.get("route")
    ]
    source_graphql = [
        item for item in source_routes_payload.get("graphql_operations", [])
        if isinstance(item, dict)
    ]
    source_hypotheses = _read_jsonl_objects(source_dir / "hypotheses.jsonl", limit=50)

    return {
        "browser": {
            "summary": _read_json_object(browser_dir / "summary.json"),
            "xhr_endpoints": _read_lines(browser_dir / "xhr_endpoints.txt"),
            "api_endpoints": _read_lines(browser_dir / "api_endpoints.txt"),
            "params": _read_lines(browser_dir / "browser_params.txt"),
            "forms": forms,
            "page_count": len(pages),
            "js_file_count": len(js_index),
            "paths": _dedupe([
                _artifact_path(browser_dir / "xhr_endpoints.txt", repo_root),
                _artifact_path(browser_dir / "api_endpoints.txt", repo_root),
                _artifact_path(browser_dir / "browser_params.txt", repo_root),
                _artifact_path(browser_dir / "page_js_map.json", repo_root),
                _artifact_path(browser_dir / "summary.json", repo_root),
            ]),
        },
        "js_intel": {
            "endpoints": js_endpoints,
            "leads": js_leads,
            "graphql_operations": js_graphql,
            "paths": _dedupe([
                _artifact_path(js_dir / "hypotheses.json", repo_root),
                _artifact_path(js_dir / "materials_summary.md", repo_root),
            ]),
        },
        "source_intel": {
            "hypotheses": source_hypotheses,
            "routes": source_routes,
            "graphql_operations": source_graphql,
            "paths": _dedupe([
                _artifact_path(source_dir / "hypotheses.jsonl", repo_root),
                _artifact_path(source_dir / "routes.json", repo_root),
                _artifact_path(source_dir / "summary.md", repo_root),
            ]),
        },
    }


def _finding_is_candidate(finding: dict) -> bool:
    status_blob = " ".join(
        str(finding.get(key) or "")
        for key in ("status", "validation_status", "report_status", "state")
    ).lower()
    if any(token in status_blob for token in ("candidate", "pending", "unvalidated", "needs_validation")):
        return True
    if any(token in status_blob for token in ("validated", "submitted", "rejected", "false_positive")):
        return False
    return bool(finding.get("id") or finding.get("type") or finding.get("endpoint") or finding.get("url"))


def _finding_anchor(finding: dict) -> str:
    label = str(finding.get("id") or finding.get("type") or finding.get("title") or "finding").strip()
    vuln = str(finding.get("vuln_class") or finding.get("class") or finding.get("category") or "").strip()
    endpoint = str(finding.get("endpoint") or finding.get("url") or "").strip()
    status = str(finding.get("validation_status") or finding.get("report_status") or finding.get("status") or "").strip()
    parts = [label]
    if vuln:
        parts.append(f"[{vuln}]")
    if endpoint:
        parts.append(f"-> {endpoint}")
    if status:
        parts.append(f"status={status}")
    return " ".join(parts)


def _safe_find_gaps(target: str, target_key: str, repo_root: Path) -> tuple[list[dict], dict]:
    gaps = find_high_value_gaps(target, repo_root=repo_root)
    matrix = load_matrix(target, repo_root=repo_root)
    if not gaps and target_key != target:
        key_gaps = find_high_value_gaps(target_key, repo_root=repo_root)
        key_matrix = load_matrix(target_key, repo_root=repo_root)
        if key_gaps or key_matrix.get("summary", {}).get("total_cells", 0):
            return key_gaps, key_matrix
    return gaps, matrix


def _surface_state(repo_root: Path, target: str, memory_dir: str | None) -> dict:
    resolved_memory_dir = memory_dir or str(default_memory_dir(repo_root))
    context = load_surface_context(
        repo_root,
        target,
        memory_dir=resolved_memory_dir,
        write_probe_log=False,
    )
    return rank_surface(context)


def _local_intel_blob(local_intel: dict) -> list[str]:
    pieces: list[str] = []
    browser = local_intel.get("browser") or {}
    pieces.extend(browser.get("xhr_endpoints") or [])
    pieces.extend(browser.get("api_endpoints") or [])
    pieces.extend(browser.get("params") or [])
    for form in (browser.get("forms") or [])[:5]:
        pieces.append(f"{form.get('method', '')} {form.get('action', '')}")

    js_intel = local_intel.get("js_intel") or {}
    for endpoint in (js_intel.get("endpoints") or [])[:10]:
        pieces.extend([
            str(endpoint.get("method") or ""),
            str(endpoint.get("path") or ""),
            str(endpoint.get("evidence") or ""),
            str(endpoint.get("auth_required") or ""),
        ])
    for lead in (js_intel.get("leads") or [])[:5]:
        pieces.extend([
            str(lead.get("title") or ""),
            str(lead.get("category") or ""),
            str(lead.get("next_action") or ""),
        ])
    for operation in (js_intel.get("graphql_operations") or [])[:5]:
        pieces.extend([
            str(operation.get("name") or ""),
            str(operation.get("type") or operation.get("operation") or ""),
        ])

    source_intel = local_intel.get("source_intel") or {}
    for hypothesis in (source_intel.get("hypotheses") or [])[:10]:
        pieces.extend([
            str(hypothesis.get("type") or ""),
            str(hypothesis.get("candidate") or ""),
            str(hypothesis.get("reason") or ""),
        ])
    for route in (source_intel.get("routes") or [])[:10]:
        pieces.extend([
            str(route.get("method") or ""),
            str(route.get("route") or ""),
        ])
    for operation in (source_intel.get("graphql_operations") or [])[:5]:
        pieces.extend([
            str(operation.get("name") or ""),
            str(operation.get("operation") or ""),
        ])
    return [piece for piece in pieces if str(piece).strip()]


def _text_blob(
    focus: str,
    goal_memory: dict,
    ranked: dict,
    gaps: list[dict],
    findings: list[dict],
    local_intel: dict,
) -> str:
    pieces: list[str] = [focus]
    active = goal_memory.get("active") or {}
    target_memory = goal_memory.get("target") or {}
    for key in ("active_goal", "current_hypothesis", "phase", "mode"):
        pieces.append(str(active.get(key) or target_memory.get(key) or ""))
    for field in ("active_leads", "next_actions", "dead_ends", "useful_patterns"):
        for item in (target_memory.get(field) or [])[-5:]:
            pieces.append(_entry_text(item))
    review_items = ranked.get("review_pool") or (ranked.get("p1", [])[:5] + ranked.get("p2", [])[:3])
    for item in review_items[:8]:
        pieces.extend([
            str(item.get("url") or ""),
            str(item.get("path") or ""),
            " ".join(str(reason) for reason in item.get("reasons", [])[:3]),
            str(item.get("suggested") or ""),
        ])
    for lead in _json_list(ranked.get("workflow_leads"))[:5]:
        pieces.extend([
            str(lead.get("title") or ""),
            str(lead.get("category") or ""),
            str(lead.get("next_action") or ""),
            str(lead.get("rationale") or ""),
        ])
    for gap in gaps[:8]:
        pieces.append(f"{gap.get('endpoint')} {gap.get('vuln_class')}")
    for finding in findings[:5]:
        pieces.append(_finding_anchor(finding))
    pieces.extend(_local_intel_blob(local_intel))
    return "\n".join(piece for piece in pieces if piece)


def _select_skill(focus: str, blob: str, ranked: dict, findings: list[dict], goal_memory: dict) -> tuple[str, str]:
    focus_l = focus.lower()
    blob_l = blob.lower()
    target_memory = goal_memory.get("target") or {}
    selected = [
        str(item).strip()
        for item in (
            (goal_memory.get("active") or {}).get("selected_skills")
            or target_memory.get("selected_skills")
            or []
        )
        if str(item).strip()
    ]
    has_candidate = any(_finding_is_candidate(item) for item in findings)
    active = goal_memory.get("active") or {}
    phase_blob = " ".join(
        str((source or {}).get(key) or "")
        for source in (active, target_memory)
        for key in ("phase", "mode", "state", "status")
    ).lower()

    if (
        "triage-validation" in focus_l
        or re.search(r"\b(validate|validation|candidate)\b", focus_l)
        or re.search(r"\b(validate|validation|candidate)\b", phase_blob)
        or has_candidate
    ):
        return "triage-validation", "已有 candidate / validation 信号，本轮优先把候选证据过验证门。"
    if "web2-recon" in focus_l or "recon" == focus_l.strip():
        return "web2-recon", "用户 focus 指向 recon，需要先补攻击面输入再进入漏洞验证。"
    if "web2-vuln-classes" in focus_l:
        return "web2-vuln-classes", "用户 focus 指向 Web2 漏洞类别验证。"
    if WEB2_VULN_FOCUS_RE.search(focus_l):
        return "web2-vuln-classes", "用户 focus 已指向具体 Web2 漏洞类别，本轮直接进入验证路径。"
    if not ranked.get("available"):
        return "web2-recon", "本地 recon/surface 缓存不足，先补最小攻击面上下文。"
    if selected:
        for item in selected:
            if item in SKILL_PATHS:
                return item, "目标记忆层已记录该 Skill，沿用当前目标上下文。"
    if re.search(r"\b(dead[-_ ]?end|stuck|no progress|plateau)\b", blob_l):
        return "bb-methodology", "目标记忆显示方向可能卡住，先用方法论 Skill 重定向。"
    if ranked.get("review_pool") or ranked.get("p1") or ranked.get("p2") or re.search(
        r"\b(idor|auth|graphql|sqli|sql[-_ ]?injection|ssrf|server[-_ ]?side[-_ ]?(?:fetch|request)|upload|race|webhook|api|tenant|org|admin|missing[-_ ]?param(?:eter)?|parameter[-_ ]?null|schema[-_ ]?error|validator[-_ ]?error|param[-_ ]?discovery|param(?:eter)?[-_ ]?pollution|hpp|mass[-_ ]?assignment|over[-_ ]?posting|overposting|api[-_ ]?docs|swagger|openapi|path[-_ ]?pattern|directory[-_ ]?fuzz(?:ing)?|target[-_ ]?wordlist|structured[-_ ]?record|raw[-_ ]?log|admin[-_ ]?panel|management[-_ ]?exposure|management[-_ ]?console|monitoring[-_ ]?console|metrics|health|config[-_ ]?(?:exposure|page|endpoint|dump|leak)|configuration|stats|trace|datasource|accesskey|secretkey|secret[-_ ]?leak)\b",
        blob_l,
    ):
        return "web2-vuln-classes", "已有可测试的 Web/API surface 或漏洞类别信号。"
    return "bb-methodology", "缺少明确类别信号，先做阶段判断和路线收敛。"


def _has_ssrf_internal_signal(text: str) -> bool:
    """识别“服务端取 URL + 内部目标”组合，避免把普通 internal/admin 误路由成 SSRF。"""

    if not text:
        return False
    if SSRF_EXPLICIT_INTERNAL_RE.search(text):
        return True
    return bool(SSRF_FETCH_CONTEXT_RE.search(text) and SSRF_INTERNAL_TARGET_RE.search(text))


def _has_api_business_logic_signal(text: str) -> bool:
    """识别 API 写操作触及价格/订单等业务状态的场景，避免默认只落到 IDOR。"""

    if not text:
        return False
    if BUSINESS_STATE_EXPLICIT_RE.search(text):
        return True
    return bool(
        API_BUSINESS_CONTEXT_RE.search(text)
        and BUSINESS_STATE_TARGET_RE.search(text)
        and BUSINESS_STATE_MUTATION_RE.search(text)
    )


def _has_api_parameter_handling_signal(text: str) -> bool:
    """识别 API 参数绑定/解析差异，优先加载 API 工作流而不是误入上传 parser。"""

    if not text:
        return False
    return bool(
        API_PARAMETER_POLLUTION_RE.search(text)
        or API_MASS_ASSIGNMENT_RE.search(text)
        or (
            API_BUSINESS_CONTEXT_RE.search(text)
            and API_PARSER_DIFF_RE.search(text)
            and (
                API_PARAMETER_FIELD_RE.search(text)
                or re.search(r"\b(param(?:eter)?|query|body|json|field|schema)\b", text, re.I)
            )
        )
    )


def _has_proxy_cache_boundary_signal(text: str) -> bool:
    """识别代理/cache/request smuggling 语境，避免 CSRF/Cookie 等证据词抢路由。"""

    return bool(
        text
        and re.search(
            r"\b(host[-_ ]?header|x[-_ ]?forwarded[-_ ]?host|forwarded|proxy[-_ ]?trust|"
            r"request[-_ ]?smuggling|http[-_ ]?smuggling|transfer[-_ ]?encoding|content[-_ ]?length|"
            r"cl\.te|te\.cl|te\.te|h2\.(?:te|cl)|cache[-_ ]?poisoning|cache[-_ ]?deception|"
            r"web[-_ ]?cache[-_ ]?(?:poisoning|deception)|unkeyed|x[-_ ]?cache|age|vary|cdn)\b",
            text,
            re.I,
        )
    )


def _has_browser_client_boundary_signal(text: str) -> bool:
    """识别 CORS/CSRF/Clickjacking/DOM 等浏览器边界信号，避免 ACA* 被当成 Authz。"""

    if not text:
        return False
    if re.search(r"\b(?:method|referer|url)[-_ ]?based[-_ ]?access[-_ ]?control\b", text, re.I):
        return False
    if _has_proxy_cache_boundary_signal(text):
        # smuggling/cache 链里常出现 CSRF、Cookie、Origin、victim request 等证据词；
        # 这些是影响验证条件，不应把主 lane 从 proxy-cache 抢到 browser-boundary。
        browser_only = re.search(
            r"\b(cors|xsrf|same[-_ ]?site|clickjacking|frame[-_ ]?ancestors|"
            r"x[-_ ]?frame[-_ ]?options|dom[-_ ]?xss|dom[-_ ]?based|postmessage|message[-_ ]?event|"
            r"hashchange|window\.name|open[-_ ]?redirect|client[-_ ]?side[-_ ]?redirect|"
            r"cookie[-_ ]?manipulation|dom[-_ ]?clobbering|access[-_ ]?control[-_ ]?allow[-_ ]?(?:origin|credentials)|"
            r"credentialed[-_ ]?read|trusted[-_ ]?origin|null[-_ ]?origin)\b",
            text,
            re.I,
        )
        return bool(browser_only)
    return bool(BROWSER_CLIENT_BOUNDARY_RE.search(text))


def _has_websocket_realtime_signal(text: str) -> bool:
    """识别 WebSocket/CSWSH 信号，避免 authz/origin 背景词抢占实时 API 路由。"""

    return bool(text and WEBSOCKET_REALTIME_RE.search(text))


def _has_ssrf_context_signal(text: str) -> bool:
    """识别 SSRF/服务端取 URL 语境；open redirect 在该语境下是 SSRF 连接器。"""

    if not text:
        return False
    return bool(
        _has_ssrf_internal_signal(text)
        or SSRF_FETCH_CONTEXT_RE.search(text)
        or re.search(
            r"\b(ssrf|server[-_ ]?side[-_ ]?(?:fetch|request)|url[-_ ]?fetch|webhook|callback|oembed|stock[-_ ]?check(?:er)?)\b",
            text,
            re.I,
        )
    )


def _has_race_condition_signal(text: str) -> bool:
    """识别真正的竞态信号，避免 stack trace 里的连续子串触发 race。"""

    return bool(text and RACE_CONDITION_RE.search(text))


def _has_upload_execution_signal(text: str) -> bool:
    """识别上传执行链，避免含 parser 字样的执行面被降级成纯解析器面。"""

    return bool(
        text
        and re.search(r"\b(?:(?:unsafe[-_ ]?)?upload|file[-_ ]?upload|uploaded[-_ ]?file)\b", text, re.I)
        and re.search(
            r"\b(execution|execute|executed|rce|remote[-_ ]?code[-_ ]?execution|web[-_ ]?shell|script[-_ ]?execution|interpreter|handler)\b",
            text,
            re.I,
        )
    )


def _cards_from_focus(focus: str) -> list[str]:
    focus_l = focus.lower()
    cards: list[str] = []
    for pattern, names in DISTILLED_TOKEN_TO_CARDS:
        if pattern.search(focus):
            cards.extend(names)
    browser_boundary_signal = _has_browser_client_boundary_signal(focus)
    websocket_realtime_signal = _has_websocket_realtime_signal(focus)
    ssrf_context_signal = _has_ssrf_context_signal(focus)
    browser_boundary_focus = browser_boundary_signal and not ssrf_context_signal
    if browser_boundary_focus and not websocket_realtime_signal:
        cards.append("browser-client-boundaries")
    if websocket_realtime_signal:
        cards.append("websocket-realtime-api")
    if _has_race_condition_signal(focus):
        cards.append("race-conditions")
    if (
        re.search(r"\bapi[-_ ]?testing\b", focus_l)
        or re.search(r"\bapi[-_ ]?test\b", focus_l)
        or re.search(r"\brest[-_ ]?api\b", focus_l)
        or re.search(r"\bsoap[-_ ]?api\b", focus_l)
        or re.search(r"\bmobile[-_ ]?api\b", focus_l)
        or _has_api_parameter_handling_signal(focus)
    ):
        cards.append("api-testing-workflow")
        if _has_api_business_logic_signal(focus):
            cards.append("business-logic-state-machines")
        if API_PARAMETER_POLLUTION_RE.search(focus):
            cards.append("missing-parameter-discovery")
        cards.append("api-idor")
    if (
        re.search(r"\bbusiness[-_ ]?logic\b", focus_l)
        or re.search(r"\blogic[-_ ]?flaws?\b", focus_l)
        or "state-machine" in focus_l
        or "workflow-validation" in focus_l
        or "client-side-controls" in focus_l
        or "price-tamper" in focus_l
        or _has_api_business_logic_signal(focus)
        or API_MASS_ASSIGNMENT_RE.search(focus)
    ):
        cards.append("business-logic-state-machines")
    if (
        re.search(r"\bpassword[-_ ]?reset\b", focus_l)
        or re.search(r"\bforgot[-_ ]?password\b", focus_l)
        or re.search(r"\baccount[-_ ]?recovery\b", focus_l)
        or re.search(r"\busername[-_ ]?enum(?:eration)?\b", focus_l)
        or re.search(r"\bcredential[-_ ]?attack\b", focus_l)
        or re.search(r"\bbrute[-_ ]?force\b", focus_l)
        or "lockout" in focus_l
        or "stay-logged-in" in focus_l
        or "remember-me" in focus_l
        or "mfa" in focus_l
        or "2fa" in focus_l
        or "otp" in focus_l
    ):
        cards.extend(["auth-credential-recovery-flows", "auth-access"])
    if "graphql" in focus_l:
        cards.append("graphql")
    if (
        "missing-param" in focus_l
        or "parameter-null" in focus_l
        or "param-discovery" in focus_l
        or "api-docs" in focus_l
        or API_PARAMETER_POLLUTION_RE.search(focus)
    ):
        cards.append("missing-parameter-discovery")
    if (
        "path-pattern" in focus_l
        or "management-exposure" in focus_l
        or "admin-panel" in focus_l
        or "monitoring-console" in focus_l
        or "structured-record" in focus_l
        or "raw-log" in focus_l
        or "config-exposure" in focus_l
        or "secret-leak" in focus_l
    ):
        cards.append("path-pattern-management-exposure")
        if "admin-panel" in focus_l:
            cards.append("auth-access")
    if re.search(r"\b(sqli|sql[-_ ]?injection|hidden[-_ ]?param(?:eter)?)\b", focus_l):
        cards.append("sqli-hidden-surfaces")
    if "nosql" in focus_l or "no-sql" in focus_l or "operator-injection" in focus_l:
        cards.append("nosql-query-injection")
    if (
        "xxe" in focus_l
        or "xml-parser" in focus_l
        or "xinclude" in focus_l
        or "external-entity" in focus_l
        or "external entity" in focus_l
    ):
        cards.append("xxe-xml-parser")
    if (
        "path-traversal" in focus_l
        or "directory-traversal" in focus_l
        or "local-file-inclusion" in focus_l
        or "lfi" in focus_l
        or "file-read" in focus_l
    ):
        cards.append("path-traversal-file-read")
    if "api-idor" in focus_l or "idor" in focus_l:
        cards.extend(["api-idor", "auth-access"])
    if (
        "access-control" in focus_l
        or "method-based-access" in focus_l
        or "referer-based-access" in focus_l
        or "url-based-access" in focus_l
        or "role-bypass" in focus_l
        or "admin-roles" in focus_l
    ) and not browser_boundary_focus and not websocket_realtime_signal:
        cards.extend(["auth-access", "api-idor"])
    if (
        "auth-hidden" in focus_l
        or "hidden-login" in focus_l
        or "login-bypass" in focus_l
        or re.search(r"\bato\b", focus_l)
    ):
        cards.extend(["auth-hidden-switches", "auth-access"])
    if (
        "jwt" in focus_l
        or "jwe" in focus_l
        or "jwks" in focus_l
        or "jku" in focus_l
        or "kid" in focus_l
        or "oauth" in focus_l
        or "oidc" in focus_l
        or "saml" in focus_l
        or "sso" in focus_l
        or "pkce" in focus_l
        or "token-binding" in focus_l
        or "account-linking" in focus_l
    ):
        cards.extend(["auth-sso-token-edge-cases", "auth-access"])
    if re.search(r"\bauth(?:entication|z)?\b", focus_l) and not browser_boundary_focus and not websocket_realtime_signal:
        cards.extend(["auth-access", "api-idor"])
    if _has_ssrf_internal_signal(focus):
        cards.extend(["ssrf-internal-impact", "ssrf-url-fetch"])
    elif (
        "ssrf" in focus_l
        or "url-fetch" in focus_l
        or "webhook" in focus_l
        or re.search(r"\bserver[-_ ]?side[-_ ]?(?:fetch|request)\b", focus_l)
    ):
        cards.append("ssrf-url-fetch")
    if (
        "upload-execution" in focus_l
        or _has_upload_execution_signal(focus)
        or re.search(r"\bweb[-_ ]?shell\b", focus_l)
        or "script-execution" in focus_l
    ):
        cards.extend(["upload-to-execution", "controlled-rce-impact"])
    elif (
        "upload" in focus_l
        or "import" in focus_l
        or (
            "parser" in focus_l
            and not _has_api_parameter_handling_signal(focus)
            and "xml-parser" not in focus_l
            and "xxe" not in focus_l
        )
    ):
        cards.append("upload-parser")
    if re.search(r"\brce\b", focus_l) or COMMAND_INJECTION_RE.search(focus) or "shell-primitive" in focus_l:
        cards.append("controlled-rce-impact")
    if SSTI_TOKEN_RE.search(focus):
        cards.extend(["server-side-template-injection", "controlled-rce-impact"])
    if (
        "deserialization" in focus_l
        or "deserialize" in focus_l
        or "signed-object" in focus_l
        or "viewstate" in focus_l
        or "rememberme" in focus_l
        or "remember-me" in focus_l
    ):
        cards.extend(["insecure-deserialization", "controlled-rce-impact"])
    if (
        (
            "cors" in focus_l
            or "csrf" in focus_l
            or "xsrf" in focus_l
            or "clickjacking" in focus_l
            or "dom" in focus_l
            or "dom-xss" in focus_l
            or "postmessage" in focus_l
            or "open-redirect" in focus_l
            or "client-side-redirect" in focus_l
            or "cookie-manipulation" in focus_l
            or "dom-clobbering" in focus_l
        )
        and not _has_proxy_cache_boundary_signal(focus)
    ):
        cards.append("browser-client-boundaries")
    if (
        "reflected-xss" in focus_l
        or "stored-xss" in focus_l
        or "client-xss" in focus_l
        or re.search(r"\bcross[-_ ]?site[-_ ]?scripting\b", focus_l)
        or re.search(r"(?<!dom[-_])\bxss\b", focus_l)
        or re.search(r"\bcsp\b", focus_l)
        or re.search(r"\bcontent[-_ ]?security[-_ ]?policy\b", focus_l)
        or "sandbox-escape" in focus_l
        or "dangling-markup" in focus_l
    ):
        cards.append("xss-client-injection")
    if (
        re.search(r"\bcsp\b", focus_l)
        or re.search(r"\bcontent[-_ ]?security[-_ ]?policy\b", focus_l)
        or "frame-ancestors" in focus_l
    ):
        cards.append("browser-client-boundaries")
    if _has_proxy_cache_boundary_signal(focus):
        cards.append("proxy-cache-boundaries")
    if "websocket" in focus_l or "web-socket" in focus_l or "cswsh" in focus_l:
        cards.append("websocket-realtime-api")
    if (
        "information-disclosure" in focus_l
        or "info-disclosure" in focus_l
        or "source-map" in focus_l
        or "debug" in focus_l
    ):
        cards.append("information-disclosure-source-config")
    if (
        re.search(r"\bweb[-_ ]?llm\b", focus_l)
        or re.search(r"\bllm\b", focus_l)
        or re.search(r"\bprompt[-_ ]?injection\b", focus_l)
        or re.search(r"\brag\b", focus_l)
        or re.search(r"\bagent[-_ ]?tool\b", focus_l)
    ):
        cards.append("web-llm-tool-chains")
    if "essential-skills" in focus_l:
        cards.append("coverage-prompts")
    if re.search(r"\brce\b", focus_l) or COMMAND_INJECTION_RE.search(focus) or "shell-primitive" in focus_l:
        cards.append("controlled-rce-impact")
    if (
        re.search(r"\b(?:node\.js|nodejs)\b", focus_l)
        or re.search(r"\bexpress\b", focus_l)
        or "prototype-pollution" in focus_l
        or "proto-pollution" in focus_l
        or "__proto__" in focus_l
        or "constructor.prototype" in focus_l
        or re.search(r"\bvm2?\b", focus_l)
    ):
        cards.append("node-prototype-pollution")
    return _dedupe(cards)


def _select_cards_and_deferred(
    blob: str,
    skill: str,
    ranked: dict,
    gaps: list[dict],
    goal_memory: dict,
    focus: str,
    repo_root: Path | str = BASE_DIR,
) -> tuple[list[str], list[str]]:
    focus_cards = _cards_from_focus(focus)
    cards: list[str] = list(focus_cards)
    for pattern, names in DISTILLED_TOKEN_TO_CARDS:
        if pattern.search(blob):
            cards.extend(names)
    for pattern, names in TOKEN_TO_CARDS:
        if pattern.search(blob):
            if names == ("browser-client-boundaries",) and _has_proxy_cache_boundary_signal(blob):
                continue
            cards.extend(names)
    target_memory = goal_memory.get("target") or {}
    if len(target_memory.get("dead_ends") or []) >= 2:
        cards.append("dead-ends")
    if gaps or skill in {"web2-recon", "bb-methodology"}:
        cards.append("coverage-prompts")
    if not ranked.get("available") and skill != "web2-vuln-classes":
        cards = (cards[:1] + ["coverage-prompts"]) if cards else ["coverage-prompts"]
    if skill == "triage-validation" and not cards:
        cards.extend(["api-idor", "auth-access"])
    if not cards:
        cards.append("coverage-prompts")
    focus_l = focus.lower()
    priority: list[str] = []
    api_business_logic_signal = _has_api_business_logic_signal(f"{focus}\n{blob}")
    browser_boundary_signal = _has_browser_client_boundary_signal(f"{focus}\n{blob}")
    websocket_realtime_signal = _has_websocket_realtime_signal(f"{focus}\n{blob}")
    ssrf_context_signal = _has_ssrf_context_signal(f"{focus}\n{blob}")
    browser_boundary_focus = browser_boundary_signal and not ssrf_context_signal
    for pattern, names in DISTILLED_TOKEN_TO_CARDS:
        if pattern.search(focus):
            priority.extend(names)
        elif pattern.search(blob):
            priority.extend(names)
    if (
        re.search(r"\bapi[-_ ]?testing\b", focus_l)
        or re.search(r"\bapi[-_ ]?test\b", focus_l)
        or re.search(r"\brest[-_ ]?api\b", focus_l)
        or re.search(r"\bsoap[-_ ]?api\b", focus_l)
        or re.search(r"\bmobile[-_ ]?api\b", focus_l)
        or re.search(r"\b(api[-_ ]?testing|api[-_ ]?test|rest[-_ ]?api|soap[-_ ]?api|mobile[-_ ]?api|openapi|swagger)\b", blob, re.I)
        or _has_api_parameter_handling_signal(blob)
    ):
        priority.append("api-testing-workflow")
        if api_business_logic_signal:
            priority.append("business-logic-state-machines")
        if API_PARAMETER_POLLUTION_RE.search(blob):
            priority.append("missing-parameter-discovery")
        priority.append("api-idor")
    if (
        re.search(r"\bbusiness[-_ ]?logic\b", focus_l)
        or re.search(r"\blogic[-_ ]?flaws?\b", focus_l)
        or "state-machine" in focus_l
        or "workflow-validation" in focus_l
        or "client-side-controls" in focus_l
        or "price-tamper" in focus_l
        or api_business_logic_signal
        or API_MASS_ASSIGNMENT_RE.search(blob)
        or re.search(
            r"\b(business[-_ ]?logic|logic[-_ ]?flaws?|state[-_ ]?machine|workflow[-_ ]?validation|client[-_ ]?side[-_ ]?controls|price[-_ ]?tamper|coupon|cart|checkout|exceptional[-_ ]?input|dual[-_ ]?use[-_ ]?endpoint)\b",
            blob,
            re.I,
        )
    ):
        priority.append("business-logic-state-machines")
    if (
        re.search(r"\bpassword[-_ ]?reset\b", focus_l)
        or re.search(r"\bforgot[-_ ]?password\b", focus_l)
        or re.search(r"\baccount[-_ ]?recovery\b", focus_l)
        or re.search(r"\busername[-_ ]?enum(?:eration)?\b", focus_l)
        or re.search(r"\bcredential[-_ ]?attack\b", focus_l)
        or re.search(r"\bbrute[-_ ]?force\b", focus_l)
        or "lockout" in focus_l
        or "stay-logged-in" in focus_l
        or "remember-me" in focus_l
        or "mfa" in focus_l
        or "2fa" in focus_l
        or "otp" in focus_l
        or re.search(
            r"\b(password[-_ ]?reset|forgot[-_ ]?password|account[-_ ]?recovery|reset[-_ ]?token|username[-_ ]?enum(?:eration)?|credential[-_ ]?attack|brute[-_ ]?force|lockout|stay[-_ ]?logged[-_ ]?in|remember[-_ ]?me|mfa|2fa|otp)\b",
            blob,
            re.I,
        )
    ):
        priority.append("auth-credential-recovery-flows")
        priority.append("auth-access")
    if (
        "missing-param" in focus_l
        or "parameter-null" in focus_l
        or "param-discovery" in focus_l
        or "api-docs" in focus_l
        or API_PARAMETER_POLLUTION_RE.search(blob)
        or re.search(
            r"\b(missing[-_ ]?param(?:eter)?|parameter[-_ ]?null|parameter is null|required[-_ ]?param(?:eter)?|schema[-_ ]?error|validator[-_ ]?error|binder[-_ ]?error|param[-_ ]?discovery|api[-_ ]?docs|swagger|openapi)\b",
            blob,
            re.I,
        )
    ):
        priority.append("missing-parameter-discovery")
    sqli_signal = (
        "sqli" in focus_l
        or "sql-injection" in focus_l
        or re.search(
            r"\b(sqli|sql[-_ ]?injection|request[-_ ]?metadata|routing[-_ ]?segment|hidden[-_ ]?param|path[-_ ]?segment|second[-_ ]?order|log[-_ ]?backed)\b",
            blob,
            re.I,
        )
    )
    if sqli_signal:
        priority.append("sqli-hidden-surfaces")
    access_control_signal = re.search(
        r"\b(access[-_ ]?control|unprotected[-_ ]?admin|admin[-_ ]?panel|administrator[-_ ]?panel|"
        r"method[-_ ]?based[-_ ]?access|referer[-_ ]?based[-_ ]?access|url[-_ ]?based[-_ ]?access|"
        r"role[-_ ]?bypass|admin[-_ ]?roles?)\b",
        blob,
        re.I,
    )
    if access_control_signal and not browser_boundary_focus and not websocket_realtime_signal:
        priority.append("auth-access")
    if (
        "path-pattern" in focus_l
        or "management-exposure" in focus_l
        or "admin-panel" in focus_l
        or "monitoring-console" in focus_l
        or "structured-record" in focus_l
        or "raw-log" in focus_l
        or "config-exposure" in focus_l
        or "secret-leak" in focus_l
        or re.search(
            r"\b(path[-_ ]?pattern|directory[-_ ]?fuzz(?:ing)?|target[-_ ]?wordlist|sibling[-_ ]?path|structured[-_ ]?record|raw[-_ ]?log|admin[-_ ]?panel|management[-_ ]?exposure|management[-_ ]?console|monitoring[-_ ]?console|metrics|health|config[-_ ]?(?:exposure|page|endpoint|dump|leak)|configuration|stats|trace|datasource|accesskey|secretkey|secret[-_ ]?leak)\b",
            blob,
            re.I,
        )
    ):
        priority.append("path-pattern-management-exposure")
    if "graphql" in focus_l:
        priority.append("graphql")
    if (
        "api-idor" in focus_l
        or "idor" in focus_l
        or "access-control" in focus_l
        or "method-based-access" in focus_l
        or "referer-based-access" in focus_l
        or "url-based-access" in focus_l
        or "role-bypass" in focus_l
        or "admin-roles" in focus_l
        or (access_control_signal and not browser_boundary_focus and not websocket_realtime_signal)
        or re.search(r"\b(idor|tenant|org|accounts|user_id|account_id|org_id|tenant_id|order_id|invoice_id|object_id)\b", blob, re.I)
    ):
        if (
            access_control_signal
            or "access-control" in focus_l
            or "method-based-access" in focus_l
            or "referer-based-access" in focus_l
            or "url-based-access" in focus_l
        ) and not browser_boundary_focus and not websocket_realtime_signal:
            priority.append("auth-access")
        priority.append("api-idor")
    if (
        "auth-hidden" in focus_l
        or "hidden-login" in focus_l
        or "login-bypass" in focus_l
        or "ato" in focus_l
        or re.search(r"\b(hidden[-_ ]?login|login[-_ ]?bypass|account[-_ ]?takeover|username[-_ ]?enum|auth[-_ ]?selector|auth[-_ ]?switch|hidden[-_ ]?provider|hidden[-_ ]?source|hidden[-_ ]?channel)\b", blob, re.I)
    ):
        priority.append("auth-hidden-switches")
        priority.append("auth-access")
    if (
        "jwt" in focus_l
        or "jwe" in focus_l
        or "jwks" in focus_l
        or "jku" in focus_l
        or "kid" in focus_l
        or "oauth" in focus_l
        or "oidc" in focus_l
        or "saml" in focus_l
        or "sso" in focus_l
        or "pkce" in focus_l
        or "token-binding" in focus_l
        or "account-linking" in focus_l
        or re.search(
            r"\b(jwt|jwe|jwks?|jku|kid|oidc|oauth|saml|sso|relaystate|samlresponse|acs|pkce|nonce|token[-_ ]?binding|account[-_ ]?linking)\b",
            blob,
            re.I,
        )
    ):
        priority.append("auth-sso-token-edge-cases")
        priority.append("auth-access")
    if re.search(r"\bauth(?:entication|z)?\b", focus_l) and not browser_boundary_focus and not websocket_realtime_signal:
        priority.append("auth-access")
    if (
        sqli_signal
    ):
        priority.append("sqli-hidden-surfaces")
    if (
        "nosql" in focus_l
        or "no-sql" in focus_l
        or "operator-injection" in focus_l
        or re.search(r"\b(nosql|no[-_ ]?sql[-_ ]?injection|mongo(?:db)?|bson|operator[-_ ]?injection)\b|\$(?:ne|regex|where|gt|nin)", blob, re.I)
    ):
        priority.append("nosql-query-injection")
    if (
        "xxe" in focus_l
        or "xml-parser" in focus_l
        or "xinclude" in focus_l
        or re.search(r"\b(xxe|xml[-_ ]?parser|xinclude|doctype|external[-_ ]?entit(?:y|ies)|soapaction|samlresponse|svg|docx|xlsx|rss|atom)\b", blob, re.I)
    ):
        priority.append("xxe-xml-parser")
    if (
        "path-traversal" in focus_l
        or "directory-traversal" in focus_l
        or "local-file-inclusion" in focus_l
        or "lfi" in focus_l
        or "file-read" in focus_l
        or re.search(r"\b(path[-_ ]?traversal|directory[-_ ]?traversal|lfi|local[-_ ]?file[-_ ]?inclusion|file[-_ ]?read|file[-_ ]?download|php://filter|web-inf|etc/passwd)\b", blob, re.I)
    ):
        priority.append("path-traversal-file-read")
    ssrf_blob = f"{focus}\n{blob}"
    if _has_ssrf_internal_signal(ssrf_blob):
        priority.append("ssrf-internal-impact")
        priority.append("ssrf-url-fetch")
    elif SSRF_FETCH_CONTEXT_RE.search(ssrf_blob):
        priority.append("ssrf-url-fetch")
    if SSTI_TOKEN_RE.search(blob):
        priority.append("server-side-template-injection")
        priority.append("controlled-rce-impact")
    if (
        "deserialization" in focus_l
        or "deserialize" in focus_l
        or "signed-object" in focus_l
        or "viewstate" in focus_l
        or re.search(r"\b(deserialization|deserialize|serialized|signed[-_ ]?object|rememberme|remember[-_ ]?me|viewstate|ysoserial|pickle|java[-_ ]?serialized|php[-_ ]?serialize)\b", blob, re.I)
    ):
        priority.append("insecure-deserialization")
        priority.append("controlled-rce-impact")
    if (
        (
            "cors" in focus_l
            or "csrf" in focus_l
            or "xsrf" in focus_l
            or "clickjacking" in focus_l
            or "dom" in focus_l
            or "postmessage" in focus_l
            or "open-redirect" in focus_l
            or "client-side-redirect" in focus_l
            or "cookie-manipulation" in focus_l
            or "dom-clobbering" in focus_l
            or (browser_boundary_focus and not websocket_realtime_signal)
        )
        and not _has_proxy_cache_boundary_signal(f"{focus}\n{blob}")
    ):
        priority.append("browser-client-boundaries")
    if (
        "reflected-xss" in focus_l
        or "stored-xss" in focus_l
        or "client-xss" in focus_l
        or re.search(r"\bcross[-_ ]?site[-_ ]?scripting\b", focus_l)
        or re.search(r"(?<!dom[-_])\bxss\b", focus_l)
        or re.search(r"\bcsp\b", focus_l)
        or re.search(r"\bcontent[-_ ]?security[-_ ]?policy\b", focus_l)
        or "sandbox-escape" in focus_l
        or "dangling-markup" in focus_l
        or re.search(
            r"\b(reflected[-_ ]?xss|stored[-_ ]?xss|client[-_ ]?xss|cross[-_ ]?site[-_ ]?scripting|csp|content[-_ ]?security[-_ ]?policy|script[-_ ]?src[-_ ]?elem|sandbox[-_ ]?escape|dangling[-_ ]?markup|angularjs[-_ ]?sandbox)\b|(?<!dom[-_])\bxss\b",
            blob,
            re.I,
        )
    ):
        priority.append("xss-client-injection")
    if (
        "host-header" in focus_l
        or "proxy-trust" in focus_l
        or "request-smuggling" in focus_l
        or "http-smuggling" in focus_l
        or "cache-poisoning" in focus_l
        or "web-cache-poisoning" in focus_l
        or "cache-deception" in focus_l
        or "web-cache-deception" in focus_l
        or re.search(r"\b(host[-_ ]?header|x[-_ ]?forwarded[-_ ]?host|forwarded|proxy[-_ ]?trust|request[-_ ]?smuggling|http[-_ ]?smuggling|transfer[-_ ]?encoding|content[-_ ]?length|cache[-_ ]?poisoning|cache[-_ ]?deception|unkeyed|x[-_ ]?cache|age|vary|cdn)\b", blob, re.I)
    ):
        priority.append("proxy-cache-boundaries")
    if (
        "websocket" in focus_l
        or "web-socket" in focus_l
        or "cswsh" in focus_l
        or websocket_realtime_signal
    ):
        priority.append("websocket-realtime-api")
    if (
        "information-disclosure" in focus_l
        or "info-disclosure" in focus_l
        or re.search(r"\b(information[-_ ]?disclosure|info[-_ ]?disclosure|debug|stack[-_ ]?trace|source[-_ ]?map|\.map|backup|\.bak|git[-_ ]?leak|directory[-_ ]?listing|robots\.txt|security\.txt|version[-_ ]?leak|error[-_ ]?leak)\b", blob, re.I)
    ):
        priority.append("information-disclosure-source-config")
    if (
        "web-llm" in focus_l
        or "llm" in focus_l
        or "prompt-injection" in focus_l
        or re.search(r"\b(web[-_ ]?llm|llm|prompt[-_ ]?injection|indirect[-_ ]?prompt|rag|agent[-_ ]?tool|tool[-_ ]?call|model[-_ ]?context)\b", blob, re.I)
    ):
        priority.append("web-llm-tool-chains")
    if (
        re.search(r"\b(?:node\.js|nodejs)\b", focus_l)
        or re.search(r"\bexpress\b", focus_l)
        or "prototype-pollution" in focus_l
        or "proto-pollution" in focus_l
        or "__proto__" in focus_l
        or "constructor.prototype" in focus_l
        or re.search(r"\bvm2?\b", focus_l)
        or re.search(
            r"\b(node\.js|nodejs|express|next\.js|nestjs|koa|hapi|fastify|prototype[-_ ]?pollution|proto[-_ ]?pollution|__proto__|constructor\.prototype|lodash|qs|flat|deep[-_ ]?extend|dot[-_ ]?prop|set[-_ ]?value|vm2?|happy[-_ ]?dom|jsdom)\b",
            blob,
            re.I,
        )
    ):
        priority.append("node-prototype-pollution")
    if not priority and re.search(r"\b(graphql|gql|mutation|subscription|introspection|global[_-]?id)\b", blob, re.I):
        priority.append("graphql")
    cards = _dedupe(focus_cards + priority + cards)
    if not ranked.get("available"):
        if skill == "web2-vuln-classes" and focus_cards:
            cards = focus_cards[:2]
        elif skill == "web2-vuln-classes" and len(cards) >= 2:
            cards = cards[:2]
        else:
            cards = _dedupe((cards[:1] if cards else []) + ["coverage-prompts"])
    candidate_paths = [CARD_PATHS[name] for name in _dedupe(cards) if name in CARD_PATHS]
    return _budget_knowledge_cards(candidate_paths, repo_root)


def _select_cards(
    blob: str,
    skill: str,
    ranked: dict,
    gaps: list[dict],
    goal_memory: dict,
    focus: str,
    repo_root: Path | str = BASE_DIR,
) -> list[str]:
    selected, _ = _select_cards_and_deferred(blob, skill, ranked, gaps, goal_memory, focus, repo_root)
    return selected


def _required_checks(skill: str, blob: str) -> list[str]:
    checks = [
        "rules/context-loading.md",
        "rules/red-lines.md",
        "rules/coverage-gate.md",
    ]
    if skill == "triage-validation":
        checks.append("rules/reporting.md")
    if re.search(r"\b(jwt|oauth|graphql|api[-_ ]?testing|api[-_ ]?test|business[-_ ]?logic|logic[-_ ]?flaws?|state[-_ ]?machine|workflow[-_ ]?validation|password[-_ ]?reset|forgot[-_ ]?password|account[-_ ]?recovery|username[-_ ]?enum(?:eration)?|credential[-_ ]?attack|brute[-_ ]?force|lockout|access[-_ ]?control|method[-_ ]?based[-_ ]?access|referer[-_ ]?based[-_ ]?access|url[-_ ]?based[-_ ]?access|ssrf|upload|url[-_ ]?fetch|webhook|xxe|xml[-_ ]?parser|path[-_ ]?traversal|lfi|file[-_ ]?read|ssti|deserialization|deserialize|nosql|host[-_ ]?header|request[-_ ]?smuggling|cache[-_ ]?(?:poisoning|deception)|cors|csrf|clickjacking|open[-_ ]?redirect|cookie[-_ ]?manipulation|dom[-_ ]?clobbering|xss|csp|content[-_ ]?security[-_ ]?policy|dom[-_ ]?xss|websocket|information[-_ ]?disclosure|web[-_ ]?llm)\b", blob, re.I):
        checks.append("rules/playbook-router.md")
    return _dedupe(checks)


def _phase(goal_memory: dict) -> str:
    active = goal_memory.get("active") or {}
    target_memory = goal_memory.get("target") or {}
    return str(active.get("phase") or target_memory.get("phase") or "unknown").strip() or "unknown"


def _active_goal(goal_memory: dict) -> str:
    active = goal_memory.get("active") or {}
    target_memory = goal_memory.get("target") or {}
    return str(active.get("active_goal") or target_memory.get("active_goal") or "").strip()


def _hypothesis(goal_memory: dict) -> str:
    active = goal_memory.get("active") or {}
    target_memory = goal_memory.get("target") or {}
    return str(active.get("current_hypothesis") or target_memory.get("current_hypothesis") or "").strip()


def _surface_anchor(item: dict) -> str:
    url = str(item.get("url") or "").strip()
    reasons = ", ".join(str(reason) for reason in (item.get("reasons") or [])[:2])
    score = item.get("score")
    review_reason = str(item.get("review_reason") or "surface evidence").strip()
    return f"Surface review {url} score_hint={score} reason={review_reason}; {reasons}".strip()


def _gap_anchor(gap: dict) -> str:
    return f"Coverage gap: {gap.get('endpoint', '')} x {gap.get('vuln_class', '')} weight={gap.get('weight', '')}"


def _local_intel_anchors(local_intel: dict) -> list[str]:
    anchors: list[str] = []
    browser = local_intel.get("browser") or {}
    for url in (browser.get("xhr_endpoints") or [])[:3]:
        anchors.append(f"Browser XHR/API: {url}")
    for line in (browser.get("params") or [])[:3]:
        anchors.append(f"Browser param: {line}")
    for form in (browser.get("forms") or [])[:2]:
        method = str(form.get("method") or "").strip() or "GET"
        action = str(form.get("action") or "").strip() or "(current page)"
        anchors.append(f"Browser form: {method} {action}")

    js_intel = local_intel.get("js_intel") or {}
    for endpoint in (js_intel.get("endpoints") or [])[:3]:
        method = str(endpoint.get("method") or "").strip()
        path = str(endpoint.get("path") or "").strip()
        source = str(endpoint.get("source_file") or "").strip()
        auth_required = str(endpoint.get("auth_required") or "").strip()
        parts = ["JS-reader endpoint:"]
        if method:
            parts.append(method)
        if path:
            parts.append(path)
        if source:
            parts.append(f"source={source}")
        if auth_required:
            parts.append(f"auth={auth_required}")
        anchors.append(" ".join(parts))
    for lead in (js_intel.get("leads") or [])[:2]:
        title = str(lead.get("title") or "").strip()
        category = str(lead.get("category") or "js").strip()
        if title:
            anchors.append(f"JS-reader lead [{category}]: {title}")

    source_intel = local_intel.get("source_intel") or {}
    for hypothesis in (source_intel.get("hypotheses") or [])[:3]:
        vuln_type = str(hypothesis.get("type") or "source").strip()
        candidate = str(hypothesis.get("candidate") or "").strip()
        reason = str(hypothesis.get("reason") or "").strip()
        if candidate:
            suffix = f" -> {reason[:120]}" if reason else ""
            anchors.append(f"Source-intel hypothesis [{vuln_type}]: {candidate}{suffix}")
    for route in (source_intel.get("routes") or [])[:2]:
        route_value = str(route.get("route") or "").strip()
        method = str(route.get("method") or "").strip()
        if route_value:
            anchors.append(f"Source route: {method} {route_value}".strip())
    return _dedupe(anchors)


def _build_evidence_anchors(
    ranked: dict,
    goal_memory: dict,
    gaps: list[dict],
    findings: list[dict],
    local_intel: dict,
) -> list[str]:
    anchors: list[str] = []
    for item in (ranked.get("review_pool") or ranked.get("p1", []))[:3]:
        anchors.append(_surface_anchor(item))
    anchors.extend(_local_intel_anchors(local_intel)[:6])
    for lead in _json_list(ranked.get("workflow_leads"))[:3]:
        title = str(lead.get("title") or "").strip()
        category = str(lead.get("category") or "workflow").strip()
        priority = str(lead.get("priority") or "medium").strip()
        anchors.append(f"Workflow lead [{priority}/{category}]: {title}")
    target_memory = goal_memory.get("target") or {}
    for label, field in (
        ("Target lead", "active_leads"),
        ("Next action", "next_actions"),
        ("Dead end", "dead_ends"),
    ):
        for item in (target_memory.get(field) or [])[-2:]:
            text = _entry_text(item)
            if text:
                anchors.append(f"{label}: {text}")
    for gap in gaps[:5]:
        anchors.append(_gap_anchor(gap))
    for finding in findings[:3]:
        anchors.append(f"Finding: {_finding_anchor(finding)}")
    return _dedupe(anchors)[:12] or ["No strong local evidence anchor yet; start from target memory and recon freshness."]


def _has_browser_intel(local_intel: dict) -> bool:
    browser = local_intel.get("browser") or {}
    return bool(
        browser.get("xhr_endpoints")
        or browser.get("api_endpoints")
        or browser.get("params")
        or browser.get("forms")
    )


def _local_intel_hypothesis_seeds(local_intel: dict) -> list[str]:
    seeds: list[str] = []
    browser = local_intel.get("browser") or {}
    browser_blob = "\n".join(
        list(browser.get("xhr_endpoints") or [])
        + list(browser.get("api_endpoints") or [])
        + list(browser.get("params") or [])
    )
    if _has_browser_intel(local_intel):
        seeds.append(
            "浏览器观察到的 XHR/API 优先按原始 method / 参数形态做登录态、角色、租户差异对比；HTTP method 本身不是红线，真实破坏性副作用才需要降级到只读或可回滚验证。"
        )
    if re.search(r"\b(user|account|tenant|org|order|invoice|object|profile|workspace)[_-]?id\b|[?&]id=", browser_blob, re.I):
        seeds.append(
            "browser_params / XHR 中的对象 ID 适合做 attacker/victim、同组织/跨组织、角色差异验证。"
        )
    if re.search(r"\b(graphql|mutation|subscription)\b", browser_blob, re.I):
        seeds.append(
            "浏览器态 GraphQL 先提取 operation、变量和对象 ID，再做低频 authz 差异，不做深层递归或 alias 加压。"
        )
    if browser.get("forms"):
        seeds.append(
            "表单 action / method 可作为 CSRF、SameSite、服务端权限绑定线索；默认不提交真实状态改变动作。"
        )

    js_intel = local_intel.get("js_intel") or {}
    if js_intel.get("endpoints") or js_intel.get("leads"):
        seeds.append(
            "JS-reader 暴露的 endpoint / lead 要和浏览器 Network 或实际 replay 交叉验证，优先找前端可见但服务端未绑定的权限边界。"
        )

    source_intel = local_intel.get("source_intel") or {}
    source_types = {
        str(item.get("type") or "").lower()
        for item in (source_intel.get("hypotheses") or [])
        if item.get("type")
    }
    if source_types:
        seeds.append(
            "source-intel hypothesis 是路线种子，不是结论；先用浏览器态或最小请求验证真实可达性和权限影响。"
        )
    if {"csrf", "auth-bypass"} & source_types:
        seeds.append(
            "source-intel 命中 CSRF/auth-bypass 时先检查 token、SameSite、Origin/Referer 和角色绑定，避免直接执行破坏性 workflow。"
        )
    return _dedupe(seeds)


def _hypothesis_seeds(cards: list[str], blob: str, local_intel: dict) -> list[str]:
    seeds: list[str] = []
    seeds.extend(_local_intel_hypothesis_seeds(local_intel))
    if CARD_PATHS["api-idor"] in cards or re.search(r"\b(idor|tenant|org|accounts|user_id|account_id|order_id)\b", blob, re.I):
        seeds.extend([
            "对象/组织/租户 ID 是否只在前端约束，服务端是否重新绑定当前身份。",
            "export/download/report 类接口是否可通过 ID 或筛选条件读取其他主体数据。",
        ])
    if CARD_PATHS["auth-access"] in cards:
        seeds.extend([
            "同一 endpoint 在匿名、普通用户、低权限成员、管理员之间是否只有 UI 差异而缺少服务端差异。",
            "访问控制要对比 method/path/header 维度：GET vs POST、X-HTTP-Method-Override、X-Original-URL/X-Rewrite-URL、Referer 和直接 API/raw replay；浏览器 fetch 不能设置受限头时不要据此停止。",
        ])
    if CARD_PATHS["auth-hidden-switches"] in cards:
        seeds.extend([
            "登录接口是否存在 UI 未传但后端读取的隐藏认证参数、模式、来源、渠道、provider 或 feature flag，能切换认证分支。",
            "留意管理员预留特权参数或内部账号分支，例如 isAdmin/admin/source/provider/soap 这类目标相关 selector；它们是联想种子，不是固定字典。",
            "本 lane 先做自有/测试账号 baseline 与单变量隐藏参数差异；若登录成为主要突破口，按 red-lines 的自主选择条件切到 /spray 或 credential-attack 受控流程。",
        ])
    if CARD_PATHS["auth-sso-token-edge-cases"] in cards:
        seeds.extend([
            "JWT/OAuth/SAML/SSO 先保存合法流程 baseline，再做 decode、metadata、callback、state/nonce/PKCE、issuer/key source 和账号绑定的单变量差异；JWT key-source 探针要和 claim-only tamper 分离，分别验证 JWK/JKU/KID/alg confusion 是否改变服务端身份/权限。",
            "JWT 签名验证 baseline 要先做 claim-only tamper：只改 sub/role/org 等单个 claim，保留无效签名或 none/alg 差异，观察服务端身份/权限是否实际改变。",
            "token/SSO 候选必须证明服务端身份、角色、租户、session 或 account-linking 边界影响；公开 metadata、可 decode token 或报错差异只算 Lead。",
        ])
    if CARD_PATHS["auth-credential-recovery-flows"] in cards:
        seeds.extend([
            "密码重置/账号恢复先建 token->账号->session 绑定模型；检查 hidden username、reset token、邮箱链接、Host/XFH、旧 token 复用和跨账号提交。",
            "用户名枚举、口令/OTP/remember-me 测试不是绝对禁用，但必须有目标依据、低频边界、锁定/限速观察和停止条件；训练资源可完整验证。",
        ])
    if CARD_PATHS["api-testing-workflow"] in cards:
        seeds.extend([
            "API testing 先把 docs/schema、JS/source、浏览器 XHR、mobile/旧版本和实际请求合并成 endpoint+method+auth matrix；不要只扫 `/api/` 路径。",
            "重点补 object/authz、隐藏/特权参数、mass assignment、content-type/parser、method override、HPP、版本差异和注入 sink；示例参数是候选形态，不是固定字典。",
            "API 参数污染/HPP 先比较 duplicate query/body、JSON 重复 key、分隔符/fragment 截断、后端 URL 构造、content-type parser 和 method override 差异；mass assignment 优先从 schema/JS/XHR 派生 role/isAdmin/plan/status/verified/approved 等高价值字段。",
        ])
    if CARD_PATHS["business-logic-state-machines"] in cards:
        seeds.extend([
            "业务逻辑先建状态机 baseline：谁能在什么前置状态下执行哪一步、服务端是否重新计算价格/权限/数量/流程顺序。",
            "重点看客户端可控价格/数量/折扣/角色/邮箱/流程步骤、异常输入、重复提交、双用途 endpoint 和跨步骤参数复用；训练/自有资源内验证，真实高影响状态默认先 dry-run。",
        ])
    if CARD_PATHS["missing-parameter-discovery"] in cards:
        seeds.extend([
            "`parameter is null` / `missing parameter` / schema 或 validator 错误只是入口信号；先从目标自身材料构造目标特定参数词表，再低频验证响应形态差异。",
            "隐藏参数命中后只做最小影响验证：状态码、长度、字段集合、空/非空结构和自有/测试对象差异；不批量枚举真实 PII、密码、地址或 token。",
        ])
    if CARD_PATHS["path-pattern-management-exposure"] in cards:
        seeds.extend([
            "发现类 fuzz 先从目标已有路径、文件名、API 前缀、参数名、子域、静态资源等命名规律生成有界词表，再验证兄弟 surface；不要直接扩大到无边界通用字典。",
            "管理/监控/日志/统计/配置/记录类 surface 优先做只读识别和结构化记录提取；疑似 access key/secret 只记录最小证据与验证计划，不接管云资源或读取真实数据。",
        ])
    if CARD_PATHS["graphql"] in cards:
        seeds.extend([
            "GraphQL mutation / global ID / node 查询是否复用 REST 的对象权限缺口。",
        ])
    if CARD_PATHS["sqli-hidden-surfaces"] in cards:
        seeds.extend([
            "显式查询语义输入是 SQLi 第一顺位 baseline：搜索、筛选、分类、排序、分页、报表、导出、对象选择、租户/范围限定等参数或路径段都应先做只读成对扰动。",
            "SQLi 不只看显式 query/body 参数；按证据检查请求元数据、路由片段、cookie/session、跨接口隐藏参数或二阶输入是否进入查询、日志、审计或风控链路。",
            "从目标材料提取高信号输入面，每次只扰动一个输入点，比较稳定的状态码、长度、错误、排序、字段集合或布尔差异。",
        ])
    if CARD_PATHS["nosql-query-injection"] in cards:
        seeds.extend([
            "NoSQL 先判断输入是否进入查询对象、过滤器、JSON parser 或表达式引擎；重点看登录、搜索、筛选、JSON body 和类型混淆。",
            "用合法 baseline 对比单变量 operator/type 差异，例如布尔绕过、数组/对象包裹、regex 形态和错误指纹；不批量枚举真实数据。",
        ])
    if CARD_PATHS["xxe-xml-parser"] in cards:
        seeds.extend([
            "XXE 先确认真实 XML 解析面：SOAP/XML API、SAML、SVG、Office 文档、RSS/Atom、导入/转换器和 content-type 兼容路径可能使用不同 parser；即使外层是 form/JSON 参数，也可能被后端组装进 XML 后触发 XInclude。",
            "验证顺序优先 harmless entity / OAST callback / XInclude 差异，再按证据判断 file-read 或 SSRF 影响；不默认批量读取敏感文件。",
            "错误响应本身不是 XXE 证据；只有业务字段或错误消息反射无害 entity、外部 entity 内容，或 OAST 记录到唯一 token 时，才把 parser 行为升级为影响线索。",
        ])
    if CARD_PATHS["path-traversal-file-read"] in cards:
        seeds.extend([
            "路径遍历先定位文件选择器：download/view/include/template/image/doc/export/theme/locale/archive 等参数、路径段、文件名和后端别名映射。",
            "用正常文件 baseline 对比 traversal 变体、编码/双编码、斜杠混用、后缀拼接和平台路径差异；命中后优先链到源码/配置/路由发现，不做批量 secret harvesting。",
        ])
    if CARD_PATHS["ssrf-url-fetch"] in cards:
        seeds.extend([
            "URL fetch、webhook、import callback、stock checker、预览/导入等是否存在 server-side fetch；先用合法 allowlisted URL 建 baseline，再比较响应体、状态码、错误和来源差异。",
        ])
    if CARD_PATHS["ssrf-internal-impact"] in cards:
        seeds.extend([
            "SSRF 内部影响只在已证明 server-side fetch 后展开；优先单个明确内部目标的状态级证据，不做内网扫描。",
            "当 SSRF 受 allowlist/local-only 限制时，open redirect / redirect connector 属于 SSRF 链路而不是浏览器跳转结论：先证明本地允许 URL 会被服务端 fetch，再证明 30x 后由服务端访问单个内部目标。",
            "内部 admin/metadata/control-plane 只做最小路径和单账号/单对象影响证明；parser discrepancy、userinfo、fragment、编码和重定向差异是候选形态，不是固定字典。",
            "Blacklist/allowlist SSRF 过滤绕过按 blocked baseline -> loopback/别名 host -> 单/双编码 path -> 状态确认分步验证；3xx/404/400 差异要保存原始请求/响应，内部动作只在测试资源上做单目标最小证明。",
        ])
    if CARD_PATHS["upload-parser"] in cards:
        seeds.extend([
            "上传、导入、预览、转换是否形成解析器链路，优先验证元数据/预览差异而非破坏性 payload；SVG/Office/XML 类二阶解析要保存上传请求、处理响应和转换/read-back 结果。",
        ])
    if CARD_PATHS["upload-to-execution"] in cards:
        seeds.extend([
            "上传执行链先证明存储/访问/解析器路径和一次性无害执行差异；webshell 只作为明确授权后的深度证明，不是默认动作。",
            "上传执行验证要拆成存储路径 proof、访问/read-back proof、处理器/解释器 proof、执行身份 proof；filename 路径分隔符和编码 parent segment 只作为存储目录选择候选形态，需同时对原上传目录和目标目录做 read-back，并保存原始 upload 请求、上传响应、read-back 请求和响应。",
            "扩展名、multipart part Content-Type、magic bytes、polyglot、.htaccess/web.config 等只是候选形态，不是固定字典；每次只改一个维度并记录服务器信任声明 MIME、检查内容、静态下载、解析、预览还是执行。",
            "需要脚本执行时优先一次性短输出或 OAST token；持久 webshell、写业务目录、读真实数据和批量枚举必须 gated，并有清理路径和停止条件。",
        ])
    if CARD_PATHS["insecure-deserialization"] in cards:
        seeds.extend([
            "Serialized session/remember-me/state blob 先保存合法 baseline，记录 cookie/header/field 名、HttpOnly/SameSite、编码层（base64/gzip/url-safe 等）、对象/类名/字段图，再做单字节 tamper 看完整性 gate。",
            "Unsigned serialized object 如果接受篡改，优先只在自有/测试账号上验证低影响 state 字段：role/admin/tenant/feature/price/quantity 等；跨账号 replay、旧 token 和用户绑定要单独对照。",
            "可解码不等于漏洞；必须证明服务端接受修改后的对象、解析错误差异或 OAST/type-error sink。签名/加密 tamper 被拒绝时先收敛到完整性结论，不直接上 gadget 或会话伪造。",
            "数据类型篡改和应用功能 gadget 分开验证：boolean/string/integer/null 变化只看服务端类型语义差异；delete/read/write 等二阶功能要证明对象字段如何流入既有业务动作，先停在测试资源和原始请求/响应证据。",
        ])
    if CARD_PATHS["controlled-rce-impact"] in cards:
        seeds.extend([
            "RCE/命令执行/SSTI/反序列化先证明 primitive，再证明执行身份和影响边界；默认不写文件、不持久化、不批量读取。",
            "RCE/模板执行的 500/超时本身不是成功证据；只有原始响应包含命令 stderr/返回码、或后续状态差异证明侧效应已经发生时，才可作为执行证据，并要配 baseline、replay 和清理说明。",
        ])
        if COMMAND_INJECTION_RE.search(blob):
            seeds.extend([
                "OS command injection 先建合法 baseline，再只改一个输入点做 single separator probe；visible output 要看响应体/状态码/长度/错误的稳定 diff，并区分协议失败、WAF/代理错误和服务端执行信号。",
                "命令注入候选形态不是固定字典：分隔符、低影响身份/系统 probe（如当前用户、id、系统类型）只在明确 sink 上按一个变量一次使用，命中即停并回到证据链。",
                "Blind 命令注入按短延迟 timing、output redirection、OAST 三类分型验证；timing 要设置低延迟上限和重复次数；output redirection 先从正常静态资源/上传/附件路径找 writable + readable read-back 位置；写文件/回连只在训练或明确授权环境 gated 执行，并记录 token、时间、来源和清理状态。",
            ])
    if CARD_PATHS["server-side-template-injection"] in cards:
        seeds.extend([
            "SSTI 先做模板求值 primitive 和模板引擎指纹：算术/字符串/上下文变量/错误差异；命中后再转 controlled-rce-impact 做受控影响证明。",
            "SSTI 要先定位 render/trigger 位置：reflected 参数、stored 内容、邮件/通知/报表/PDF/预览/后台审核可能分离；记录输入步、触发步和渲染证据。",
            "模板 probe 是候选形态不是固定字典：按引擎分隔符、运算符、过滤器、错误类型和上下文变量做单变量 fingerprint；Tornado/Mako/Handlebars/Mustache/Nunjucks/Pug/EJS 等引擎名只有与 template/render/code-context/helper/sandbox 线索同现时才进入 SSTI，避免前端模板名或 Node 运行时名误路由。",
            "Code-context SSTI 先证明当前表达式/字符串/模板块可闭合：baseline -> 无害表达式 -> trigger render；设置点和触发点分离时保存原始设置请求、触发请求和响应；sandbox/user-supplied object 只证明对象边界，文件或命令执行进 controlled-rce gate。",
        ])
    if CARD_PATHS["browser-client-boundaries"] in cards:
        seeds.extend([
            "浏览器边界类先用真实浏览器 baseline：Origin/Referer/SameSite、frame policy、DOM source->sink、postMessage origin check 和实际凭据发送情况。",
            "CSRF/CORS/Clickjacking/DOM 候选必须证明状态改变、跨源读能力、可点击敏感动作或 source-to-sink；单独 header 缺失或反射只算 Lead。",
            "DOM open redirect/cookie/clobbering 先找 source->navigation/cookie/global-object sink；例如未编码 `url=https://...` 被正则取出后赋给 `location.href`。",
        ])
        if re.search(r"\b(cors|origin|acao|acac|trusted[-_ ]?origin|trusted[-_ ]?insecure)\b", blob, re.I):
            seeds.append(
                "CORS trusted-origin 需要同时证明服务端信任该 Origin、攻击者可在该 Origin 投递/执行 JS、浏览器带凭据读到敏感响应。"
            )
        if re.search(r"\b(csrf|xsrf|same[-_ ]?site|referer)\b", blob, re.I):
            seeds.append(
                "CSRF 不只看是否有 token；按 valid baseline -> missing/bad token -> method swap -> cross-session token -> token-cookie pair / duplicate-cookie 矩阵验证；SameSite 要区分 site/origin，覆盖 Lax 顶层 GET、Strict 站内 gadget、sibling-domain XSS/CSWSH、OAuth/SSO cookie refresh 和新 cookie 时间窗口；Referer 要测 no-referrer、full-url/path query 域名注入和弱字符串匹配。"
            )
        if re.search(r"\b(clickjacking|frame[-_ ]?ancestors|x[-_ ]?frame[-_ ]?options|iframe)\b", blob, re.I):
            seeds.append(
                "Clickjacking 要在真实第三方 top origin 验证：frame policy 为空不够，还要确认 iframe 内登录态 cookie/SameSite、生效坐标和点击结果；表单页还要检查 URL/hash/localStorage 是否可预填攻击者控制的提交值，frame-buster JS 要测试 sandbox 禁脚本保留表单能力，按钮不在首屏时要计算 iframe offset；同时寻找 DOM XSS / workflow connector，多步流程要记录每一步坐标和 iframe state transition。"
            )
        if re.search(r"\bcookie[-_ ]?manipulation|document\.cookie|last[-_ ]?viewed|cookie[-_ ]?to[-_ ]?xss\b", blob, re.I):
            seeds.append(
                "Cookie manipulation 要追踪写入页和消费页：window.location/document.cookie 污染后，必须跳到实际读取 cookie 的页面验证 link/html/状态 sink。"
            )
        if re.search(r"\bdom[-_ ]?clobbering|clobber|defaultavatar|htmlcollection\b", blob, re.I):
            seeds.append(
                "DOM clobbering 先读脚本里的全局变量/配置名和 sanitizer/filter 逻辑，再验证 duplicate id/name -> HTMLCollection/property chain，并检查 payload 是否在 sink 或属性清洗之前生效。"
            )
    if CARD_PATHS["xss-client-injection"] in cards:
        seeds.extend([
            "XSS 先识别 reflected/stored/DOM 输入面和输出上下文：HTML text、attribute、JS string、URL、template、Markdown/富文本或 sanitizer 后输出。",
            "Candidate 必须有真实浏览器执行证据和最小可复现 payload；真实目标上不默认主动存储污染他人可见内容，训练/测试资源或明确授权除外。",
            "CSP 绕过先读完整 header；重点看 nonce/hash、script-src-elem、report-uri/base-uri/object-src 缺口、可反射 directive 和允许脚本源。",
        ])
    if CARD_PATHS["proxy-cache-boundaries"] in cards:
        seeds.extend([
            "Host/proxy/cache/smuggling 先分层建模：前端代理、后端应用、cache key、路由重写、连接复用和 backend connection pool；每次只改一个 header 或传输边界，request smuggling 要区分 CL.TE、TE.CL、TE.TE/TE obfuscation，并用新连接 GET/POST probe 验证 `GGET`/`GPOST` 或 differential 404 队列污染；H2.TE 要确认客户端真的发送了 `transfer-encoding` forbidden header，高级 H2 库可能静默过滤；H2.CL 要确认 `content-length: 0` 与 DATA mismatch 被保留，并用 SMUGGLED/404 或 host-controlled redirect 证明队列影响；H2 CRLF header injection 要区分 `\\r\\nTransfer-Encoding: chunked` 注入真实 header 和 `\\r\\n\\r\\nGET /x HTTP/1.1` 直接 request splitting，并用 404 sentinel 证明第二条请求进入后端队列；绕过 front-end controls 时检查内部 Host（如 localhost）、header conflict/body absorber 和原始字节长度；确认 desync 后继续评估 smuggled reflected XSS、请求捕获、cache/redirect 连接器或内部动作等 victim-facing 影响。",
            "Cache/Host 候选要证明未入 key 的输入影响可缓存响应或安全链接；按 cache-buster oracle -> no-header hit -> victim request shape hit -> victim path delivery 验证，注意 Vary/User-Agent/Accept/browser navigation 分桶。",
            "Web cache poisoning 常见链路包括 unkeyed header resource import、unkeyed cookie JS context、multiple-header redirect、targeted unknown header、unkeyed query/parameter、parameter cloaking、fat GET、URL normalization、multi-entry poisoning、cache key injection 和 internal fragment cache；smuggling-to-cache poisoning 重点找 host-controlled redirect connector、未被正常响应预热的 cacheable JS key、inner Content-Length/body absorber，并证明 `miss -> 302 Location -> hit`；最终 key 若已是正常 `X-Cache: hit/Age`，先换未使用资源路径或等 TTL 过期，否则会把 302 错配证据覆盖掉；H2.CL resource delivery 要让 exploit server path/query 对齐 redirect 后路径，并卡在 victim JS import 前；Web cache deception 覆盖 path mapping、delimiter、origin/cache normalization、exact-match file rule，smuggling-to-WCD 重点看 incomplete-header inner request 是否继承 victim Cookie、victim 是否已进入可投递节奏，以及最终 JS/CSS/image key 是否未被正常响应预热；response queue poisoning 用 404 sentinel、目标用户节奏和 `Set-Cookie`/302 线索识别捕获响应；capture-other-users 类要让内层存储请求带齐攻击者会话/CSRF/Content-Type/Content-Length，poll 读回遇到空响应先按后端连接池状态 reset/重试；对 HTML/URL 编码后的 request 做 decode，避免 Cookie 被 Content-Length 截断，并优先复用完整 Cookie line；smuggling 候选要有稳定 timing/desync/queue/malformed method 证据，不做高频扰动。",
            "复杂 cache 链要分别证明每个条目：状态/语言/redirect 连接器、最终资源或 DOM sink、clean hit、victim navigation/resource request；`Set-Cookie` 不可缓存时回看 cacheable redirect/rewrite/normalized path；WCD 泄露 CSRF token 时可在训练环境链到自动提交表单证明影响。",
            "Cache key injection 先用 key oracle 读 URL、Vary、Origin/header 分量和 excluded 参数；再找 harmful response 与 victim key collision，HTTP/2/header injection 只作为目标支持时的候选形态。",
            "多层 cache 要区分外层页面 cache 与 internal fragment cache（内层 fragment cache）：随机 query 可绕过外层，去掉 XFH/Host 后片段仍污染才说明内层 key 缺陷。",
            "Web cache deception 要从自有账号私有页 baseline 开始，分别测试 path mapping、delimiter、origin/cache normalization 和 exact-match file rule；smuggling-to-WCD 还要检查 incomplete-header inner request 是否继承 victim Cookie、victim readiness/访问节奏和未预热 JS/CSS/image key，并把私有页错配到资源 cache key；投递 victim 前换唯一 URL，最后用 no-cookie/raw read 证明私有响应被共享缓存。",
            "WCD 如果泄露 CSRF token、API key 或账户页敏感字段，要评估能否链到最小影响动作；训练环境可用自动提交表单证明，真实目标保持非破坏性。",
        ])
    if CARD_PATHS["websocket-realtime-api"] in cards:
        seeds.extend([
            "WebSocket 先捕获握手、Origin、Cookie/token、消息 schema 和首批 server messages；再做 raw frame replay、CSWSH exfil、订阅越权、消息级权限和 handshake header mutation（如 X-Forwarded-For/Protocol）差异。",
        ])
    if CARD_PATHS["information-disclosure-source-config"] in cards:
        seeds.extend([
            "信息泄露先区分公开信息、调试/错误/源码/配置/备份/source map；命中后提取最小必要证据并链到权限、token、路由或依赖风险。",
        ])
    if CARD_PATHS["web-llm-tool-chains"] in cards:
        seeds.extend([
            "Web LLM 先枚举模型可见上下文、可调用工具、数据源和权限边界；prompt injection 需要证明越权读、工具调用或业务动作影响。",
        ])
    if CARD_PATHS["node-prototype-pollution"] in cards:
        seeds.extend([
            "Node/prototype 方向先找 merge/path-set/query-parser source 和可观察 sink；live 验证只用唯一 inert marker，不先污染 role、权限或执行相关字段。",
            "有 prototype pollution primitive 不等于 RCE；先证明 marker -> sink 差异，命中模板/VM/执行 sink 后再转 controlled-rce-impact。",
        ])
    if CARD_PATHS["race-conditions"] in cards:
        seeds.extend([
            "并发风险先做低频状态模型和幂等性推理，不做高并发或真实资金/库存状态改变。",
            "Race 验证顺序是合法单次 baseline、单次 replay 幂等检查、状态窗口/锁粒度推理、协议能力探测（如 HTTP/2 multiplex 或 last-byte 同步）和最小同步触发；只有训练/自有可回滚资源才进入低请求数并发验证。",
        ])
    if CARD_PATHS["coverage-prompts"] in cards:
        seeds.append("把 surface review pool 映射到 authz、IDOR、SSRF、Upload、GraphQL、Race 等高价值 lane，找未测组合；分数只是提示，最终由 Claude 结合证据判断。")
    if CARD_PATHS["dead-ends"] in cards:
        seeds.append("复查 dead end 的停止条件：只有出现新证据时才重开旧方向。")
    return _dedupe(seeds)[:6]


def _alternative_angles(cards: list[str], ranked: dict, local_intel: dict) -> list[str]:
    angles = [
        "如果主路径证据不足，转到相邻高信号 review candidate，而不是扩大读取全量日志。",
        "对浏览器态 XHR/API、JS-reader、source-intel 的新证据保持开放，必要时改选 Skill。",
    ]
    browser = local_intel.get("browser") or {}
    if _has_browser_intel(local_intel):
        angles.extend([
            "用 Playwright/浏览器复用登录态重放关键页面，只看 Network/Console 差异和只读响应变化。",
            "用 Chrome DevTools Network/Console 对照真实前端请求，再决定是否转成 curl/local helper 精确 replay。",
            "对同一 browser-observed endpoint 做匿名、低权限、高权限账号差异，而不是只测单账号成功路径。",
        ])
    if browser.get("page_count") or browser.get("js_file_count"):
        angles.append("从 page_js_map 反查哪个页面加载目标 JS，再回到对应 workflow 捕获 XHR。")
    js_intel = local_intel.get("js_intel") or {}
    source_intel = local_intel.get("source_intel") or {}
    if js_intel.get("endpoints") and source_intel.get("hypotheses"):
        angles.append("把 JS-reader endpoint 与 source-intel route/hypothesis 交叉，优先验证两者重合的权限边界。")
    if CARD_PATHS["api-idor"] in cards:
        angles.append("从 REST IDOR 横向扩展到导出、报表、批量查询、成员管理和 invite 流程。")
    if CARD_PATHS["auth-hidden-switches"] in cards:
        angles.append("登录绕过无信号时，回到 JS/source/browser 找 sibling 登录端点、旧入口、移动端入口和隐藏认证分支选择器。")
    if CARD_PATHS["auth-sso-token-edge-cases"] in cards:
        angles.append("SSO/token 无直接结果时，回到合法流程 baseline、issuer/JWKS metadata、callback 绑定、state/nonce/PKCE 和 account-linking 映射差异。")
    if CARD_PATHS["auth-credential-recovery-flows"] in cards:
        angles.append("认证恢复无结果时，回到 reset/change-password/remember-me/MFA/lockout 的状态机，比较账号绑定、一次性 token、错误差异和限速边界。")
    if CARD_PATHS["api-testing-workflow"] in cards:
        angles.append("API testing 无结果时，回到浏览器态 XHR、JS/source-derived routes、OpenAPI/schema、移动端/旧版本、content-type 和 method/version 差异。")
    if CARD_PATHS["business-logic-state-machines"] in cards:
        angles.append("业务逻辑无结果时，不换 payload spray；回到正常业务流程，重排步骤、修改客户端字段、构造边界值、复用旧 token/优惠/订单状态和双账号对照。")
    if CARD_PATHS["missing-parameter-discovery"] in cards:
        angles.append("缺参/校验信号无结果时，回到 JS/source/schema/浏览器 XHR/历史请求/表单/GraphQL/sibling endpoint/路径分段，而不是扩大通用字典喷洒。")
    if CARD_PATHS["path-pattern-management-exposure"] in cards:
        angles.append("命名规律没有直接结果时，提取只读结构化记录、访问记录、统计接口、配置字段和 raw log 反哺二次 recon，并把 secret 候选降级为最小验证线索。")
    if CARD_PATHS["graphql"] in cards:
        angles.append("GraphQL 无结果时检查同业务的 REST sibling endpoint、global ID 解码和前端缓存。")
    if CARD_PATHS["sqli-hidden-surfaces"] in cards:
        angles.append("常规参数无 SQLi 信号时，转向目标相关的非显式输入面：请求元数据、路径/路由变量、cookie/session、JS/source-derived sibling 参数或二阶链路。")
    if CARD_PATHS["nosql-query-injection"] in cards:
        angles.append("NoSQL 无显式信号时，回到 JSON/form parser、登录/搜索/filter 参数、数组对象包裹和 schema/type 错误差异。")
    if CARD_PATHS["xxe-xml-parser"] in cards:
        angles.append("XXE 无直接回显时，换到同业务的 XML/SOAP/SAML/SVG/Office 导入 sibling parser，或用一次性 OAST 证明解析器外连。")
    if CARD_PATHS["path-traversal-file-read"] in cards:
        angles.append("路径遍历无结果时，检查路由规范化、静态文件别名、下载/预览 sibling、压缩包条目和 PHP/Java/Windows 特定读取语义。")
    if CARD_PATHS["upload-parser"] in cards:
        angles.append("上传链路无结果时转向 import URL、预览 worker、异步转换状态和权限绑定。")
    if CARD_PATHS["upload-to-execution"] in cards:
        angles.append("上传执行无结果时回到扩展/MIME/magic bytes、metadata、转换器、预览 worker 和可访问路径差异。")
    if CARD_PATHS["ssrf-internal-impact"] in cards:
        angles.append("SSRF 内部影响无结果时回到 parser discrepancy、redirect、DNS/IP 编码和单个 health/status 级内部目标。")
    if CARD_PATHS["controlled-rce-impact"] in cards:
        angles.append("执行类 primitive 无结果时先换低风险 probe、OAST 或 source/sink 证据，不直接升级 shell 或文件写入。")
    if CARD_PATHS["server-side-template-injection"] in cards:
        angles.append("SSTI 无结果时回到模板出现位置、邮件/预览/报表/错误页/富文本渲染链，区分客户端模板与服务端模板。")
    if CARD_PATHS["insecure-deserialization"] in cards:
        angles.append("反序列化无结果时回到 cookie/state/import/export/queue/RPC 与框架指纹，先确认格式和完整性保护再考虑 gadget。")
    if CARD_PATHS["browser-client-boundaries"] in cards:
        angles.append("浏览器边界无结果时，用 Playwright 对比真实 Origin/Referer/SameSite、iframe 可加载性、DOM source-to-sink、navigation sink、cookie 写入和 postMessage origin 处理。")
    if CARD_PATHS["xss-client-injection"] in cards:
        angles.append("XSS 无结果时，切换输出上下文和渲染链：attribute、JS string、template、Markdown/富文本、DOM sink、存储后触发页和 CSP/sanitizer 差异。")
    if CARD_PATHS["proxy-cache-boundaries"] in cards:
        angles.append("代理/cache 无结果时，回到 Host/XFH/Forwarded、scheme/port、cache key、Vary、static extension 和 CL/TE 传输差异。")
    if CARD_PATHS["websocket-realtime-api"] in cards:
        angles.append("WebSocket 无结果时，回到握手 Origin、频道订阅、消息 schema、对象 ID、重连 token 和同功能 REST sibling。")
    if CARD_PATHS["information-disclosure-source-config"] in cards:
        angles.append("信息泄露无结果时，转到 source map、错误页、备份命名、静态资源 manifest、robots/security.txt 和版本/组件线索。")
    if CARD_PATHS["web-llm-tool-chains"] in cards:
        angles.append("Web LLM 无结果时，回到工具清单、RAG 引用、系统提示泄露、间接 prompt 注入载体和权限绑定。")
    if CARD_PATHS["node-prototype-pollution"] in cards:
        angles.append("Node/prototype 无信号时，回到 package/source/sink grep，确认 deep merge/path set 与 gadget 后再做 live marker。")
    if CARD_PATHS["race-conditions"] in cards:
        angles.append("Race 不直接加压；先寻找可回滚测试资源、幂等 key、状态机边界和重复提交证据。")
    if not ranked.get("available"):
        angles.append("如果 recon 缺失，先只补最小可用 surface，再回到漏洞类别验证。")
    return _dedupe(angles)[:6]


def _unknowns(
    ranked: dict,
    goal_memory: dict,
    matrix: dict,
    findings: list[dict],
    local_intel: dict,
) -> list[str]:
    items: list[str] = []
    if not ranked.get("available"):
        items.append("No surface review pack available from local recon cache.")
    stats = ranked.get("stats") or {}
    if ranked.get("available") and not stats.get("review_pool") and not stats.get("p1") and not stats.get("p2"):
        items.append("Surface review pool has no candidates; recon may be thin or low-signal.")
    browser = ranked.get("browser") or {}
    local_browser = local_intel.get("browser") or {}
    if (
        not browser.get("xhr_count")
        and not browser.get("api_count")
        and not local_browser.get("xhr_endpoints")
        and not local_browser.get("api_endpoints")
    ):
        items.append("No browser-observed XHR/API context loaded.")
    summary = matrix.get("summary") or {}
    if not summary.get("total_cells"):
        items.append("Coverage matrix is empty or not rebuilt for this target.")
    if not findings:
        items.append("No structured findings.json entries found for this target.")
    if not (goal_memory.get("active") or goal_memory.get("target")):
        items.append("No target memory found; write back the first concrete lead/handoff after work.")
    return items or ["No major local unknowns surfaced by context_pack."]


def _token_overlap(a: str, b: str) -> bool:
    tokens = {
        token
        for token in re.findall(r"[a-z0-9_./:-]{4,}", a.lower())
        if token not in {"https", "http", "target", "tested", "without", "with"}
    }
    haystack = b.lower()
    return any(token in haystack for token in list(tokens)[:12])


def _contradictions(
    target: str,
    goal_memory: dict,
    ranked: dict,
    gaps: list[dict],
    local_intel: dict,
) -> list[str]:
    items: list[str] = []
    dead_ends = [
        _entry_text(item)
        for item in ((goal_memory.get("target") or {}).get("dead_ends") or [])[-5:]
        if _entry_text(item)
    ]
    new_evidence = "\n".join(
        [_surface_anchor(item) for item in (ranked.get("review_pool") or ranked.get("p1", []))[:5]]
        + [
            f"{lead.get('title', '')} {lead.get('next_action', '')}"
            for lead in _json_list(ranked.get("workflow_leads"))[:5]
        ]
        + [_gap_anchor(gap) for gap in gaps[:5]]
        + _local_intel_blob(local_intel)[:20]
    )
    for dead in dead_ends:
        if _token_overlap(dead, new_evidence):
            items.append(
                f"Remembered dead end may have new evidence now: {dead[:140]}"
            )
    workflow_leads = _json_list(ranked.get("workflow_leads"))
    if not gaps and workflow_leads:
        items.append(
            "Coverage gaps are empty, but workflow leads still exist; do not treat empty matrix gaps as full exhaustion."
        )
    if not ranked.get("available") and ((goal_memory.get("target") or {}).get("active_leads")):
        items.append(
            "Target memory has active leads, but local surface is unavailable; use memory as hypothesis, not proof."
        )
    return _dedupe(items) or ["None detected."]


def _write_back_commands(target: str) -> list[str]:
    return [
        f'python3 tools/target_memory.py lead "Evidence: ... Why it matters: ... Next action: ... Stop condition: ..." --target {target}',
        f'python3 tools/target_memory.py next "..." --target {target}',
        f'python3 tools/target_memory.py dead-end "..." --target {target}',
        f'python3 tools/target_memory.py handoff "..." --target {target}',
        "/retrospect <target>  # 可复用经验只建议晋升到知识库 / Skill / Rules，默认不自动改文件",
    ]


def _local_intel_paths(local_intel: dict) -> list[str]:
    paths: list[str] = []
    for section in ("browser", "js_intel", "source_intel"):
        paths.extend(((local_intel.get(section) or {}).get("paths") or [])[:3])
    return _dedupe(paths)


def _local_intel_source_summary(local_intel: dict) -> dict:
    browser = local_intel.get("browser") or {}
    js_intel = local_intel.get("js_intel") or {}
    source_intel = local_intel.get("source_intel") or {}
    return {
        "browser_xhr": len(browser.get("xhr_endpoints") or []),
        "browser_api": len(browser.get("api_endpoints") or []),
        "browser_params": len(browser.get("params") or []),
        "browser_forms": len(browser.get("forms") or []),
        "browser_pages_with_js": int(browser.get("page_count") or 0),
        "js_intel_endpoints": len(js_intel.get("endpoints") or []),
        "js_intel_leads": len(js_intel.get("leads") or []),
        "js_intel_graphql": len(js_intel.get("graphql_operations") or []),
        "source_intel_hypotheses": len(source_intel.get("hypotheses") or []),
        "source_intel_routes": len(source_intel.get("routes") or []),
        "source_intel_graphql": len(source_intel.get("graphql_operations") or []),
    }


def _focus_endpoints_for_ledger(ranked: dict, gaps: list[dict], local_intel: dict) -> list[str]:
    endpoints: list[str] = []
    review_items = ranked.get("review_pool") or (ranked.get("p1", [])[:4] + ranked.get("p2", [])[:2])
    for item in review_items[:6]:
        endpoints.append(str(item.get("url") or item.get("path") or ""))
    for gap in gaps[:4]:
        endpoints.append(str(gap.get("endpoint") or ""))
    browser = local_intel.get("browser") or {}
    endpoints.extend((browser.get("xhr_endpoints") or [])[:4])
    js_intel = local_intel.get("js_intel") or {}
    for endpoint in (js_intel.get("endpoints") or [])[:3]:
        endpoints.append(str(endpoint.get("path") or ""))
    source_intel = local_intel.get("source_intel") or {}
    for hypothesis in (source_intel.get("hypotheses") or [])[:3]:
        endpoints.append(str(hypothesis.get("candidate") or ""))
    return _dedupe(endpoints)[:8]


def _ledger_vuln_classes(cards: list[str], blob: str) -> list[str]:
    classes: list[str] = []
    if CARD_PATHS["api-idor"] in cards or re.search(r"\b(idor|account_id|tenant_id|org_id|user_id|order_id)\b", blob, re.I):
        classes.append("IDOR")
    if CARD_PATHS["auth-access"] in cards or re.search(r"\b(authz|rbac|role|admin|permission)\b", blob, re.I):
        classes.append("Authz")
    if CARD_PATHS["auth-hidden-switches"] in cards or re.search(r"\b(login[-_ ]?bypass|account[-_ ]?takeover|ato|hidden[-_ ]?login|auth[-_ ]?selector|auth[-_ ]?switch)\b", blob, re.I):
        classes.append("Authz")
    if CARD_PATHS["auth-sso-token-edge-cases"] in cards or re.search(r"\b(jwt|jwe|jwks?|jku|kid|oauth|oidc|saml|sso|pkce|token[-_ ]?binding|account[-_ ]?linking)\b", blob, re.I):
        classes.append("Authz")
    if CARD_PATHS["auth-credential-recovery-flows"] in cards or re.search(r"\b(password[-_ ]?reset|forgot[-_ ]?password|account[-_ ]?recovery|username[-_ ]?enum(?:eration)?|credential[-_ ]?attack|brute[-_ ]?force|mfa|2fa|otp)\b", blob, re.I):
        classes.append("Authz")
    if CARD_PATHS["api-testing-workflow"] in cards or re.search(r"\b(api[-_ ]?testing|api[-_ ]?test|rest[-_ ]?api|soap[-_ ]?api|mobile[-_ ]?api)\b", blob, re.I):
        classes.extend(["IDOR", "Authz", "SQLi"])
    if CARD_PATHS["business-logic-state-machines"] in cards or re.search(r"\b(business[-_ ]?logic|logic[-_ ]?flaws?|state[-_ ]?machine|workflow[-_ ]?validation|client[-_ ]?side[-_ ]?controls|coupon|cart|checkout)\b", blob, re.I):
        classes.extend(["Authz", "Race"])
    if CARD_PATHS["missing-parameter-discovery"] in cards or re.search(r"\b(missing[-_ ]?param(?:eter)?|parameter[-_ ]?null|parameter is null|required[-_ ]?param(?:eter)?|schema[-_ ]?error|validator[-_ ]?error|binder[-_ ]?error|param[-_ ]?discovery)\b", blob, re.I):
        classes.extend(["IDOR", "Authz"])
    if CARD_PATHS["path-pattern-management-exposure"] in cards or re.search(r"\b(path[-_ ]?pattern|admin[-_ ]?panel|management[-_ ]?console|monitoring[-_ ]?console|metrics|health|config[-_ ]?(?:exposure|page|endpoint|dump|leak)|configuration|stats|log|trace|datasource|accesskey|secretkey|secret[-_ ]?leak)\b", blob, re.I):
        classes.extend(["Authz", "Path"])
    if CARD_PATHS["graphql"] in cards or re.search(r"\b(graphql|mutation|subscription)\b", blob, re.I):
        classes.append("GraphQL")
    if CARD_PATHS["sqli-hidden-surfaces"] in cards or re.search(r"\b(sqli|sql[-_ ]?injection|hidden[-_ ]?param)\b", blob, re.I):
        classes.append("SQLi")
    if CARD_PATHS["nosql-query-injection"] in cards or re.search(r"\b(nosql|no[-_ ]?sql[-_ ]?injection|mongo(?:db)?|operator[-_ ]?injection)\b", blob, re.I):
        classes.append("SQLi")
    if CARD_PATHS["xxe-xml-parser"] in cards or re.search(r"\b(xxe|xml[-_ ]?parser|xinclude|external[-_ ]?entit(?:y|ies))\b", blob, re.I):
        classes.append("XXE")
    if CARD_PATHS["path-traversal-file-read"] in cards or re.search(r"\b(path[-_ ]?traversal|directory[-_ ]?traversal|lfi|file[-_ ]?read)\b", blob, re.I):
        classes.append("Path")
    if CARD_PATHS["ssrf-url-fetch"] in cards or CARD_PATHS["ssrf-internal-impact"] in cards or re.search(r"\b(ssrf|url[-_ ]?fetch|metadata)\b", blob, re.I):
        classes.append("SSRF")
    if CARD_PATHS["upload-parser"] in cards or CARD_PATHS["upload-to-execution"] in cards or re.search(r"\b(upload|file[-_ ]?parser|web[-_ ]?shell)\b", blob, re.I):
        classes.append("Upload")
    if CARD_PATHS["controlled-rce-impact"] in cards or re.search(r"\b(rce|command[-_ ]?injection|ssti|deserialization)\b", blob, re.I):
        classes.append("RCE")
    if CARD_PATHS["server-side-template-injection"] in cards:
        classes.append("RCE")
    if CARD_PATHS["insecure-deserialization"] in cards:
        classes.append("RCE")
    if CARD_PATHS["browser-client-boundaries"] in cards or re.search(r"\b(cors|csrf|xsrf|clickjacking|dom[-_ ]?xss|postmessage)\b", blob, re.I):
        classes.extend(["XSS", "CSRF", "Authz"])
    if CARD_PATHS["xss-client-injection"] in cards or re.search(r"\b(reflected[-_ ]?xss|stored[-_ ]?xss|client[-_ ]?xss|cross[-_ ]?site[-_ ]?scripting)\b|(?<!dom[-_])\bxss\b", blob, re.I):
        classes.append("XSS")
    if CARD_PATHS["proxy-cache-boundaries"] in cards or re.search(r"\b(host[-_ ]?header|request[-_ ]?smuggling|cache[-_ ]?(?:poisoning|deception))\b", blob, re.I):
        classes.extend(["Authz", "Path"])
    if CARD_PATHS["websocket-realtime-api"] in cards or re.search(r"\b(websocket|cswsh|subscription)\b", blob, re.I):
        classes.append("Authz")
    if CARD_PATHS["information-disclosure-source-config"] in cards or re.search(r"\b(information[-_ ]?disclosure|debug|source[-_ ]?map|backup|stack[-_ ]?trace)\b", blob, re.I):
        classes.extend(["Path", "Authz"])
    if CARD_PATHS["web-llm-tool-chains"] in cards or re.search(r"\b(web[-_ ]?llm|prompt[-_ ]?injection|rag|tool[-_ ]?call)\b", blob, re.I):
        classes.append("Authz")
    if CARD_PATHS["node-prototype-pollution"] in cards or re.search(r"\b(prototype[-_ ]?pollution|proto[-_ ]?pollution|__proto__|constructor\.prototype|vm2?)\b", blob, re.I):
        classes.append("RCE")
    if re.search(r"\b(csrf|xsrf|same[-_ ]?site|origin|referer)\b", blob, re.I):
        classes.append("CSRF")
    return _dedupe(classes)[:3] or ["IDOR", "Authz"]


def _ledger_relative_path(summary: dict, repo_root: Path) -> str:
    path = str(summary.get("path") or "").strip()
    if not path or not summary.get("path_exists"):
        return ""
    try:
        return str(Path(path).relative_to(repo_root))
    except ValueError:
        return path


def _ledger_anchors(summary: dict) -> list[str]:
    anchors: list[str] = []
    for entry in (summary.get("recent_entries") or [])[-3:]:
        anchors.append(
            "Ledger: {method} {endpoint} x {vuln} {actor}/{scope}/{variant} -> {result}".format(
                method=entry.get("method", ""),
                endpoint=entry.get("endpoint", ""),
                vuln=entry.get("vuln_class", ""),
                actor=entry.get("actor", ""),
                scope=entry.get("object_scope", ""),
                variant=entry.get("variant", ""),
                result=entry.get("result", ""),
            )
        )
    matrix = summary.get("actor_matrix") or {}
    for gap in (matrix.get("gaps") or [])[:3]:
        anchors.append(
            "Actor gap: {endpoint} x {vuln} {actor}/{scope}/{variant} expected={expected} status={status}".format(
                endpoint=gap.get("endpoint", ""),
                vuln=gap.get("vuln_class", ""),
                actor=gap.get("actor", ""),
                scope=gap.get("object_scope", ""),
                variant=gap.get("variant", ""),
                expected=gap.get("expected", ""),
                status=gap.get("status", ""),
            )
        )
    return _dedupe(anchors)


def _ledger_unknowns(summary: dict) -> list[str]:
    items: list[str] = []
    if not summary.get("entry_count"):
        items.append("No evidence ledger entries found; exact actor/object/replay coverage is not recorded yet.")
    matrix = summary.get("actor_matrix") or {}
    if matrix.get("gap_count"):
        items.append(
            f"Actor matrix has {matrix.get('gap_count')} missing/pending/blocked role-object checks."
        )
    if summary.get("redline_unchecked_count"):
        items.append(
            f"Evidence ledger has {summary.get('redline_unchecked_count')} state-changing record(s) without red-line check."
        )
    return items


def _ledger_source_summary(summary: dict) -> dict:
    matrix = summary.get("actor_matrix") or {}
    result_counts = summary.get("result_counts") or {}
    return {
        "evidence_ledger_entries": int(summary.get("entry_count") or 0),
        "actor_matrix_gaps": int(matrix.get("gap_count") or 0),
        "actor_matrix_covered": int(matrix.get("covered_count") or 0),
        "evidence_candidates": int(result_counts.get("candidate", 0) or 0),
        "evidence_redline_unchecked": int(summary.get("redline_unchecked_count") or 0),
    }


def _reference_hints(cards: list[str], blob: str, focus: str, skill: str) -> list[dict]:
    """按当前证据给 `/autopilot` 提供按需 reference 提示，不默认加载大字典。"""

    evidence = f"{focus}\n{blob}"
    hints: list[dict] = []

    def add(key: str, when: str) -> None:
        path = REFERENCE_PATHS[key]
        if any(item["path"] == path for item in hints):
            return
        hints.append({"path": path, "when": when})

    bypass_signal = bool(
        re.search(
            r"\b(?:bypass|blacklist|allowlist|whitelist|filter|parser|parse|normalization|"
            r"canonicali[sz]ation|waf|magic[-_ ]?bytes?|polyglot|content[-_ ]?type|"
            r"double[-_ ]?encod(?:e|ing)|redirect[-_ ]?chain)\b",
            evidence,
            re.I,
        )
        and (
            CARD_PATHS["ssrf-url-fetch"] in cards
            or CARD_PATHS["ssrf-internal-impact"] in cards
            or CARD_PATHS["upload-parser"] in cards
            or CARD_PATHS["upload-to-execution"] in cards
            or CARD_PATHS["sqli-hidden-surfaces"] in cards
            or re.search(r"\b(open[-_ ]?redirect|sql(?:i|[-_ ]?injection)|ssrf|upload|file[-_ ]?upload)\b", evidence, re.I)
        )
    )
    if bypass_signal:
        add(
            "bypass-patterns",
            "Parser or validation bypass is evidenced for SSRF/open-redirect/upload/SQLi; load only for concrete bypass shape selection.",
        )

    payload_signal = bool(
        CARD_PATHS["server-side-template-injection"] in cards
        or CARD_PATHS["xxe-xml-parser"] in cards
        or CARD_PATHS["proxy-cache-boundaries"] in cards
        or COMMAND_INJECTION_RE.search(evidence)
        or re.search(
            r"\b(ssti|template[-_ ]?injection|command[-_ ]?injection|cmdi|xxe|"
            r"request[-_ ]?smuggling|http[-_ ]?smuggling|cl\.te|te\.cl|h2\.(?:cl|te))\b",
            evidence,
            re.I,
        )
    )
    if payload_signal:
        add(
            "payload-families",
            "SSTI/command/XXE/smuggling primitive needs concrete probe family detail after baseline evidence.",
        )

    sink_grep_signal = bool(
        re.search(
            r"\b(source[-_ ]?review|source[-_ ]?audit|code[-_ ]?review|grep|sink|"
            r"source[-_ ]?to[-_ ]?sink|innerhtml|document\.write|postmessage|"
            r"dom[-_ ]?xss|client[-_ ]?xss)\b",
            evidence,
            re.I,
        )
        and (
            CARD_PATHS["xss-client-injection"] in cards
            or CARD_PATHS["browser-client-boundaries"] in cards
            or re.search(r"\b(dom|xss|javascript|typescript|python|php|ruby|rust|golang|go)\b", evidence, re.I)
        )
    )
    if sink_grep_signal:
        add(
            "sink-and-grep-patterns",
            "Source or bundle review needs concrete DOM sinks, client sources, or language grep patterns.",
        )

    recon_tool_signal = bool(
        skill == "web2-recon"
        or re.search(
            r"\b(recon|ffuf|semgrep|endpoint[-_ ]?discovery|api[-_ ]?endpoint[-_ ]?discovery|"
            r"scope[-_ ]?retrieval|subdomain|httpx|nuclei|katana|waybackurls|gau)\b",
            evidence,
            re.I,
        )
    )
    if recon_tool_signal:
        add(
            "recon-tool-usage",
            "Recon, ffuf, Semgrep, endpoint discovery, or scope command detail is needed for an executable action.",
        )

    return hints


def build_context_pack(
    repo_root: Path | str = BASE_DIR,
    *,
    target: str,
    focus: str = "",
    memory_dir: str | None = None,
) -> dict:
    repo = Path(repo_root)
    resolved_target = canonical_target_value(target)
    target_key = target_storage_key(resolved_target)
    goal_memory = _load_goal_memory(repo, resolved_target)
    ranked = _surface_state(repo, resolved_target, memory_dir)
    gaps, matrix = _safe_find_gaps(resolved_target, target_key, repo)
    findings = _load_findings(repo, target_key)
    local_intel = _load_local_intel(repo, target_key)
    blob = _text_blob(focus, goal_memory, ranked, gaps, findings, local_intel)
    skill, why_skill = _select_skill(focus, blob, ranked, findings, goal_memory)
    cards, deferred_cards = _select_cards_and_deferred(blob, skill, ranked, gaps, goal_memory, focus, repo)
    checks = _required_checks(skill, blob)
    evidence_summary = build_evidence_summary(
        repo,
        target=resolved_target,
        focus_endpoints=_focus_endpoints_for_ledger(ranked, gaps, local_intel),
        vuln_classes=_ledger_vuln_classes(cards, blob),
    )
    ledger_path = _ledger_relative_path(evidence_summary, repo)

    must_read = _dedupe([
        goal_memory["active_path"],
        goal_memory["target_path"],
        "skills/runtime-protocol.md",
        SKILL_PATHS[skill],
        "knowledge/index.md",
        ledger_path,
    ] + _local_intel_paths(local_intel))

    pack = {
        "target": resolved_target,
        "target_storage_key": target_key,
        "phase": _phase(goal_memory),
        "active_goal": _active_goal(goal_memory),
        "current_hypothesis": _hypothesis(goal_memory),
        "focus": focus,
        "selected_skill": SKILL_PATHS[skill],
        "selected_skill_id": skill,
        "why_this_skill": why_skill,
        "must_read": must_read,
        "knowledge_cards": cards,
        "knowledge_card_capabilities": _card_capabilities(cards, repo),
        "deferred_knowledge_cards": deferred_cards,
        "deferred_knowledge_card_capabilities": _card_capabilities(deferred_cards, repo),
        "reference_hints": _reference_hints(cards, blob, focus, skill),
        "required_checks": checks,
        "evidence_anchors": _build_evidence_anchors(ranked, goal_memory, gaps, findings, local_intel)
        + _ledger_anchors(evidence_summary),
        "hypothesis_seeds": _hypothesis_seeds(cards, blob, local_intel),
        "alternative_angles": _alternative_angles(cards, ranked, local_intel),
        "unknowns": _unknowns(ranked, goal_memory, matrix, findings, local_intel)
        + _ledger_unknowns(evidence_summary),
        "contradictions": _contradictions(resolved_target, goal_memory, ranked, gaps, local_intel),
        "actor_matrix_gaps": (evidence_summary.get("actor_matrix") or {}).get("gaps", [])[:8],
        "do_not_load": [
            "full skills/* tree",
            "full knowledge/cards/* tree",
            "full skills/security-arsenal/REFERENCES.md unless playbook-router requires it",
            "raw large recon logs, full JSONL, full HTML responses, or unrelated historical sessions",
            "raw browser capture requests/console/storage unless validating one exact replay path",
            "all findings evidence bodies; start from findings/<target>/findings.json index only",
        ],
        "write_back": _write_back_commands(resolved_target) + (evidence_summary.get("record_commands") or [])[:3],
        "ai_override": (
            "Claude may choose another skill, knowledge card, or path if the evidence supports it; "
            "state the reason, keep red-lines/coverage checks loaded, and write the decision back "
            "to target memory or /retrospect."
        ),
        "source_summary": {
            "surface_available": bool(ranked.get("available")),
            "p1": (ranked.get("stats") or {}).get("p1", 0),
            "p2": (ranked.get("stats") or {}).get("p2", 0),
            "workflow_leads": len(_json_list(ranked.get("workflow_leads"))),
            "coverage_gaps": len(gaps),
            "findings": len(findings),
            **_local_intel_source_summary(local_intel),
            **_ledger_source_summary(evidence_summary),
        },
    }
    return pack


def _format_list(lines: list[str]) -> list[str]:
    if not lines:
        return ["  - None"]
    return [f"  - {line}" for line in lines]


def format_context_pack(pack: dict) -> str:
    lines = [
        "CONTEXT PACK",
        f"- Target: {pack['target']}",
        f"- Phase: {pack['phase']}",
        f"- Active goal: {pack.get('active_goal') or '-'}",
        f"- Current hypothesis: {pack.get('current_hypothesis') or '-'}",
        f"- Selected skill: {pack['selected_skill']}",
        f"- Why this skill: {pack['why_this_skill']}",
        "- Must read:",
        *_format_list(pack["must_read"]),
        "- Knowledge cards:",
        *_format_list(pack["knowledge_cards"]),
        "- Knowledge card capabilities:",
        *_format_list([
            "{file} — layer={layer}, load={load}, purpose={purpose}".format(
                file=item.get("file", ""),
                layer=item.get("layer", ""),
                load=item.get("load", ""),
                purpose=item.get("purpose", ""),
            )
            for item in pack.get("knowledge_card_capabilities", [])
        ]),
        "- Deferred knowledge cards:",
        *_format_list(pack.get("deferred_knowledge_cards", [])),
        "- Reference hints:",
        *_format_list([
            "{path} — {when}".format(
                path=item.get("path", ""),
                when=item.get("when", ""),
            )
            for item in pack.get("reference_hints", [])
        ]),
        "- Required checks:",
        *_format_list(pack["required_checks"]),
        "- Evidence anchors:",
        *_format_list(pack["evidence_anchors"]),
        "- Hypothesis seeds:",
        *_format_list(pack["hypothesis_seeds"]),
        "- Alternative angles:",
        *_format_list(pack["alternative_angles"]),
        "- Unknowns:",
        *_format_list(pack["unknowns"]),
        "- Actor matrix gaps:",
        *_format_list([
            "{endpoint} x {vuln}: {actor}/{scope}/{variant} expected={expected} status={status}".format(
                endpoint=item.get("endpoint", ""),
                vuln=item.get("vuln_class", ""),
                actor=item.get("actor", ""),
                scope=item.get("object_scope", ""),
                variant=item.get("variant", ""),
                expected=item.get("expected", ""),
                status=item.get("status", ""),
            )
            for item in pack.get("actor_matrix_gaps", [])
        ]),
        "- Contradictions:",
        *_format_list(pack["contradictions"]),
        "- Do not load:",
        *_format_list(pack["do_not_load"]),
        "- Write-back:",
        *_format_list(pack["write_back"]),
        f"- AI override: {pack['ai_override']}",
    ]
    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Build a read-only Claude CLI context pack for one target."
    )
    parser.add_argument("args", nargs="*", help="optional target and/or focus words")
    parser.add_argument("--target", default="", help="target; defaults to active target memory")
    parser.add_argument("--focus", default="", help="focus such as api-idor, graphql, upload, race")
    parser.add_argument("--repo-root", default=str(BASE_DIR))
    parser.add_argument("--memory-dir", default="")
    parser.add_argument("--json", action="store_true", help="output JSON")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    repo_root = Path(args.repo_root)
    target, focus = _resolve_cli_args(args, repo_root)
    pack = build_context_pack(
        repo_root,
        target=target,
        focus=focus,
        memory_dir=args.memory_dir or None,
    )
    if args.json:
        print(json.dumps(pack, ensure_ascii=False, indent=2))
    else:
        print(format_context_pack(pack))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
