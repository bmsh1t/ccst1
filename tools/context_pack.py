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
    from tools.closure_resolver import ClosureResolver
    from tools.coverage_matrix import high_value_gaps_from_matrix, load_matrix
    from tools.evidence_ledger import ACTOR_MATRIX_VULN_CLASSES, build_summary as build_evidence_summary
    from tools.knowledge_registry import (
        load_card_metadata_by_file,
        load_card_paths,
    )
    from tools.structured_findings import (
        format_validation_runner_candidate_lines,
        load_validation_runner_candidate_pool,
    )
    from tools.surface import load_surface_context, rank_surface
    from tools.surface_index import surface_safe_preview
    from tools.surface_projection import load_surface_projection
    from tools.target_paths import compact_url, canonical_target_value, target_storage_key
    from tools.target_memory import load_active_file, load_goal_memory
except ImportError:  # pragma: no cover - direct tools/ execution
    from memory.target_profile import default_memory_dir
    from closure_resolver import ClosureResolver  # type: ignore
    from coverage_matrix import high_value_gaps_from_matrix, load_matrix  # type: ignore
    from evidence_ledger import ACTOR_MATRIX_VULN_CLASSES, build_summary as build_evidence_summary  # type: ignore
    from knowledge_registry import (  # type: ignore
        load_card_metadata_by_file,
        load_card_paths,
    )
    from structured_findings import (  # type: ignore
        format_validation_runner_candidate_lines,
        load_validation_runner_candidate_pool,
    )
    from surface import load_surface_context, rank_surface  # type: ignore
    from surface_index import surface_safe_preview  # type: ignore
    from surface_projection import load_surface_projection  # type: ignore
    from target_paths import compact_url, canonical_target_value, target_storage_key  # type: ignore
    from target_memory import load_active_file, load_goal_memory  # type: ignore


# S1 native skill loading (ai-capability-roadmap batch 3): every skill loads
# on demand via the native Claude Code Skill tool (frontmatter description is
# the routing surface). The pack no longer recommends a single skill; it
# publishes the on-disk skill catalog (id + path + description) and the AI
# selects and loads skills itself. `selected_skill` / `skill_route` /
# `selected_skill_id` / `why_this_skill` remain as empty compatibility shells
# for old checkpoint/witness readers.

KNOWN_SKILL_OR_FOCUS = {
    # Primary skill ids (kept from the retired catalog whitelist era so
    # `web2-recon`-style focus words are not mistaken for a target host).
    "bb-methodology",
    "bug-bounty",
    "credential-attack",
    "triage-validation",
    "web2-recon",
    "web2-vuln-classes",
    "cicd-security",
    "meme-coin-audit",
    "mobile-pentest",
    "web3-audit",
    "security-arsenal",
    "report-writing",
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
    "cdn",
    "cdn-differential",
    "catch-all",
    "wildcard-dns",
    "origin-discovery",
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
    "grpc",
    "grpc-web",
    "protobuf",
    "js-reverse",
    "client-signature",
    "custom-binary-protocol",
    "protocol-reverse",
    "odata",
    "ldap-injection",
    "xpath-injection",
    "nextjs-image",
    "nextjs-data",
    "spring-actuator",
    "legacy-auth-surface",
    "shadow-throttle",
    "cognito",
    "identity-pool",
    "kubernetes",
    "k8s",
    "kubelet",
    "rbac",
    "dependency-confusion",
    "package-registry",
    "package-history",
    "published-artifact",
    "container-image",
    "historical-release",
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

WEB_LLM_AGENT_SIGNAL_PATTERN = (
    r"web[-_ ]?llm|llm|prompt[-_ ]?injection|indirect[-_ ]?prompt|rag|"
    r"agent[-_ ]?tool|tool[-_ ]?call|model[-_ ]?context|agent[-_ ]?attack[-_ ]?chain|"
    r"tool[-_ ]?descriptions?[-_ ]?(?:change(?:d)?|drift)|shadow[-_ ]?tool|"
    r"cross[-_ ]?session[-_ ]?memory|"
    r"multi[-_ ]?agent[-_ ]?impersonation"
)
WEB_LLM_AGENT_SIGNAL_RE = re.compile(rf"\b(?:{WEB_LLM_AGENT_SIGNAL_PATTERN})\b", re.I)
WEB_LLM_AGENT_AMBIGUOUS_RE = re.compile(r"\b(?:rug[-_ ]?pull|schema[-_ ]?drift)\b", re.I)
WEB_LLM_AGENT_CONTEXT_RE = re.compile(
    r"\b(?:agent|mcp|tool|function[-_ ]?call|model|llm)\b",
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

API_ANCESTOR_PREFIX_RE = re.compile(
    r"\b(?:observed|known|discovered|captured|browser|xhr|js|openapi|recon)[-_ ]?"
    r"(?:api[-_ ]?(?:path|route|endpoint)|endpoint[-_ ]?path)\b|"
    r"\b(?:api[-_ ]?(?:path|route|endpoint)|endpoint[-_ ]?path)[-_ ]?"
    r"(?:ancestor|parent)[-_ ]?prefix\b",
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

JSON_VIEW_DIFFERENTIAL_RE = re.compile(
    r"(?:\b(view[-_ ]?differential|validation view|consumption view|verified view|executed view|"
    r"canonicalization gap|validate[-_ ]?(?:proxy|store)|json[-_ ]?parser[-_ ]?differential|"
    r"(?:unpaired|lone)[-_ ]?(?:utf[-_ ]?16[-_ ]?)?surrogate|unicode[-_ ]?truncation|"
    r"parse[-_ ]+seriali[sz]e(?:[-_ ]+round[-_ ]?trip)?[-_ ]+mismatch|"
    r"duplicate[-_ ]?(?:json[-_ ]?)?key.{0,120}(?:first|last|validation|consumption|parser)|"
    r"(?:first[-_ ]?key.{0,120}last[-_ ]?key|last[-_ ]?key.{0,120}first[-_ ]?key))\b|"
    r"\\ud[89ab][0-9a-f]{2}(?!\\ud[c-f][0-9a-f]{2})|"
    r"(?<!\\ud[89ab][0-9a-f]{2})\\ud[c-f][0-9a-f]{2}|"
    r"(?:校验|验证|消费|执行)视图|规范化(?:差异|碰撞)|"
    r"(?:未配对(?:UTF[-_ ]?16)?|孤立)代理(?:对|字符)|(?:Unicode|字符)[-_ ]?截断|"
    r"解析(?:后)?(?:与|和)?(?:重新)?序列化(?:结果)?不一致|"
    r"重复(?:的)?(?:JSON)?键.{0,120}(?:首键|末键|校验|验证|消费|解析)|"
    r"(?:首键.{0,120}末键|末键.{0,120}首键))",
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

ODATA_BOUNDARY_RE = re.compile(
    r"\b(?:odata|odata[-_ ]?version|dataserviceversion|odata[-_ ]?(?:filter|select|expand|batch|metadata))\b"
    r"|(?<!\w)\$(?:metadata|filter|select|orderby|expand|batch|count|top|skip)\b",
    re.I,
)

LDAP_XPATH_BOUNDARY_RE = re.compile(
    r"\b(?:ldap[-_ ]?(?:injection|filter|dn|search|query|error)|xpath|xpath[-_ ]?injection|"
    r"directory[-_ ]?query|rfc[-_ ]?4515|javax\.naming|"
    r"system\.directoryservices|invalidsearchfilter)\b",
    re.I,
)

NEXTJS_IMAGE_RE = re.compile(
    r"/_next/image\b|\bnext(?:\.js|js)?[-_ ]?image[-_ ]?optimizer\b",
    re.I,
)

NEXTJS_DATA_RE = re.compile(
    r"/_next/data\b|__next_data__|\bnext(?:\.js|js)?[-_ ]?prerender(?:ed)?[-_ ]?json\b",
    re.I,
)

ACTUATOR_MANAGEMENT_RE = re.compile(
    r"(?:^|[/\s])actuator(?:[/\s]|$)|\b(?:whitelabel|"
    r"x[-_ ]?application[-_ ]?context|jolokia|heapdump)\b",
    re.I,
)

LEGACY_AUTH_SURFACE_RE = re.compile(
    r"\b(?:legacy|alternate|native|sibling|mobile|old)[-_ ]?(?:auth|authentication|login)\b"
    r"|\b(?:xml[-_ ]?rpc|xmlrpc|authentication\.asmx)\b",
    re.I,
)

RATE_LIMIT_REGIME_RE = re.compile(
    r"\b(?:rate[-_ ]?limit[-_ ]?regime|hard[-_ ]?lockout|explicit[-_ ]?throttle|"
    r"shadow[-_ ]?throttle|silent[-_ ]?throttle|captcha[-_ ]?(?:injection|switch)|"
    r"known[-_ ]?good[-_ ]?control)\b",
    re.I,
)

PUBLIC_PACKAGE_ARTIFACT_RE = re.compile(
    r"\b(?:package[-_ ]?registry|package[-_ ]?history|published[-_ ]?(?:package|artifact)|"
    r"registry[-_ ]?artifact|historical[-_ ]?release|container[-_ ]?image[-_ ]?history|"
    r"historical[-_ ]?container[-_ ]?image)\b"
    r"|\b(?:npm|pypi|rubygems|nuget|maven|packagist|crates\.io|docker[-_ ]?hub|ghcr)\b"
    r"[\s\S]{0,120}\b(?:package|registry|release|version|tarball|wheel|image|layer)\b"
    r"|\b(?:package|registry|release|version|tarball|wheel|image|layer)\b"
    r"[\s\S]{0,120}\b(?:npm|pypi|rubygems|nuget|maven|packagist|crates\.io|docker[-_ ]?hub|ghcr)\b",
    re.I,
)

JS_RUNTIME_SIGNATURE_RE = re.compile(
    r"\b(?:js|javascript)[-_ ]?reverse(?:[-_ ]?engineering)?\b|"
    r"\b(?:client|frontend)[-_ ]?signature\b|"
    r"\brequest[-_ ]?initiator\b|\bfirst[-_ ]?divergence\b|"
    r"\blocal[-_ ]?js[-_ ]?rebuild\b|"
    r"\b(?:js|javascript|browser|client|frontend)\b[\s\S]{0,120}"
    r"\b(?:encrypted[-_ ]?(?:param(?:eter)?|payload)|runtime[-_ ]?(?:hook|sampling|capture)|"
    r"environment[-_ ]?patch|signature[-_ ]?(?:reconstruction|rebuild))\b|"
    r"\b(?:encrypted[-_ ]?(?:param(?:eter)?|payload)|runtime[-_ ]?(?:hook|sampling|capture)|"
    r"environment[-_ ]?patch|signature[-_ ]?(?:reconstruction|rebuild))\b[\s\S]{0,120}"
    r"\b(?:js|javascript|browser|client|frontend)\b",
    re.I,
)

CUSTOM_PROTOCOL_STATE_RE = re.compile(
    r"\b(?:custom[-_ ]?binary[-_ ]?protocol|protocol[-_ ]?reverse|binary[-_ ]?frames?|"
    r"frame[-_ ]?layout|message[-_ ]?dictionary)\b|"
    r"\b(?:pcap(?:ng)?|tshark|wireshark|messagepack|flatbuffers?|mqtt|private[-_ ]?rpc)\b"
    r"[\s\S]{0,120}\b(?:framing|opcode|tlv|length[-_ ]?(?:prefix|field)|endian(?:ness)?|"
    r"checksum|crc|state[-_ ]?(?:recovery|transition))\b|"
    r"\b(?:framing|opcode|tlv|length[-_ ]?(?:prefix|field)|endian(?:ness)?|checksum|crc|"
    r"state[-_ ]?(?:recovery|transition))\b[\s\S]{0,120}"
    r"\b(?:pcap(?:ng)?|tshark|wireshark|messagepack|flatbuffers?|mqtt|private[-_ ]?rpc)\b",
    re.I,
)

TELERIK_DIALOG_SIGNAL_RE = re.compile(
    r"\b(?:telerik|asyncupload|serializedparameters|dialogparameters)\b",
    re.I,
)

PRESIGNED_URL_CAPABILITY_RE = re.compile(
    r"\b(?:pre[-_ ]?signed|presigned|signed)[-_ ]?(?:url|download|upload)\b|"
    r"\b(?:s3|blob|object[-_ ]?storage)\b[\s\S]{0,120}"
    r"\b(?:presign(?:ed)?|signed[-_ ]?(?:url|download|upload))\b",
    re.I,
)

OBSERVABILITY_TRACE_RE = re.compile(
    r"\b(?:zipkin|jaeger|open[-_ ]?telemetry|opentelemetry|otel|"
    r"distributed[-_ ]?trac(?:e|ing)|trace[-_ ]?id|span[-_ ]?id)\b",
    re.I,
)

EXTERNAL_AUTHZ_POLICY_RE = re.compile(
    r"\b(?:open[-_ ]?policy[-_ ]?agent|opa|cedar)\b[\s\S]{0,120}"
    r"\b(?:authz|authori[sz]ation|policy|decision|enforcement|pdp|pep)\b|"
    r"\b(?:authz|authori[sz]ation|policy|decision|enforcement|pdp|pep)\b"
    r"[\s\S]{0,120}\b(?:open[-_ ]?policy[-_ ]?agent|opa|cedar)\b",
    re.I,
)

# Tech-stack inventory word signal kept as a VISIBLE annotation source for
# card recall; it never auto-selects a card anymore.
_WORDPRESS_SIGNAL_RE = re.compile(
    r"\b(?:wordpress|wp[-_ ]?json|wp[-_ ]?content|wp[-_ ]?admin|admin[-_ ]?ajax|xmlrpc(?:\.php)?|"
    r"wordpress[-_ ]?(?:plugin|theme))\b",
    re.I,
)

API_AUTHZ_REFINEMENT_RES = (
    PRESIGNED_URL_CAPABILITY_RE,
    OBSERVABILITY_TRACE_RE,
    EXTERNAL_AUTHZ_POLICY_RE,
)

CARD_PATHS = load_card_paths(BASE_DIR)


def _load_capability_registry(repo_root: Path | str = BASE_DIR) -> dict[str, dict[str, str]]:
    """读取 card file -> metadata；临时 target repo 可回落到安装仓库。"""
    raw = load_card_metadata_by_file(repo_root, fallback_root=BASE_DIR)
    return {
        path: {key: str(value) for key, value in item.items() if value is not None}
        for path, item in raw.items()
    }


def _card_capability(
    path: str,
    repo_root: Path | str = BASE_DIR,
    *,
    registry: dict[str, dict[str, str]] | None = None,
) -> dict[str, str]:
    registry = registry if registry is not None else _load_capability_registry(repo_root)
    item = registry.get(path, {})
    return {
        "file": path,
        "id": item.get("id") or Path(path).stem,
        "layer": item.get("layer") or "unregistered",
        "load": item.get("load") or "unknown",
        "purpose": item.get("purpose") or "unknown",
    }


def _card_catalog(
    repo_root: Path | str = BASE_DIR,
    *,
    registry: dict[str, dict[str, str]] | None = None,
) -> list[dict[str, str]]:
    """Publish the FULL card catalog (id + layer + load + purpose).

    Selection authority stays with the AI: the pack presents every card and
    its purpose line; word-list matches appear as signal annotations in
    knowledge_card_recall; nothing is hidden by not matching a token table.
    """
    registry = registry if registry is not None else _load_capability_registry(repo_root)
    seen: set[str] = set()
    catalog: list[dict[str, str]] = []
    for path in sorted(registry):
        if path in seen:
            continue
        seen.add(path)
        capability = _card_capability(path, repo_root, registry=registry)
        catalog.append(capability)
    return catalog


def _card_capabilities(
    paths: list[str],
    repo_root: Path | str = BASE_DIR,
    *,
    registry: dict[str, dict[str, str]] | None = None,
) -> list[dict[str, str]]:
    registry = registry if registry is not None else _load_capability_registry(repo_root)
    return [_card_capability(path, repo_root, registry=registry) for path in paths]


def _budget_knowledge_cards(
    paths: list[str],
    repo_root: Path | str = BASE_DIR,
    *,
    max_cards: int = 2,
    max_case_router: int = 1,
    registry: dict[str, dict[str, str]] | None = None,
) -> tuple[list[str], list[str]]:
    """按 registry 做保守预算。

    只限制 case-router 涌入：core/core、core/reference 等既有组合不变。
    被挤出的卡进入 deferred，供 AI 明确需要时回捞，而不是 silent drop。
    """
    selected: list[str] = []
    deferred: list[str] = []
    case_router_count = 0
    registry = registry if registry is not None else _load_capability_registry(repo_root)
    for path in _dedupe(paths):
        meta = _card_capability(path, repo_root, registry=registry)
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

DISTILLED_TOKEN_TO_CARDS = (
    (API_ANCESTOR_PREFIX_RE, ("api-testing-workflow", "path-pattern-management-exposure")),
    (JS_RUNTIME_SIGNATURE_RE, ("js-runtime-signature-reconstruction",)),
    (CUSTOM_PROTOCOL_STATE_RE, ("custom-protocol-state-recovery",)),
    (PRESIGNED_URL_CAPABILITY_RE, ("api-idor", "auth-access")),
    (
        OBSERVABILITY_TRACE_RE,
        ("api-idor", "information-disclosure-source-config", "path-pattern-management-exposure"),
    ),
    (EXTERNAL_AUTHZ_POLICY_RE, ("auth-access", "api-idor")),
    (ODATA_BOUNDARY_RE, ("odata-query-boundaries",)),
    (LDAP_XPATH_BOUNDARY_RE, ("ldap-xpath-query-boundaries",)),
    (PUBLIC_PACKAGE_ARTIFACT_RE, ("public-package-artifact-intelligence",)),
    (NEXTJS_IMAGE_RE, ("ssrf-url-fetch",)),
    (NEXTJS_DATA_RE, ("api-idor", "information-disclosure-source-config")),
    (ACTUATOR_MANAGEMENT_RE, ("path-pattern-management-exposure", "information-disclosure-source-config")),
    (LEGACY_AUTH_SURFACE_RE, ("auth-hidden-switches", "auth-access")),
    (RATE_LIMIT_REGIME_RE, ("auth-credential-recovery-flows", "auth-access")),
    (re.compile(r"\b(payment[-_ ]?(?:callback|webhook|notify)|callback[-_ ]?signature|webhook[-_ ]?signature|idempotenc(?:y|t)|replay[-_ ]?(?:window|nonce)|async[-_ ]?settlement)\b", re.I), ("payment-callback-idempotency",)),
    # OIDC 也常作为独立身份信号；只有同时出现 workflow/runner/deploy 边界时才路由到 CI/CD 卡。
    (re.compile(r"(?:\b(ci[-_ ]?/?cd|cicd|github[-_ ]?actions|gitlab[-_ ]?ci|jenkins|self[-_ ]?hosted[-_ ]?runner|workflow[-_ ]?trigger|pull_request_target|artifact[-_ ]?deploy|dependency[-_ ]?confusion|public[-_ ]?registry|cyclonedx|spdx|sbom)\b|(?=.*\boidc\b)(?=.*\b(?:runner|workflow|artifact|deploy)\b))", re.I), ("cicd-trust-boundaries",)),
    (re.compile(r"\b(aws[-_ ]?cognito|cognito[-_ ]?identity|identity[-_ ]?pool|unauth(?:enticated)?[-_ ]?(?:identity|role)|get[-_ ]?credentials[-_ ]?for[-_ ]?identity)\b", re.I), ("cloud-cognito-identity-pool", "cloud-control-plane-pivots")),
    (re.compile(r"\b(grpc|grpc[-_ ]?web|grpc[-_ ]?gateway|protobuf|proto3|server[-_ ]?reflection|json[-_ ]?transcoding)\b", re.I), ("grpc-api-boundaries",)),
    (re.compile(r"\b(kubernetes|k8s|kubelet|self[-_ ]?subject[-_ ]?(?:rules|access)[-_ ]?review|nodes?[/_-]?proxy|projected[-_ ]?service[-_ ]?account)\b", re.I), ("k8s-control-plane-boundaries", "cloud-control-plane-pivots")),
    (re.compile(r"\b(cloud[-_ ]?control[-_ ]?plane|cloud[-_ ]?metadata|metadata[-_ ]?service|cloud[-_ ]?(?:iam|rbac)|service[-_ ]?account|workload[-_ ]?identity|assume[-_ ]?role|pass[-_ ]?role|control[-_ ]?plane)\b", re.I), ("cloud-control-plane-pivots",)),
    (re.compile(r"\b(subdomain[-_ ]?takeover|dangling[-_ ]?(?:dns|cname)|dns[-_ ]?trust|mx[-_ ]?record|email[-_ ]?spoof|spf|dkim|dmarc)\b", re.I), ("dns-email-trust-boundaries",)),
    (re.compile(r"\b(cdn|edge[-_ ]?proxy|reverse[-_ ]?proxy[-_ ]?filter|catch[-_ ]?all|wildcard[-_ ]?dns|dns[-_ ]?differential|multi[-_ ]?resolver|origin[-_ ]?discovery|status[-_ ]?code[-_ ]?filter(?:ing|ed)?|502[-_ ]?filter)\b", re.I), ("cdn-response-differential",)),
    (re.compile(r"\b(signature[-_ ]?scope[-_ ]?mismatch|signed bytes|consumption object|xsw|duplicate assertion)\b", re.I), ("signature-scope-mismatch",)),
    (re.compile(r"\b(oauth[-_ ]?sso[-_ ]?trust|email trust|audience confusion|redirect_uri trust)\b", re.I), ("auth-sso-token-edge-cases",)),
    (JSON_VIEW_DIFFERENTIAL_RE, ("view-differential",)),
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
            r"\b(password[-_ ]?reset|forgot[-_ ]?password|account[-_ ]?recovery|reset[-_ ]?token|username[-_ ]?enum(?:eration)?|credential[-_ ]?attack|brute[-_ ]?force|lockout|shadow[-_ ]?throttle|silent[-_ ]?throttle|known[-_ ]?good[-_ ]?control|stay[-_ ]?logged[-_ ]?in|remember[-_ ]?me|mfa|2fa|otp)\b",
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
        WEB_LLM_AGENT_SIGNAL_RE,
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
    if limit <= 0:
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return []
        return _dedupe([line.strip() for line in lines if line.strip()])[:limit]
    items: list[str] = []
    seen: set[str] = set()
    try:
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                value = line.strip()
                if not value or value in seen:
                    continue
                seen.add(value)
                items.append(value)
                if len(items) >= limit:
                    break
    except OSError:
        return []
    return items


def _read_jsonl_objects(path: Path, limit: int = 50) -> list[dict]:
    if not path.is_file():
        return []
    items: list[dict] = []
    try:
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            for line in handle:
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
    except OSError:
        return []
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
        active = load_active_file(repo_root / "memory" / "goals" / "active.json")
        target = str(active.get("target") or "").strip()
    if not target:
        raise SystemExit(
            "No target resolved. Use --target target.com or set active target with "
            "`python3 tools/target_memory.py set <target>`."
        )

    return canonical_target_value(target), " ".join(focus_parts).strip()


def _load_goal_memory(repo_root: Path, target: str) -> dict:
    projection = load_goal_memory(repo_root, target)
    projection["active_path"] = _display(repo_root / "memory" / "goals" / "active.json", repo_root)
    projection["target_path"] = _display(
        repo_root / "memory" / "goals" / "targets" / f"{target_storage_key(target)}.json",
        repo_root,
    )
    return projection


def _target_facts_projection(goal_memory: dict, *, limit: int = 20) -> list[dict]:
    """Project the keyed confirmed-fact map into the pack.

    Facts are the cheap context-recovery layer: after compaction, reading
    these key/text pairs replaces re-reading full history. Bounded by design.
    """
    target_memory = goal_memory.get("target") or {}
    facts = target_memory.get("facts")
    if not isinstance(facts, dict):
        return []
    projected = []
    for key in sorted(facts):
        item = facts.get(key)
        if not isinstance(item, dict):
            continue
        text = str(item.get("text", "")).strip()
        if not text:
            continue
        refs = item.get("evidence_refs")
        projected.append(
            {
                "key": key,
                "text": text,
                "evidence_refs": [str(ref) for ref in refs] if isinstance(refs, list) else [],
            }
        )
        if len(projected) >= limit:
            break
    return projected


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
    source_signals = [item for item in source_routes_payload.get("signals", []) if isinstance(item, dict)]

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
            "signals": source_signals,
            "routes": source_routes,
            "graphql_operations": source_graphql,
            "paths": _dedupe([
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


def _finding_anchor(finding: dict, *, compact: bool = False) -> str:
    label = str(finding.get("id") or finding.get("type") or finding.get("title") or "finding").strip()
    vuln = str(finding.get("vuln_class") or finding.get("class") or finding.get("category") or "").strip()
    endpoint = str(finding.get("endpoint") or finding.get("url") or "").strip()
    if compact:
        endpoint = compact_url(endpoint)
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
    matrix = load_matrix(target, repo_root=repo_root)
    gaps = high_value_gaps_from_matrix(matrix)
    if not gaps and target_key != target:
        key_matrix = load_matrix(target_key, repo_root=repo_root)
        key_gaps = high_value_gaps_from_matrix(key_matrix)
        if key_gaps or key_matrix.get("summary", {}).get("total_cells", 0):
            return key_gaps, key_matrix
    return gaps, matrix


def _surface_state(repo_root: Path, target: str, memory_dir: str | None) -> dict:
    resolved_memory_dir = memory_dir or str(default_memory_dir(repo_root))
    projection = load_surface_projection(
        repo_root,
        target,
        memory_dir=resolved_memory_dir,
    )
    if projection.get("status") == "valid":
        return dict(projection.get("surface") or {})
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
        pieces.append(
            "{method} {action} {fields}".format(
                method=form.get("method", ""),
                action=form.get("action", ""),
                fields=" ".join(str(field) for field in (form.get("hidden_fields") or [])),
            )
        )

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


def _ranked_tech_stack(ranked: dict, *, limit: int = 12) -> list[str]:
    """Return a small, ordered technology projection from ranked candidates."""

    values: list[str] = []
    sources = [ranked.get("tech_stack")]
    for key in ("review_pool", "p1", "p2"):
        items = ranked.get(key) or []
        sources.extend(
            item.get("tech_stack")
            for item in items[:16]
            if isinstance(item, dict)
        )
    for source in sources:
        if isinstance(source, str):
            source = [source]
        if not isinstance(source, (list, tuple)):
            continue
        for item in source:
            name = item.get("name") if isinstance(item, dict) else item
            name = str(name or "").strip()
            if name and name.casefold() not in {value.casefold() for value in values}:
                values.append(name)
                if len(values) >= limit:
                    return values
    return values


def _routing_blob_without_tech_stack(blob: str) -> str:
    """Keep the tech projection visible without treating it as raw evidence."""

    return re.sub(r"(?im)^tech_stack=[^\n]*\n?", "", blob)


NODE_RUNTIME_RE = re.compile(
    r"\b(?:node(?:\.js|js)?|express|next\.js|nestjs|koa|hapi|fastify)\b", re.I
)
NODE_POLLUTION_RE = re.compile(
    r"\b(?:prototype[-_ ]?pollution|proto[-_ ]?pollution|__proto__|constructor\.prototype|vm2?|happy[-_ ]?dom|jsdom)\b",
    re.I,
)
NODE_STRUCTURAL_INPUT_RE = re.compile(
    r"\b(?:merge|deep[-_ ]?(?:set|merge)|nested[-_ ]?json|json[-_ ]?(?:body|input)|application/json|"
    r"lodash|\bqs\b|\bflat\b|dot[-_ ]?prop|set[-_ ]?value|config[-_ ]?(?:input|object|merge))\b",
    re.I,
)


def _text_blob(
    focus: str,
    goal_memory: dict,
    ranked: dict,
    gaps: list[dict],
    findings: list[dict],
    local_intel: dict,
) -> str:
    pieces: list[str] = [focus]
    tech_stack = _ranked_tech_stack(ranked)
    active = goal_memory.get("active") or {}
    target_memory = goal_memory.get("target") or {}
    for key in ("active_goal", "current_hypothesis", "phase", "mode"):
        pieces.append(str(active.get(key) or target_memory.get(key) or ""))
    for field in ("active_leads", "next_actions", "dead_ends", "useful_patterns"):
        for item in (target_memory.get(field) or [])[-5:]:
            pieces.append(_entry_text(item))
    review_items = ranked.get("review_pool") or (ranked.get("p1", [])[:5] + ranked.get("p2", [])[:3])
    for item in review_items[:8]:
        semantic = item.get("semantic_shape") if isinstance(item.get("semantic_shape"), dict) else {}
        request_shapes = item.get("request_shapes") if isinstance(item.get("request_shapes"), list) else []
        request_hint = ""
        if request_shapes:
            request_bits = []
            for shape in request_shapes[:2]:
                if not isinstance(shape, dict):
                    continue
                body = shape.get("body") if isinstance(shape.get("body"), dict) else {}
                request_bits.append(
                    f"{str(shape.get('method') or 'GET').upper()} {body.get('content_type_hint') or ''}".strip()
                )
            request_hint = " ".join(request_bits)
        pieces.extend([
            surface_safe_preview(str(item.get("url") or "")),
            str(item.get("path") or ""),
            f"semantic={semantic.get('path_template', '')} params={','.join(str(name) for name, _count in semantic.get('parameter_multiset', [])[:12])} {request_hint}".strip(),
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
    if tech_stack:
        pieces.append("tech_stack=" + " ".join(tech_stack))
    pieces.extend(_local_intel_blob(local_intel))
    return "\n".join(piece for piece in pieces if piece)


def _has_ssrf_internal_signal(text: str) -> bool:
    """识别“服务端取 URL + 内部目标”组合，避免把普通 internal/admin 误路由成 SSRF。"""

    if not text:
        return False
    if SSRF_EXPLICIT_INTERNAL_RE.search(text):
        return True
    return bool(SSRF_FETCH_CONTEXT_RE.search(text) and SSRF_INTERNAL_TARGET_RE.search(text))


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


def _required_checks(blob: str, has_candidate: bool) -> list[str]:
    # Platform startup owns action safety; Context Pack only emits route checks.
    # Skill recommendation is retired (S1 native loading): the reporting rule
    # loads on the owner fact "a candidate awaits validation", which is what
    # the old triage-validation recommendation encoded.
    checks = ["rules/coverage-gate.md"]
    if has_candidate:
        checks.append("rules/reporting.md")
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
    url = surface_safe_preview(str(item.get("url") or "").strip())
    reasons = ", ".join(str(reason) for reason in (item.get("reasons") or [])[:2])
    score = item.get("score")
    review_reason = str(item.get("review_reason") or "surface evidence").strip()
    value_summary = item.get("value_summary") if isinstance(item.get("value_summary"), dict) else {}
    value_bits = []
    for signal in (value_summary.get("signals") or [])[:3]:
        classes = "/".join(str(value) for value in signal.get("classes", [])[:3] if str(value))
        name = str(signal.get("name") or "param")[:40]
        value_bits.append(f"{name}:{classes or 'structured'}:{signal.get('length', '?')}")
    value_hint = f" values={','.join(value_bits)}" if value_bits else ""
    return f"Surface review {url} score_hint={score} reason={review_reason}{value_hint}; {reasons}".strip()


def _gap_anchor(gap: dict) -> str:
    return f"Coverage gap: {gap.get('endpoint', '')} x {gap.get('vuln_class', '')} weight={gap.get('weight', '')}"


def _runner_candidate_anchors(candidates: list[dict]) -> list[str]:
    anchors: list[str] = []
    for item in candidates[:4]:
        anchors.append(
            "Runner candidate evidence: {lane}/{result} {method} {url}; "
            "requires /validate gates before report".format(
                lane=item.get("lane", ""),
                result=item.get("result", ""),
                method=item.get("method", "GET"),
                url=compact_url(item.get("url", "")),
            )
        )
    return anchors


def _local_intel_anchors(local_intel: dict) -> list[str]:
    anchors: list[str] = []
    browser = local_intel.get("browser") or {}
    for url in (browser.get("xhr_endpoints") or [])[:3]:
        anchors.append(f"Browser XHR/API: {compact_url(url)}")
    for line in (browser.get("params") or [])[:3]:
        anchors.append(f"Browser param: {line}")
    for form in (browser.get("forms") or [])[:2]:
        method = str(form.get("method") or "").strip() or "GET"
        action = str(form.get("action") or "").strip() or "(current page)"
        hidden_fields = [str(field) for field in (form.get("hidden_fields") or []) if str(field).strip()]
        suffix = f" hidden_fields={','.join(hidden_fields[:4])}" if hidden_fields else ""
        anchors.append(f"Browser form: {method} {action}{suffix}")

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
    for signal in (source_intel.get("signals") or [])[:3]:
        anchors.append(f"Source marker [{signal.get('kind', '')}]: {signal.get('source', '')} :: {signal.get('evidence', '')}")
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
        anchors.append(f"Finding: {_finding_anchor(finding, compact=True)}")
    return _dedupe(anchors)[:12] or ["No strong local evidence anchor yet; start from target memory and recon freshness."]


def _has_browser_intel(local_intel: dict) -> bool:
    browser = local_intel.get("browser") or {}
    return bool(
        browser.get("xhr_endpoints")
        or browser.get("api_endpoints")
        or browser.get("params")
        or browser.get("forms")
    )


def _has_telerik_dialog_signal(value: str) -> bool:
    return bool(TELERIK_DIALOG_SIGNAL_RE.search(value))


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
    observation_inventory = ranked.get("observation_inventory") or {}
    inventory_error = str(observation_inventory.get("error") or "").strip()
    if inventory_error:
        items.append(f"Observation inventory could not be read: {inventory_error}")
    elif observation_inventory.get("available") and observation_inventory.get("untouched"):
        items.append(
            "Observation inventory still has {untouched} untouched item(s), including {stale} stale; "
            "use the bounded sample or inventory list before declaring surface exhaustion.".format(
                untouched=observation_inventory.get("untouched", 0),
                stale=observation_inventory.get("stale", 0),
            )
        )
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


URL_TOKEN_RE = re.compile(r"https?://[^\s\]\"'<>]+")
PATH_TOKEN_RE = re.compile(r"(?<![:/])(/[A-Za-z0-9._~%!$&'()*+,;=:@/-]+(?:\?[A-Za-z0-9._~%!$&'()*+,;=:@/?-]+)?)")


def _normalise_path_token(value: str) -> str:
    raw = str(value or "").strip().rstrip(".,;:)]}'\"")
    if not raw:
        return ""
    if "://" in raw:
        try:
            raw = urlparse(raw).path or "/"
        except ValueError:
            raw = raw.split("?", 1)[0].split("#", 1)[0]
    path = raw.split("?", 1)[0].split("#", 1)[0].strip()
    if not path:
        return ""
    if not path.startswith("/"):
        path = "/" + path
    if path != "/":
        path = path.rstrip("/")
    return path


def _entry_ts(item: object) -> str:
    if isinstance(item, dict):
        return str(item.get("ts") or "").strip()
    return ""


def _dead_end_paths(text: str) -> list[str]:
    value = str(text or "")
    paths: list[str] = []
    for match in URL_TOKEN_RE.finditer(value):
        paths.append(_normalise_path_token(match.group(0)))
    value_without_urls = URL_TOKEN_RE.sub(" ", value)
    paths.extend([
        path
        for path in (_normalise_path_token(match.group(0)) for match in PATH_TOKEN_RE.finditer(value_without_urls))
        if path and path != "/"
    ])
    return _dedupe([path for path in paths if path and path != "/"])


def _ledger_closed_after_dead_end(dead_text: str, dead_ts: str, evidence_summary: dict) -> bool:
    """Return true when newer explicit ledger closure resolves a memory conflict.

    Target memory dead-ends are useful reminders, but once Claude writes a later
    final ledger row for the same endpoint, repeating "may have new evidence" is
    stale steering.  This only suppresses the contradiction message; raw memory
    and evidence remain available for reopening.
    """
    if not dead_ts:
        return False
    paths = _dead_end_paths(dead_text)
    if not paths:
        return False
    return ClosureResolver(evidence_summary or {}).closed_after(paths, dead_ts)


def _contradictions(
    target: str,
    goal_memory: dict,
    ranked: dict,
    gaps: list[dict],
    local_intel: dict,
    evidence_summary: dict | None = None,
) -> list[str]:
    items: list[str] = []
    dead_ends = [
        {"text": _entry_text(item), "ts": _entry_ts(item)}
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
        dead_text = str(dead.get("text") or "")
        if _ledger_closed_after_dead_end(dead_text, str(dead.get("ts") or ""), evidence_summary or {}):
            continue
        if _token_overlap(dead_text, new_evidence):
            items.append(
                f"Remembered dead end may have new evidence now: {dead_text[:140]}"
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
        "source_intel_signals": len(source_intel.get("signals") or []),
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
    for route in (source_intel.get("routes") or [])[:3]:
        endpoints.append(str(route.get("route") or ""))
    return _dedupe(endpoints)[:8]


def _owner_backed_vuln_classes(coverage_gaps: list[dict]) -> list[str]:
    canonical_by_name = {item.casefold(): item for item in ACTOR_MATRIX_VULN_CLASSES}
    return _dedupe([
        canonical_by_name[value.casefold()]
        for gap in coverage_gaps
        if isinstance(gap, dict)
        and (value := str(gap.get("vuln_class") or "").strip())
        and value.casefold() in canonical_by_name
    ])


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


def build_context_pack(
    repo_root: Path | str = BASE_DIR,
    *,
    target: str,
    focus: str = "",
    memory_dir: str | None = None,
    surface_state: dict | None = None,
    coverage_state: tuple[list[dict], dict] | None = None,
    validation_runner_candidates: list[dict] | None = None,
    ledger_diagnostics: dict | None = None,
) -> dict:
    repo = Path(repo_root)
    resolved_target = canonical_target_value(target)
    target_key = target_storage_key(resolved_target)
    goal_memory = _load_goal_memory(repo, resolved_target)
    ranked = surface_state if surface_state is not None else _surface_state(repo, resolved_target, memory_dir)
    gaps, matrix = coverage_state or _safe_find_gaps(resolved_target, target_key, repo)
    findings = _load_findings(repo, target_key)
    runner_candidates = (
        validation_runner_candidates
        if isinstance(validation_runner_candidates, list)
        else load_validation_runner_candidate_pool(repo, resolved_target)
    )
    local_intel = _load_local_intel(repo, target_key)
    tech_stack = _ranked_tech_stack(ranked)
    blob = _text_blob(focus, goal_memory, ranked, gaps, findings, local_intel)
    telerik_dialog_signal = _has_telerik_dialog_signal(blob)
    viewstate_signal = bool(re.search(r"\bviewstate\b|__viewstate", blob, re.I))
    has_candidate = any(_finding_is_candidate(item) for item in findings)
    historical_patterns = []
    # 2026-09-12 收敛裁定：跨目标现场经验不自动进入本目标的 Pack。
    # surface 新计算路径已不再产生跨目标 pattern_suggestions，但升级前的
    # 旧 v2 投影在输入 owner 未变时仍被判 valid——这里的消费边界负责拒绝
    # 任何非当前目标 provenance 的残留建议，缓存与真源（新计算）双侧闭合。
    for item in ((ranked.get("memory") or {}).get("pattern_suggestions") or []):
        lesson = str(item).strip()
        provenance, separator, stripped_lesson = lesson.partition(": ")
        if separator:
            try:
                same_target = canonical_target_value(provenance).casefold() == resolved_target.casefold()
            except ValueError:
                same_target = False
            if not same_target:
                # 其他目标的残留建议（旧投影缓存）：跳过，不进 historical_patterns。
                continue
            lesson = stripped_lesson.strip()
        if lesson and lesson not in historical_patterns:
            historical_patterns.append(lesson)
        if len(historical_patterns) == 3:
            break
    registry = _load_capability_registry(repo)
    # 语义选卡已退役（原生能力审计 2026-09-13）：关键词分支/否定盲/人工
    # 排序是在替 AI 做语义理解。Pack 发布完整卡片目录（card_catalog，
    # id + layer + load + purpose），选择权在 AI；knowledge_cards 等
    # 字段保留为空兼容投影，消费方不破坏。
    cards: list[str] = []
    deferred_cards: list[str] = []
    knowledge_card_recall: list[dict[str, object]] = []
    checks = _required_checks(blob, has_candidate)
    evidence_summary = build_evidence_summary(
        repo,
        target=resolved_target,
        focus_endpoints=_focus_endpoints_for_ledger(ranked, gaps, local_intel),
        vuln_classes=_owner_backed_vuln_classes(gaps),
        _diagnostics=ledger_diagnostics,
    )
    ledger_path = _ledger_relative_path(evidence_summary, repo)

    # Must-read lists only paths that exist: goal memory is legitimately
    # absent after a reset/fresh start, and a contract that points at missing
    # files gives the reader no way to tell a defect from a fresh start.
    # Repo-owned assets (runtime protocol, signal-matched tools) are
    # unconditional: they live in the repository, not in target state.
    _REPO_UNCONDITIONAL = {
        "skills/runtime-protocol.md",
        "tools/aspnet_viewstate_knownkey.py",
        "tools/telerik_knownkey.py",
    }

    def _must_read_candidate(relative: str) -> bool:
        if not relative:
            return False
        if relative in _REPO_UNCONDITIONAL:
            return True
        try:
            return (repo / relative).is_file()
        except OSError:
            return False

    must_read = _dedupe([
        goal_memory["active_path"],
        goal_memory["target_path"],
        "skills/runtime-protocol.md",
        ledger_path,
    ] + (["tools/aspnet_viewstate_knownkey.py"] if viewstate_signal else []) + (["tools/telerik_knownkey.py"] if telerik_dialog_signal else []) + _local_intel_paths(local_intel) + [
        str(item.get("summary_path") or "")
        for item in runner_candidates[:6]
        if item.get("summary_path")
    ])
    must_read = [item for item in must_read if _must_read_candidate(item)]

    pack = {
        "target": resolved_target,
        "target_storage_key": target_key,
        "phase": _phase(goal_memory),
        "active_goal": _active_goal(goal_memory),
        "current_hypothesis": _hypothesis(goal_memory),
        "facts": _target_facts_projection(goal_memory),
        "focus": focus,
        "tech_stack": tech_stack,
        # Compatibility shells (S1 native skill loading, batch 3): the pack no
        # longer recommends a skill. Empty values stay schema-compatible with
        # old checkpoint/witness readers. Skills are selected and loaded by
        # the AI via the native Skill tool; the platform's skill listing is
        # the routing surface, the pack does not duplicate it.
        "selected_skill": "",
        "selected_skill_id": "",
        "why_this_skill": "",
        "skill_route": {},
        "must_read": must_read,
        "knowledge_cards": cards,
        "card_catalog": _card_catalog(repo, registry=registry),
        "knowledge_card_capabilities": _card_capabilities(cards, repo, registry=registry),
        "deferred_knowledge_cards": deferred_cards,
        "deferred_knowledge_card_capabilities": _card_capabilities(deferred_cards, repo, registry=registry),
        "knowledge_card_recall": knowledge_card_recall,
        # Compatibility field: generic technique references are intentionally
        # retired; project-specific guidance comes from knowledge_cards.
        "reference_hints": [],
        "historical_patterns": historical_patterns,
        "required_checks": checks,
        "evidence_anchors": _build_evidence_anchors(ranked, goal_memory, gaps, findings, local_intel)
        + _runner_candidate_anchors(runner_candidates)
        + _ledger_anchors(evidence_summary),
        "validation_runner_candidates": runner_candidates,
        # 静态假设/发散建议已退役（原生能力审计 2026-09-13）：
        # if 某张卡 in cards: append 固定思路 是卡片正文的复读层，
        # 独有知识已确认在对应卡片中（语义覆盖审计）。假设由 AI 在
        # 真实证据和完整卡片上自己提出。字段保留为空兼容投影。
        "hypothesis_seeds": [],
        "alternative_angles": [],
        "unknowns": _unknowns(ranked, goal_memory, matrix, findings, local_intel)
        + _ledger_unknowns(evidence_summary),
        "contradictions": _contradictions(resolved_target, goal_memory, ranked, gaps, local_intel, evidence_summary),
        "actor_matrix_gaps": (evidence_summary.get("actor_matrix") or {}).get("gaps", [])[:8],
        "do_not_load": [
            "full skills/* tree",
            "full knowledge/cards/* tree",
            "generic technique catalogues and external reference indexes",
            "raw large recon logs, full JSONL, full HTML responses, or unrelated historical sessions",
            "raw browser capture requests/console/storage unless validating one exact replay path",
            "all findings evidence bodies; start from findings/<target>/findings.json index only",
        ],
        "write_back": _write_back_commands(resolved_target) + (evidence_summary.get("record_commands") or [])[:3],
        "ai_override": (
            "Skill and knowledge-card fields are advisory. Claude must explicitly choose and load "
            "the applicable route at Action Queue claim, keep the coverage check loaded, and "
            "write the selected skill and tested dimensions into the Action Queue. "
            "skill_override_reason is required only when replacing an action-owned route."
        ),
        "source_summary": {
            "surface_available": bool(ranked.get("available")),
            "tech_stack": tech_stack,
            "p1": (ranked.get("stats") or {}).get("p1", 0),
            "p2": (ranked.get("stats") or {}).get("p2", 0),
            "workflow_leads": len(_json_list(ranked.get("workflow_leads"))),
            "observation_total": int((ranked.get("observation_inventory") or {}).get("total", 0) or 0),
            "observation_untouched": int((ranked.get("observation_inventory") or {}).get("untouched", 0) or 0),
            "observation_stale": int((ranked.get("observation_inventory") or {}).get("stale", 0) or 0),
            "coverage_gaps": len(gaps),
            "findings": len(findings),
            "validation_runner_candidates": len(runner_candidates),
            "historical_patterns": len(historical_patterns),
            "viewstate_signal": viewstate_signal,
            "telerik_dialog_signal": telerik_dialog_signal,
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
        f"- Tech stack: {', '.join(pack.get('tech_stack') or []) or '-'}",
        "- Skill recommendation retired (S1 native loading): select and load skills on demand via the Claude Code Skill tool (the platform's skill listing is the routing surface).",
        "- Must read:",
        *_format_list(pack["must_read"]),
        "- Card selection retired (2026-09-13 native audit): the catalog below is the discovery surface; AI selects cards by information gap.",
        "- Knowledge card catalog:",
        *_format_list([
            "{file} — layer={layer}, load={load}, purpose={purpose}".format(
                file=item.get("file", ""),
                layer=item.get("layer", ""),
                load=item.get("load", ""),
                purpose=item.get("purpose", ""),
            )
            for item in pack.get("card_catalog", [])
        ]),
        "- Retired card projections (kept empty for compatibility):",
        *_format_list([
            "knowledge_cards", "deferred_knowledge_cards", "knowledge_card_recall",
        ]),
        "- Reference hints (retired; generic technique detail comes from the model):",
        *_format_list([
            "{path} — {when}".format(
                path=item.get("path", ""),
                when=item.get("when", ""),
            )
            for item in pack.get("reference_hints", [])
        ]),
        "- Historical patterns (advisory; require current-target evidence):",
        *_format_list(pack.get("historical_patterns", [])),
        "- Required checks:",
        *_format_list(pack["required_checks"]),
        "- Evidence anchors:",
        *_format_list(pack["evidence_anchors"]),
        "- Validation runner candidate evidence (advisory; not report-ready):",
        *_format_list(format_validation_runner_candidate_lines(
            pack.get("validation_runner_candidates", []),
            limit=6,
        )),
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
