#!/usr/bin/env python3
"""为 surface 排名和 action queue 提供共享的高价值信号打分。"""

from __future__ import annotations

import re
from dataclasses import dataclass, field


HIGH_VALUE_TYPES = {
    "idor",
    "authz",
    "access-control",
    "auth-bypass",
    "business-logic",
    "graphql",
    "oauth",
    "jwt",
    "ssrf",
    "sqli",
    "xxe",
    "rce",
    "path",
    "lfi",
    "file-read",
    "ssti",
    "deserialization",
    "upload",
    "webhook",
    "csrf",
    "race",
    "secret",
    "ci-cd",
}

ACTION_TYPE_BONUS = {
    "candidate-evidence-gap": 8,
    "secret-verification": 7,
    "evidence-convergence": 7,
    "known-software-intel": 6,
    "coverage-gap": 5,
}

HIGH_VALUE_PATH_HINTS = (
    "admin",
    "internal",
    "billing",
    "payment",
    "payout",
    "invoice",
    "refund",
    "oauth",
    "saml",
    "sso",
    "session",
    "webhook",
    "callback",
    "upload",
    "import",
    "export",
    "download",
    "graphql",
    "tenant",
    "org",
    "workspace",
    "account",
    "user",
    "order",
    "token",
    "secret",
    "ci",
    "cd",
)

CONTEXTUAL_NUMERIC_ID_RE = re.compile(
    r"/(?:users?|accounts?|profiles?|members?|customers?|orgs?|organizations?|tenants?|workspaces?|"
    r"orders?|invoices?|tickets?|messages?|comments?|files?|addresses?|carts?|products?|items?)/"
    r"\d{1,8}(?:/|$)",
    re.I,
)


@dataclass(frozen=True)
class HighValueSignal:
    """用于排序决策的确定性高价值信号摘要。"""

    score: int = 0
    classes: tuple[str, ...] = field(default_factory=tuple)
    reasons: tuple[str, ...] = field(default_factory=tuple)


def _dedupe(items: list[str]) -> tuple[str, ...]:
    seen: set[str] = set()
    out: list[str] = []
    for item in items:
        if not item or item in seen:
            continue
        seen.add(item)
        out.append(item)
    return tuple(out)


def _contains_hint(text: str, token: str) -> bool:
    """短缩写必须按 word/segment 边界匹配，避免 hostname/普通单词误命中。"""
    if len(token) > 3:
        return token in text
    return bool(re.search(rf"(?<![a-z0-9]){re.escape(token)}(?![a-z0-9])", text))


def classify_high_value_signal(*, path: str = "", query_keys: list[str] | None = None, item_type: str = "", evidence: str = "") -> HighValueSignal:
    """根据路径、参数、动作类型和证据，返回一个轻量高价值加分。

    这是软偏置，只用于拉开排序优先级，不替代现有的加法打分模型。
    """
    query_keys = [key.lower() for key in (query_keys or []) if key]
    lower_path = (path or "").lower()
    lower_evidence = (evidence or "").lower()
    lower_type = (item_type or "").lower()

    score = 0
    classes: list[str] = []
    reasons: list[str] = []

    def add(points: int, klass: str, reason: str) -> None:
        nonlocal score
        score += points
        classes.append(klass)
        reasons.append(reason)

    action_bonus = ACTION_TYPE_BONUS.get(lower_type, 0)
    if action_bonus:
        add(action_bonus, lower_type, f"action:{lower_type}")
    if lower_type in HIGH_VALUE_TYPES:
        add(6, lower_type, f"type:{lower_type}")

    if lower_path.startswith("/api/") or re.search(r"/api/v\d+/", lower_path):
        add(2, "api", "api")

    for token in ("admin", "internal", "billing", "payment", "oauth", "saml", "webhook", "callback", "graphql", "upload", "export", "download", "tenant", "workspace", "account", "order", "secret", "ci", "cd"):
        if _contains_hint(lower_path, token):
            add(2, token, f"path:{token}")
            break
    for token in ("wordpress", "plugin", "theme", "cve", "advisory", "version", "affected", "reachable", "idor", "ssrf", "sqli", "rce", "upload", "oauth", "saml", "secret"):
        if _contains_hint(lower_evidence, token):
            add(2, token, f"evidence:{token}")
            break

    if any(key in {"id", "user_id", "account_id", "order_id"} or key.endswith("_id") for key in query_keys):
        add(3, "id-ref", "id-param")
    if any(key in {"url", "uri", "dest", "destination", "callback", "webhook", "target", "next", "return", "redirect_uri"} for key in query_keys):
        add(4, "server-side", "server-side-input")
    if any(key in {"token", "secret", "key", "password", "session"} for key in query_keys):
        add(4, "secret", "secret-param")
    if "graphql" in lower_path or "graphql" in lower_evidence:
        add(5, "graphql", "graphql")
    if "websocket" in lower_path or lower_path.startswith("/ws") or "/ws" in lower_path:
        add(4, "websocket", "websocket")
    if CONTEXTUAL_NUMERIC_ID_RE.search(lower_path):
        add(3, "sequential", "sequential-id")
    if any(token in lower_path for token in ("upload", "import", "export", "download", "preview", "render")):
        add(3, "file", "file-flow")
    if any(token in lower_path for token in ("oauth", "saml", "sso", "session")):
        add(4, "auth", "auth-flow")
    if any(token in lower_path for token in ("webhook", "callback")):
        add(4, "callback", "callback-flow")
    if any(token in lower_path for token in ("admin", "internal", "billing", "payment", "payout", "invoice", "refund", "tenant", "workspace", "account", "order")):
        add(3, "high-value", "high-value-path")
    if query_keys and not classes:
        add(1, "parameterized", "parameterized")

    return HighValueSignal(score=score, classes=_dedupe(classes), reasons=_dedupe(reasons))


def summarize_high_value_signal(signal: HighValueSignal) -> str:
    if not signal.score:
        return ""
    label = "+".join(signal.classes[:4]) or "signal"
    return f"high-value:{label} (+{signal.score})"
