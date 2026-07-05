#!/usr/bin/env python3
"""匿名公开响应里的高价值暴露信号提取。

这个模块只做一件事：把“匿名可读接口”继续区分成
1) 值得进入 authz/public exposure 验证的高价值候选
2) 普通公开 catalog / metadata / challenge 列表

目标不是全量秘密扫描，而是给 scanner / validation_runner 提供稳定、
可复用、低误报的 body-backed 信号。
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from typing import Any

URL_MARKERS = {
    "admin": re.compile(r"\badmin(?:istrat(?:or|ion))?\b", re.I),
    "configuration": re.compile(r"\bapplication[-_/ ]?configuration\b|\bconfig(?:uration)?\b|\bsettings\b", re.I),
    "oauth": re.compile(r"\boauth|client[_-]?id|redirect[_-]?uri|authorizedredirects\b", re.I),
    "security-answer": re.compile(r"\bsecurity(?:question|answer)s?\b", re.I),
    "secret-like": re.compile(
        r"\b(secret|token|api[_-]?key|password(?:hash)?|private[-_ ]?key|seed(?:[-_ ]?phrase)?|mnemonic)\b",
        re.I,
    ),
}

BODY_PATH_MARKERS = {
    "admin": re.compile(r"\badmin(?:istrat(?:or|ion))?\b", re.I),
    "configuration": re.compile(r"\bconfig(?:uration)?\b|\bsettings\b", re.I),
    "oauth": re.compile(r"\boauth|clientid|redirecturi|authorizedredirects\b", re.I),
    "security-answer": re.compile(r"\bsecurity(?:question|answer)\b", re.I),
    "secret-like": re.compile(
        r"\b(secret|token|api[_-]?key|password(?:hash)?|privatekey|seedphrase|mnemonic)\b",
        re.I,
    ),
}

RAW_ASSIGNMENT_MARKERS = {
    "admin": re.compile(r"['\"]?admin(?:istrat(?:or|ion))?['\"]?\s*[:=]", re.I),
    "configuration": re.compile(
        r"['\"]?(?:application[-_/ ]?configuration|config(?:uration)?|settings)['\"]?\s*[:=]",
        re.I,
    ),
    "oauth": re.compile(r"['\"]?(?:oauth|client[_-]?id|redirect[_-]?uri|authorizedredirects)['\"]?\s*[:=]", re.I),
    "security-answer": re.compile(r"['\"]?security(?:question|answer)['\"]?\s*[:=]", re.I),
    "secret-like": re.compile(
        r"['\"]?(?:secret|token|api[_-]?key|password(?:hash)?|private[_-]?key|seed(?:[-_ ]?phrase)?|mnemonic)['\"]?\s*[:=]",
        re.I,
    ),
}

JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")
PEM_PRIVATE_KEY_RE = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")
MNEMONIC_CUE_RE = re.compile(
    r"(?i)(wallet|mnemonic|seed(?:[-_ ]?phrase)?|recovery(?:[-_ ]?phrase)?|secret(?:[-_ ]?phrase)?)"
    r"[^\n]{0,120}['\"]([a-z]{3,12}(?: [a-z]{3,12}){11,23})['\"]"
)
SECURITY_TXT_FIELD_RE = re.compile(
    r"(?im)^(contact|expires|encryption|acknowledgments|preferred-languages|policy|hiring|canonical):"
)
STANDARD_PUBLIC_METADATA_PATHS = {
    "oidc-discovery": re.compile(r"/\.well-known/openid-configuration/?$", re.I),
    "jwks": re.compile(r"(?:/\.well-known)?/jwks(?:\.json)?/?$", re.I),
    "csaf-provider-metadata": re.compile(r"/\.well-known/csaf/provider-metadata\.json/?$", re.I),
    "security-txt": re.compile(r"/\.well-known/security\.txt/?$", re.I),
}
STANDARD_PUBLIC_METADATA_KEYS = {
    "oidc-discovery": {"issuer", "authorization_endpoint", "token_endpoint", "jwks_uri"},
    "jwks": {"keys"},
    "csaf-provider-metadata": {
        "canonical_url",
        "distributions",
        "metadata_version",
        "public_openpgp_keys",
        "publisher",
        "role",
    },
}


def _safe_json_loads(body: str) -> Any | None:
    try:
        return json.loads(body)
    except (TypeError, ValueError, json.JSONDecodeError):
        return None


def _flatten_json_paths(value: Any, prefix: str = "") -> list[str]:
    """把 JSON key path 展平成稳定文本，避免扫整段自然语言 description。"""
    items: list[str] = []
    if isinstance(value, dict):
        for key, inner in value.items():
            key_text = str(key)
            path = f"{prefix}.{key_text}" if prefix else key_text
            items.append(path)
            items.extend(_flatten_json_paths(inner, path))
    elif isinstance(value, list):
        for inner in value:
            items.extend(_flatten_json_paths(inner, prefix))
    return items


def _flatten_json_string_values(value: Any) -> list[str]:
    items: list[str] = []
    if isinstance(value, dict):
        for inner in value.values():
            items.extend(_flatten_json_string_values(inner))
    elif isinstance(value, list):
        for inner in value:
            items.extend(_flatten_json_string_values(inner))
    elif isinstance(value, str):
        items.append(value)
    return items


def _top_level_json_keys(value: Any) -> set[str]:
    if not isinstance(value, dict):
        return set()
    return {str(key) for key in value.keys()}


def _has_strong_secret_value(*texts: str) -> bool:
    for text in texts:
        candidate = str(text or "")
        if not candidate:
            continue
        if JWT_RE.search(candidate) or PEM_PRIVATE_KEY_RE.search(candidate) or MNEMONIC_CUE_RE.search(candidate):
            return True
    return False


def public_exposure_marker_sources(url: str, body: str) -> dict[str, list[str]]:
    """返回 url/body 各自命中的 marker。

    关键策略：
    - url 允许保留弱信号（admin/config/...），用于路由
    - body 不扫整段自然语言；优先看 JSON key path / 赋值语境 / 强秘密值形态
    """
    url_text = str(url or "")
    body_text = str(body or "")
    url_hits = {
        name for name, pattern in URL_MARKERS.items()
        if pattern.search(url_text)
    }

    body_hits: set[str] = set()

    payload = _safe_json_loads(body_text)
    if payload is not None:
        path_text = "\n".join(_flatten_json_paths(payload)).replace("_", "").replace("-", "").replace(" ", "")
        for name, pattern in BODY_PATH_MARKERS.items():
            if pattern.search(path_text):
                body_hits.add(name)
        string_values = _flatten_json_string_values(payload)
    else:
        string_values = []

    for name, pattern in RAW_ASSIGNMENT_MARKERS.items():
        if pattern.search(body_text):
            body_hits.add(name)

    if _has_strong_secret_value("\n".join(string_values), body_text):
        body_hits.add("secret-like")

    return {
        "url": sorted(url_hits),
        "body": sorted(body_hits),
    }


def public_exposure_markers(url: str, body: str) -> list[str]:
    sources = public_exposure_marker_sources(url, body)
    return sorted(set(sources["url"]) | set(sources["body"]))


def public_exposure_candidate_ready(status: int, marker_sources: dict[str, list[str]]) -> bool:
    """只在 body-backed 高价值信号足够时才判定为候选。"""
    if int(status or 0) != 200:
        return False

    body_markers = set(marker_sources.get("body") or [])
    url_markers = set(marker_sources.get("url") or [])
    all_markers = body_markers | url_markers

    if "secret-like" in body_markers:
        return True
    if "security-answer" in body_markers:
        return True
    if "configuration" in body_markers and all_markers & {"admin", "oauth"}:
        return True
    if "oauth" in body_markers and all_markers & {"admin", "configuration"}:
        return True
    return False


def standard_public_metadata_kind(url: str, body: str) -> str | None:
    """识别“预期公开”的标准 metadata 端点，避免当成高价值暴露。"""
    url_text = str(url or "")
    body_text = str(body or "")
    payload = _safe_json_loads(body_text)
    top_level_keys = _top_level_json_keys(payload)

    if STANDARD_PUBLIC_METADATA_PATHS["oidc-discovery"].search(url_text):
        required = STANDARD_PUBLIC_METADATA_KEYS["oidc-discovery"]
        if required.issubset(top_level_keys):
            return "oidc-discovery"

    if STANDARD_PUBLIC_METADATA_PATHS["jwks"].search(url_text):
        if isinstance(payload, dict) and "keys" in payload and isinstance(payload.get("keys"), list):
            return "jwks"

    if STANDARD_PUBLIC_METADATA_PATHS["csaf-provider-metadata"].search(url_text):
        required = STANDARD_PUBLIC_METADATA_KEYS["csaf-provider-metadata"]
        if required.issubset(top_level_keys):
            return "csaf-provider-metadata"

    if STANDARD_PUBLIC_METADATA_PATHS["security-txt"].search(url_text):
        if len(SECURITY_TXT_FIELD_RE.findall(body_text)) >= 2:
            return "security-txt"

    return None


def looks_like_standard_public_metadata(url: str, body: str, *, status: int = 200) -> bool:
    """仅在“像标准公开 metadata 且没有高价值 body 证据”时返回 True。"""
    if int(status or 0) != 200:
        return False
    kind = standard_public_metadata_kind(url, body)
    if not kind:
        return False
    marker_sources = public_exposure_marker_sources(url, body)
    return not public_exposure_candidate_ready(int(status or 0), marker_sources)


def classify_public_response(url: str, body: str, *, status: int = 200) -> dict[str, Any]:
    marker_sources = public_exposure_marker_sources(url, body)
    markers = sorted(set(marker_sources["url"]) | set(marker_sources["body"]))
    metadata_kind = standard_public_metadata_kind(url, body)
    return {
        "status": int(status or 0),
        "markers": markers,
        "marker_sources": marker_sources,
        "candidate_ready": public_exposure_candidate_ready(int(status or 0), marker_sources),
        "standard_public_metadata": bool(metadata_kind)
        and not public_exposure_candidate_ready(int(status or 0), marker_sources),
        "standard_public_metadata_kind": metadata_kind,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="提取匿名公开响应里的高价值暴露信号。")
    parser.add_argument("--url", required=True)
    parser.add_argument("--status", type=int, default=200)
    parser.add_argument("--body-file", default="", help="可选：从文件读取 body；默认从 stdin 读。")
    parser.add_argument(
        "--authz-candidate",
        action="store_true",
        help="只根据 candidate_ready 返回退出码；ready=0，不 ready=1。",
    )
    parser.add_argument(
        "--candidate-ready",
        action="store_true",
        help="只根据 body-backed exposure candidate_ready 返回退出码；ready=0，不 ready=1。",
    )
    parser.add_argument(
        "--standard-public-metadata",
        action="store_true",
        help="只根据标准公开 metadata 返回退出码；是 metadata=0，否则=1。",
    )
    parser.add_argument("--json", action="store_true", help="输出 JSON 结果。")
    args = parser.parse_args(argv)

    if args.body_file:
        body = open(args.body_file, encoding="utf-8", errors="replace").read()
    else:
        body = sys.stdin.read()

    payload = classify_public_response(args.url, body, status=args.status)
    predicate_only = args.authz_candidate or args.candidate_ready or args.standard_public_metadata
    if args.json or not predicate_only:
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    if args.standard_public_metadata:
        return 0 if payload["standard_public_metadata"] else 1
    if args.candidate_ready or args.authz_candidate:
        return 0 if payload["candidate_ready"] else 1
    return 0 if payload["candidate_ready"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
