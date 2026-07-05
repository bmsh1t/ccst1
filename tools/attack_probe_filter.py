"""共享的历史 payload/probe URL 过滤器。

Recon 会保留原始 URL 方便审计，但 surface ranking 和 coverage matrix
都只应消费“稳定端点”。带有明显攻击 payload 的历史 URL 是验证证据或
人工复核材料，不应被提升成新的 endpoint × vuln_class 执行动作。
"""

from __future__ import annotations

import re
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit


# Payload markers that indicate a URL is a historical attack probe
# (waymore/gau replay of prior attacker attempts) rather than a real
# endpoint. Patterns are case-insensitive and match against the FULL URL
# (path + query). Both raw and URL-encoded forms are covered.
PAYLOAD_MARKERS: list[re.Pattern] = [
    # SQLi
    re.compile(r"\bunion[\s+%20]+select\b", re.I),
    re.compile(r"\bor[\s+%20]+1\s*=\s*1\b", re.I),
    re.compile(r"['%27]\s*(?:or|and)\s*['%27]", re.I),
    re.compile(r"\bsleep\s*\(\s*\d+\s*\)", re.I),
    re.compile(r"\bbenchmark\s*\(\s*\d+", re.I),
    # XSS
    re.compile(r"<script\b", re.I),
    re.compile(r"</script>", re.I),
    re.compile(r"%3cscript", re.I),
    re.compile(r"\bonerror\s*=", re.I),
    re.compile(r"\bonload\s*=", re.I),
    re.compile(r"\bjavascript:", re.I),
    re.compile(r"\bdata:text/html", re.I),
    # Malformed/probe path fragments. A standalone encoded quote can be
    # legitimate in rare REST paths, but encoded backslash+quote is a strong
    # scanner/probe artifact and should not become a stable coverage endpoint.
    re.compile(r"%5c%22|%5c\\?\"|\\%22", re.I),
    # Path traversal / LFI
    re.compile(r"\.\./\.\./", re.I),
    re.compile(r"\.\.%2f\.\.%2f", re.I),
    re.compile(r"%2e%2e%2f", re.I),
    re.compile(r"\betc/passwd\b", re.I),
    re.compile(r"\betc/hosts\b", re.I),
    re.compile(r"/proc/self/", re.I),
    re.compile(r"\bwindows/win\.ini\b", re.I),
    # RCE / command injection
    re.compile(r"\beval\s*\(", re.I),
    re.compile(r"\bsystem\s*\(", re.I),
    re.compile(r"\bphpinfo\s*\(", re.I),
    re.compile(r";\s*cat\s+/", re.I),
    re.compile(r"\|\s*cat\s+/", re.I),
    re.compile(r"&&\s*cat\s+/", re.I),
    re.compile(r"\$\([^)]+\)", re.I),
    # XXE
    re.compile(r"<\?xml\b", re.I),
    re.compile(r"<!ENTITY\b", re.I),
    re.compile(r'SYSTEM\s+"file:', re.I),
    # Log4Shell / JNDI
    re.compile(r"\$\{jndi:", re.I),
    re.compile(r"\$\{env:", re.I),
    re.compile(r"\$\{lower:", re.I),
    re.compile(r"%24%7bjndi", re.I),
    # SSTI
    re.compile(r"\{\{\s*\d+\s*\*\s*\d+\s*\}\}"),
    re.compile(r"\$\{\{\s*\d+\s*\*\s*\d+\s*\}\}"),
    re.compile(r"<%=\s*\d+\s*\*\s*\d+\s*%>"),
    re.compile(r"#\{\s*\d+\s*\*\s*\d+\s*\}"),
    # NoSQLi
    re.compile(r"\[\$ne\]", re.I),
    re.compile(r"\[\$gt\]", re.I),
    re.compile(r"\[\$where\]", re.I),
    re.compile(r"%24where", re.I),
    re.compile(r"%5b%24ne%5d", re.I),
]

SAFE_PROBE_VALUE = "__probe__"
NOSQL_OPERATOR_KEY_RE = re.compile(r"\[\$[A-Za-z0-9_:-]+\]", re.I)
PATH_PROBE_SEGMENT_RE = re.compile(r"(?i)(?:%5c%22|%5c\\?\"|\\%22)")


def is_attack_probe(url: str) -> bool:
    """Return True if a URL contains payload markers rather than stable surface."""
    if not url:
        return False
    return any(pattern.search(url) for pattern in PAYLOAD_MARKERS)


def _safe_probe_key(key: str) -> str:
    """把 payload 型参数名降级为原始业务参数名，避免后续 replay 复用攻击算子。"""
    cleaned = NOSQL_OPERATOR_KEY_RE.sub("", key).strip()
    return cleaned or "param"


def sanitize_attack_probe_url(url: str) -> str:
    """把历史 payload URL 转成可排名的惰性攻击面形状。

    发现阶段不能因为 URL 带 payload 就丢掉端点/参数，否则会漏攻击面；
    但也不能把历史 payload 原样送进自动 replay。这里保留 scheme/host/path
    和参数名，把参数值替换成惰性占位符，并清理明显的路径型 probe 片段。
    """
    if not url or not is_attack_probe(url):
        return url

    parts = urlsplit(url)
    path = PATH_PROBE_SEGMENT_RE.sub("", parts.path or "")
    path = re.sub(r"/{2,}", "/", path).rstrip("/") or "/"

    query = ""
    if parts.query:
        pairs = parse_qsl(parts.query, keep_blank_values=True)
        query = urlencode([
            (_safe_probe_key(key), SAFE_PROBE_VALUE)
            for key, _value in pairs
            if key
        ])

    return urlunsplit((parts.scheme, parts.netloc, path, query, ""))


def filter_attack_probes(
    urls: list[str],
    *,
    log_path: Path | None = None,
    preserve_surfaces: bool = False,
) -> list[str]:
    """Return URLs minus raw attack probes and optionally keep inert surfaces."""
    if not urls:
        return []
    kept: list[str] = []
    dropped: list[str] = []
    for url in urls:
        if is_attack_probe(url):
            dropped.append(url)
            if preserve_surfaces:
                sanitized = sanitize_attack_probe_url(url)
                if sanitized and sanitized != url:
                    kept.append(sanitized)
        else:
            kept.append(url)
    if dropped and log_path is not None:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        with open(log_path, "a", encoding="utf-8") as handle:
            for url in dropped:
                handle.write(url + "\n")
    return kept
