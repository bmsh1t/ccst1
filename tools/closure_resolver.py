#!/usr/bin/env python3
"""统一 closure 状态查询。

这个模块只回答一个机械问题：某条 Claude-facing 任务是否已经被账本终态关闭。
它不排序、不打分、不判断价值、不删除原始攻击面。未知类型一律 fail-open，
避免工具替 AI 静默丢线索。
"""

from __future__ import annotations

from urllib.parse import urlparse


CLOSED_LEDGER_RESULTS = {
    "tested_clean",
    "tested_finding",
    "dead_end",
    "not_applicable",
    "blocked_redline",
}
CLOSED_MATRIX_STATUSES = {"tested_clean", "tested_finding", "n_a"}

# A matrix is a projection owned by Coverage; only structural N/A cells are
# self-authenticating.  Every observed terminal result must come from the
# Evidence Ledger so a hand-edited matrix cannot close a lane by itself.
_STRUCTURAL_NA_MARKERS = (
    "static asset;",
    "standard/public metadata;",
    "route prefix/container;",
    "minified JS property-chain artifact;",
)


CANONICAL_VULN_CLASSES = (
    "IDOR", "SSRF", "XSS", "Race", "Authz",
    "GraphQL", "OAuth", "Upload", "Webhook", "JWT",
    "SQLi", "XXE", "RCE", "Path", "CSRF",
    "NoSQLi", "PrototypePollution", "OpenRedirect", "BusinessLogic",
)
# Coverage Matrix owns the append-only Web2 classes above. Workflow
# is a closeable evidence family, but remains outside that matrix taxonomy.
CLOSURE_ONLY_FAMILIES = ("Workflow",)
CLOSURE_FAMILIES = CANONICAL_VULN_CLASSES + CLOSURE_ONLY_FAMILIES

VULN_CLASS_ALIASES = {
    **{vuln_class.lower(): vuln_class for vuln_class in CLOSURE_FAMILIES},
    "auth": "Authz",
    "access": "Authz",
    "access-control": "Authz",
    "auth-bypass": "Authz",
    "authentication-bypass": "Authz",
    "authorization-bypass": "Authz",
    "public-exposure": "Authz",
    "business-logic": "BusinessLogic",
    "businesslogic": "BusinessLogic",
    "mfa": "Authz",
    "saml": "Authz",
    "sql": "SQLi",
    "sql-injection": "SQLi",
    "sqlinjection": "SQLi",
    "sqlblind": "SQLi",
    "sqli-blind": "SQLi",
    "sqli-time": "SQLi",
    "blindsqli": "SQLi",
    "nosqli": "NoSQLi",
    "nosql-injection": "NoSQLi",
    "nosqlinjection": "NoSQLi",
    "cross-site-scripting": "XSS",
    "xss-dom": "XSS",
    "dom-xss": "XSS",
    "domxss": "XSS",
    "prototype-pollution": "PrototypePollution",
    "prototypepollution": "PrototypePollution",
    "pp": "PrototypePollution",
    "toctou": "Race",
    "file-upload": "Upload",
    "openredirect": "OpenRedirect",
    "open-redirect": "OpenRedirect",
    "redirect": "OpenRedirect",
    "oscommand": "RCE",
    "os-command": "RCE",
    "cmdinjection": "RCE",
    "cmd-injection": "RCE",
    "commandinjection": "RCE",
    "ssti": "RCE",
    "command-injection": "RCE",
    "deser": "RCE",
    "deserialization": "RCE",
    "unserialize": "RCE",
    "template-injection": "RCE",
    "templateinjection": "RCE",
    "lfi": "Path",
    "rfi": "Path",
    "pathtraversal": "Path",
    "path-traversal": "Path",
    "directory-traversal": "Path",
    "directorytraversal": "Path",
    "csrf-token": "CSRF",
    "xsrf": "CSRF",
    "xxe-blind": "XXE",
    "xml-injection": "XXE",
    "xmlinjection": "XXE",
    "xinclude": "XXE",
}


def canonical_vuln_class(vuln_hint: str) -> str:
    """归一化 closure 用的漏洞类名；未知/空/generic 返回空字符串。

    返回空字符串代表 fail-open：调用方不得把该线索视为已关闭。
    """
    value = str(vuln_hint or "").strip().lower().replace("_", "-")
    if not value or value == "generic":
        return ""
    return VULN_CLASS_ALIASES.get(value, "")


def extract_endpoint_parts(value: str) -> tuple[str, str]:
    """Return an endpoint's path and fragment using one URL parser."""
    raw = str(value or "").strip()
    if not raw:
        return "", ""
    if "://" in raw:
        try:
            parsed = urlparse(raw)
            path = parsed.path or "/"
            fragment = parsed.fragment
        except ValueError:
            path, _, fragment = raw.partition("#")
    else:
        path, _, fragment = raw.partition("#")
    return path.split("?", 1)[0], fragment


def extract_endpoint_path(value: str) -> str:
    """Project a URL or endpoint to its path without identity normalization."""
    return extract_endpoint_parts(value)[0]


def _normalize_endpoint_path(path: str) -> str:
    path = str(path or "").strip()
    if not path:
        return ""
    if not path.startswith("/"):
        path = "/" + path
    if path != "/":
        path = path.rstrip("/")
    return path


def canonical_endpoint_identity(value: str) -> str:
    """Return an exact endpoint identity while discarding document fragments."""
    raw = str(value or "").strip()
    if not raw:
        return ""
    try:
        parsed = urlparse(raw) if "://" in raw else urlparse(f"local://host/{raw.lstrip('/')}")
        path = _normalize_endpoint_path(parsed.path or "/")
        query = parsed.query
        fragment = parsed.fragment
    except ValueError:
        base, _, fragment = raw.partition("#")
        path, separator, query = base.partition("?")
        query = query if separator else ""
        path = _normalize_endpoint_path(path)
    if not path:
        return ""
    identity = f"{path}?{query}" if query else path
    if fragment.startswith("/"):
        identity = f"{identity}#{fragment}"
    return identity


def canonical_endpoint_path(value: str) -> str:
    """Normalize to a path while retaining semantic SPA hash routes."""
    identity = canonical_endpoint_identity(value)
    if not identity:
        return ""
    server_route, separator, fragment = identity.partition("#")
    path = server_route.split("?", 1)[0]
    if not separator:
        return path
    return f"{path}#{fragment.split('?', 1)[0]}"


def _closure_cell_key(value: dict | object):
    """Decode through the contract even when top-level/tools imports coexist."""
    from tools.identity_contract import ClosureCellKey

    if isinstance(value, ClosureCellKey):
        return value
    if not isinstance(value, dict) and callable(getattr(value, "to_dict", None)):
        value = value.to_dict()
    return ClosureCellKey.from_dict(value)


class ClosureResolver:
    """从 evidence summary / coverage matrix 构建闭合索引。"""

    def __init__(self, evidence_summary: dict | None = None, matrix: dict | None = None) -> None:
        self._closed_classes: dict[str, set[str]] = {}
        self._closed_ts: dict[str, str] = {}
        self._closed_results: dict[tuple[str, str], str] = {}
        self._closed_result_ts: dict[tuple[str, str], str] = {}
        self._closed_v2: dict[str, tuple[str, str]] = {}
        self._ingest_ledger(evidence_summary or {})
        self._ingest_matrix(matrix or {})

    def _mark(
        self,
        endpoint: str,
        vuln_class: str,
        ts: str = "",
        result: str = "",
    ) -> None:
        ep = canonical_endpoint_identity(endpoint)
        vc = canonical_vuln_class(vuln_class)
        if not ep or not vc:
            return
        self._closed_classes.setdefault(ep, set()).add(vc)
        ts = str(ts or "").strip()
        if ts:
            self._closed_ts[ep] = max(self._closed_ts.get(ep, ""), ts)
        result = str(result or "").strip()
        if result:
            key = (ep, vc)
            previous_ts = self._closed_result_ts.get(key, "")
            # 有时间戳时保留最新终态；旧记录没有时间戳时按 append 顺序覆盖。
            if not previous_ts or not ts or ts >= previous_ts:
                self._closed_results[key] = result
                self._closed_result_ts[key] = ts

    def _ingest_ledger(self, evidence_summary: dict) -> None:
        for cell in evidence_summary.get("closed_cells_v2") or []:
            if not isinstance(cell, dict):
                continue
            identity = cell.get("identity_v2")
            if not isinstance(identity, dict):
                continue
            try:
                key = _closure_cell_key(identity)
            except (ImportError, TypeError, ValueError, KeyError):
                continue
            result = str(cell.get("result") or "").strip()
            if result not in CLOSED_LEDGER_RESULTS:
                continue
            identity_key = key.identity_key
            ts = str(cell.get("ts") or "").strip()
            previous = self._closed_v2.get(identity_key)
            if previous is None or not previous[1] or not ts or ts >= previous[1]:
                self._closed_v2[identity_key] = (result, ts)
        for cell in evidence_summary.get("closed_cells") or []:
            if not isinstance(cell, dict):
                continue
            result = str(cell.get("result") or "").strip()
            if result and result not in CLOSED_LEDGER_RESULTS:
                continue
            self._mark(
                str(cell.get("endpoint") or ""),
                str(cell.get("vuln_class") or ""),
                str(cell.get("ts") or ""),
                result,
            )

    def _ingest_matrix(self, matrix: dict) -> None:
        """Ingest only structural N/A projections from Coverage.

        ``tested_clean``/``tested_finding`` and operator-authored ``n_a``
        statuses require a matching Ledger terminal row.  Treating all matrix
        statuses as evidence made an arbitrary JSON edit sufficient for
        closure.
        """
        for endpoint_row in matrix.get("endpoints") or []:
            if not isinstance(endpoint_row, dict):
                continue
            endpoint = str(endpoint_row.get("endpoint") or "")
            cells = endpoint_row.get("cells")
            if not isinstance(cells, dict):
                continue
            for vuln_class, cell in cells.items():
                if not isinstance(cell, dict):
                    continue
                status = str(cell.get("status") or "")
                reason = str(cell.get("reason") or "")
                if status == "n_a" and any(
                    marker in reason for marker in _STRUCTURAL_NA_MARKERS
                ):
                    self._mark(
                        endpoint,
                        str(vuln_class),
                        result=status,
                    )

    def is_cell_closed(
        self,
        endpoint: str,
        vuln_class: str,
        *,
        identity_v2: dict | object | None = None,
    ) -> bool:
        """同一 endpoint × vuln_class 是否已关闭。

        Authz 和 IDOR 不互相关闭；unknown/generic 不关闭。
        """
        if identity_v2 is not None:
            try:
                key = _closure_cell_key(identity_v2)
            except (ImportError, TypeError, ValueError, KeyError):
                return False
            if (
                key.endpoint != canonical_endpoint_identity(endpoint)
                or key.family != canonical_vuln_class(vuln_class)
            ):
                return False
            return self.is_closure_closed(key)
        ep = canonical_endpoint_identity(endpoint)
        vc = canonical_vuln_class(vuln_class)
        if not ep or not vc:
            return False
        return vc in self._closed_classes.get(ep, set())

    def is_closure_closed(self, identity_v2: dict | object) -> bool:
        """Check only a complete v2 key; malformed/incomplete keys fail open."""
        try:
            key = _closure_cell_key(identity_v2)
        except (ImportError, TypeError, ValueError, KeyError):
            return False
        result_ts = self._closed_v2.get(key.identity_key)
        return bool(result_ts and result_ts[0])

    def closed_result(
        self,
        endpoint: str,
        vuln_class: str,
        *,
        identity_v2: dict | object | None = None,
    ) -> str:
        """返回精确 endpoint × vuln_class 的终态标签；未知类型 fail-open。"""
        if identity_v2 is not None:
            try:
                key = _closure_cell_key(identity_v2)
            except (ImportError, TypeError, ValueError, KeyError):
                return ""
            if (
                key.endpoint != canonical_endpoint_identity(endpoint)
                or key.family != canonical_vuln_class(vuln_class)
            ):
                return ""
            return self._closed_v2.get(key.identity_key, ("", ""))[0]
        ep = canonical_endpoint_identity(endpoint)
        vc = canonical_vuln_class(vuln_class)
        if not ep or not vc:
            return ""
        return self._closed_results.get((ep, vc), "")

    def are_endpoints_closed(
        self,
        endpoints: list[str],
        required_classes: set[str] | None = None,
    ) -> bool:
        """一批 endpoint 是否全部关闭。

        required_classes 非空时，每个 endpoint 必须命中其中一个已关闭漏洞类；
        为空时，有任意已关闭类即可。空 endpoint 列表 fail-open。
        """
        eps = [canonical_endpoint_identity(item) for item in endpoints or []]
        eps = [item for item in eps if item]
        if not eps:
            return False
        required = {
            canonical_vuln_class(item)
            for item in (required_classes or set())
        }
        required.discard("")
        if required_classes and not required:
            return False
        for ep in eps:
            classes = self._closed_classes.get(ep, set())
            if required:
                if not (classes & required):
                    return False
            elif not classes:
                return False
        return True

    def closed_after(self, endpoint_paths: list[str], ts: str) -> bool:
        """任一 endpoint 是否在 ts 之后出现终态关闭。"""
        ts = str(ts or "").strip()
        if not ts:
            return False
        for raw in endpoint_paths or []:
            ep = canonical_endpoint_identity(raw)
            if ep and self._closed_ts.get(ep, "") > ts:
                return True
        return False


def from_summary(evidence_summary: dict | None, matrix: dict | None = None) -> ClosureResolver:
    return ClosureResolver(evidence_summary, matrix)
