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

_VULN_ALIAS = {
    "idor": "IDOR",
    "authz": "Authz",
    "auth": "Authz",
    "access": "Authz",
    "access-control": "Authz",
    "auth-bypass": "Authz",
    "public-exposure": "Authz",
    "business-logic": "Authz",
    "sqli": "SQLi",
    "sql": "SQLi",
    "sql-injection": "SQLi",
    "xss": "XSS",
    "cross-site-scripting": "XSS",
    "ssrf": "SSRF",
    "race": "Race",
    "toctou": "Race",
    "graphql": "GraphQL",
    "oauth": "OAuth",
    "jwt": "JWT",
    "csrf": "CSRF",
    "upload": "Upload",
    "file-upload": "Upload",
    "webhook": "Webhook",
    "openredirect": "OpenRedirect",
    "open-redirect": "OpenRedirect",
    "redirect": "OpenRedirect",
    "rce": "RCE",
    "ssti": "RCE",
    "command-injection": "RCE",
    "path": "Path",
    "lfi": "Path",
    "path-traversal": "Path",
    "xxe": "XXE",
}


def canonical_vuln_class(vuln_hint: str) -> str:
    """归一化 closure 用的漏洞类名；未知/空/generic 返回空字符串。

    返回空字符串代表 fail-open：调用方不得把该线索视为已关闭。
    """
    value = str(vuln_hint or "").strip().lower().replace("_", "-")
    if not value or value == "generic":
        return ""
    return _VULN_ALIAS.get(value, "")


def canonical_endpoint_path(value: str) -> str:
    """归一化 endpoint 到 path-only 形态。"""
    raw = str(value or "").strip()
    if not raw:
        return ""
    if "://" in raw:
        try:
            parsed = urlparse(raw)
            path = parsed.path or "/"
        except ValueError:
            path = raw
    else:
        path = raw
    path = path.split("?", 1)[0].split("#", 1)[0].strip()
    if not path:
        return ""
    if not path.startswith("/"):
        path = "/" + path
    if path != "/":
        path = path.rstrip("/")
    return path


class ClosureResolver:
    """从 evidence summary / coverage matrix 构建闭合索引。"""

    def __init__(self, evidence_summary: dict | None = None, matrix: dict | None = None) -> None:
        self._closed_classes: dict[str, set[str]] = {}
        self._closed_ts: dict[str, str] = {}
        self._ingest_ledger(evidence_summary or {})
        self._ingest_matrix(matrix or {})

    def _mark(self, endpoint: str, vuln_class: str, ts: str = "") -> None:
        ep = canonical_endpoint_path(endpoint)
        vc = canonical_vuln_class(vuln_class)
        if not ep or not vc:
            return
        self._closed_classes.setdefault(ep, set()).add(vc)
        ts = str(ts or "").strip()
        if ts:
            self._closed_ts[ep] = max(self._closed_ts.get(ep, ""), ts)

    def _ingest_ledger(self, evidence_summary: dict) -> None:
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
            )

        # 兜底：summary 的 closed_cells 如果裁剪过，recent_entries 里的终态也能闭合。
        for entry in evidence_summary.get("recent_entries") or []:
            if not isinstance(entry, dict):
                continue
            if str(entry.get("result") or "") not in CLOSED_LEDGER_RESULTS:
                continue
            self._mark(
                str(entry.get("endpoint") or entry.get("raw_endpoint") or ""),
                str(entry.get("vuln_class") or ""),
                str(entry.get("ts") or ""),
            )

    def _ingest_matrix(self, matrix: dict) -> None:
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
                if str(cell.get("status") or "") in CLOSED_MATRIX_STATUSES:
                    self._mark(endpoint, str(vuln_class))

    def is_cell_closed(self, endpoint: str, vuln_class: str) -> bool:
        """同一 endpoint × vuln_class 是否已关闭。

        Authz 和 IDOR 不互相关闭；unknown/generic 不关闭。
        """
        ep = canonical_endpoint_path(endpoint)
        vc = canonical_vuln_class(vuln_class)
        if not ep or not vc:
            return False
        return vc in self._closed_classes.get(ep, set())

    def are_endpoints_closed(
        self,
        endpoints: list[str],
        required_classes: set[str] | None = None,
    ) -> bool:
        """一批 endpoint 是否全部关闭。

        required_classes 非空时，每个 endpoint 必须命中其中一个已关闭漏洞类；
        为空时，有任意已关闭类即可。空 endpoint 列表 fail-open。
        """
        eps = [canonical_endpoint_path(item) for item in endpoints or []]
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
            ep = canonical_endpoint_path(raw)
            if ep and self._closed_ts.get(ep, "") > ts:
                return True
        return False


def from_summary(evidence_summary: dict | None, matrix: dict | None = None) -> ClosureResolver:
    return ClosureResolver(evidence_summary, matrix)
