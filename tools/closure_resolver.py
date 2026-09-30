#!/usr/bin/env python3
"""统一 closure 状态查询。

这个模块只回答一个机械问题：某条 Claude-facing 任务是否已经被账本终态关闭。
它不排序、不打分、不判断价值、不删除原始攻击面。未知类型一律 fail-open，
避免工具替 AI 静默丢线索。
"""

from __future__ import annotations

# A matrix is a projection owned by Coverage; only structural N/A cells are
# self-authenticating.  Every observed terminal result must come from the
# Evidence Ledger so a hand-edited matrix cannot close a lane by itself.
STRUCTURAL_NA_MARKERS = {
    "static_asset": "static asset;",
    "public_metadata": "standard/public metadata;",
    "route_prefix": "route prefix/container;",
    "minified_js_property_chain": "minified JS property-chain artifact;",
}


def is_structural_na(cell: dict) -> bool:
    """Only the controlled Coverage writer grants identity-free N/A."""
    marker = STRUCTURAL_NA_MARKERS.get(str(cell.get("structural_code") or ""))
    return bool(
        marker and cell.get("status") == "n_a"
        and cell.get("structural_source") == "coverage:endpoint_kind"
        and cell.get("structural_marker") == marker
        and str(cell.get("reason") or "").startswith(marker)
    )


try:
    from tools.evidence_identity import (
        CANONICAL_VULN_CLASSES, CLOSED_LEDGER_RESULTS, CLOSED_MATRIX_STATUSES,
        CLOSURE_ONLY_FAMILIES, CLOSURE_FAMILIES,
        VULN_CLASS_ALIASES, canonical_vuln_class, extract_endpoint_parts,
        extract_endpoint_path, canonical_endpoint_identity, canonical_endpoint_path, exact_endpoint_identity,
    )
except ImportError:  # pragma: no cover - direct tools/ execution
    from evidence_identity import (
        CANONICAL_VULN_CLASSES, CLOSED_LEDGER_RESULTS, CLOSED_MATRIX_STATUSES,
        CLOSURE_ONLY_FAMILIES, CLOSURE_FAMILIES,
        VULN_CLASS_ALIASES, canonical_vuln_class, extract_endpoint_parts,
        extract_endpoint_path, canonical_endpoint_identity, canonical_endpoint_path, exact_endpoint_identity,
    )


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
        self._closed_results: dict[tuple[str, str], str] = {}
        self._closed_v2: dict[str, tuple[str, str]] = {}
        self._ingest_ledger(evidence_summary or {})
        self._ingest_matrix(matrix or {})

    def _mark(
        self,
        endpoint: str,
        vuln_class: str,
        result: str = "",
    ) -> None:
        ep = canonical_endpoint_identity(endpoint)
        vc = canonical_vuln_class(vuln_class)
        if not ep or not vc:
            return
        self._closed_classes.setdefault(ep, set()).add(vc)
        result = str(result or "").strip()
        if result:
            key = (ep, vc)
            self._closed_results[key] = result

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
            if key.schema_version != 3:
                continue
            result = str(cell.get("result") or "").strip()
            if result not in CLOSED_LEDGER_RESULTS:
                continue
            identity_key = key.identity_key
            ts = str(cell.get("ts") or "").strip()
            previous = self._closed_v2.get(identity_key)
            if previous is None or not previous[1] or not ts or ts >= previous[1]:
                self._closed_v2[identity_key] = (result, ts)
        # Legacy endpoint×family cells remain audit-only and never authorize closure.

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
                if is_structural_na(cell):
                    self._mark(endpoint, str(vuln_class), result="n_a")

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
                key.endpoint != endpoint
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
                key.endpoint != endpoint
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

def from_summary(evidence_summary: dict | None, matrix: dict | None = None) -> ClosureResolver:
    return ClosureResolver(evidence_summary, matrix)
