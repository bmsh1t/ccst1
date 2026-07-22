#!/usr/bin/env python3
"""Intel v2 远端 advisory 来源、缓存和统一 projection。

本模块只负责可重放的数据获取与规范化，不决定 finding、action 或最终攻击优先级。
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import signal
import ssl
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable


CACHE_SCHEMA_VERSION = 1
DEFAULT_COMPONENT_TTL_SECONDS = 6 * 60 * 60
DEFAULT_KEV_TTL_SECONDS = 6 * 60 * 60
DEFAULT_EPSS_TTL_SECONDS = 24 * 60 * 60
EPSS_BATCH_SIZE = 100
DEFAULT_COMPONENT_CONCURRENCY = 4
DEFAULT_NVD_MAX_SECONDS = 120.0
DEFAULT_NVD_REQUEST_MAX_SECONDS = 25.0
DEFAULT_NVD_RESULTS_PER_PAGE = 200

OSV_QUERY_URL = "https://api.osv.dev/v1/query"
GITHUB_ADVISORY_URL = "https://api.github.com/advisories"
NVD_CVE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"


class IntelSourceError(RuntimeError):
    """远端来源或缓存读取失败。"""


JsonFetcher = Callable[..., object]


def _call_with_wall_timeout(call: Callable[[], object], seconds: float) -> object:
    """在 POSIX 主线程中限制一次阻塞调用的真实墙钟时间。"""
    try:
        previous_timer = signal.getitimer(signal.ITIMER_REAL)
        previous_handler = signal.getsignal(signal.SIGALRM)
        if previous_timer[0] > 0:
            return call()

        def _raise_timeout(_signum, _frame):
            raise TimeoutError(f"wall-clock timeout after {seconds:g}s")

        signal.signal(signal.SIGALRM, _raise_timeout)
        signal.setitimer(signal.ITIMER_REAL, seconds)
    except (AttributeError, ValueError):
        return call()

    try:
        return call()
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous_handler)


def _map_queries_in_order(
    queries: list[dict],
    worker: Callable[[dict], tuple[dict, dict | None, str]],
    *,
    max_workers: int,
) -> list[tuple[dict, dict | None, str]]:
    """有界并发执行独立 query，并保持输入顺序供稳定合并。"""
    if not queries:
        return []
    worker_count = max(1, min(int(max_workers), len(queries)))
    if worker_count == 1:
        return [worker(query) for query in queries]
    with ThreadPoolExecutor(max_workers=worker_count) as executor:
        return list(executor.map(worker, queries))


PACKAGE_MAPPINGS: dict[str, dict] = {
    "nextjs": {"package": "next", "osv_ecosystem": "npm", "github_ecosystem": "npm", "nvd_keyword": "Next.js"},
    "next.js": {"package": "next", "osv_ecosystem": "npm", "github_ecosystem": "npm", "nvd_keyword": "Next.js"},
    "graphql": {"package": "graphql", "osv_ecosystem": "npm", "github_ecosystem": "npm", "nvd_keyword": "GraphQL"},
    "react": {"package": "react", "osv_ecosystem": "npm", "github_ecosystem": "npm", "nvd_keyword": "React"},
    "express": {"package": "express", "osv_ecosystem": "npm", "github_ecosystem": "npm", "nvd_keyword": "Express.js"},
    "axios": {"package": "axios", "osv_ecosystem": "npm", "github_ecosystem": "npm", "nvd_keyword": "Axios"},
    "webpack": {"package": "webpack", "osv_ecosystem": "npm", "github_ecosystem": "npm", "nvd_keyword": "webpack"},
    "lodash": {"package": "lodash", "osv_ecosystem": "npm", "github_ecosystem": "npm", "nvd_keyword": "lodash"},
    "jquery": {"package": "jquery", "osv_ecosystem": "npm", "github_ecosystem": "npm", "nvd_keyword": "jQuery"},
    "jsonwebtoken": {"package": "jsonwebtoken", "osv_ecosystem": "npm", "github_ecosystem": "npm", "nvd_keyword": "jsonwebtoken"},
    "django": {"package": "Django", "osv_ecosystem": "PyPI", "github_ecosystem": "pip", "nvd_keyword": "Django"},
    "flask": {"package": "Flask", "osv_ecosystem": "PyPI", "github_ecosystem": "pip", "nvd_keyword": "Flask"},
    "ruby on rails": {"package": "rails", "osv_ecosystem": "RubyGems", "github_ecosystem": "rubygems", "nvd_keyword": "Ruby on Rails"},
    "rails": {"package": "rails", "osv_ecosystem": "RubyGems", "github_ecosystem": "rubygems", "nvd_keyword": "Ruby on Rails"},
    "laravel": {"package": "laravel/framework", "osv_ecosystem": "Packagist", "github_ecosystem": "composer", "nvd_keyword": "Laravel"},
    "wordpress": {"nvd_keyword": "WordPress", "allow_nvd_without_version": True},
    "elementor": {"nvd_keyword": "WordPress Elementor plugin"},
    "gravity forms": {"nvd_keyword": "WordPress Gravity Forms plugin"},
    "contact form 7": {"nvd_keyword": "WordPress Contact Form 7 plugin"},
    "yoast seo": {"nvd_keyword": "WordPress Yoast SEO plugin"},
    "yoast seo premium": {"nvd_keyword": "WordPress Yoast SEO Premium plugin"},
    "monsterinsights": {"nvd_keyword": "WordPress MonsterInsights plugin"},
    "ivory search": {"nvd_keyword": "WordPress Ivory Search plugin"},
    "site kit": {"nvd_keyword": "WordPress Site Kit plugin"},
    "nginx": {"nvd_keyword": "nginx", "allow_nvd_without_version": True},
    "apache http server": {"nvd_keyword": "Apache HTTP Server", "allow_nvd_without_version": True},
    "tomcat": {"nvd_keyword": "Apache Tomcat", "allow_nvd_without_version": True},
    "php": {"nvd_keyword": "PHP", "allow_nvd_without_version": False},
    "jenkins": {"nvd_keyword": "Jenkins", "allow_nvd_without_version": True},
    "drupal": {"nvd_keyword": "Drupal", "allow_nvd_without_version": True},
    "joomla": {"nvd_keyword": "Joomla", "allow_nvd_without_version": True},
    "cpanel": {"nvd_keyword": "cPanel", "allow_nvd_without_version": True},
}


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _iso_utc(value: datetime | None = None) -> str:
    return (value or _now_utc()).astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_utc(value: str) -> datetime | None:
    text = str(value or "").strip()
    if not text:
        return None
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _ssl_context() -> ssl.SSLContext:
    try:
        import certifi  # type: ignore
    except ImportError:
        return ssl.create_default_context()
    return ssl.create_default_context(cafile=certifi.where())


def fetch_json(
    url: str,
    *,
    method: str = "GET",
    body: object | None = None,
    headers: dict[str, str] | None = None,
    timeout: int = 20,
) -> object:
    """执行一次 JSON HTTP 请求；错误向上转换为可诊断异常。"""
    request_headers = {
        "Accept": "application/json",
        "User-Agent": "ccst-intel-v2/1.0",
        **(headers or {}),
    }
    data = None
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        request_headers.setdefault("Content-Type", "application/json")
    request = urllib.request.Request(
        url,
        data=data,
        headers=request_headers,
        method=method.upper(),
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout, context=_ssl_context()) as response:
            raw = response.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        retry_after = exc.headers.get("Retry-After", "") if exc.headers else ""
        detail = f"HTTP {exc.code}"
        if retry_after:
            detail += f" retry-after={retry_after}"
        raise IntelSourceError(f"{detail} for {url}") from exc
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise IntelSourceError(f"request failed for {url}: {exc}") from exc
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        raise IntelSourceError(f"invalid JSON from {url}: {exc}") from exc


def _write_json_atomic(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            "w",
            encoding="utf-8",
            dir=str(path.parent),
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as handle:
            temp_path = Path(handle.name)
            handle.write(json.dumps(payload, ensure_ascii=False, indent=2) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        temp_path.replace(path)
    except Exception:
        if temp_path is not None:
            try:
                temp_path.unlink()
            except FileNotFoundError:
                pass
        raise


def _cache_path(repo_root: str | Path, source: str, query: object) -> Path:
    serialized = json.dumps(query, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    digest = hashlib.sha256(serialized.encode("utf-8")).hexdigest()
    return Path(repo_root) / "state" / "intel-cache" / source / f"{digest}.json"


def _read_cache(path: Path, *, source: str, query: object) -> dict | None:
    if not path.is_file():
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(payload, dict) or payload.get("schema_version") != CACHE_SCHEMA_VERSION:
        return None
    if payload.get("source") != source or payload.get("query") != query:
        return None
    if "data" not in payload or _parse_utc(str(payload.get("fetched_at") or "")) is None:
        return None
    return payload


def cached_json_request(
    repo_root: str | Path,
    *,
    source: str,
    query: object,
    ttl_seconds: int,
    request: Callable[[], object],
    validate: Callable[[object], object] | None = None,
    now: datetime | None = None,
) -> dict:
    """返回缓存/远端结果；远端失败时允许显式使用 stale cache。"""
    current = (now or _now_utc()).astimezone(timezone.utc)
    path = _cache_path(repo_root, source, query)
    cached = _read_cache(path, source=source, query=query)
    if cached and validate is not None:
        try:
            cached["data"] = validate(cached["data"])
        except IntelSourceError:
            cached = None
    if cached:
        fetched_at = _parse_utc(str(cached.get("fetched_at") or ""))
        if fetched_at and (current - fetched_at).total_seconds() <= ttl_seconds:
            return {
                "data": cached["data"],
                "cached": True,
                "stale": False,
                "fetched_at": cached["fetched_at"],
                "error": "",
                "cache_path": str(path),
            }

    try:
        data = request()
        if validate is not None:
            data = validate(data)
    except Exception as exc:
        if cached:
            return {
                "data": cached["data"],
                "cached": True,
                "stale": True,
                "fetched_at": cached["fetched_at"],
                "error": str(exc),
                "cache_path": str(path),
            }
        raise IntelSourceError(str(exc)) from exc

    fetched_at = _iso_utc(current)
    _write_json_atomic(path, {
        "schema_version": CACHE_SCHEMA_VERSION,
        "source": source,
        "query": query,
        "fetched_at": fetched_at,
        "expires_at": _iso_utc(current + timedelta(seconds=ttl_seconds)),
        "data": data,
    })
    return {
        "data": data,
        "cached": False,
        "stale": False,
        "fetched_at": fetched_at,
        "error": "",
        "cache_path": str(path),
    }


def _mapping_for_name(name: str) -> dict:
    normalized = str(name or "").strip().lower()
    return dict(PACKAGE_MAPPINGS.get(normalized) or {})


def build_component_queries(components: list[dict]) -> list[dict]:
    """把 host 级组件观测折叠为目标级 package/product query。"""
    grouped: dict[tuple[str, str], dict] = {}
    for component in components:
        # 只有端口或通用 service 名称时先做版本/产品发现，不能按端口猜 CVE。
        if component.get("kind") == "unknown_service":
            continue
        name = str(component.get("name") or "").strip().lower()
        version = str(component.get("version") or "").strip()
        if not name:
            continue
        key = (name, version)
        item = grouped.setdefault(key, {
            "name": name,
            "display_name": str(component.get("display_name") or name).strip(),
            "version": version,
            "hosts": [],
            "urls": [],
            **_mapping_for_name(name),
        })
        kind = str(component.get("kind") or "").strip()
        if kind == "network_service":
            # Nmap 已给出产品身份时允许 product-level 回退；没有 product 的
            # unknown_service 已在上方排除。
            item["allow_nvd_without_version"] = True
        if version and not item.get("nvd_keyword"):
            # 未登记生态映射的新组件仍可做保守的 NVD product fallback；
            # 没有版本时不自动放宽，避免 CDN/header 标签制造大量关键词噪声。
            item["nvd_keyword"] = item["display_name"]
        elif kind == "network_service" and not item.get("nvd_keyword"):
            item["nvd_keyword"] = item["display_name"]
        host = str(component.get("host") or "").strip()
        url = str(component.get("url") or "").strip()
        if host and host not in item["hosts"]:
            item["hosts"].append(host)
        if url and url not in item["urls"]:
            item["urls"].append(url)
        try:
            port = int(component.get("port") or 0)
        except (TypeError, ValueError):
            port = 0
        if port and port not in item.get("ports", []):
            item.setdefault("ports", []).append(port)
        protocol = str(component.get("protocol") or "").strip().lower()
        if protocol and protocol not in item.get("protocols", []):
            item.setdefault("protocols", []).append(protocol)
        cpe = str(component.get("cpe") or "").strip()
        if cpe and cpe not in item.get("cpes", []):
            item.setdefault("cpes", []).append(cpe)
        if cpe.startswith("cpe:2.3:"):
            item["nvd_cpe"] = cpe
    return list(grouped.values())


def _severity(value: object) -> str:
    text = str(value or "UNKNOWN").upper()
    aliases = {"MODERATE": "MEDIUM", "IMPORTANT": "HIGH"}
    text = aliases.get(text, text)
    return text if text in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"} else "UNKNOWN"


def _require_object_collection(payload: object, *, source: str, field: str) -> dict:
    """校验对象型 API 响应，避免结构漂移被误解释为成功空结果。"""
    if not isinstance(payload, dict):
        raise IntelSourceError(f"{source} response must be a JSON object")
    values = payload.get(field, [])
    if not isinstance(values, list):
        raise IntelSourceError(f"{source} response field {field!r} must be an array")
    return payload


def _require_array_response(payload: object, *, source: str) -> list:
    """校验数组型 API 响应；校验发生在缓存写入前。"""
    if not isinstance(payload, list):
        raise IntelSourceError(f"{source} response must be a JSON array")
    return payload


def _component_ref(component: dict) -> dict:
    return {
        "name": component.get("name", ""),
        "display_name": component.get("display_name", ""),
        "version": component.get("version", ""),
        "package": component.get("package", ""),
        "ecosystem": component.get("osv_ecosystem") or component.get("github_ecosystem") or "",
        "hosts": list(component.get("hosts") or []),
        "urls": list(component.get("urls") or []),
        "ports": list(component.get("ports") or []),
        "protocols": list(component.get("protocols") or []),
        "cpes": list(component.get("cpes") or []),
    }


def _reference_has_poc_signal(url: str) -> bool:
    """只把明确 exploit/POC 形态的引用升级为 POC 信号。"""
    value = str(url or "").strip().lower()
    if not value:
        return False
    if any(
        domain in value
        for domain in (
            "exploit-db.com",
            "packetstormsecurity.com",
            "cxsecurity.com",
            "rapid7.com/db/modules/",
        )
    ):
        return True
    if "github.com" not in value:
        return False
    path = urllib.parse.urlparse(value).path
    return bool(
        re.search(r"(?:^|[-_/])(poc|proof-of-concept|exploit|metasploit)(?:$|[-_/])", path)
        or re.search(r"/(?:[^/]+/)?cve-\d{4}-\d{4,}(?:$|[-_/])", path)
    )


def _extract_fixed_versions(affected: object) -> list[str]:
    fixed: list[str] = []
    for entry in affected if isinstance(affected, list) else []:
        if not isinstance(entry, dict):
            continue
        for range_item in entry.get("ranges") or []:
            if not isinstance(range_item, dict):
                continue
            for event in range_item.get("events") or []:
                if isinstance(event, dict) and event.get("fixed"):
                    value = str(event["fixed"]).strip()
                    if value and value not in fixed:
                        fixed.append(value)
    return fixed


def _osv_item(item: dict, component: dict, fetched_at: str) -> dict:
    aliases = [str(alias) for alias in item.get("aliases") or [] if str(alias).strip()]
    item_id = str(item.get("id") or "").strip()
    if item_id and item_id not in aliases:
        aliases.insert(0, item_id)
    references = [
        str(ref.get("url") or "").strip()
        for ref in item.get("references") or []
        if isinstance(ref, dict) and str(ref.get("url") or "").strip()
    ]
    database_specific = item.get("database_specific") or {}
    return {
        "id": item_id or (aliases[0] if aliases else ""),
        "aliases": aliases,
        "source": "osv",
        "component": _component_ref(component),
        "applicability": "affected",
        "severity": _severity(database_specific.get("severity")),
        "cvss": None,
        "summary": str(item.get("summary") or item.get("details") or "").strip()[:500],
        "published": str(item.get("published") or ""),
        "modified": str(item.get("modified") or ""),
        "fixed_versions": _extract_fixed_versions(item.get("affected")),
        "affected_ranges": item.get("affected") or [],
        "poc_available": any(_reference_has_poc_signal(url) for url in references),
        "source_refs": [{
            "source": "osv",
            "id": item_id,
            "url": f"https://osv.dev/vulnerability/{urllib.parse.quote(item_id)}" if item_id else "",
            "references": references,
            "fetched_at": fetched_at,
        }],
    }


def fetch_osv_for_components(
    components: list[dict],
    repo_root: str | Path,
    *,
    fetcher: JsonFetcher = fetch_json,
    ttl_seconds: int = DEFAULT_COMPONENT_TTL_SECONDS,
    now: datetime | None = None,
    max_workers: int = DEFAULT_COMPONENT_CONCURRENCY,
) -> dict:
    component_queries = build_component_queries(components)
    queries = [
        item for item in component_queries
        if item.get("package") and item.get("osv_ecosystem") and item.get("version")
    ]
    items: list[dict] = []
    errors: list[str] = []
    cached_count = 0
    stale_count = 0
    fetched_at_values: list[str] = []

    def fetch_component(component: dict) -> tuple[dict, dict | None, str]:
        request_body = {
            "package": {
                "name": component["package"],
                "ecosystem": component["osv_ecosystem"],
            },
            "version": component["version"],
        }
        try:
            result = cached_json_request(
                repo_root,
                source="osv",
                query=request_body,
                ttl_seconds=ttl_seconds,
                request=lambda body=request_body: _require_object_collection(
                    fetcher(OSV_QUERY_URL, method="POST", body=body, timeout=20),
                    source="osv",
                    field="vulns",
                ),
                validate=lambda payload: _require_object_collection(
                    payload,
                    source="osv",
                    field="vulns",
                ),
                now=now,
            )
        except IntelSourceError as exc:
            return component, None, f"{component['name']}@{component['version']}: {exc}"
        return component, result, ""

    for component, result, error in _map_queries_in_order(
        queries,
        fetch_component,
        max_workers=max_workers,
    ):
        if error or result is None:
            errors.append(error)
            continue
        cached_count += int(result["cached"])
        stale_count += int(result["stale"])
        fetched_at_values.append(str(result["fetched_at"]))
        if result["error"]:
            errors.append(f"{component['name']}@{component['version']}: {result['error']}")
        payload = result["data"] if isinstance(result["data"], dict) else {}
        for raw in payload.get("vulns") or []:
            if isinstance(raw, dict):
                items.append(_osv_item(raw, component, result["fetched_at"]))

    return _source_envelope(
        "osv",
        items,
        eligible=len(queries),
        total_components=len(component_queries),
        errors=errors,
        cached_count=cached_count,
        stale_count=stale_count,
        fetched_at_values=fetched_at_values,
        now=now,
    )


def _github_item(item: dict, component: dict, fetched_at: str) -> dict:
    aliases: list[str] = []
    for identifier in item.get("identifiers") or []:
        if isinstance(identifier, dict) and identifier.get("value"):
            value = str(identifier["value"]).strip()
            if value and value not in aliases:
                aliases.append(value)
    for value in (item.get("ghsa_id"), item.get("cve_id")):
        text = str(value or "").strip()
        if text and text not in aliases:
            aliases.append(text)
    canonical = next((value for value in aliases if value.startswith("CVE-")), "")
    canonical = canonical or str(item.get("ghsa_id") or "").strip() or (aliases[0] if aliases else "")
    fixed_versions: list[str] = []
    affected_ranges: list[dict] = []
    for vuln in item.get("vulnerabilities") or []:
        if not isinstance(vuln, dict):
            continue
        affected_ranges.append(vuln)
        patched = vuln.get("first_patched_version")
        if isinstance(patched, dict) and patched.get("identifier"):
            value = str(patched["identifier"]).strip()
            if value and value not in fixed_versions:
                fixed_versions.append(value)
    cvss_payload = item.get("cvss") or {}
    try:
        cvss = float(cvss_payload.get("score")) if cvss_payload.get("score") is not None else None
    except (TypeError, ValueError):
        cvss = None
    url = str(item.get("html_url") or "").strip()
    references = []
    for value in item.get("references") or []:
        reference = str(value.get("url") or "").strip() if isinstance(value, dict) else str(value).strip()
        if reference and reference not in references:
            references.append(reference)
    if url and url not in references:
        references.append(url)
    poc_available = any(_reference_has_poc_signal(reference) for reference in references)
    return {
        "id": canonical,
        "aliases": aliases,
        "source": "github_advisory",
        "component": _component_ref(component),
        "applicability": "affected" if component.get("version") else "unknown",
        "severity": _severity(item.get("severity")),
        "cvss": cvss,
        "summary": str(item.get("summary") or item.get("description") or "").strip()[:500],
        "published": str(item.get("published_at") or ""),
        "modified": str(item.get("updated_at") or ""),
        "fixed_versions": fixed_versions,
        "affected_ranges": affected_ranges,
        "poc_available": poc_available,
        "source_refs": [{
            "source": "github_advisory",
            "id": str(item.get("ghsa_id") or canonical),
            "url": url,
            "references": references,
            "fetched_at": fetched_at,
        }],
    }


def fetch_github_advisories_for_components(
    components: list[dict],
    repo_root: str | Path,
    *,
    fetcher: JsonFetcher = fetch_json,
    ttl_seconds: int = DEFAULT_COMPONENT_TTL_SECONDS,
    now: datetime | None = None,
    max_workers: int = DEFAULT_COMPONENT_CONCURRENCY,
) -> dict:
    component_queries = build_component_queries(components)
    queries = [
        item for item in component_queries
        if item.get("package") and item.get("github_ecosystem")
    ]
    items: list[dict] = []
    errors: list[str] = []
    cached_count = 0
    stale_count = 0
    fetched_at_values: list[str] = []

    def fetch_component(component: dict) -> tuple[dict, dict | None, str]:
        affects = component["package"]
        if component.get("version"):
            affects += f"@{component['version']}"
        params = urllib.parse.urlencode({
            "ecosystem": component["github_ecosystem"],
            "affects": affects,
            "per_page": 100,
        })
        url = f"{GITHUB_ADVISORY_URL}?{params}"
        query = {"ecosystem": component["github_ecosystem"], "affects": affects, "per_page": 100}
        try:
            result = cached_json_request(
                repo_root,
                source="github-advisory",
                query=query,
                ttl_seconds=ttl_seconds,
                request=lambda request_url=url: _require_array_response(
                    fetcher(
                        request_url,
                        headers={"X-GitHub-Api-Version": "2022-11-28"},
                        timeout=20,
                    ),
                    source="github_advisory",
                ),
                validate=lambda payload: _require_array_response(
                    payload,
                    source="github_advisory",
                ),
                now=now,
            )
        except IntelSourceError as exc:
            return (
                component,
                None,
                f"{component['name']}@{component.get('version') or '?'}: {exc}",
            )
        return component, result, ""

    for component, result, error in _map_queries_in_order(
        queries,
        fetch_component,
        max_workers=max_workers,
    ):
        if error or result is None:
            errors.append(error)
            continue
        cached_count += int(result["cached"])
        stale_count += int(result["stale"])
        fetched_at_values.append(str(result["fetched_at"]))
        if result["error"]:
            errors.append(f"{component['name']}@{component.get('version') or '?'}: {result['error']}")
        payload = result["data"] if isinstance(result["data"], list) else []
        for raw in payload:
            if isinstance(raw, dict):
                items.append(_github_item(raw, component, result["fetched_at"]))

    return _source_envelope(
        "github_advisory",
        items,
        eligible=len(queries),
        total_components=len(component_queries),
        errors=errors,
        cached_count=cached_count,
        stale_count=stale_count,
        fetched_at_values=fetched_at_values,
        now=now,
    )


def _nvd_cvss(cve: dict) -> tuple[float | None, str]:
    metrics = cve.get("metrics") or {}
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        values = metrics.get(key) or []
        if not values or not isinstance(values[0], dict):
            continue
        cvss_data = values[0].get("cvssData") or {}
        try:
            score = float(cvss_data.get("baseScore"))
        except (TypeError, ValueError):
            score = None
        severity = _severity(cvss_data.get("baseSeverity") or values[0].get("baseSeverity"))
        return score, severity
    return None, "UNKNOWN"


_NVD_BRANCH_BEFORE_RE = re.compile(
    r"\b(?P<branch>\d+(?:\.\d+){1,2})\.[xX*]\s+"
    r"(?:versions?\s+)?(?:before|prior\s+to)\s+v?"
    r"(?P<fixed>\d+(?:\.\d+){1,3})\b",
    re.IGNORECASE,
)
_STRICT_NUMERIC_VERSION_RE = re.compile(r"^\d+(?:\.\d+){1,3}$")


def _nvd_summary_version_boundary(summary: str, component: dict) -> dict:
    """从明确的 NVD 英文摘要中提取保守的数字分支边界。"""
    text = str(summary or "").strip()
    labels = {
        str(component.get(key) or "").strip()
        for key in ("name", "display_name", "nvd_keyword")
        if str(component.get(key) or "").strip()
    }
    if not text or not labels:
        return {"applicability": "unknown", "fixed_versions": [], "affected_ranges": []}

    boundaries = []
    for sentence in re.split(r"(?<=[.!?;])\s+", text):
        if not any(
            re.match(
                rf"^\s*(?:the\s+)?{re.escape(label)}"
                r"(?:\s+(?:core|versions?|releases?))?\s+(?=\d)",
                sentence,
                re.IGNORECASE,
            )
            for label in labels
        ):
            continue
        for match in _NVD_BRANCH_BEFORE_RE.finditer(sentence):
            branch = match.group("branch")
            fixed = match.group("fixed")
            branch_parts = tuple(int(value) for value in branch.split("."))
            fixed_parts = tuple(int(value) for value in fixed.split("."))
            if fixed_parts[:len(branch_parts)] != branch_parts:
                continue
            boundaries.append({
                "type": "NVD_DESCRIPTION",
                "source": "nvd_description",
                "branch": f"{branch}.x",
                "fixed": fixed,
            })

    fixed_versions = list(dict.fromkeys(item["fixed"] for item in boundaries))
    observed = str(component.get("version") or "").strip()
    if not boundaries or not _STRICT_NUMERIC_VERSION_RE.fullmatch(observed):
        return {
            "applicability": "unknown",
            "fixed_versions": fixed_versions,
            "affected_ranges": boundaries,
        }

    observed_parts = tuple(int(value) for value in observed.split("."))
    matching = []
    for boundary in boundaries:
        branch_parts = tuple(int(value) for value in boundary["branch"][:-2].split("."))
        fixed_parts = tuple(int(value) for value in boundary["fixed"].split("."))
        if observed_parts[:len(branch_parts)] != branch_parts or len(observed_parts) != len(fixed_parts):
            continue
        matching.append("affected" if observed_parts < fixed_parts else "not_affected")
    applicability = matching[0] if matching and len(set(matching)) == 1 else "unknown"
    return {
        "applicability": applicability,
        "fixed_versions": fixed_versions,
        "affected_ranges": boundaries,
    }


def _nvd_item(raw: dict, component: dict, fetched_at: str) -> dict | None:
    cve = raw.get("cve") if isinstance(raw.get("cve"), dict) else raw
    if not isinstance(cve, dict):
        return None
    cve_id = str(cve.get("id") or "").strip()
    if not cve_id:
        return None
    descriptions = cve.get("descriptions") or []
    summary = next(
        (str(item.get("value") or "") for item in descriptions if isinstance(item, dict) and item.get("lang") == "en"),
        "",
    )
    cvss, severity = _nvd_cvss(cve)
    references = [
        str(item.get("url") or "").strip()
        for item in cve.get("references") or []
        if isinstance(item, dict) and str(item.get("url") or "").strip()
    ]
    configurations = cve.get("configurations") or []
    summary_boundary = (
        _nvd_summary_version_boundary(summary, component)
        if not configurations
        else {"applicability": "unknown", "fixed_versions": [], "affected_ranges": configurations}
    )
    return {
        "id": cve_id,
        "aliases": [cve_id],
        "source": "nvd",
        "component": _component_ref(component),
        "applicability": summary_boundary["applicability"],
        "severity": severity,
        "cvss": cvss,
        "summary": summary[:500],
        "published": str(cve.get("published") or ""),
        "modified": str(cve.get("lastModified") or ""),
        "fixed_versions": summary_boundary["fixed_versions"],
        "affected_ranges": summary_boundary["affected_ranges"],
        "poc_available": any(_reference_has_poc_signal(url) for url in references),
        "source_refs": [{
            "source": "nvd",
            "id": cve_id,
            "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            "references": references,
            "fetched_at": fetched_at,
        }],
    }


def fetch_nvd_for_components(
    components: list[dict],
    repo_root: str | Path,
    *,
    fetcher: JsonFetcher = fetch_json,
    ttl_seconds: int = DEFAULT_COMPONENT_TTL_SECONDS,
    now: datetime | None = None,
    max_components: int = 20,
    max_seconds: float = DEFAULT_NVD_MAX_SECONDS,
) -> dict:
    if max_components < 1:
        raise ValueError("max_components must be >= 1")
    if max_seconds <= 0:
        raise ValueError("max_seconds must be > 0")
    eligible_queries = []
    for item in build_component_queries(components):
        keyword = str(item.get("nvd_keyword") or "").strip()
        cpe_name = str(item.get("nvd_cpe") or "").strip()
        if not keyword and not cpe_name:
            continue
        if not item.get("version") and not item.get("allow_nvd_without_version"):
            continue
        eligible_queries.append(item)
    queries = eligible_queries[:max_components]
    partial_reasons = []
    if len(eligible_queries) > len(queries):
        partial_reasons.append(
            f"bounded NVD query limit applied: queried {len(queries)} "
            f"of {len(eligible_queries)} eligible components"
        )
    items: list[dict] = []
    errors: list[str] = []
    cached_count = 0
    stale_count = 0
    fetched_at_values: list[str] = []
    attempted_queries = 0
    deadline = time.monotonic() + max_seconds
    stop_nvd = False
    api_key = os.environ.get("NVD_API_KEY", "").strip()
    pending = deque()
    for component in queries:
        cpe_name = str(component.get("nvd_cpe") or "").strip()
        base_query = {"cpeName": cpe_name} if cpe_name else {
            "keywordSearch": component["nvd_keyword"]
        }
        pending.append((component, base_query, 0))

    while pending and not stop_nvd:
        component, base_query, start_index = pending.popleft()
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            partial_reasons.append(
                f"NVD time budget exhausted after {max_seconds:g}s; "
                "preserved cached/fetched pages for the next run"
            )
            break
        if start_index == 0:
            attempted_queries += 1
        query = {
            **base_query,
            "resultsPerPage": DEFAULT_NVD_RESULTS_PER_PAGE,
            "startIndex": start_index,
        }
        url = f"{NVD_CVE_URL}?{urllib.parse.urlencode(query)}"
        request_timeout = max(
            0.01,
            min(DEFAULT_NVD_REQUEST_MAX_SECONDS, remaining),
        )
        try:
            result = cached_json_request(
                repo_root,
                source="nvd",
                query=query,
                ttl_seconds=ttl_seconds,
                request=lambda request_url=url: _require_object_collection(
                    _call_with_wall_timeout(
                        lambda: fetcher(
                            request_url,
                            timeout=request_timeout,
                            headers={"apiKey": api_key} if api_key else None,
                        ),
                        request_timeout,
                    ),
                    source="nvd",
                    field="vulnerabilities",
                ),
                validate=lambda payload: _require_object_collection(
                    payload,
                    source="nvd",
                    field="vulnerabilities",
                ),
                now=now,
            )
        except IntelSourceError as exc:
            detail = f"{component['name']}@{component.get('version') or '?'}: {exc}"
            if re.search(r"\bHTTP (?:403|429)\b", str(exc)):
                partial_reasons.append(f"NVD rate limit stopped remaining queries: {detail}")
                stop_nvd = True
            elif "wall-clock timeout" in str(exc):
                partial_reasons.append(f"NVD request timeout; continuing other components: {detail}")
            else:
                errors.append(detail)
            continue
        cached_count += int(result["cached"])
        stale_count += int(result["stale"])
        fetched_at_values.append(str(result["fetched_at"]))
        if result["error"]:
            detail = (
                f"{component['name']}@{component.get('version') or '?'}: "
                f"{result['error']}"
            )
            if re.search(r"\bHTTP (?:403|429)\b", str(result["error"])):
                partial_reasons.append(
                    f"NVD rate limit stopped remaining queries: {detail}"
                )
                stop_nvd = True
            elif "wall-clock timeout" in str(result["error"]):
                partial_reasons.append(
                    f"NVD request timeout; continuing other components: {detail}"
                )
            else:
                errors.append(detail)
        payload = result["data"] if isinstance(result["data"], dict) else {}
        page = payload.get("vulnerabilities") or []
        for raw in page:
            if isinstance(raw, dict):
                item = _nvd_item(raw, component, result["fetched_at"])
                if item is not None:
                    items.append(item)

        # stale cache 已保留可用页，但限流后不能继续分页或查询其它组件。
        if stop_nvd:
            break

        try:
            total_results = int(payload.get("totalResults"))
        except (TypeError, ValueError):
            total_results = start_index + len(page)
        try:
            response_start = int(payload.get("startIndex", start_index))
        except (TypeError, ValueError):
            response_start = start_index
        if response_start != start_index:
            partial_reasons.append(
                f"NVD pagination start mismatch for {component['name']}: "
                f"requested {start_index}, received {response_start}"
            )
            continue
        next_index = start_index + len(page)
        if next_index >= total_results:
            continue
        if not page:
            partial_reasons.append(
                f"NVD pagination stopped early for {component['name']}: "
                f"received {next_index} of {total_results} results"
            )
            continue
        pending.append((component, base_query, next_index))

    return _source_envelope(
        "nvd",
        items,
        eligible=len(eligible_queries),
        attempted=attempted_queries,
        total_components=len(build_component_queries(components)),
        errors=errors,
        partial_reasons=partial_reasons,
        cached_count=cached_count,
        stale_count=stale_count,
        fetched_at_values=fetched_at_values,
        now=now,
    )


def _source_envelope(
    source: str,
    items: list[dict],
    *,
    eligible: int,
    attempted: int | None = None,
    total_components: int,
    errors: list[str],
    partial_reasons: list[str] | None = None,
    cached_count: int,
    stale_count: int,
    fetched_at_values: list[str],
    now: datetime | None,
) -> dict:
    attempted = eligible if attempted is None else attempted
    partial_reasons = partial_reasons or []
    if eligible == 0:
        status = "unavailable"
        error = "no eligible component/package query"
    elif errors and not fetched_at_values:
        status = "error"
        error = "; ".join(errors[:5])
    elif errors or stale_count or partial_reasons:
        status = "partial"
        error = "; ".join([*errors[:5], *partial_reasons[:3]])
    else:
        status = "ok"
        error = ""
    return {
        "source": source,
        "status": status,
        "fetched_at": min((value for value in fetched_at_values if value), default=_iso_utc(now)),
        "cached": bool(cached_count),
        "stale": bool(stale_count),
        "error": error,
        "items": items,
        "stats": {
            "eligible_queries": eligible,
            "attempted_queries": attempted,
            "total_components": total_components,
            "item_count": len(items),
            "cached_queries": cached_count,
            "stale_queries": stale_count,
            "error_count": len(errors),
        },
    }


def fetch_advisory_sources(
    components: list[dict],
    repo_root: str | Path,
    *,
    fetcher: JsonFetcher = fetch_json,
    now: datetime | None = None,
) -> list[dict]:
    """顺序收集目标组件 advisory；调用方负责合并与优先级。"""
    return [
        fetch_osv_for_components(components, repo_root, fetcher=fetcher, now=now),
        fetch_github_advisories_for_components(components, repo_root, fetcher=fetcher, now=now),
        fetch_nvd_for_components(components, repo_root, fetcher=fetcher, now=now),
    ]


def fetch_kev(
    repo_root: str | Path,
    *,
    fetcher: JsonFetcher = fetch_json,
    ttl_seconds: int = DEFAULT_KEV_TTL_SECONDS,
    now: datetime | None = None,
) -> dict:
    query = {"catalog": "cisa-kev"}
    try:
        result = cached_json_request(
            repo_root,
            source="kev",
            query=query,
            ttl_seconds=ttl_seconds,
            request=lambda: _require_object_collection(
                fetcher(KEV_URL, timeout=30),
                source="kev",
                field="vulnerabilities",
            ),
            validate=lambda payload: _require_object_collection(
                payload,
                source="kev",
                field="vulnerabilities",
            ),
            now=now,
        )
    except IntelSourceError as exc:
        return {
            "source": "kev",
            "status": "error",
            "fetched_at": _iso_utc(now),
            "cached": False,
            "stale": False,
            "error": str(exc),
            "items": {},
            "stats": {"item_count": 0},
        }
    payload = result["data"] if isinstance(result["data"], dict) else {}
    index = {}
    for item in payload.get("vulnerabilities") or []:
        if not isinstance(item, dict):
            continue
        cve_id = str(item.get("cveID") or "").strip().upper()
        if cve_id:
            index[cve_id] = item
    return {
        "source": "kev",
        "status": "partial" if result["stale"] else "ok",
        "fetched_at": result["fetched_at"],
        "cached": result["cached"],
        "stale": result["stale"],
        "error": result["error"],
        "items": index,
        "stats": {"item_count": len(index), "catalog_version": payload.get("catalogVersion", "")},
    }


def fetch_epss(
    cve_ids: list[str],
    repo_root: str | Path,
    *,
    fetcher: JsonFetcher = fetch_json,
    ttl_seconds: int = DEFAULT_EPSS_TTL_SECONDS,
    now: datetime | None = None,
) -> dict:
    normalized = sorted({str(value).strip().upper() for value in cve_ids if str(value).upper().startswith("CVE-")})
    if not normalized:
        return {
            "source": "epss",
            "status": "unavailable",
            "fetched_at": _iso_utc(now),
            "cached": False,
            "stale": False,
            "error": "no CVE identifiers to enrich",
            "items": {},
            "stats": {"item_count": 0, "batch_count": 0},
        }

    scores: dict[str, dict] = {}
    errors: list[str] = []
    cached_count = 0
    stale_count = 0
    fetched_at_values: list[str] = []
    batches = [normalized[index:index + EPSS_BATCH_SIZE] for index in range(0, len(normalized), EPSS_BATCH_SIZE)]
    for batch in batches:
        query = {"cve": batch}
        params = urllib.parse.urlencode({"cve": ",".join(batch)})
        url = f"{EPSS_URL}?{params}"
        try:
            result = cached_json_request(
                repo_root,
                source="epss",
                query=query,
                ttl_seconds=ttl_seconds,
                request=lambda request_url=url: _require_object_collection(
                    fetcher(request_url, timeout=20),
                    source="epss",
                    field="data",
                ),
                validate=lambda payload: _require_object_collection(
                    payload,
                    source="epss",
                    field="data",
                ),
                now=now,
            )
        except IntelSourceError as exc:
            errors.append(str(exc))
            continue
        cached_count += int(result["cached"])
        stale_count += int(result["stale"])
        fetched_at_values.append(str(result["fetched_at"]))
        if result["error"]:
            errors.append(result["error"])
        payload = result["data"] if isinstance(result["data"], dict) else {}
        for item in payload.get("data") or []:
            if not isinstance(item, dict):
                continue
            cve_id = str(item.get("cve") or "").strip().upper()
            if not cve_id:
                continue
            try:
                score = float(item.get("epss"))
            except (TypeError, ValueError):
                score = None
            try:
                percentile = float(item.get("percentile"))
            except (TypeError, ValueError):
                percentile = None
            scores[cve_id] = {
                "score": score,
                "percentile": percentile,
                "date": str(item.get("date") or ""),
            }

    if errors and not fetched_at_values:
        status = "error"
    elif errors or stale_count:
        status = "partial"
    else:
        status = "ok"
    return {
        "source": "epss",
        "status": status,
        "fetched_at": min((value for value in fetched_at_values if value), default=_iso_utc(now)),
        "cached": bool(cached_count),
        "stale": bool(stale_count),
        "error": "; ".join(errors[:5]),
        "items": scores,
        "stats": {"item_count": len(scores), "batch_count": len(batches)},
    }
