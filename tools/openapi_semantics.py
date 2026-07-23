#!/usr/bin/env python3
"""从 Recon 候选中提取 OpenAPI/Swagger operation 与认证声明。

该工具只写 discovery facts；schema 中的认证声明不会被提升为漏洞或已验证结论。
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import tempfile
import urllib.error
import urllib.request
from pathlib import Path
from typing import Callable
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit

try:
    from tools.target_paths import canonical_target_value, target_storage_key
except ImportError:  # pragma: no cover - 兼容 python3 tools/openapi_semantics.py
    from target_paths import canonical_target_value, target_storage_key


SCHEMA_VERSION = 1
HTTP_METHODS = frozenset({"get", "put", "post", "delete", "options", "head", "patch", "trace"})
PLATFORM_PATHS = {
    "firebase_init": "/__/firebase/init.json",
    "oauth_authorization_server": "/.well-known/oauth-authorization-server",
    "oauth_protected_resource": "/.well-known/oauth-protected-resource",
}
DEFAULT_MAX_RESPONSE_BYTES = 4 * 1024 * 1024
DEFAULT_MAX_PLATFORM_HOSTS = 20
URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.I)

SPEC_CANDIDATE_GROUPS = (
    (
        Path("exposure/api_doc_candidates.txt.validated"),
        Path("exposure/api_doc_candidates.txt"),
    ),
    (
        Path("exposure/api_leak_candidates.txt.validated"),
        Path("exposure/api_leak_candidates.txt"),
    ),
    (Path("exposure/api_leaks/swagger_leaks.txt"),),
    (Path("exposure/api_leaks/postleaks_urls.txt"),),
)

OWNED_ARTIFACTS = {
    "spec_urls": "spec_urls.txt",
    "operations": "operations.jsonl",
    "public_operations": "public_operations.txt",
    "auth_boundary_candidates": "auth_boundary_candidates.jsonl",
    "platform_metadata": "platform_metadata.jsonl",
    "errors": "errors.jsonl",
    "summary": "summary.json",
    "summary_markdown": "summary.md",
    "unauth_api_findings": "unauth_api_findings.txt",
}


class FetchError(RuntimeError):
    """远端文档获取失败，保留可选 HTTP 状态供 metadata miss 判断。"""

    def __init__(self, message: str, *, status: int | None = None):
        super().__init__(message)
        self.status = status


Fetcher = Callable[[str, int, int], tuple[bytes, str]]


def _dedupe_keep_order(values: list[str]) -> list[str]:
    seen: set[str] = set()
    output: list[str] = []
    for value in values:
        if value and value not in seen:
            seen.add(value)
            output.append(value)
    return output


def _read_lines(path: Path) -> list[str]:
    if not path.is_file():
        return []
    return [
        line.strip()
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines()
        if line.strip()
    ]


def _atomic_write_text(path: Path, content: str) -> None:
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
            handle.write(content)
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


def _jsonl(records: list[dict]) -> str:
    if not records:
        return ""
    return "\n".join(
        json.dumps(record, ensure_ascii=False, sort_keys=True)
        for record in records
    ) + "\n"


def _fetch_url(url: str, timeout: int, max_bytes: int) -> tuple[bytes, str]:
    request = urllib.request.Request(
        url,
        headers={
            "Accept": "application/json, application/yaml, text/yaml, */*;q=0.5",
            "User-Agent": "ccst-openapi-semantics/1.0",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            content_length = response.headers.get("Content-Length", "")
            if content_length.isdigit() and int(content_length) > max_bytes:
                raise FetchError(f"response exceeds {max_bytes} bytes")
            raw = response.read(max_bytes + 1)
            if len(raw) > max_bytes:
                raise FetchError(f"response exceeds {max_bytes} bytes")
            return raw, response.headers.get("Content-Type", "")
    except urllib.error.HTTPError as exc:
        raise FetchError(f"HTTP {exc.code} for {url}", status=exc.code) from exc
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise FetchError(f"request failed for {url}: {exc}") from exc


def _load_yaml(text: str) -> object:
    try:
        import yaml
    except ImportError as exc:  # pragma: no cover - 当前项目环境已安装 PyYAML
        raise ValueError("YAML parser unavailable (PyYAML not installed)") from exc
    try:
        return yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise ValueError(f"invalid YAML: {exc}") from exc


def parse_document(raw: bytes) -> dict:
    """解析 JSON/YAML，并拒绝非 OpenAPI/Swagger object。"""
    text = raw.decode("utf-8-sig", errors="replace")
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        payload = _load_yaml(text)
    if not isinstance(payload, dict):
        raise ValueError("document is not a JSON/YAML object")

    openapi_version = str(payload.get("openapi") or "")
    swagger_version = str(payload.get("swagger") or "")
    if openapi_version.startswith("3."):
        payload["_ccst_spec_kind"] = "openapi3"
        payload["_ccst_spec_version"] = openapi_version
    elif swagger_version.startswith("2."):
        payload["_ccst_spec_kind"] = "swagger2"
        payload["_ccst_spec_version"] = swagger_version
    else:
        raise ValueError("document is not OpenAPI 3.x or Swagger 2.x")
    if not isinstance(payload.get("paths"), dict):
        raise ValueError("schema paths must be an object")
    return payload


def _resolve_local_ref(spec: dict, value: object) -> object:
    if not isinstance(value, dict) or not isinstance(value.get("$ref"), str):
        return value
    ref = value["$ref"]
    if not ref.startswith("#/"):
        return value
    current: object = spec
    for raw_part in ref[2:].split("/"):
        part = raw_part.replace("~1", "/").replace("~0", "~")
        if not isinstance(current, dict) or part not in current:
            return value
        current = current[part]
    return current


def _normalize_parameter(spec: dict, raw: object) -> dict | None:
    resolved = _resolve_local_ref(spec, raw)
    if not isinstance(resolved, dict):
        return None
    location = str(resolved.get("in") or "").lower()
    name = str(resolved.get("name") or "").strip()
    if location not in {"path", "query", "header", "cookie"} or not name:
        return None
    schema = resolved.get("schema") if isinstance(resolved.get("schema"), dict) else {}
    parameter_type = str(schema.get("type") or resolved.get("type") or "")
    parameter_format = str(schema.get("format") or resolved.get("format") or "")
    output = {
        "name": name,
        "in": location,
        "required": bool(resolved.get("required")) or location == "path",
    }
    if parameter_type:
        output["type"] = parameter_type
    if parameter_format:
        output["format"] = parameter_format
    if isinstance(raw, dict) and isinstance(raw.get("$ref"), str):
        output["ref"] = raw["$ref"]
    return output


def _merge_parameters(spec: dict, path_item: dict, operation: dict) -> list[dict]:
    merged: dict[tuple[str, str], dict] = {}
    for raw in list(path_item.get("parameters") or []) + list(operation.get("parameters") or []):
        parameter = _normalize_parameter(spec, raw)
        if parameter:
            merged[(parameter["in"], parameter["name"])] = parameter
    return sorted(merged.values(), key=lambda item: (item["in"], item["name"]))


def _security_declaration(spec: dict, operation: dict) -> dict:
    if "security" in operation:
        value = operation.get("security")
        origin = "operation"
    elif "security" in spec:
        value = spec.get("security")
        origin = "global"
    else:
        return {"status": "unspecified", "schemes": [], "origin": "none"}

    if value == []:
        return {"status": "explicit_public", "schemes": [], "origin": origin}
    if not isinstance(value, list):
        return {"status": "unspecified", "schemes": [], "origin": origin}

    allows_anonymous = any(isinstance(item, dict) and not item for item in value)
    schemes = sorted({
        str(name)
        for item in value
        if isinstance(item, dict)
        for name in item
        if str(name).strip()
    })
    if allows_anonymous:
        status = "anonymous_optional"
    elif schemes:
        status = "declared_required"
    else:
        status = "unspecified"
    return {"status": status, "schemes": schemes, "origin": origin}


def _source_origin(source_url: str) -> str:
    parsed = urlsplit(source_url)
    return urlunsplit((parsed.scheme or "https", parsed.netloc, "", "", "")).rstrip("/")


def _expand_server_url(server: object, source_url: str) -> str | None:
    if not isinstance(server, dict) or not isinstance(server.get("url"), str):
        return None
    value = server["url"].strip()
    if not value:
        return None
    variables = server.get("variables") if isinstance(server.get("variables"), dict) else {}
    for name, definition in variables.items():
        if isinstance(definition, dict) and "default" in definition:
            value = value.replace("{" + str(name) + "}", str(definition["default"]))
    return urljoin(source_url, value)


def _operation_servers(spec: dict, path_item: dict, operation: dict, source_url: str) -> list[str]:
    if spec["_ccst_spec_kind"] == "swagger2":
        source = urlsplit(source_url)
        host = str(spec.get("host") or source.netloc).strip()
        if not host:
            return []
        schemes = spec.get("schemes") if isinstance(spec.get("schemes"), list) else []
        normalized_schemes = [str(item).lower() for item in schemes if str(item).lower() in {"http", "https"}]
        if not normalized_schemes:
            normalized_schemes = [source.scheme or "https"]
        base_path = "/" + str(spec.get("basePath") or "").strip("/")
        return [f"{scheme}://{host}{base_path}".rstrip("/") for scheme in normalized_schemes]

    raw_servers = operation.get("servers") or path_item.get("servers") or spec.get("servers") or []
    servers = [
        expanded
        for raw_server in raw_servers
        if (expanded := _expand_server_url(raw_server, source_url))
    ] if isinstance(raw_servers, list) else []
    return _dedupe_keep_order(servers or [_source_origin(source_url)])


def _join_operation_url(server: str, operation_path: str, parameters: list[dict]) -> str:
    parsed = urlsplit(server)
    joined_path = "/".join(
        part.strip("/")
        for part in (parsed.path, operation_path)
        if part.strip("/")
    )
    path = "/" + joined_path if joined_path else "/"
    query = parse_qsl(parsed.query, keep_blank_values=True)
    query.extend(
        (parameter["name"], "FUZZ")
        for parameter in parameters
        if parameter["in"] == "query"
    )
    return urlunsplit((parsed.scheme, parsed.netloc, path, urlencode(query), ""))


def extract_operations(spec: dict, source_url: str) -> list[dict]:
    """将单个 schema 展开成未合并的 operation facts。"""
    output: list[dict] = []
    title = str((spec.get("info") or {}).get("title") or "API") if isinstance(spec.get("info"), dict) else "API"
    for operation_path, raw_path_item in spec["paths"].items():
        path_item = _resolve_local_ref(spec, raw_path_item)
        if not isinstance(path_item, dict):
            continue
        for method, raw_operation in path_item.items():
            normalized_method = str(method).lower()
            operation = _resolve_local_ref(spec, raw_operation)
            if normalized_method not in HTTP_METHODS or not isinstance(operation, dict):
                continue
            parameters = _merge_parameters(spec, path_item, operation)
            security = _security_declaration(spec, operation)
            for server in _operation_servers(spec, path_item, operation, source_url):
                url = _join_operation_url(server, str(operation_path), parameters)
                output.append({
                    "schema_version": SCHEMA_VERSION,
                    "record_type": "openapi_operation",
                    "method": normalized_method.upper(),
                    "url": url,
                    "path": str(operation_path),
                    "operation_id": str(operation.get("operationId") or ""),
                    "operation_ids": [str(operation["operationId"])] if operation.get("operationId") else [],
                    "summary": str(operation.get("summary") or ""),
                    "api_title": title,
                    "parameters": parameters,
                    "security_status": security["status"],
                    "security_schemes": security["schemes"],
                    "security_declarations": [{"source": source_url, **security}],
                    "sources": [source_url],
                    "spec_versions": [spec["_ccst_spec_version"]],
                })
    return output


def merge_operations(operations: list[dict]) -> list[dict]:
    """按 method + resolved URL 合并重复 schema，同时保留冲突声明。"""
    merged: dict[tuple[str, str], dict] = {}
    for operation in operations:
        key = (operation["method"], operation["url"])
        current = merged.get(key)
        if current is None:
            merged[key] = operation
            continue
        current["sources"] = sorted(set(current["sources"] + operation["sources"]))
        current["spec_versions"] = sorted(set(current["spec_versions"] + operation["spec_versions"]))
        current["operation_ids"] = sorted(set(current["operation_ids"] + operation["operation_ids"]))
        current["operation_id"] = current["operation_ids"][0] if current["operation_ids"] else ""
        parameters = {
            (item["in"], item["name"]): item
            for item in current["parameters"] + operation["parameters"]
        }
        current["parameters"] = sorted(parameters.values(), key=lambda item: (item["in"], item["name"]))
        declarations = current["security_declarations"] + operation["security_declarations"]
        unique_declarations = {
            json.dumps(item, ensure_ascii=False, sort_keys=True): item
            for item in declarations
        }
        current["security_declarations"] = [
            unique_declarations[key]
            for key in sorted(unique_declarations)
        ]
        statuses = {item["status"] for item in current["security_declarations"]}
        current["security_status"] = statuses.pop() if len(statuses) == 1 else "conflicting_declarations"
        current["security_schemes"] = sorted({
            scheme
            for item in current["security_declarations"]
            for scheme in item.get("schemes", [])
        })
    return sorted(merged.values(), key=lambda item: (item["url"], item["method"]))


def _candidate_urls(recon_dir: Path) -> list[str]:
    lines: list[str] = []
    for candidates in SPEC_CANDIDATE_GROUPS:
        # validated 决定优先级，不替代 raw；exact 去重后两者并集不会重复获取。
        for relative_path in candidates:
            lines.extend(_read_lines(recon_dir / relative_path))
    urls: list[str] = []
    for line in lines:
        urls.extend(match.rstrip(")]},.;") for match in URL_RE.findall(line))
    return _dedupe_keep_order(urls)


def _live_origins(recon_dir: Path) -> list[str]:
    origins: list[str] = []
    for value in _read_lines(recon_dir / "live" / "urls.txt"):
        candidate = value if "://" in value else f"https://{value}"
        parsed = urlsplit(candidate)
        if parsed.scheme in {"http", "https"} and parsed.netloc:
            origins.append(urlunsplit((parsed.scheme, parsed.netloc, "", "", "")).rstrip("/"))
    return _dedupe_keep_order(origins)


def _metadata_fields(kind: str, payload: dict) -> dict:
    keys = {
        "firebase_init": (
            "projectId", "appId", "databaseURL", "storageBucket", "authDomain",
            "messagingSenderId", "measurementId", "apiKey",
        ),
        "oauth_authorization_server": (
            "issuer", "authorization_endpoint", "token_endpoint", "registration_endpoint",
            "jwks_uri", "revocation_endpoint", "introspection_endpoint", "scopes_supported",
            "response_types_supported", "grant_types_supported",
        ),
        "oauth_protected_resource": (
            "resource", "authorization_servers", "jwks_uri", "scopes_supported",
            "bearer_methods_supported", "resource_signing_alg_values_supported",
        ),
    }[kind]
    return {key: payload[key] for key in keys if key in payload}


def _collect_platform_metadata(
    origins: list[str],
    *,
    max_hosts: int,
    timeout: int,
    max_bytes: int,
    fetcher: Fetcher,
) -> tuple[list[dict], list[dict], dict]:
    selected = origins if max_hosts == 0 else origins[:max_hosts]
    records: list[dict] = []
    errors: list[dict] = []
    for origin in selected:
        for kind, path in PLATFORM_PATHS.items():
            url = origin + path
            try:
                raw, _content_type = fetcher(url, timeout, max_bytes)
            except FetchError as exc:
                # 常见 4xx 只是标准路径不存在；网络/5xx/超限才是采集错误。
                if exc.status is None or exc.status >= 500:
                    errors.append(_error_record(url, "metadata_fetch", str(exc)))
                continue
            try:
                payload = json.loads(raw.decode("utf-8-sig", errors="replace"))
            except json.JSONDecodeError:
                continue
            if not isinstance(payload, dict):
                continue
            fields = _metadata_fields(kind, payload)
            if not fields:
                continue
            discovered_urls = sorted({
                value
                for value in fields.values()
                if isinstance(value, str) and value.startswith(("http://", "https://"))
            })
            records.append({
                "schema_version": SCHEMA_VERSION,
                "record_type": "platform_metadata",
                "kind": kind,
                "url": url,
                "origin": origin,
                "fields": fields,
                "discovered_urls": discovered_urls,
            })
    return records, errors, {
        "total": len(origins),
        "attempted": len(selected),
        "overflow": max(0, len(origins) - len(selected)),
    }


def _error_record(source: str, stage: str, error: str) -> dict:
    return {
        "schema_version": SCHEMA_VERSION,
        "record_type": "openapi_semantics_error",
        "source": source,
        "stage": stage,
        "error": error,
    }


def _auth_boundary_records(operations: list[dict]) -> list[dict]:
    records = []
    for operation in operations:
        if operation["security_status"] == "unspecified":
            continue
        records.append({
            "schema_version": SCHEMA_VERSION,
            "record_type": "openapi_auth_boundary_candidate",
            "method": operation["method"],
            "url": operation["url"],
            "operation_id": operation["operation_id"],
            "security_status": operation["security_status"],
            "security_schemes": operation["security_schemes"],
            "security_declarations": operation["security_declarations"],
            "sources": operation["sources"],
            "requires_runtime_validation": True,
        })
    return records


def _summary_markdown(summary: dict) -> str:
    counts = summary["counts"]
    hosts = summary["metadata_hosts"]
    return (
        "# OpenAPI Semantic Recon\n\n"
        f"- Status: `{summary['status']}`\n"
        f"- Spec candidates: {counts['candidate_urls']}\n"
        f"- Parsed specs: {counts['specs_parsed']}\n"
        f"- Operations: {counts['operations']}\n"
        f"- Public/optional declarations: {counts['public_operations']}\n"
        f"- Auth boundary candidates: {counts['auth_boundary_candidates']}\n"
        f"- Platform metadata hits: {counts['platform_metadata']}\n"
        f"- Errors: {counts['errors']}\n"
        f"- Metadata hosts: total={hosts['total']}, attempted={hosts['attempted']}, overflow={hosts['overflow']}\n\n"
        "Schema authentication is discovery evidence only. Capture an anonymous baseline and a "
        "controlled authenticated/role/object differential before promoting any finding.\n"
    )


def run(
    repo_root: str | Path,
    target: str,
    *,
    max_platform_hosts: int = DEFAULT_MAX_PLATFORM_HOSTS,
    timeout: int = 10,
    max_response_bytes: int = DEFAULT_MAX_RESPONSE_BYTES,
    fetcher: Fetcher = _fetch_url,
) -> dict:
    if max_platform_hosts < 0:
        raise ValueError("max_platform_hosts must be >= 0")
    if timeout <= 0 or max_response_bytes <= 0:
        raise ValueError("timeout and max_response_bytes must be > 0")

    repo = Path(repo_root)
    resolved_target = canonical_target_value(target)
    storage_key = target_storage_key(resolved_target)
    recon_dir = repo / "recon" / storage_key
    api_specs_dir = recon_dir / "api_specs"
    candidate_urls = _candidate_urls(recon_dir)
    errors: list[dict] = []
    parsed_sources: list[str] = []
    raw_operations: list[dict] = []

    for source_url in candidate_urls:
        try:
            raw, _content_type = fetcher(source_url, timeout, max_response_bytes)
        except FetchError as exc:
            errors.append(_error_record(source_url, "spec_fetch", str(exc)))
            continue
        try:
            spec = parse_document(raw)
        except ValueError as exc:
            errors.append(_error_record(source_url, "spec_parse", str(exc)))
            continue
        parsed_sources.append(source_url)
        raw_operations.extend(extract_operations(spec, source_url))

    operations = merge_operations(raw_operations)
    public_operations = [
        operation
        for operation in operations
        if operation["security_status"] in {"explicit_public", "anonymous_optional"}
    ]
    auth_boundaries = _auth_boundary_records(operations)
    metadata, metadata_errors, metadata_hosts = _collect_platform_metadata(
        _live_origins(recon_dir),
        max_hosts=max_platform_hosts,
        timeout=timeout,
        max_bytes=max_response_bytes,
        fetcher=fetcher,
    )
    errors.extend(metadata_errors)

    if errors:
        status = "partial"
    elif parsed_sources or metadata:
        status = "ok"
    else:
        status = "empty"

    artifact_paths = {
        key: f"recon/{storage_key}/api_specs/{filename}"
        for key, filename in OWNED_ARTIFACTS.items()
    }
    summary = {
        "schema_version": SCHEMA_VERSION,
        "status": status,
        "target": resolved_target,
        "storage_key": storage_key,
        "counts": {
            "candidate_urls": len(candidate_urls),
            "specs_parsed": len(parsed_sources),
            "operations": len(operations),
            "public_operations": len(public_operations),
            "auth_boundary_candidates": len(auth_boundaries),
            "platform_metadata": len(metadata),
            "errors": len(errors),
        },
        "metadata_hosts": metadata_hosts,
        "artifacts": artifact_paths,
        "declaration_only": True,
    }

    writes = {
        "spec_urls": "\n".join(_dedupe_keep_order(parsed_sources)) + ("\n" if parsed_sources else ""),
        "operations": _jsonl(operations),
        "public_operations": "".join(
            f"{item['method']}\t{item['url']}\t{item['security_status']}\n"
            for item in public_operations
        ),
        "auth_boundary_candidates": _jsonl(auth_boundaries),
        "platform_metadata": _jsonl(metadata),
        "errors": _jsonl(errors),
        "summary_markdown": _summary_markdown(summary),
        # 兼容旧读取方；声明不能写入真实未认证 finding 文件。
        "unauth_api_findings": "",
    }
    for key, content in writes.items():
        _atomic_write_text(api_specs_dir / OWNED_ARTIFACTS[key], content)

    endpoints_path = recon_dir / "urls" / "api_endpoints.txt"
    merged_endpoints = _dedupe_keep_order(
        _read_lines(endpoints_path) + [operation["url"] for operation in operations]
    )
    _atomic_write_text(
        endpoints_path,
        "\n".join(merged_endpoints) + ("\n" if merged_endpoints else ""),
    )
    # summary.json 是本轮派生产物的完成标记，必须最后发布。
    _atomic_write_text(
        api_specs_dir / OWNED_ARTIFACTS["summary"],
        json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
    )
    return summary


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", required=True)
    parser.add_argument("--repo-root", default=".")
    parser.add_argument("--max-platform-hosts", type=int, default=DEFAULT_MAX_PLATFORM_HOSTS)
    parser.add_argument("--timeout", type=int, default=10)
    parser.add_argument("--max-response-bytes", type=int, default=DEFAULT_MAX_RESPONSE_BYTES)
    parser.add_argument("--json", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        summary = run(
            args.repo_root,
            args.target,
            max_platform_hosts=args.max_platform_hosts,
            timeout=args.timeout,
            max_response_bytes=args.max_response_bytes,
        )
    except (OSError, ValueError) as exc:
        print(f"openapi semantics failed: {exc}", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(summary, ensure_ascii=False, sort_keys=True))
    else:
        counts = summary["counts"]
        print(
            f"OpenAPI semantics: status={summary['status']} "
            f"specs={counts['specs_parsed']} operations={counts['operations']} "
            f"auth_boundaries={counts['auth_boundary_candidates']}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
