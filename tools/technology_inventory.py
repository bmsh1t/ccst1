#!/usr/bin/env python3
"""从 httpx 原始观测构建可重建的组件与版本清单。

`httpx_full.txt` 的方括号字段会随启用参数变化，调用方不能再自行用固定
下标读取技术栈。本模块拥有解析、规范化、source binding 与派生清单发布。
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

try:
    from tools.target_paths import canonical_target_value, target_storage_key
except ImportError:  # pragma: no cover - direct tools/ execution
    from target_paths import canonical_target_value, target_storage_key  # type: ignore


INVENTORY_SCHEMA_VERSION = 1
INVENTORY_RELATIVE_PATH = Path("live/technology_inventory.json")
HTTPX_JSON_CANDIDATES = (
    Path("live/httpx_full.jsonl"),
    Path("live/httpx.jsonl"),
)
HTTPX_TEXT_CANDIDATES = (
    Path("live/httpx_full.txt"),
    Path("httpx_full.txt"),
)

_STATUS_RE = re.compile(r"^\d{3}(?:,\d{3})*$")
_VERSION_SUFFIX_RE = re.compile(
    r"^(?P<name>.+?)(?P<sep>[:/])(?P<version>v?\d[0-9A-Za-z._+~-]*)$"
)
_SPACE_RE = re.compile(r"\s+")

# 仅用于无法同时识别 title/tech 的 legacy 行，避免把普通页面标题升级为组件。
_KNOWN_TECH_NAMES = {
    "akismet", "amazon cloudfront", "amazon s3", "amazon web services",
    "apache http server", "asp.net", "caddy", "cloudflare",
    "cloudflare bot management", "django", "drupal", "elementor",
    "express", "flask", "google cloud", "graphql", "hsts", "http/3",
    "iis windows server", "java", "jquery", "laravel", "litespeed",
    "microsoft httpapi", "mysql", "next.js", "nextjs", "nginx", "node.js",
    "php", "react", "ruby", "ruby on rails", "spring", "tomcat", "varnish",
    "vue.js", "wordpress", "wordpress block editor", "wp engine",
}

class TechnologyInventoryError(RuntimeError):
    """组件清单读取或校验失败。"""


def _now_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _normalized_name(value: str) -> str:
    return _SPACE_RE.sub(" ", str(value or "").strip()).lower()


def split_component_label(raw_label: str) -> tuple[str, str, str]:
    """返回 `(normalized_name, display_name, version)`。

    只把以数字开头的 `name:version` / `name/version` 后缀解释为版本，避免
    把普通标题中的冒号误当成组件版本。
    """
    label = _SPACE_RE.sub(" ", str(raw_label or "").strip())
    if not label:
        return "", "", ""
    match = _VERSION_SUFFIX_RE.match(label)
    if match:
        display_name = match.group("name").strip()
        version = match.group("version").lstrip("vV")
    else:
        display_name = label
        version = ""
    return _normalized_name(display_name), display_name, version


def _component_from_label(
    raw_label: str,
    *,
    url: str,
    host: str,
    source: str,
    confidence: str,
) -> dict | None:
    name, display_name, version = split_component_label(raw_label)
    if not name:
        return None
    return {
        "name": name,
        "display_name": display_name,
        "version": version,
        "raw_label": str(raw_label).strip(),
        "url": url,
        "host": host,
        "source": source,
        "confidence": confidence,
    }


def _looks_like_legacy_tech_group(value: str) -> bool:
    """保守识别缺少 title/length 字段的 legacy tech group。"""
    labels = [item.strip() for item in str(value or "").split(",") if item.strip()]
    if not labels:
        return False
    for label in labels:
        name, _display, version = split_component_label(label)
        if not version and name not in _KNOWN_TECH_NAMES:
            return False
    return True


def _status_from_json(payload: dict) -> str:
    value = payload.get("status_code")
    if value is None:
        value = payload.get("status-code")
    if value is None:
        return ""
    return str(value).strip()


def _json_tech_labels(payload: dict) -> list[str]:
    value = payload.get("tech")
    if value is None:
        value = payload.get("technologies")
    if isinstance(value, str):
        labels = [item.strip() for item in value.split(",") if item.strip()]
    elif isinstance(value, list):
        labels = [str(item).strip() for item in value if str(item).strip()]
    else:
        labels = []

    webserver = str(payload.get("webserver") or "").strip()
    if webserver and _normalized_name(webserver) not in {_normalized_name(item) for item in labels}:
        labels.append(webserver)
    return labels


def parse_httpx_json_line(line: str) -> dict | None:
    """解析一行 ProjectDiscovery httpx JSON。"""
    try:
        payload = json.loads(line)
    except json.JSONDecodeError:
        return None
    if not isinstance(payload, dict):
        return None

    url = str(payload.get("url") or payload.get("final_url") or "").strip()
    input_value = str(payload.get("input") or "").strip()
    if not url and input_value:
        url = input_value if "://" in input_value else f"https://{input_value}"
    parsed = urlparse(url)
    host = str(payload.get("host") or parsed.netloc or parsed.path or input_value).strip()
    if not url or not host:
        return None

    labels = _json_tech_labels(payload)
    components = [
        component
        for label in labels
        if (component := _component_from_label(
            label,
            url=url,
            host=host,
            source="httpx_jsonl",
            confidence="high",
        )) is not None
    ]
    return {
        "url": url,
        "host": host,
        "status": _status_from_json(payload),
        "title": str(payload.get("title") or "").strip(),
        "components": components,
    }


def parse_httpx_text_line(line: str) -> dict | None:
    """解析当前 recon 使用的 httpx 文本行。

    真实文件通常为 `URL [status] [length] [title] [tech]`。只有确认存在
    tech group 时才解析最后一组，宁可保留 unknown 也不把标题升级为组件。
    """
    text = str(line or "").strip()
    if not text:
        return None
    url = text.split(maxsplit=1)[0]
    if not url.startswith(("http://", "https://")):
        return None
    parsed = urlparse(url)
    host = parsed.netloc or parsed.path
    groups = [item.strip() for item in re.findall(r"\[([^\]]*)\]", text)]
    status = groups[0] if groups and _STATUS_RE.match(groups[0]) else ""

    # httpx 文本字段顺序会随模板变化，项目历史中同时存在：
    #   status -> length -> title -> tech
    #   status -> title -> tech -> length
    # 因此不能依赖固定下标。先排除 status 与纯数字 length，再在剩余组中
    # 保守区分 title/tech；原始 URL 与完整变体仍由 recon artifact 保留。
    content_groups = [
        value
        for index, value in enumerate(groups)
        if not (index == 0 and _STATUS_RE.match(value)) and not value.isdigit()
    ]
    tech_group = ""
    title = ""
    if len(content_groups) >= 2:
        title = content_groups[-2]
        tech_group = content_groups[-1]
    elif len(content_groups) == 1:
        only_group = content_groups[0]
        if _looks_like_legacy_tech_group(only_group):
            tech_group = only_group
        else:
            title = only_group

    labels = [item.strip() for item in tech_group.split(",") if item.strip()]
    components = [
        component
        for label in labels
        if (component := _component_from_label(
            label,
            url=url,
            host=host,
            source="httpx_text",
            confidence="medium",
        )) is not None
    ]
    return {
        "url": url,
        "host": host,
        "status": status,
        "title": title,
        "components": components,
    }


def _source_binding(path: Path, source_format: str) -> dict:
    stat = path.stat()
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return {
        "path": str(path),
        "format": source_format,
        "size": stat.st_size,
        "mtime_ns": stat.st_mtime_ns,
        "sha256": digest.hexdigest(),
    }


def _select_httpx_source(recon_dir: Path) -> tuple[Path | None, str]:
    for relative in HTTPX_JSON_CANDIDATES:
        candidate = recon_dir / relative
        if candidate.is_file() and _jsonl_has_observation(candidate):
            return candidate, "jsonl"
    for relative in HTTPX_TEXT_CANDIDATES:
        candidate = recon_dir / relative
        if candidate.is_file():
            return candidate, "text"
    return None, ""


def _jsonl_has_observation(path: Path) -> bool:
    """只把至少含一条有效观测的 JSONL 作为优先 source。"""
    try:
        with path.open(encoding="utf-8", errors="replace") as handle:
            return any(parse_httpx_json_line(line) is not None for line in handle if line.strip())
    except OSError:
        return False


def _dedupe_components(components: list[dict]) -> list[dict]:
    by_key: dict[tuple[str, str, str, str], dict] = {}
    for item in components:
        key = (
            str(item.get("name") or ""),
            str(item.get("version") or ""),
            str(item.get("host") or ""),
            str(item.get("url") or ""),
        )
        if key[0] and key not in by_key:
            by_key[key] = item
    return list(by_key.values())


def _dedupe_hosts(hosts: list[dict]) -> list[dict]:
    by_key: dict[tuple[str, str], dict] = {}
    for item in hosts:
        key = (str(item.get("host") or ""), str(item.get("url") or ""))
        if key[0]:
            by_key[key] = item
    return list(by_key.values())


def build_inventory_from_source(path: Path, source_format: str, *, target: str) -> dict:
    """从选定 raw source 构建 inventory payload。"""
    parser = parse_httpx_json_line if source_format == "jsonl" else parse_httpx_text_line
    hosts: list[dict] = []
    components: list[dict] = []
    parse_errors = 0
    with path.open(encoding="utf-8", errors="replace") as handle:
        for raw_line in handle:
            if not raw_line.strip():
                continue
            item = parser(raw_line)
            if item is None:
                parse_errors += 1
                continue
            hosts.append(item)
            components.extend(item.get("components") or [])

    return {
        "schema_version": INVENTORY_SCHEMA_VERSION,
        "target": canonical_target_value(target),
        "generated_at": _now_utc(),
        "status": "ready",
        "source": _source_binding(path, source_format),
        "hosts": _dedupe_hosts(hosts),
        "components": _dedupe_components(components),
        "stats": {
            "host_count": len(_dedupe_hosts(hosts)),
            "component_count": len(_dedupe_components(components)),
            "parse_errors": parse_errors,
        },
    }


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


def validate_inventory(payload: object) -> dict:
    if not isinstance(payload, dict):
        raise TechnologyInventoryError("technology inventory must be a JSON object")
    if payload.get("schema_version") != INVENTORY_SCHEMA_VERSION:
        raise TechnologyInventoryError(
            f"unsupported technology inventory schema: {payload.get('schema_version')!r}"
        )
    if not isinstance(payload.get("components"), list) or not isinstance(payload.get("hosts"), list):
        raise TechnologyInventoryError("technology inventory components/hosts must be arrays")
    if any(not isinstance(item, dict) for item in payload.get("components") or []):
        raise TechnologyInventoryError("technology inventory components must contain objects")
    if any(not isinstance(item, dict) for item in payload.get("hosts") or []):
        raise TechnologyInventoryError("technology inventory hosts must contain objects")
    if payload.get("status") != "ready":
        raise TechnologyInventoryError(
            f"invalid persisted technology inventory status: {payload.get('status')!r}"
        )
    if not str(payload.get("target") or "").strip():
        raise TechnologyInventoryError("technology inventory target is missing")
    if not isinstance(payload.get("source"), dict):
        raise TechnologyInventoryError("technology inventory source binding is missing")
    source = payload["source"]
    if source.get("format") not in {"jsonl", "text"}:
        raise TechnologyInventoryError("technology inventory source format is invalid")
    if not str(source.get("path") or "").strip():
        raise TechnologyInventoryError("technology inventory source path is missing")
    if not isinstance(source.get("size"), int) or not isinstance(source.get("mtime_ns"), int):
        raise TechnologyInventoryError("technology inventory source stat binding is invalid")
    if not re.fullmatch(r"[0-9a-f]{64}", str(source.get("sha256") or "")):
        raise TechnologyInventoryError("technology inventory source digest is invalid")
    return payload


def read_inventory(path: Path) -> dict:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise TechnologyInventoryError(f"invalid technology inventory {path}: {exc}") from exc
    return validate_inventory(payload)


def _binding_matches(binding: dict, path: Path, source_format: str) -> bool:
    try:
        stat = path.stat()
    except OSError:
        return False
    metadata_matches = bool(
        binding.get("format") == source_format
        and binding.get("size") == stat.st_size
        and binding.get("mtime_ns") == stat.st_mtime_ns
        and binding.get("path") == str(path)
    )
    if not metadata_matches:
        return False
    # 某些文件系统的时间戳粒度不足，同尺寸快速覆盖可能保持相同 mtime。
    # source binding 已保存 digest，因此 exact hit 还需比较内容指纹。
    return binding.get("sha256") == _source_binding(path, source_format).get("sha256")


def load_or_build_inventory(
    repo_root: str | Path,
    target: str,
    *,
    force: bool = False,
) -> dict:
    """读取 exact-hit inventory；缺失、损坏或 stale 时从 raw recon 重建。"""
    repo = Path(repo_root)
    resolved_target = canonical_target_value(target)
    recon_dir = repo / "recon" / target_storage_key(resolved_target)
    return load_or_build_inventory_for_recon_dir(
        recon_dir,
        target=resolved_target,
        force=force,
    )


def load_or_build_inventory_for_recon_dir(
    recon_dir: str | Path,
    *,
    target: str = "",
    force: bool = False,
) -> dict:
    """按已解析的 recon 目录读取/重建 inventory。

    Surface、legacy hunt 等 consumer 已持有 recon path，使用此入口可避免
    重复推导 target storage key。`target` 仅用于 artifact 可读标签。
    """
    recon_dir = Path(recon_dir)
    resolved_target = canonical_target_value(target) if target else recon_dir.name
    inventory_path = recon_dir / INVENTORY_RELATIVE_PATH
    source_path, source_format = _select_httpx_source(recon_dir)
    if source_path is None:
        return {
            "schema_version": INVENTORY_SCHEMA_VERSION,
            "target": resolved_target,
            "generated_at": _now_utc(),
            "status": "unavailable",
            "source": {},
            "hosts": [],
            "components": [],
            "stats": {"host_count": 0, "component_count": 0, "parse_errors": 0},
        }

    if inventory_path.is_file() and not force:
        try:
            existing = read_inventory(inventory_path)
        except TechnologyInventoryError:
            existing = {}
        if existing and existing.get("target") != resolved_target:
            existing = {}
        if existing and _binding_matches(existing.get("source") or {}, source_path, source_format):
            return existing

    payload = build_inventory_from_source(source_path, source_format, target=resolved_target)
    _write_json_atomic(inventory_path, payload)
    return payload


def component_labels(inventory: dict, *, include_versions: bool = True, limit: int = 0) -> list[str]:
    """返回目标级去重组件标签，供 legacy tech-stack consumer 兼容使用。"""
    labels: list[str] = []
    seen: set[str] = set()
    for item in inventory.get("components") or []:
        name = str(item.get("name") or "").strip()
        version = str(item.get("version") or "").strip()
        if not name:
            continue
        label = f"{name}:{version}" if include_versions and version else name
        if label in seen:
            continue
        seen.add(label)
        labels.append(label)
        if limit and len(labels) >= limit:
            break
    return labels


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Build normalized technology inventory from recon httpx output")
    parser.add_argument("--target", required=True, help="Target domain/IP/list")
    parser.add_argument("--repo-root", default=str(Path(__file__).resolve().parent.parent))
    parser.add_argument("--force", action="store_true", help="Rebuild even when source binding matches")
    parser.add_argument("--json", action="store_true", help="Print the complete inventory JSON")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        payload = load_or_build_inventory(args.repo_root, args.target, force=args.force)
    except (OSError, TechnologyInventoryError, ValueError) as exc:
        print(f"technology inventory error: {exc}", file=sys.stderr)
        return 1
    if args.json:
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    else:
        stats = payload.get("stats") or {}
        print(
            f"technology inventory: status={payload.get('status')} "
            f"hosts={stats.get('host_count', 0)} components={stats.get('component_count', 0)}"
        )
        for label in component_labels(payload):
            print(f"- {label}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
