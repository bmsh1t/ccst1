"""
Recon output adapter — normalizes recon data across formats.

Reads the nested directory format produced by recon_engine.sh and provides
a unified API for agent.py, brain.py, and recon-ranker to consume recon data.

Handles fallback paths (e.g. httpx_full.txt at root vs live/httpx_full.txt)
and can normalize a recon directory by creating missing stub files that
brain.py expects (priority/, api_specs/, urls/graphql.txt, etc.).

Usage:
    adapter = ReconAdapter(Path("recon/target.com"))
    subs = adapter.get_subdomains()
    adapter.normalize()  # create missing stubs for brain.py
"""

import argparse
import gzip
import hashlib
import json
import os
import re
import tempfile
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator
from urllib.parse import urlsplit


FFUF_SUMMARY_SCHEMA = "ffuf-summary-v1"
FFUF_SUMMARY_PATH = Path("dirs/ffuf_summary.json")
FFUF_CANONICAL_PATHS = (
    Path("dirs/ffuf_results.jsonl.gz"),
    Path("dirs/ffuf_results.jsonl"),
)
FFUF_SAMPLE_LIMIT = 4
FFUF_HEAVY_CAPACITY = 16
FFUF_HEAVY_OUTPUT_LIMIT = 8
FFUF_ERROR_PREVIEW_LIMIT = 20
FFUF_PAGE_LIMIT_MAX = 1000


class ReconAdapter:
    """Unified reader for recon output directories."""

    GRAPHQL_PATTERNS = re.compile(
        r"graphql|/gql\b|/graphiql|/altair|/playground",
        re.IGNORECASE,
    )

    def __init__(self, recon_dir: str | Path):
        self._dir = Path(recon_dir)

    def _read_lines(self, *paths: str) -> list[str]:
        """Read non-empty lines from the first existing file in paths.

        Tries each path relative to self._dir in order, returns lines
        from the first one found. Deduplicates and strips whitespace.
        """
        for p in paths:
            fp = self._dir / p
            if fp.is_file():
                seen = set()
                result = []
                for line in fp.read_text(encoding="utf-8", errors="replace").splitlines():
                    line = line.strip()
                    if line and line not in seen:
                        seen.add(line)
                        result.append(line)
                return result
        return []

    # ── Data accessors ────────────────────────────────────────────────────

    def get_subdomains(self) -> list[str]:
        """All discovered subdomains."""
        return self._read_lines("subdomains/all.txt")

    def get_resolved_subdomains(self) -> list[str]:
        """Resolved subdomains (DNS-confirmed). Falls back to all.txt."""
        return self._read_lines("subdomains/resolved.txt", "subdomains/all.txt")

    def get_live_hosts(self) -> list[str]:
        """Live HTTP hosts. Extracts URLs from httpx output if needed."""
        # Try live/urls.txt first (clean URLs)
        lines = self._read_lines("live/urls.txt")
        if lines:
            return lines
        # Fallback: parse httpx_full.txt (format: "https://host [status] [type]")
        for path in ("live/httpx_full.txt", "httpx_full.txt"):
            fp = self._dir / path
            if fp.is_file():
                seen = set()
                result = []
                for line in fp.read_text(encoding="utf-8", errors="replace").splitlines():
                    url = line.strip().split()[0] if line.strip() else ""
                    if url and url not in seen:
                        seen.add(url)
                        result.append(url)
                return result
        return []

    def get_urls(self) -> list[str]:
        """All collected URLs."""
        return self._read_lines("urls/all.txt")

    def get_parameterized_urls(self) -> list[str]:
        """URLs with query parameters."""
        return self._read_lines("urls/with_params.txt", "params/with_params.txt")

    def get_js_files(self) -> list[str]:
        """JavaScript file URLs."""
        return self._read_lines("urls/js_files.txt")

    def get_api_endpoints(self) -> list[str]:
        """API endpoint URLs."""
        return self._read_lines("urls/api_endpoints.txt")

    def get_sensitive_paths(self) -> list[str]:
        """Sensitive file paths discovered."""
        return self._read_lines("urls/sensitive_paths.txt")

    def get_js_secrets(self) -> list[str]:
        """Potential secrets found in JavaScript files."""
        return self._read_lines("js/potential_secrets.txt")

    def get_interesting_params(self) -> list[str]:
        """Parameters flagged for injection testing."""
        return self._read_lines("params/interesting_params.txt")

    def get_config_exposure(self) -> list[str]:
        """Exposed configuration files."""
        return self._read_lines("exposure/config_files.txt")

    def get_graphql_endpoints(self) -> list[str]:
        """GraphQL endpoints — from dedicated file or filtered from all URLs."""
        # Prefer dedicated file
        dedicated = self._read_lines("urls/graphql.txt")
        if dedicated:
            return dedicated
        # Filter from all URLs
        all_urls = self.get_urls()
        return [u for u in all_urls if self.GRAPHQL_PATTERNS.search(u)]

    # ── FFUF artifact contract ───────────────────────────────────────────

    @staticmethod
    def _ffuf_error(error_state: dict | None, message: str) -> None:
        """记录 FFUF 解析错误，同时限制 AI-facing preview 的体积。"""
        if error_state is None:
            return
        error_state["count"] = int(error_state.get("count", 0) or 0) + 1
        preview = error_state.setdefault("preview", [])
        if len(preview) < FFUF_ERROR_PREVIEW_LIMIT:
            preview.append(str(message)[:240])

    @staticmethod
    def _open_ffuf_text(path: Path):
        """打开明文或 gzip 压缩的 FFUF 文本产物。"""
        if path.name.endswith(".gz"):
            return gzip.open(path, "rt", encoding="utf-8", errors="replace")
        return path.open("r", encoding="utf-8", errors="replace")

    @staticmethod
    def _safe_int(value: object) -> int:
        try:
            return int(value or 0)
        except (TypeError, ValueError):
            return 0

    @staticmethod
    def _safe_text(value: object) -> str:
        if value is None:
            return ""
        return " ".join(str(value).strip().splitlines())

    @classmethod
    def _project_ffuf_result(cls, record: object) -> dict | None:
        """把 FFUF result 投影为不含 config/header/cookie 的稳定事实字段。"""
        if not isinstance(record, dict):
            return None
        raw_url = record.get("url")
        if not isinstance(raw_url, str) or "\n" in raw_url or "\r" in raw_url:
            return None
        url = raw_url.strip()
        try:
            parsed = urlsplit(url)
        except ValueError:
            return None
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            return None

        input_value = ""
        raw_input = record.get("input")
        if isinstance(raw_input, dict):
            input_value = cls._safe_text(raw_input.get("FUZZ"))

        host = cls._safe_text(record.get("host")) or parsed.netloc
        return {
            "url": url,
            "status": cls._safe_int(record.get("status")),
            "length": cls._safe_int(record.get("length")),
            "words": cls._safe_int(record.get("words")),
            "lines": cls._safe_int(record.get("lines")),
            "content_type": cls._safe_text(
                record.get("content-type", record.get("content_type"))
            ),
            "redirect_location": cls._safe_text(
                record.get("redirectlocation", record.get("redirect_location"))
            ),
            "input": input_value,
            "host": host,
        }

    @staticmethod
    def _ffuf_signature(observation: dict) -> tuple[int, int, int, int, str]:
        return (
            int(observation.get("status", 0) or 0),
            int(observation.get("length", 0) or 0),
            int(observation.get("words", 0) or 0),
            int(observation.get("lines", 0) or 0),
            str(observation.get("content_type", "") or ""),
        )

    @staticmethod
    def _ffuf_signature_id(signature: tuple[int, int, int, int, str]) -> str:
        encoded = json.dumps(signature, ensure_ascii=False, separators=(",", ":"))
        return hashlib.sha256(encoded.encode("utf-8")).hexdigest()[:12]

    def _canonical_ffuf_path(self) -> Path | None:
        for relative_path in FFUF_CANONICAL_PATHS:
            path = self._dir / relative_path
            if path.is_file():
                return path
        return None

    def _legacy_ffuf_paths(self) -> list[Path]:
        """返回旧 root-JSON FFUF 文件，排除派生产物。"""
        dirs = self._dir / "dirs"
        if not dirs.is_dir():
            return []
        excluded = {"ffuf_summary.json"}
        paths = [
            path
            for pattern in ("ffuf_*.json", "ffuf_*.json.gz")
            for path in dirs.glob(pattern)
            if path.name not in excluded
        ]
        return sorted(set(paths), key=lambda item: item.name)

    def _ffuf_source_paths(self, *, include_legacy: bool) -> list[Path]:
        canonical = self._canonical_ffuf_path()
        if canonical is not None:
            return [canonical]
        return self._legacy_ffuf_paths() if include_legacy else []

    def _iter_ffuf_jsonl_records(
        self,
        path: Path,
        error_state: dict | None = None,
    ) -> Iterator[dict]:
        try:
            with self._open_ffuf_text(path) as handle:
                for line_number, line in enumerate(handle, 1):
                    text = line.strip()
                    if not text:
                        continue
                    try:
                        record = json.loads(text)
                    except json.JSONDecodeError as exc:
                        self._ffuf_error(
                            error_state,
                            f"{path.name}:{line_number}: invalid JSON ({exc.msg})",
                        )
                        continue
                    if not isinstance(record, dict):
                        self._ffuf_error(
                            error_state,
                            f"{path.name}:{line_number}: result is not an object",
                        )
                        continue
                    yield record
        except (OSError, EOFError) as exc:
            self._ffuf_error(error_state, f"{path.name}: read failed ({exc})")

    def _iter_ffuf_legacy_records(
        self,
        path: Path,
        error_state: dict | None = None,
    ) -> Iterator[dict]:
        """显式兼容旧 root JSON；默认 runtime/surface 不调用此大文件路径。"""
        try:
            with self._open_ffuf_text(path) as handle:
                payload = json.load(handle)
        except (OSError, EOFError, json.JSONDecodeError) as exc:
            self._ffuf_error(error_state, f"{path.name}: invalid legacy JSON ({exc})")
            return
        if not isinstance(payload, dict) or not isinstance(payload.get("results"), list):
            self._ffuf_error(error_state, f"{path.name}: missing results array")
            return
        for index, record in enumerate(payload["results"]):
            if not isinstance(record, dict):
                self._ffuf_error(error_state, f"{path.name}:results[{index}] is not an object")
                continue
            yield record

    def _iter_ffuf_records(
        self,
        paths: list[Path],
        error_state: dict | None = None,
    ) -> Iterator[dict]:
        for path in paths:
            if path.name.endswith((".jsonl", ".jsonl.gz")):
                yield from self._iter_ffuf_jsonl_records(path, error_state)
            else:
                yield from self._iter_ffuf_legacy_records(path, error_state)

    def _iter_projected_ffuf(
        self,
        paths: list[Path],
        error_state: dict | None = None,
    ) -> Iterator[dict]:
        for index, record in enumerate(self._iter_ffuf_records(paths, error_state), 1):
            observation = self._project_ffuf_result(record)
            if observation is None:
                self._ffuf_error(error_state, f"observation {index}: invalid or non-HTTP(S) URL")
                continue
            yield observation

    def iter_ffuf_observations(self, *, include_legacy: bool = False) -> Iterator[dict]:
        """逐条返回安全 FFUF observation，不将完整产物加载到内存。"""
        paths = self._ffuf_source_paths(include_legacy=include_legacy)
        yield from self._iter_projected_ffuf(paths)

    def get_ffuf_observations(
        self,
        *,
        offset: int = 0,
        limit: int = 100,
        status: int | None = None,
        signature_id: str = "",
        include_legacy: bool = False,
    ) -> list[dict]:
        """读取一页有界 FFUF 证据，可按客观 response group 过滤。"""
        if offset < 0:
            raise ValueError("offset must be >= 0")
        if limit < 0 or limit > FFUF_PAGE_LIMIT_MAX:
            raise ValueError(f"limit must be between 0 and {FFUF_PAGE_LIMIT_MAX}")
        wanted_signature = str(signature_id or "").strip().lower()
        result = []
        matched = 0
        for observation in self.iter_ffuf_observations(include_legacy=include_legacy):
            if status is not None and observation["status"] != status:
                continue
            if wanted_signature:
                current_id = self._ffuf_signature_id(self._ffuf_signature(observation))
                if current_id != wanted_signature:
                    continue
            if matched < offset:
                matched += 1
                continue
            matched += 1
            if len(result) >= limit:
                break
            result.append(observation)
        return result

    @staticmethod
    def _misra_gries_update(
        candidates: dict[tuple[int, int, int, int, str], int],
        signature: tuple[int, int, int, int, str],
    ) -> None:
        if signature in candidates:
            candidates[signature] += 1
            return
        if len(candidates) < FFUF_HEAVY_CAPACITY:
            candidates[signature] = 1
            return
        expired = []
        for current in list(candidates):
            candidates[current] -= 1
            if candidates[current] <= 0:
                expired.append(current)
        for current in expired:
            candidates.pop(current, None)

    def _read_ffuf_controls(self, controls_path: str | Path | None, error_state: dict) -> list[dict]:
        if not controls_path:
            return []
        path = Path(controls_path)
        if not path.is_file():
            self._ffuf_error(error_state, f"{path.name}: control artifact missing")
            return []
        controls = []
        for record in self._iter_ffuf_jsonl_records(path, error_state):
            observation = self._project_ffuf_result(record)
            if observation is None:
                self._ffuf_error(error_state, f"{path.name}: invalid control observation")
                continue
            if len(controls) < 32:
                controls.append(observation)
        return controls

    def get_ffuf_control_filter_size(self, controls_path: str | Path) -> int:
        """仅当两条 FFUF control 都是相同 200 时返回 SPA size。"""
        error_state: dict = {"count": 0, "preview": []}
        controls = self._read_ffuf_controls(controls_path, error_state)
        if error_state["count"] or len(controls) != 2:
            return 0
        first, second = controls
        first_length = int(first.get("length", 0) or 0)
        if (
            first.get("status") == 200
            and second.get("status") == 200
            and first_length > 0
            and int(second.get("length", 0) or 0) == first_length
        ):
            return first_length
        return 0

    def _relative_artifact_metadata(self, paths: list[Path]) -> list[dict]:
        metadata = []
        for path in paths:
            stat = path.stat()
            metadata.append({
                "path": path.relative_to(self._dir).as_posix(),
                "bytes": stat.st_size,
                "mtime_ns": stat.st_mtime_ns,
            })
        return metadata

    def _write_json_atomic(self, path: Path, payload: dict) -> None:
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
            os.replace(temp_path, path)
        except Exception:
            if temp_path is not None:
                try:
                    temp_path.unlink()
                except FileNotFoundError:
                    pass
            raise

    def summarize_ffuf_results(
        self,
        *,
        attempted: int = 0,
        succeeded: int = 0,
        failed: int = 0,
        control_failed: int = 0,
        controls_path: str | Path | None = None,
        include_legacy: bool = True,
    ) -> dict:
        """流式汇总 FFUF 证据为有界、事实性的 AI-facing summary。"""
        paths = self._ffuf_source_paths(include_legacy=include_legacy)
        if not paths:
            raise FileNotFoundError("no FFUF result artifact found")

        error_state: dict = {"count": 0, "preview": []}
        controls = self._read_ffuf_controls(controls_path, error_state)
        control_signatures = {self._ffuf_signature(item) for item in controls}
        status_counts: Counter[str] = Counter()
        heavy_candidates: dict[tuple[int, int, int, int, str], int] = {}
        sample = []
        sample_signatures: set[tuple[int, int, int, int, str]] = set()
        observations = 0

        for observation in self._iter_projected_ffuf(paths, error_state):
            observations += 1
            status_counts[str(observation["status"])] += 1
            signature = self._ffuf_signature(observation)
            self._misra_gries_update(heavy_candidates, signature)
            if signature not in sample_signatures and len(sample) < FFUF_SAMPLE_LIMIT:
                sample_signatures.add(signature)
                sample.append(observation)

        exact_counts: Counter[tuple[int, int, int, int, str]] = Counter()
        if heavy_candidates:
            wanted = set(heavy_candidates)
            for observation in self._iter_projected_ffuf(paths):
                signature = self._ffuf_signature(observation)
                if signature in wanted:
                    exact_counts[signature] += 1

        heavy_signatures = []
        ordered = sorted(exact_counts.items(), key=lambda item: (-item[1], item[0]))
        for signature, count in ordered[:FFUF_HEAVY_OUTPUT_LIMIT]:
            status_value, length, words, lines, content_type = signature
            heavy_signatures.append({
                "signature_id": self._ffuf_signature_id(signature),
                "status": status_value,
                "length": length,
                "words": words,
                "lines": lines,
                "content_type": content_type,
                "count": count,
                "ratio": round(count / observations, 6) if observations else 0.0,
                "matches_random_miss_control": signature in control_signatures,
            })

        artifacts = self._relative_artifact_metadata(paths)
        payload = {
            "schema": FFUF_SUMMARY_SCHEMA,
            "available": True,
            "artifact": artifacts[0]["path"] if len(artifacts) == 1 else "",
            "artifacts": artifacts,
            "attempted": max(0, int(attempted or 0)),
            "succeeded": max(0, int(succeeded or 0)),
            "failed": max(0, int(failed or 0)),
            "control_failed": max(0, int(control_failed or 0)),
            "observations": observations,
            "status_counts": dict(
                sorted(status_counts.items(), key=lambda item: self._safe_int(item[0]))
            ),
            "controls": controls,
            "heavy_signatures": heavy_signatures,
            "other_signature_observations": max(
                0,
                observations - sum(item["count"] for item in heavy_signatures),
            ),
            "review_sample": sample,
            "sample_count": len(sample),
            "overflow": max(0, observations - len(sample)),
            "parse_error_count": error_state["count"],
            "parse_error_preview": error_state["preview"],
            "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        }
        self._write_json_atomic(self._dir / FFUF_SUMMARY_PATH, payload)
        return payload

    def _summary_unavailable(self, *, stale: bool = False) -> dict:
        canonical = self._canonical_ffuf_path()
        legacy_count = len(self._legacy_ffuf_paths())
        return {
            "schema": FFUF_SUMMARY_SCHEMA,
            "available": False,
            "stale": stale,
            "needs_summary": bool(canonical or legacy_count),
            "legacy_raw_files": legacy_count,
            "artifact": canonical.relative_to(self._dir).as_posix() if canonical else "",
            "observations": 0,
            "status_counts": {},
            "controls": [],
            "heavy_signatures": [],
            "review_sample": [],
            "sample_count": 0,
            "overflow": 0,
        }

    def _resolve_summary_artifact(self, relative_path: object) -> Path | None:
        if not isinstance(relative_path, str) or not relative_path.strip():
            return None
        rel = Path(relative_path)
        if rel.is_absolute():
            return None
        try:
            path = (self._dir / rel).resolve()
            path.relative_to(self._dir.resolve())
        except (OSError, ValueError):
            return None
        return path

    def get_ffuf_summary(self) -> dict:
        """只读取 compact summary；此路径绝不解析完整 FFUF artifact。"""
        path = self._dir / FFUF_SUMMARY_PATH
        if not path.is_file():
            return self._summary_unavailable()
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return self._summary_unavailable(stale=True)
        if not isinstance(payload, dict) or payload.get("schema") != FFUF_SUMMARY_SCHEMA:
            return self._summary_unavailable(stale=True)

        artifacts = payload.get("artifacts")
        if not isinstance(artifacts, list) or not artifacts:
            return self._summary_unavailable(stale=True)
        for item in artifacts:
            if not isinstance(item, dict):
                return self._summary_unavailable(stale=True)
            artifact_path = self._resolve_summary_artifact(item.get("path"))
            if artifact_path is None or not artifact_path.is_file():
                return self._summary_unavailable(stale=True)
            try:
                stat = artifact_path.stat()
                expected_bytes = int(item.get("bytes", -1))
                expected_mtime = int(item.get("mtime_ns", -1))
            except (OSError, TypeError, ValueError):
                return self._summary_unavailable(stale=True)
            if stat.st_size != expected_bytes or stat.st_mtime_ns != expected_mtime:
                return self._summary_unavailable(stale=True)

        result = dict(payload)
        result["available"] = True
        result["stale"] = False
        result["needs_summary"] = False
        result["legacy_raw_files"] = len(self._legacy_ffuf_paths())
        return result

    # ── Summary ───────────────────────────────────────────────────────────

    def summary(self) -> dict:
        """Quick overview of recon data counts."""
        return {
            "subdomains": len(self.get_subdomains()),
            "live_hosts": len(self.get_live_hosts()),
            "urls": len(self.get_urls()),
            "parameterized_urls": len(self.get_parameterized_urls()),
            "js_files": len(self.get_js_files()),
            "api_endpoints": len(self.get_api_endpoints()),
            "sensitive_paths": len(self.get_sensitive_paths()),
            "graphql_endpoints": len(self.get_graphql_endpoints()),
        }

    # ── Normalize ─────────────────────────────────────────────────────────

    def normalize(self) -> None:
        """Ensure all files expected by brain.py exist.

        Creates missing directories and stub files so that brain.py's strict
        path lookups don't fail. Existing files are never overwritten.
        """
        if not self._dir.is_dir():
            return

        # Ensure directories
        for subdir in ("priority", "api_specs"):
            (self._dir / subdir).mkdir(parents=True, exist_ok=True)

        # subdomains/resolved.txt — derive from live hosts if missing
        self._ensure_file(
            "subdomains/resolved.txt",
            lambda: "\n".join(self._extract_domains_from_live()) + "\n"
            if self._extract_domains_from_live() else "",
        )

        # urls/graphql.txt — filter from all URLs
        self._ensure_file(
            "urls/graphql.txt",
            lambda: "\n".join(self.get_graphql_endpoints()) + "\n"
            if self.get_graphql_endpoints() else "",
        )

        # priority/prioritized_hosts.json
        self._ensure_file(
            "priority/prioritized_hosts.json",
            lambda: json.dumps(self._build_priority_json(), indent=2) + "\n",
        )

        # priority/critical_hosts.txt
        self._ensure_file("priority/critical_hosts.txt", lambda: "")

        # priority/high_hosts.txt
        self._ensure_file("priority/high_hosts.txt", lambda: "")

        # priority/attack_surface.md
        self._ensure_file(
            "priority/attack_surface.md",
            lambda: self._build_attack_surface_md(),
        )

        # api_specs stubs
        for stub in ("spec_urls.txt", "public_operations.txt",
                      "unauth_api_findings.txt", "summary.md"):
            self._ensure_file(f"api_specs/{stub}", lambda: "")

        # live/nuclei_takeovers.txt
        self._ensure_file("live/nuclei_takeovers.txt", lambda: "")

    def _ensure_file(self, rel_path: str, content_fn) -> None:
        """Create file if it doesn't exist. Never overwrites."""
        fp = self._dir / rel_path
        if fp.exists():
            return
        fp.parent.mkdir(parents=True, exist_ok=True)
        fp.write_text(content_fn(), encoding="utf-8")

    def _extract_domains_from_live(self) -> list[str]:
        """Extract bare domains from live host URLs."""
        hosts = self.get_live_hosts()
        domains = set()
        for url in hosts:
            # Strip scheme
            if "://" in url:
                url = url.split("://", 1)[1]
            domain = url.split("/", 1)[0].split(":")[0]
            if domain:
                domains.add(domain)
        return sorted(domains)

    def _build_priority_json(self) -> dict:
        """Build a basic prioritized hosts structure."""
        live = self.get_live_hosts()
        apis = self.get_api_endpoints()
        gql = self.get_graphql_endpoints()
        sensitive = self.get_sensitive_paths()

        hosts = {}
        for url in live:
            if "://" in url:
                domain = url.split("://", 1)[1].split("/", 1)[0]
            else:
                domain = url.split("/", 1)[0]

            if domain not in hosts:
                hosts[domain] = {"host": domain, "signals": [], "priority": "medium"}

            # Boost priority based on signals
            if any(domain in a for a in apis):
                hosts[domain]["signals"].append("api_endpoints")
                hosts[domain]["priority"] = "high"
            if any(domain in g for g in gql):
                hosts[domain]["signals"].append("graphql")
                hosts[domain]["priority"] = "high"
            if any(domain in s for s in sensitive):
                hosts[domain]["signals"].append("sensitive_paths")
                hosts[domain]["priority"] = "critical"

        return {"hosts": hosts}

    def _build_attack_surface_md(self) -> str:
        """Build a markdown attack surface summary."""
        s = self.summary()
        lines = [
            "# Attack Surface Summary\n",
            f"- Subdomains: {s['subdomains']}",
            f"- Live hosts: {s['live_hosts']}",
            f"- URLs collected: {s['urls']}",
            f"- Parameterized URLs: {s['parameterized_urls']}",
            f"- API endpoints: {s['api_endpoints']}",
            f"- JS files: {s['js_files']}",
            f"- GraphQL endpoints: {s['graphql_endpoints']}",
            f"- Sensitive paths: {s['sensitive_paths']}",
            "",
        ]
        return "\n".join(lines)


def _build_cli_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Read and normalize cached recon artifacts")
    parser.add_argument("--recon-dir", required=True, help="Per-target recon directory")
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--summarize-ffuf", action="store_true")
    action.add_argument("--read-ffuf", action="store_true")
    action.add_argument("--ffuf-control-size", action="store_true")
    parser.add_argument("--controls", default="", help="Result-only FFUF control JSONL")
    parser.add_argument("--attempted", type=int, default=0)
    parser.add_argument("--succeeded", type=int, default=0)
    parser.add_argument("--failed", type=int, default=0)
    parser.add_argument("--control-failed", type=int, default=0)
    parser.add_argument("--offset", type=int, default=0)
    parser.add_argument("--limit", type=int, default=100)
    parser.add_argument("--status", type=int)
    parser.add_argument("--signature-id", default="")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_cli_parser().parse_args(argv)
    adapter = ReconAdapter(args.recon_dir)
    try:
        if args.ffuf_control_size:
            if not args.controls:
                raise ValueError("--controls is required with --ffuf-control-size")
            print(adapter.get_ffuf_control_filter_size(args.controls))
            return 0
        if args.summarize_ffuf:
            payload = adapter.summarize_ffuf_results(
                attempted=args.attempted,
                succeeded=args.succeeded,
                failed=args.failed,
                control_failed=args.control_failed,
                controls_path=args.controls or None,
                include_legacy=True,
            )
            print(json.dumps(payload, ensure_ascii=False, sort_keys=True))
            return 0

        observations = adapter.get_ffuf_observations(
            offset=args.offset,
            limit=args.limit,
            status=args.status,
            signature_id=args.signature_id,
            include_legacy=True,
        )
        for observation in observations:
            print(json.dumps(observation, ensure_ascii=False, sort_keys=True))
        return 0
    except (FileNotFoundError, OSError, ValueError) as exc:
        print(json.dumps({"error": str(exc)}, ensure_ascii=False, sort_keys=True))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
