"""
Recon output adapter — normalizes recon data across formats.

Reads the nested directory format produced by recon_engine.sh and provides
a unified API for Surface and native evidence review.

Handles fallback paths (e.g. httpx_full.txt at root vs live/httpx_full.txt)
and can normalize a recon directory by creating missing derived files used by
older artifact layouts (priority/, api_specs/, urls/graphql.txt, etc.).

Usage:
    adapter = ReconAdapter(Path("recon/target.com"))
    subs = adapter.get_subdomains()
    adapter.normalize()  # create missing derived artifact stubs
"""

import argparse
import base64
import gzip
import hashlib
import json
import re
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator
from urllib.parse import urlsplit


try:
    from tools.artifact_io import write_json_atomic, write_text_atomic
    from tools.technology_inventory import parse_httpx_text_line
except ImportError:  # pragma: no cover - direct tools/ execution
    from artifact_io import write_json_atomic, write_text_atomic
    from technology_inventory import parse_httpx_text_line


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
FFUF_BODY_DIGEST_MAX_BYTES = 1024 * 1024


class ReconAdapter:
    """Unified reader for recon output directories."""

    GRAPHQL_PATTERNS = re.compile(
        r"graphql|/gql\b|/graphiql|/altair|/playground",
        re.IGNORECASE,
    )

    def __init__(self, recon_dir: str | Path):
        self._dir = Path(recon_dir)

    def publish_xnlinkfinder_receipts(self, capture: Path, seeds: Path, raw: Path,
                                     output: Path, results: Path, exit_code: int,
                                     target: str) -> bool:
        """Preserve links; only observed successful inputs can advance collection."""
        from tools.scope_context import url_belongs_to_target

        attempted = seeds.read_text(encoding="utf-8").splitlines()
        log = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", capture.read_text(encoding="utf-8", errors="replace"))
        responses: dict[str, list[int]] = {}
        for line in log.splitlines():
            match = re.fullmatch(r"Response (\d{3}): (https?://\S+)", line.strip())
            if match and match[2] in attempted:
                responses.setdefault(match[2], []).append(int(match[1]))
        # xnLinkFinder can swallow errors and exit zero, including after a response.
        normal_output = (exit_code == 0 and raw.is_file()
                         and re.search(r"(?m)^Potential unique links found for .+: \d+", log)
                         and (f"Links successfully written to file {raw}" in log
                              or "No links were found so nothing written to file." in log)
                         and not re.search(r"(?im)^\s*ERROR\b|THE PROGRAM WAS STOPPED|DATA IS LIKELY TO BE INCOMPLETE", log))
        links = []
        if raw.is_file():
            for line in raw.read_text(encoding="utf-8", errors="replace").splitlines():
                value = line.strip()
                if value and (not value.lower().startswith(("http://", "https://", "//"))
                              or url_belongs_to_target(value, target)):
                    links.append(value)
        successful = {url for url, statuses in responses.items()
                      if normal_output and all(200 <= code < 300 for code in statuses)}
        write_text_atomic(output, "".join(url + "\n" for url in dict.fromkeys(links)))
        write_text_atomic(results, "".join(url + "\t" + ("ok" if url in successful else "partial") + "\n"
                                          for url in attempted))
        return len(successful) == len(attempted)

    def publish_katana_receipts(self, capture: Path, seeds: Path, output: Path,
                                results: Path, exit_code: int) -> None:
        """Publish discovered URLs before per-seed collection receipts; retain raw."""
        seen, successful, failed_origins = set(), set(), set()
        if capture.is_file():
            with capture.open(encoding="utf-8") as handle:
                for line in handle:
                    if not line.strip():
                        continue
                    row = json.loads(line)
                    request = row.get("request") if isinstance(row, dict) else None
                    endpoint = request.get("endpoint") if isinstance(request, dict) else None
                    if not isinstance(endpoint, str) or not endpoint.startswith(("http://", "https://")):
                        raise ValueError("invalid Katana request receipt")
                    seen.add(endpoint)
                    # Katana also emits discovery/deduplicated rows without a response.
                    if "response" not in row and not row.get("error"):
                        continue
                    response = row.get("response")
                    status = response.get("status_code") if isinstance(response, dict) else None
                    if row.get("error") or type(status) is not int or status < 100 or status >= 500 or status == 429:
                        failed_origins.add(urlsplit(endpoint)[:2])
                    else:
                        successful.add(endpoint.rstrip("/"))
        receipts = []
        for seed in seeds.read_text(encoding="utf-8").splitlines():
            ok = exit_code == 0 and seed.rstrip("/") in successful and urlsplit(seed)[:2] not in failed_origins
            receipts.append(seed + "\t" + ("ok" if ok else "partial") + "\n")
        write_text_atomic(output, "".join(url + "\n" for url in sorted(seen)))
        write_text_atomic(results, "".join(receipts))

    def publish_httpx_receipts(self, capture: Path, seeds: Path, results: Path,
                               exit_code: int) -> None:
        """Merge actual responses before marking inputs complete; keep misses retryable."""
        attempted = seeds.read_text(encoding="utf-8").splitlines()
        successful = set()
        rows = []
        for line in capture.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            parsed = parse_httpx_text_line(line)
            if parsed is None or not re.fullmatch(r"[1-5]\d\d", str(parsed["status"])):
                raise ValueError("invalid httpx response receipt")
            url = urlsplit(parsed["url"])
            matched = False
            for seed in attempted:
                candidate = urlsplit(seed if "://" in seed else "//" + seed)
                if candidate.hostname != url.hostname:
                    continue
                if candidate.scheme and candidate.scheme != url.scheme:
                    continue
                candidate_port = candidate.port or {"http": 80, "https": 443}.get(candidate.scheme)
                response_port = url.port or {"http": 80, "https": 443}.get(url.scheme)
                if candidate_port is not None and candidate_port != response_port:
                    continue
                if candidate.scheme and (candidate.path or "/", candidate.query) != (url.path or "/", url.query):
                    continue
                matched = True
                successful.add(seed)
            if not matched:
                raise ValueError("httpx response is outside the selected probe inputs")
            rows.append(line)
        canonical = self._dir / "live/httpx_full.txt"
        previous = canonical.read_text(encoding="utf-8").splitlines() if canonical.is_file() else []
        combined = list(dict.fromkeys([*previous, *rows]))
        write_text_atomic(canonical, "".join(line + "\n" for line in combined))
        live = list(dict.fromkeys([*self._read_lines("live/urls.txt"),
            *(line.split()[0] for line in combined if line.startswith(("http://", "https://")))]))
        write_text_atomic(self._dir / "live/urls.txt", "".join(url + "\n" for url in live))
        write_text_atomic(results, "".join(seed + "\t" + (
            "ok" if exit_code == 0 and seed in successful else "partial"
        ) + "\n" for seed in attempted))

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
    def _ffuf_body_digest(cls, value: object) -> tuple[str, bool]:
        if value is None:
            return "", True
        if isinstance(value, bytes):
            raw = value
        elif isinstance(value, str):
            raw = value.encode("utf-8", errors="replace")
        else:
            raw = json.dumps(value, ensure_ascii=False, sort_keys=True).encode("utf-8")
        complete = len(raw) <= FFUF_BODY_DIGEST_MAX_BYTES
        return hashlib.sha256(raw[:FFUF_BODY_DIGEST_MAX_BYTES]).hexdigest(), complete

    @staticmethod
    def _ffuf_path_depth(url: str) -> int:
        return sum(bool(part) for part in urlsplit(url).path.split("/"))

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
        body_sha256, body_digest_complete = cls._ffuf_body_digest(record.get("body"))
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
            "body_sha256": body_sha256,
            "body_digest_complete": body_digest_complete,
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

    @classmethod
    def _ffuf_control_matches(cls, observation: dict, control: dict) -> bool:
        if cls._ffuf_signature(observation) != cls._ffuf_signature(control):
            return False
        if str(observation.get("host", "")).lower() != str(control.get("host", "")).lower():
            return False
        if cls._ffuf_path_depth(str(observation.get("url", ""))) != cls._ffuf_path_depth(str(control.get("url", ""))):
            return False
        observation_digest = str(observation.get("body_sha256") or "")
        control_digest = str(control.get("body_sha256") or "")
        if not observation.get("body_digest_complete", True) or not control.get("body_digest_complete", True):
            return False
        return not observation_digest or not control_digest or observation_digest == control_digest

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
        """拒绝无效 controls；仅当两条 control 都是相同 200 时返回 SPA size。"""
        error_state: dict = {"count": 0, "preview": []}
        controls = self._read_ffuf_controls(controls_path, error_state)
        if error_state["count"] or len(controls) != 2:
            detail = "; ".join(error_state["preview"])
            raise ValueError(
                f"{controls_path}: expected exactly 2 valid FFUF controls, got {len(controls)}"
                + (f"; {detail}" if detail else "")
            )
        for observation in controls:
            self._check_ffuf_status(observation)
        first, second = controls
        first_length = int(first.get("length", 0) or 0)
        if (
            first.get("status") == 200
            and second.get("status") == 200
            and str(first.get("host", "")).lower() == str(second.get("host", "")).lower()
            and self._ffuf_path_depth(str(first.get("url", ""))) == self._ffuf_path_depth(str(second.get("url", "")))
            and first_length > 0
            and int(second.get("length", 0) or 0) == first_length
            and first.get("body_digest_complete", True)
            and second.get("body_digest_complete", True)
            and (
                not first.get("body_sha256")
                or not second.get("body_sha256")
                or first.get("body_sha256") == second.get("body_sha256")
            )
        ):
            return first_length
        return 0

    @staticmethod
    def _check_ffuf_status(observation: dict) -> None:
        status = observation["status"]
        if status < 100 or status in {408, 429} or status >= 500:
            raise ValueError(f"FFUF collection incomplete: HTTP {status} at {observation['url']}")

    def check_ffuf_run(self, results_path: str | Path, wordlist_path: str | Path) -> None:
        """Exit-zero alone does not prove that the target served the requests."""
        # FFUF's stdin wordlist retains blank, comment and duplicate lines without -ic.
        with Path(wordlist_path).open("rb") as wordlist:
            words = [line.removesuffix(b"\n").removesuffix(b"\r") for line in wordlist]
        expected = len(words)
        errors: dict = {"count": 0, "preview": []}
        positions = set()
        for record in self._iter_ffuf_jsonl_records(Path(results_path), errors):
            observation = self._project_ffuf_result(record)
            if observation is None:
                raise ValueError("invalid FFUF response")
            self._check_ffuf_status(observation)
            position = record.get("position")
            inputs = record.get("input")
            if (type(position) is not int or not 1 <= position <= expected or position in positions
                    or not isinstance(inputs, dict) or not isinstance(inputs.get("FUZZ"), str)):
                raise ValueError("FFUF collection incomplete: invalid or duplicate input position")
            if base64.b64decode(inputs["FUZZ"], validate=True) != words[position - 1]:
                raise ValueError("FFUF response input differs from the selected wordlist")
            positions.add(position)
        if errors["count"]:
            raise ValueError("; ".join(errors["preview"]))
        if not expected or len(positions) != expected:
            raise ValueError(f"FFUF collection incomplete: expected {expected} responses, received {len(positions)}")

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
        write_json_atomic(path, payload)

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
        control_match_counts: Counter[tuple[int, int, int, int, str]] = Counter()
        status_counts: Counter[str] = Counter()
        heavy_candidates: dict[tuple[int, int, int, int, str], int] = {}
        sample = []
        sample_signatures: set[tuple[int, int, int, int, str]] = set()
        observations = 0

        for observation in self._iter_projected_ffuf(paths, error_state):
            observations += 1
            status_counts[str(observation["status"])] += 1
            signature = self._ffuf_signature(observation)
            if any(self._ffuf_control_matches(observation, control) for control in controls):
                control_match_counts[signature] += 1
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
                "control_match_count": control_match_counts.get(signature, 0),
                "control_match_ratio": round(control_match_counts.get(signature, 0) / count, 6) if count else 0.0,
                "matches_random_miss_control": bool(control_match_counts.get(signature, 0)),
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
        """Ensure expected derived artifact files exist.

        Creates missing directories and stub files for older artifact layouts.
        Existing files are never overwritten.
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
    action.add_argument("--check-ffuf-run", action="store_true")
    action.add_argument("--katana-receipts", action="store_true")
    action.add_argument("--httpx-receipts", action="store_true")
    parser.add_argument("--capture", type=Path)
    parser.add_argument("--seeds", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--results", type=Path)
    parser.add_argument("--wordlist", type=Path)
    parser.add_argument("--exit-code", type=int, default=0)
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
        if args.httpx_receipts:
            if not all((args.capture, args.seeds, args.results)):
                raise ValueError("--httpx-receipts requires --capture, --seeds and --results")
            adapter.publish_httpx_receipts(args.capture, args.seeds, args.results, args.exit_code)
            return 0
        if args.katana_receipts:
            if not all((args.capture, args.seeds, args.output, args.results)):
                raise ValueError("--katana-receipts requires --capture, --seeds, --output and --results")
            adapter.publish_katana_receipts(args.capture, args.seeds, args.output, args.results, args.exit_code)
            return 0
        if args.ffuf_control_size:
            if not args.controls:
                raise ValueError("--controls is required with --ffuf-control-size")
            print(adapter.get_ffuf_control_filter_size(args.controls))
            return 0
        if args.check_ffuf_run:
            if not args.results or not args.wordlist:
                raise ValueError("--results and --wordlist are required with --check-ffuf-run")
            adapter.check_ffuf_run(args.results, args.wordlist)
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
