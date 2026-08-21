#!/usr/bin/env python3
"""
Recon noise filtering utilities.
Reduces false positives in URL collection and exposure detection.
"""

from collections import Counter
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import tempfile
from urllib.parse import parse_qsl, unquote_plus, urlencode, urlparse, urlunsplit

try:
    from tools.attack_probe_filter import is_attack_probe, sanitize_attack_probe_url
    from tools.surface_index import surface_shape
except ImportError:  # pragma: no cover - direct tools/ execution
    from attack_probe_filter import is_attack_probe, sanitize_attack_probe_url  # type: ignore
    from surface_index import surface_shape  # type: ignore


# Active is a lossless replay inventory after semantic noise removal. A shape
# cap is still available for callers that explicitly want a bounded projection.
DEFAULT_MAX_PER_SHAPE = 0
DEFAULT_LOG_SAMPLE_LIMIT = 64


def _normalize_domain(value):
    """Normalize a target-ish domain/URL into a hostname for suffix matching."""
    candidate = (value or "").strip().lower().strip(".")
    if candidate.startswith("*."):
        candidate = candidate[2:]

    try:
        parsed = urlparse(candidate if "://" in candidate or candidate.startswith("//") else f"//{candidate}")
        hostname = parsed.hostname or candidate.split("/")[0].split(":")[0]
    except ValueError:
        hostname = candidate.split("/")[0].split(":")[0]
    hostname = hostname.lower().strip(".")
    if hostname.startswith("*."):
        hostname = hostname[2:]
    return hostname


def _url_hostname(url):
    """Return URL hostname; relative paths intentionally return an empty string."""
    candidate = (url or "").strip()
    if not candidate:
        return ""
    if candidate.startswith("//"):
        pass
    elif candidate.startswith("/"):
        return ""
    if "://" not in candidate and ":" in candidate:
        prefix, _, rest = candidate.partition(":")
        looks_like_scheme = re.fullmatch(r"[A-Za-z][A-Za-z0-9+.-]*", prefix) is not None
        looks_like_host_port = re.match(r"^\d{1,5}(/|$)", rest) is not None
        if looks_like_scheme and not looks_like_host_port:
            return "\0"
    try:
        parsed = urlparse(candidate if "://" in candidate or candidate.startswith("//") else f"//{candidate}")
        if parsed.scheme and parsed.scheme not in {"http", "https"}:
            return "\0"
        return (parsed.hostname or "").lower().strip(".")
    except ValueError:
        return "\0"


def _append_log(log_file, lines):
    if not log_file or not lines:
        return
    try:
        path = Path(log_file)
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as handle:
            for line in lines:
                handle.write(line.rstrip("\n") + "\n")
    except OSError:
        return


def _atomic_replace_text(path: Path, content: str) -> None:
    """Publish a small text artifact without exposing a partial file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            "w",
            encoding="utf-8",
            dir=str(path.parent),
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as handle:
            temporary = Path(handle.name)
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except Exception:
        if temporary is not None:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass
        raise


def _active_url(url: str) -> tuple[str, bool]:
    """Return a replay-safe representative while preserving endpoint shape."""
    value = sanitize_attack_probe_url(url) if is_attack_probe(url) else str(url or "").strip()
    had_authority = value.startswith("//") or "://" in value
    try:
        parsed = urlparse(value if "://" in value or value.startswith("//") else f"//{value}")
        if not parsed.query:
            return value, value != url
        meaningful_parts = []
        for part in parsed.query.split("&"):
            key_raw, separator, _item = part.partition("=")
            key = unquote_plus(key_raw)
            if not is_cache_param_in_context(value, key):
                meaningful_parts.append(part if separator else key_raw)
        query = "&".join(meaningful_parts)
        if query == parsed.query:
            return value, value != url
        normalized = urlunsplit((parsed.scheme, parsed.netloc, parsed.path, query, parsed.fragment))
        if not had_authority and normalized.startswith("//"):
            normalized = normalized[2:]
        return normalized, value != url or normalized != value
    except (TypeError, ValueError):
        return value, value != url


def _is_in_scope_or_relative(url, target_domain):
    hostname = _url_hostname(url)
    if not hostname:
        return True
    target = _normalize_domain(target_domain)
    return hostname == target or hostname.endswith("." + target)


def filter_external_urls(urls, target_domain):
    """
    Filter out URLs that don't belong to target domain or its subdomains.

    Args:
        urls: List of URL strings
        target_domain: Target domain (e.g., 'example.com')

    Returns:
        List of target-matched URLs
    """
    filtered = []
    for url in urls:
        try:
            if _is_in_scope_or_relative(url, target_domain):
                filtered.append(url)
        except Exception:
            continue

    return filtered


def has_url_encoding_error(url):
    """
    Detect URLs with encoded newlines/tabs/control chars (crawl artifacts).

    Common patterns:
    - %5Cn, %5Cr, %5Ct = encoded backslash + n/r/t (from source code strings)
    - %0A, %0D, %09 = actual newline/carriage return/tab

    Args:
        url: URL string

    Returns:
        True if URL has encoding errors, False otherwise
    """
    # Encoded backslash + control char (source code artifacts)
    if re.search(r'%5C[nrtfv]', url, re.I):
        return True

    # Actual control characters
    if re.search(r'%0[0-9A-D]', url, re.I):
        return True

    return False


def has_html_unicode_encoding(url):
    """
    Detect URLs with HTML Unicode encoding (crawl artifacts).

    Common patterns:
    - \\u003c = < (tag start)
    - \\u003e = > (tag end)
    - Multiple HTML tags in URL path/query

    Args:
        url: URL string

    Returns:
        True if HTML Unicode encoding detected, False otherwise
    """
    # Unicode-escaped HTML special chars (<, >, ", ')
    if re.search(r'(\\u|%5Cu)00[23][cCeE]', url, re.I):
        return True

    # Multiple escaped chars (likely HTML fragment)
    if url.count('\\u003') + len(re.findall(r'%5Cu003', url, re.I)) >= 3:
        return True

    # Literal HTML tags in URL (edge case)
    if re.search(r'<[a-z]+>|</[a-z]+>', url, re.I):
        return True

    return False


_JS_PATH_SEGMENT_RE = re.compile(r"^[A-Za-z_$][A-Za-z0-9_$]*(?:\.[A-Za-z_$][A-Za-z0-9_$]*)+$")
_JS_LEADING_VAR_SEGMENT_RE = re.compile(r"^[A-Za-z_$]\.[A-Za-z_$][A-Za-z0-9_$]*(?:\.[A-Za-z_$][A-Za-z0-9_$]*)*$")
_LIKELY_FILE_SEGMENT_RE = re.compile(r"\.(?:js|mjs|cjs|css|json|xml|txt|svg|png|jpe?g|gif|webp|avif|ico|html?)$", re.I)
_JS_MEMBER_SIGNAL_TOKENS = {
    "document",
    "window",
    "navigator",
    "location",
    "visualviewport",
    "offsetheight",
    "offsetwidth",
    "localstorage",
    "sessionstorage",
    "prototype",
    "constructor",
    "innerhtml",
    "outerhtml",
    "cookie",
    "dom",
}


def has_js_path_artifact(url):
    """
    Detect crawler artifacts where JS member expressions are mistaken for paths.

    Examples:
    - /i.visualViewport.scale/i.document.do
    - /r.dom.offsetHeight/r.do

    Heuristic goals:
    - catch multi-segment property chains from minified/browser JS
    - avoid stripping normal dotted filenames like /login.do or /app.config.json
    """
    candidate = (url or "").strip()
    if not candidate:
        return False
    try:
        parsed = urlparse(candidate if "://" in candidate or candidate.startswith("//") else f"//{candidate}")
    except ValueError:
        return False

    segments = [segment for segment in (parsed.path or "").split("/") if segment]
    if len(segments) < 2:
        return False

    suspicious = 0
    js_signal_hits = 0
    for segment in segments:
        lowered = segment.lower()
        if _LIKELY_FILE_SEGMENT_RE.search(segment):
            continue
        if not _JS_PATH_SEGMENT_RE.fullmatch(segment):
            continue
        parts = [part.lower() for part in segment.split(".") if part]
        if len(parts) < 2:
            continue
        if _JS_LEADING_VAR_SEGMENT_RE.fullmatch(segment):
            suspicious += 1
        elif len(parts) >= 3 and _JS_MEMBER_SIGNAL_TOKENS.intersection(parts):
            suspicious += 1
        if _JS_MEMBER_SIGNAL_TOKENS.intersection(parts):
            js_signal_hits += 1

    return suspicious >= 2 or (suspicious >= 1 and js_signal_hits >= 2)


def has_malformed_path(url):
    """Detect invalid unbalanced brackets in a URL path without touching raw evidence."""
    try:
        path = urlparse(str(url or "")).path
    except ValueError:
        return True
    return path.count("[") != path.count("]")


def detect_path_explosion(url, threshold=4, log_file=None):
    """
    Detect URLs with recursive/repeated path segments (e.g., /API/API/API/).

    Args:
        url: URL string
        threshold: Max allowed repetitions of same segment (default: 4, safer than 3)
        log_file: Optional file to log filtered URLs for review

    Returns:
        True if path explosion detected, False otherwise
    """
    try:
        parsed = urlparse(url)
        path = parsed.path

        # Split path and count segment occurrences
        segments = [s for s in path.split('/') if s]

        if not segments:
            return False

        counts = Counter(segments)

        # Check if any segment repeats >= threshold times
        for segment, count in counts.items():
            if count >= threshold:
                # Log if file specified
                if log_file:
                    _append_log(log_file, [f"[PATH_EXPLOSION] {url}"])
                return True

        return False
    except Exception:
        return False


def is_invalid_url(url):
    """Reject non-web schemes and malformed absolute URLs from active views."""
    value = str(url or "").strip()
    if not value or any(char.isspace() or ord(char) < 32 for char in value):
        return True
    if re.match(r"^(?:javascript|data|mailto|file|blob|ws|wss):", value, re.I):
        return True
    try:
        parsed = urlparse(value if "://" in value or value.startswith("//") else f"//{value}")
    except ValueError:
        return True
    if parsed.scheme and parsed.scheme.lower() not in {"http", "https"}:
        return True
    if value.startswith(("http://", "https://", "//")) and not parsed.hostname:
        return True
    return False


def _dedupe_key(url):
    """Ignore cache-only query values while preserving the first raw URL."""
    value = str(url or "").strip()
    try:
        parsed = urlparse(value if "://" in value or value.startswith("//") else f"//{value}")
        if not parsed.query:
            return parsed._replace(fragment="").geturl()
        pairs = parse_qsl(parsed.query, keep_blank_values=True)
        meaningful = [
            (key, val)
            for key, val in pairs
            if not is_cache_param_in_context(value, key)
        ]
        if len(meaningful) == len(pairs):
            return parsed._replace(fragment="").geturl()
        query = urlencode(meaningful, doseq=True)
        return parsed._replace(query=query, fragment="").geturl()
    except (TypeError, ValueError):
        return value


def _has_cache_param(url):
    try:
        parsed = urlparse(str(url or ""))
        return any(
            is_cache_param_in_context(str(url), key)
            for key, _value in parse_qsl(parsed.query, keep_blank_values=True)
        )
    except (TypeError, ValueError):
        return False


def is_cache_param_in_context(url, param_name):
    """
    Context-aware cache param detection.
    In API contexts, 'v' and 'version' may be API versions, not cache params.

    Args:
        url: Full URL string for context
        param_name: Parameter name to check

    Returns:
        True if cache param, False otherwise
    """
    parsed = urlparse(url)

    # API endpoints: exempt 'v' and 'version' (likely API version)
    if re.search(r'/api/|/v\d+/', parsed.path, re.I):
        if param_name.lower() in ['v', 'version']:
            return False  # NOT a cache param in API context

    # Otherwise use standard detection
    return is_cache_param(param_name)


def is_cache_param(param_name):
    """
    Check if parameter name is a common cache-busting param.

    Args:
        param_name: Parameter name (e.g., 'v', 'bust')

    Returns:
        True if cache param, False otherwise
    """
    cache_params = [
        'v', 'ver', 'version', 'bust', '_', 'nocache', 'cachebuster',
        'cb', 'random', 'rand', 'utm_source', 'utm_medium', 'utm_campaign',
        'utm_term', 'utm_content', 'fbclid', 'gclid', 'msclkid'
    ]

    param_lower = param_name.lower()

    # Exact match
    if param_lower in cache_params:
        return True

    # Pattern match for underscore-only params
    if re.match(r'^_+$', param_name):
        return True

    return False


def filter_urls_batch(input_file, output_file, target_domain,
                     remove_external=True, remove_path_explosion=True,
                     explosion_threshold=4, log_file=None,
                     max_per_shape=DEFAULT_MAX_PER_SHAPE,
                     summary_file=None,
                     max_log_samples=DEFAULT_LOG_SAMPLE_LIMIT):
    """
    Batch filter URLs from file.

    Args:
        input_file: Input file with URLs (one per line)
        output_file: Output file for filtered URLs
        target_domain: Target domain
        remove_external: Remove external URLs
        remove_path_explosion: Remove path explosion URLs
        explosion_threshold: Path explosion detection threshold (default: 4)
        log_file: Optional file to log filtered URLs for review
        max_per_shape: Optional explicit cap; zero keeps all distinct URLs

    Returns:
        Dict with stats (total, kept, removed_external, removed_explosion)
    """
    stats = {'total': 0, 'kept': 0, 'removed_external': 0, 'removed_explosion': 0,
             'removed_encoding_errors': 0, 'removed_html_encoding': 0,
             'removed_js_path_artifacts': 0, 'removed_malformed_paths': 0,
             'removed_invalid': 0, 'removed_duplicates': 0, 'removed_cache_only': 0,
             'removed_shape_overflow': 0, 'sanitized_attack_probes': 0,
             'normalized_cache_params': 0}
    dedupe_keys = set()
    shape_counts = Counter()
    log_samples: dict[str, list[str]] = {}
    log_handle = None
    if log_file:
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log_handle = log_path.open("w", encoding="utf-8")

    def reject(counter, label, url):
        stats[counter] += 1
        samples = log_samples.setdefault(label, [])
        should_log = len(samples) < max(0, int(max_log_samples))
        if should_log:
            samples.append(url)
        if log_handle and should_log:
            log_handle.write(f"[{label}] {url}\n")

    input_path = Path(input_file)
    output_path = Path(output_file)
    output_temp: Path | None = None
    output_digest = hashlib.sha256()
    try:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(
            "wb", dir=str(output_path.parent), prefix=f".{output_path.name}.", suffix=".tmp", delete=False
        ) as staged:
            output_temp = Path(staged.name)
            with input_path.open("r", encoding="utf-8", errors="ignore") as source:
                for raw in source:
                    original_url = raw.strip()
                    if not original_url:
                        continue
                    url = original_url
                    probe_url = sanitize_attack_probe_url(url) if is_attack_probe(url) else url
                    if probe_url != url:
                        stats['sanitized_attack_probes'] += 1
                        url = probe_url
                    stats['total'] += 1
                    if is_invalid_url(url):
                        reject('removed_invalid', 'INVALID_URL', original_url)
                        continue
                    if has_url_encoding_error(url):
                        reject('removed_encoding_errors', 'ENCODING_ERROR', original_url)
                        continue
                    if has_malformed_path(url):
                        reject('removed_malformed_paths', 'MALFORMED_PATH', original_url)
                        continue
                    if has_html_unicode_encoding(url):
                        reject('removed_html_encoding', 'HTML_ENCODING', original_url)
                        continue
                    if has_js_path_artifact(url):
                        reject('removed_js_path_artifacts', 'JS_PATH_ARTIFACT', original_url)
                        continue
                    if remove_external and not _is_in_scope_or_relative(url, target_domain):
                        reject('removed_external', 'EXTERNAL', original_url)
                        continue
                    if remove_path_explosion and detect_path_explosion(url, explosion_threshold):
                        reject('removed_explosion', 'PATH_EXPLOSION', original_url)
                        continue

                    active_url, changed = _active_url(url)
                    if _has_cache_param(url) and changed:
                        stats['normalized_cache_params'] += 1
                    key = _dedupe_key(active_url)
                    if key in dedupe_keys:
                        reject('removed_duplicates', 'DUPLICATE_URL', original_url)
                        if _has_cache_param(url):
                            stats['removed_cache_only'] += 1
                        continue
                    dedupe_keys.add(key)
                    shape_id = str(surface_shape(active_url).get("id") or "")
                    if max_per_shape and shape_id and shape_counts[shape_id] >= max_per_shape:
                        reject('removed_shape_overflow', 'SHAPE_OVERFLOW', original_url)
                        continue
                    if shape_id:
                        shape_counts[shape_id] += 1
                    encoded = f"{active_url}\n".encode("utf-8")
                    staged.write(encoded)
                    output_digest.update(encoded)
                    stats['kept'] += 1
            staged.flush()
            os.fsync(staged.fileno())
        os.replace(output_temp, output_path)
        output_temp = None
    finally:
        if log_handle:
            log_handle.close()
        if output_temp is not None:
            try:
                output_temp.unlink()
            except FileNotFoundError:
                pass
    if summary_file:
        summary = {
            "schema_version": 1,
            "input": str(input_path),
            "output": str(output_path),
            "total": stats["total"],
            "kept": stats["kept"],
            "removed": stats["total"] - stats["kept"],
            "output_sha256": output_digest.hexdigest(),
            "max_per_shape": max_per_shape,
            "log_sample_limit": max_log_samples,
            "stats": stats,
            "log_samples": log_samples,
        }
        _atomic_replace_text(Path(summary_file), json.dumps(summary, ensure_ascii=False, indent=2) + "\n")

    return stats


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Publish a filtered Active recon URL view.",
    )
    parser.add_argument("input_file")
    parser.add_argument("output_file")
    parser.add_argument("target_domain")
    parser.add_argument("--log-file", default=None)
    parser.add_argument("--summary-file", default=None)
    parser.add_argument("--max-log-samples", type=int, default=DEFAULT_LOG_SAMPLE_LIMIT)
    parser.add_argument("--explosion-threshold", type=int, default=4)
    parser.add_argument("--max-per-shape", type=int, default=DEFAULT_MAX_PER_SHAPE)
    parser.add_argument("--no-remove-external", action="store_true")
    parser.add_argument(
        "--no-remove-path-explosion",
        "--no-path-explosion",
        dest="no_remove_path_explosion",
        action="store_true",
    )
    args = parser.parse_args(sys.argv[1:] if argv is None else argv)
    if args.max_per_shape < 0:
        parser.error("--max-per-shape must be >= 0")
    if args.max_log_samples < 0:
        parser.error("--max-log-samples must be >= 0")

    stats = filter_urls_batch(
        args.input_file,
        args.output_file,
        args.target_domain,
        remove_external=not args.no_remove_external,
        remove_path_explosion=not args.no_remove_path_explosion,
        explosion_threshold=args.explosion_threshold,
        log_file=args.log_file,
        max_per_shape=args.max_per_shape,
        summary_file=args.summary_file,
        max_log_samples=args.max_log_samples,
    )
    kept_percent = (stats['kept'] / stats['total'] * 100) if stats['total'] else 0.0

    print(f"Filtering complete:")
    print(f"  Total URLs: {stats['total']}")
    print(f"  Removed encoding errors: {stats['removed_encoding_errors']}")
    print(f"  Removed HTML encoding: {stats['removed_html_encoding']}")
    print(f"  Removed JS path artifacts: {stats['removed_js_path_artifacts']}")
    print(f"  Removed malformed paths: {stats['removed_malformed_paths']}")
    print(f"  Removed external: {stats['removed_external']}")
    print(f"  Removed path explosion: {stats['removed_explosion']}")
    print(f"  Removed invalid URLs: {stats['removed_invalid']}")
    print(f"  Removed duplicate URLs: {stats['removed_duplicates']}")
    print(f"  Removed cache-only duplicates: {stats['removed_cache_only']}")
    print(f"  Removed shape overflow: {stats['removed_shape_overflow']}")
    print(f"  Sanitized historical probes: {stats['sanitized_attack_probes']}")
    print(f"  Normalized cache parameters: {stats['normalized_cache_params']}")
    print(f"  Kept: {stats['kept']} ({kept_percent:.1f}%)")
    return 0


if __name__ == '__main__':
    sys.exit(main())
