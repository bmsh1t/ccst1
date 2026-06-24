"""
Deterministic target-set matcher — code check, not LLM judgment.

Matches URLs against configured domain patterns for target bookkeeping and
optional filtering.
Uses anchored suffix matching (not raw fnmatch) to prevent subdomain confusion:
  - "*.target.com" matches "sub.target.com" but NOT "evil-target.com"
  - "target.com" matches exactly "target.com"
"""

import ipaddress
import argparse
import json
import sys
from urllib.parse import urlparse


class ScopeChecker:
    """Deterministic target-set matcher for host / URL classification."""

    def __init__(
        self,
        domains: list[str],
        excluded_domains: list[str] | None = None,
        excluded_classes: list[str] | None = None,
        unrestricted: bool = False,
    ):
        """
        Args:
            domains: Target patterns like ["*.target.com", "api.target.com"]
            excluded_domains: Optional exclusion patterns like ["blog.target.com"]
            excluded_classes: Optional class labels used by callers
            unrestricted: If true, disable all target/class restrictions.
        """
        self.domains = [d.lower() for d in domains]
        self.excluded_domains = [d.lower() for d in (excluded_domains or [])]
        self.excluded_classes = [c.lower() for c in (excluded_classes or [])]
        self.unrestricted = bool(unrestricted)

    def is_in_scope(self, url: str) -> bool:
        """Check if a URL's hostname matches the configured target set.

        Returns:
            True if the hostname matches a configured pattern and is not excluded.
            False otherwise (including for malformed URLs and empty input).
        """
        if self.unrestricted:
            return bool(url and isinstance(url, str))

        if not url or not isinstance(url, str):
            return False

        # Ensure we have a scheme for urlparse
        normalized = url if "://" in url else f"https://{url}"

        try:
            parsed = urlparse(normalized)
        except Exception:
            return False

        hostname = parsed.hostname
        if not hostname:
            return False

        hostname = hostname.lower()

        ip = _parse_ip(hostname)

        if ip is not None:
            for excluded in self.excluded_domains:
                if _ip_matches(ip, excluded):
                    return False

            for pattern in self.domains:
                if _ip_matches(ip, pattern):
                    return True

            return False

        # Strip port if present (urlparse handles this, but be safe)
        # hostname from urlparse should already exclude port

        # Check exclusion list first
        for excluded in self.excluded_domains:
            if _domain_matches(hostname, excluded):
                return False

        # Check allowlist
        for pattern in self.domains:
            if _domain_matches(hostname, pattern):
                return True

        return False

    def is_vuln_class_allowed(self, vuln_class: str) -> bool:
        """Check if a caller-supplied class label is currently allowed."""
        if self.unrestricted:
            return True
        return vuln_class.lower() not in self.excluded_classes

    def filter_urls(self, urls: list[str]) -> tuple[list[str], list[str]]:
        """Split a list of URLs into (matched, unmatched)."""
        in_scope = []
        out_of_scope = []
        for url in urls:
            if self.is_in_scope(url):
                in_scope.append(url)
            else:
                out_of_scope.append(url)
        return in_scope, out_of_scope

    def filter_file(self, input_path: str, output_path: str | None = None) -> tuple[int, int]:
        """Filter a file of URLs (one per line) through target matching.

        Args:
            input_path: Path to file with URLs, one per line.
            output_path: If provided, write matched URLs here. If None, filter in-place.

        Returns:
            (matched_count, unmatched_count)
        """
        with open(input_path, "r") as f:
            lines = [line.strip() for line in f if line.strip()]

        in_scope, out_of_scope = self.filter_urls(lines)

        dest = output_path or input_path
        with open(dest, "w") as f:
            for url in in_scope:
                f.write(url + "\n")

        if out_of_scope:
            print(
                f"WARNING: filtered {len(out_of_scope)} non-matching URLs from {input_path}",
                file=sys.stderr,
            )

        return len(in_scope), len(out_of_scope)


def _domain_matches(hostname: str, pattern: str) -> bool:
    """Anchored domain matching — prevents subdomain confusion.

    *.target.com  → matches sub.target.com, a.b.target.com
                  → does NOT match target.com, evil-target.com
    target.com    → matches target.com exactly
    """
    if pattern.startswith("*."):
        # Wildcard: must be a proper subdomain
        suffix = pattern[1:]  # ".target.com"
        return hostname.endswith(suffix) and hostname != suffix[1:]
    else:
        # Exact match
        return hostname == pattern


def _parse_ip(hostname: str) -> ipaddress._BaseAddress | None:
    """Parse an IPv4/IPv6 hostname, returning None for non-IP hostnames."""
    try:
        return ipaddress.ip_address(hostname)
    except ValueError:
        return None


def _ip_matches(ip: ipaddress._BaseAddress, pattern: str) -> bool:
    """Match an IP against an exact-IP or CIDR allow/block entry."""
    try:
        return ip == ipaddress.ip_address(pattern)
    except ValueError:
        pass

    try:
        return ip in ipaddress.ip_network(pattern, strict=False)
    except ValueError:
        return False


def _split_patterns(values: list[str]) -> list[str]:
    """展开 CLI 中可重复、可逗号分隔的 pattern 参数。"""
    patterns: list[str] = []
    for value in values:
        for part in value.split(","):
            part = part.strip()
            if part:
                patterns.append(part)
    return patterns


def main(argv: list[str] | None = None) -> int:
    """CLI 入口：仅提供确定性检查/过滤能力，不改变库函数语义。"""
    parser = argparse.ArgumentParser(
        description="Deterministically check assets against the configured target set."
    )
    parser.add_argument("asset", nargs="?", help="URL, hostname, IP, or CIDR member to check")
    parser.add_argument(
        "--domain",
        "-d",
        action="append",
        default=[],
        help="Allowed domain/IP/CIDR pattern. Repeat or comma-separate, e.g. target.com,*.target.com,10.0.0.0/8",
    )
    parser.add_argument(
        "--exclude-domain",
        "-x",
        action="append",
        default=[],
        help="Excluded domain/IP/CIDR pattern. Repeat or comma-separate.",
    )
    parser.add_argument(
        "--exclude-class",
        action="append",
        default=[],
        help="Excluded vulnerability class. Repeat or comma-separate.",
    )
    parser.add_argument("--vuln-class", help="Optional vulnerability class label to check")
    parser.add_argument("--input-file", help="Filter URLs/assets from a file, one per line")
    parser.add_argument("--output", help="Output path for matched URLs/assets")
    parser.add_argument("--unrestricted", action="store_true", help="Allow every non-empty asset/class")
    parser.add_argument("--json", action="store_true", help="Print machine-readable JSON")
    args = parser.parse_args(argv)

    domains = _split_patterns(args.domain)
    excluded_domains = _split_patterns(args.exclude_domain)
    excluded_classes = _split_patterns(args.exclude_class)

    if not domains and not args.unrestricted:
        parser.error("at least one --domain pattern is required unless --unrestricted is set")
    if not args.asset and not args.input_file and not args.vuln_class:
        parser.error("provide an asset, --input-file, or --vuln-class")

    checker = ScopeChecker(
        domains,
        excluded_domains=excluded_domains,
        excluded_classes=excluded_classes,
        unrestricted=args.unrestricted,
    )
    result: dict[str, object] = {
        "domains": domains,
        "excluded_domains": excluded_domains,
        "excluded_classes": excluded_classes,
        "unrestricted": args.unrestricted,
    }
    exit_code = 0

    if args.asset:
        matched = checker.is_in_scope(args.asset)
        result["asset"] = args.asset
        result["matched"] = matched
        if not matched:
            exit_code = 2

    if args.vuln_class:
        allowed = checker.is_vuln_class_allowed(args.vuln_class)
        result["vuln_class"] = args.vuln_class
        result["vuln_class_allowed"] = allowed
        if not allowed:
            exit_code = 2

    if args.input_file:
        try:
            matched_count, unmatched_count = checker.filter_file(args.input_file, args.output)
        except OSError as exc:
            parser.error(str(exc))
        result["input_file"] = args.input_file
        result["output"] = args.output or args.input_file
        result["matched_count"] = matched_count
        result["unmatched_count"] = unmatched_count

    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        if "asset" in result:
            verdict = "MATCHED" if result["matched"] else "UNMATCHED"
            print(f"{verdict}: {result['asset']}")
        if "vuln_class" in result:
            verdict = "ALLOWED" if result["vuln_class_allowed"] else "EXCLUDED"
            print(f"{verdict}: vulnerability class {result['vuln_class']}")
        if "input_file" in result:
            print(
                "Filtered assets: "
                f"{result['matched_count']} matched, "
                f"{result['unmatched_count']} unmatched -> {result['output']}"
            )

    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
