#!/usr/bin/env python3
"""
HIBP k-anonymity password breach checker.

Reads a password wordlist, queries the HaveIBeenPwned /range/ API using
k-anonymity (only first 5 chars of SHA-1 are sent), enriches each password
with its breach count, then writes candidates in input order.

Counts describe HIBP observations, not candidate priority or target relevance.
Failed queries remain unknown (-1); zero requires a valid range response.
Legacy bucket names and the default -ranked.txt filename remain compatible.
Exit 2 means enrichment is incomplete; available results are still written.

Usage:
  tools/breach_checker.py <wordlist.txt>
  tools/breach_checker.py <wordlist.txt> -o ranked.txt --with-counts
  tools/breach_checker.py <wordlist.txt> --min-count 1 --max-count 1000000
  tools/breach_checker.py <wordlist.txt> --limit 5000   # test/preview
"""
from __future__ import annotations
import argparse
import hashlib
import random
import sys
import time
import urllib.error
import urllib.request
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from http.client import HTTPException
from itertools import islice
from pathlib import Path

API_URL = "https://api.pwnedpasswords.com/range/{}"
USER_AGENT = "ccst/breach_checker"


def positive_int(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be a positive integer") from exc
    if parsed < 1:
        raise argparse.ArgumentTypeError("must be a positive integer")
    return parsed


def bucket_for_count(count: int) -> str:
    """Return legacy count-band labels; the names do not assign priority."""
    if count < 0:
        return "unknown"
    if count == 0:
        return "zero"
    if count <= 1000:
        return "sweet"
    return "common"


def rank_results(passwords: list[str], results: dict[str, int]) -> list[tuple[str, int]]:
    """Legacy entry point: attach counts while preserving candidate input order."""
    return [(password, results.get(password, -1)) for password in passwords]


def sha1_prefix_suffix(password: str) -> tuple[str, str]:
    """Return (first 5 chars, remaining 35 chars) of SHA-1, uppercase."""
    digest = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    return digest[:5], digest[5:]


def _parse_range_response(body: str) -> dict[str, int]:
    """Reject invalid responses instead of treating them as zero-count ranges."""
    if not body.strip():
        raise ValueError("empty HIBP range response")
    counts: dict[str, int] = {}
    for line in body.splitlines():
        suffix, separator, count_text = line.strip().partition(":")
        if (
            not separator
            or len(suffix) != 35
            or any(char not in "0123456789abcdefABCDEF" for char in suffix)
            or not count_text.isascii()
            or not count_text.isdecimal()
        ):
            raise ValueError("invalid HIBP range response")
        suffix = suffix.upper()
        count = int(count_text)
        if suffix in counts and counts[suffix] != count:
            raise ValueError("conflicting counts in HIBP range response")
        counts[suffix] = count
    return {suffix: count for suffix, count in counts.items() if count > 0}


def query_range(prefix: str, retries: int = 3) -> dict[str, int]:
    """Query HIBP /range/{prefix}, return {suffix: count}.

    Uses Add-Padding header (HIBP-recommended privacy feature that pads the
    response with random fake entries so an observer can't infer real hits
    from response size). ``retries`` is the total attempt limit; failures
    propagate when it is exhausted.
    """
    if retries < 1:
        raise ValueError("retries must be a positive integer")
    req = urllib.request.Request(
        API_URL.format(prefix),
        headers={"User-Agent": USER_AGENT, "Add-Padding": "true"},
    )
    for attempt in range(retries):
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                body = resp.read().decode("utf-8")
            return _parse_range_response(body)
        except urllib.error.HTTPError as e:
            if e.code != 429 or attempt == retries - 1:
                raise
        except (urllib.error.URLError, TimeoutError):
            if attempt == retries - 1:
                raise
        time.sleep(2 ** attempt)


def check_batch(passwords: list[str], concurrent: int) -> dict[str, int]:
    """Check passwords against HIBP, return {password: count}.

    Groups by SHA-1 prefix to minimize API calls. Many passwords typically
    map to the same prefix (5-char hex = 1M buckets; for a 100k wordlist
    expect ~9% collision rate -> ~91k unique prefix queries).
    """
    prefix_groups: dict[str, list[tuple[str, str]]] = {}
    for pwd in passwords:
        prefix, suffix = sha1_prefix_suffix(pwd)
        prefix_groups.setdefault(prefix, []).append((pwd, suffix))

    results: dict[str, int] = {}
    failures: Counter[str] = Counter()
    completed = 0
    total = len(prefix_groups)
    start = time.time()

    prefixes = iter(prefix_groups)
    with ThreadPoolExecutor(max_workers=concurrent) as executor:
        while batch := list(islice(prefixes, concurrent * 4)):
            futures = {executor.submit(query_range, prefix): prefix for prefix in batch}
            for future in as_completed(futures):
                prefix = futures[future]
                completed += 1
                try:
                    bucket = future.result()
                    for pwd, suffix in prefix_groups[prefix]:
                        results[pwd] = bucket.get(suffix, 0)
                except (OSError, ValueError, HTTPException) as exc:
                    # API 失败保持 unknown，不伪装成未泄露。
                    for pwd, _ in prefix_groups[prefix]:
                        results[pwd] = -1
                    reason = f"HTTP {exc.code}" if isinstance(exc, urllib.error.HTTPError) else type(exc).__name__
                    failures[reason] += 1

                if completed % 500 == 0 or completed == total:
                    elapsed = time.time() - start
                    rate = completed / elapsed if elapsed > 0 else 0
                    eta = (total - completed) / rate if rate > 0 else 0
                    print(
                        f"\r    [*] {completed:,}/{total:,} prefixes "
                        f"({rate:.0f}/s, ETA {eta:.0f}s)",
                        end="",
                        file=sys.stderr,
                        flush=True,
                    )

    print("", file=sys.stderr)
    if failures:
        reasons = ", ".join(f"{reason}: {count}" for reason, count in sorted(failures.items()))
        print(f"[!] Failed HIBP prefixes ({reasons}); associated counts remain unknown.", file=sys.stderr)
    return results


def main() -> int:
    p = argparse.ArgumentParser(
        description="HIBP k-anonymity breach checker for password wordlists",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument("wordlist", type=Path, help="Input wordlist (one password per line)")
    p.add_argument("-o", "--output", type=Path,
                   help="Output candidates in input order (default: <input>-ranked.txt)")
    p.add_argument("--min-count", type=int, default=0,
                   help="Keep known counts >= N (default: 0); unknown counts are always kept")
    p.add_argument("--max-count", type=int, default=None,
                   help="Keep known counts <= N; unknown counts are always kept")
    p.add_argument("--concurrent", type=positive_int, default=20,
                   help="Parallel HIBP requests (default: 20)")
    p.add_argument("--limit", type=positive_int, default=None,
                   help="Process only first N unique passwords (testing/preview)")
    p.add_argument("--shuffle", action="store_true",
                   help="Shuffle wordlist before --limit (avoids ASCII-sort bias on samples)")
    p.add_argument("--seed", type=int, default=None,
                   help="Seed for --shuffle (default: non-deterministic)")
    p.add_argument("--with-counts", action="store_true",
                   help="Also write <output>-counts.tsv with breach counts")
    args = p.parse_args()

    if args.min_count < 0:
        p.error("--min-count must be non-negative")
    if args.max_count is not None and args.max_count < args.min_count:
        p.error("--max-count must be greater than or equal to --min-count")

    if not args.wordlist.is_file():
        print(f"[-] Wordlist not found: {args.wordlist}", file=sys.stderr)
        return 1

    output = args.output or args.wordlist.with_name(args.wordlist.stem + "-ranked.txt")

    with args.wordlist.open() as f:
        passwords = list(dict.fromkeys(
            line.strip() for line in f if line.strip()
        ))

    if args.shuffle:
        rng = random.Random(args.seed)
        rng.shuffle(passwords)

    if args.limit:
        passwords = passwords[: args.limit]

    if not passwords:
        print("[-] Wordlist is empty", file=sys.stderr)
        return 1

    unique_prefixes = len({sha1_prefix_suffix(p)[0] for p in passwords})
    est_secs = unique_prefixes / args.concurrent

    print(f"[*] Wordlist: {args.wordlist}  ({len(passwords):,} unique passwords)")
    print(f"[*] Unique SHA-1 prefixes: {unique_prefixes:,}  "
          f"({len(passwords)/unique_prefixes:.1f}x grouping factor)")
    print(f"[*] Estimated time: {est_secs:.0f}s "
          f"({est_secs/60:.1f}m) at {args.concurrent} concurrent")
    print(f"[*] Querying HaveIBeenPwned (k-anonymity, no full passwords sent)...")

    start = time.time()
    results = check_batch(passwords, args.concurrent)
    elapsed = time.time() - start

    print(f"[*] Queries finished in {elapsed:.1f}s")

    # API error 保持为 unknown；显式 count 范围只过滤已知计数。
    filtered = [
        (pwd, count)
        for pwd, count in rank_results(passwords, results)
        if count < 0
        or (
            count >= args.min_count
            and (args.max_count is None or count <= args.max_count)
        )
    ]

    with output.open("w") as f:
        for pwd, _ in filtered:
            f.write(pwd + "\n")
    output.chmod(0o600)

    if args.with_counts:
        counts_out = output.with_name(output.stem + "-counts.tsv")
        with counts_out.open("w") as f:
            f.write("bucket\tcount\tpassword\n")
            for pwd, c in filtered:
                f.write(f"{bucket_for_count(c)}\t{c}\t{pwd}\n")
        counts_out.chmod(0o600)

    # Stats
    in_breach = sum(1 for _, c in filtered if c > 0)
    count_1_to_1000 = sum(1 for _, c in filtered if 1 <= c <= 1000)
    count_over_1000 = sum(1 for _, c in filtered if c > 1000)
    unknown = sum(1 for _, c in filtered if c < 0)

    print()
    print("=" * 60)
    print("  Breach Check Summary")
    print("=" * 60)
    print(f"  Status:           {'partial' if unknown else 'complete'}")
    print(f"  Output:           {output}")
    if args.with_counts:
        print(f"  Counts TSV:       {output.with_name(output.stem + '-counts.tsv')}")
    print(f"  Total output:     {len(filtered):,}")
    if filtered:
        print(f"  Count 1-1000:     {count_1_to_1000:,}")
        print(f"  Count >1000:      {count_over_1000:,}")
        print(f"  Count 0:          {len(filtered)-in_breach-unknown:,}")
        print(f"  Unknown:          {unknown:,}")
    print("=" * 60)

    if unknown:
        print("[!] Enrichment incomplete; unknown candidates are retained (exit 2).", file=sys.stderr)
    return 2 if unknown else 0


if __name__ == "__main__":
    sys.exit(main())
