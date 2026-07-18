#!/usr/bin/env python3
"""验证大规模 Surface 的无损索引、bounded ranking 与 warm bootstrap。"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import resource
import subprocess
import sys
import tempfile
import time
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parents[2]
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from tools.autopilot_state import build_autopilot_bootstrap_state
from tools.surface_finalizer import finalize_surface
from tools.surface_index import iter_surface_index, load_surface_index_status
from tools.surface_projection import load_surface_projection


def _rss_mib() -> float:
    # Linux ru_maxrss 使用 KiB；本项目的 Claude runtime 目标环境为 Linux。
    return resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024.0


def _write_host(recon: Path, target: str) -> None:
    (recon / "live").mkdir(parents=True, exist_ok=True)
    (recon / "urls").mkdir(parents=True, exist_ok=True)
    (recon / "browser").mkdir(parents=True, exist_ok=True)
    (recon / "live" / "httpx_full.txt").write_text(
        f"https://api.{target} [200] [API] [Python] [100]\n",
        encoding="utf-8",
    )


def _write_synthetic_surface(repo: Path, target: str, count: int) -> str:
    recon = repo / "recon" / target
    _write_host(recon, target)
    param_path = recon / "urls" / "with_params.txt"
    with param_path.open("w", encoding="utf-8") as handle:
        for index in range(max(0, count - 1)):
            handle.write(
                f"https://api.{target}/catalog/search?facet={index}&page={index % 997}\n"
            )
        tail = f"https://api.{target}/admin/payments?account_id=999999"
        handle.write(tail + "\n")
    (recon / "urls" / "api_endpoints.txt").write_text(tail + "\n", encoding="utf-8")
    (recon / "browser" / "xhr_endpoints.txt").write_text(tail + "\n", encoding="utf-8")
    return tail


def _write_large_legacy_inventory(repo: Path, target: str, mib: int, with_params: Path) -> None:
    recon = repo / "recon" / target
    _write_host(recon, target)
    (recon / "urls" / "with_params.txt").symlink_to(with_params)
    state_dir = repo / "state" / target
    state_dir.mkdir(parents=True)
    inventory = state_dir / "observations.json"
    prefix = (
        '{"schema_version":1,"target":"' + target
        + '","storage_key":"' + target
        + '","source_fingerprint":"legacy","last_synced_at":"",'
        + '"observations":[],"padding":"'
    ).encode("utf-8")
    suffix = b'"}\n'
    requested = max(len(prefix) + len(suffix), mib * 1024 * 1024)
    with inventory.open("wb") as handle:
        handle.write(prefix)
        remaining = requested - len(prefix) - len(suffix)
        block = b"x" * (1024 * 1024)
        while remaining:
            chunk = block[: min(remaining, len(block))]
            handle.write(chunk)
            remaining -= len(chunk)
        handle.write(suffix)

    findings = repo / "findings" / target
    findings.mkdir(parents=True)
    (findings / "findings.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "target": target,
                "findings": [
                    {
                        "id": "candidate-scale",
                        "type": "idor",
                        "url": f"https://api.{target}/orders/1",
                        "validation_status": "candidate",
                        "report_status": "not_generated",
                        "rubric": {"ready": False, "status": "needs-evidence"},
                    }
                ],
            }
        ),
        encoding="utf-8",
    )


def _worker(mode: str, repo: Path, target: str, tail: str = "") -> dict:
    started = time.perf_counter()
    if mode == "finalize":
        result = finalize_surface(repo, target)
        projection = load_surface_projection(repo, target)
        surface = projection.get("surface") or {}
        stats = surface.get("stats") or {}
        candidate_urls = {
            str(item.get("url") or "")
            for bucket in ("p1", "p2", "review_pool")
            for item in (surface.get(bucket) or [])
            if isinstance(item, dict)
        }
        index_status = load_surface_index_status(repo, target)
        index_summary = index_status.get("summary") or {}
        payload = {
            "status": result.get("status"),
            "index_status": index_status.get("status"),
            "projection_status": projection.get("status"),
            "total_candidates": int(stats.get("total_candidates", 0) or 0),
            "observation_total": int(stats.get("observation_total", 0) or 0),
            "observation_untouched": int(stats.get("observation_untouched", 0) or 0),
            "observation_stale": int(stats.get("observation_stale", 0) or 0),
            "tail_preserved": bool(tail and tail in candidate_urls),
            "index_summary": {
                key: int(index_summary.get(key, 0) or 0)
                for key in (
                    "source_rows",
                    "unique_urls",
                    "exact_duplicates",
                    "target_owned_urls",
                    "off_target_urls",
                    "shape_count",
                    "max_shape_variants",
                    "duplicate_key_urls",
                    "encoded_query_urls",
                    "non_default_port_urls",
                )
            },
        }
    elif mode == "bootstrap":
        state = build_autopilot_bootstrap_state(str(repo), target)
        payload = {
            "next_action": state.get("next_action"),
            "projection_status": (state.get("surface_projection") or {}).get("status"),
            "has_recon": bool(state.get("has_recon")),
        }
    else:  # pragma: no cover - parser restricts worker mode
        raise ValueError(f"unknown worker mode: {mode}")
    payload["seconds"] = round(time.perf_counter() - started, 3)
    payload["peak_rss_mib"] = round(_rss_mib(), 1)
    return payload


def _run_worker(mode: str, repo: Path, target: str, *, tail: str = "") -> dict:
    command = [
        sys.executable,
        str(Path(__file__).resolve()),
        "--worker",
        mode,
        "--repo-root",
        str(repo),
        "--target",
        target,
    ]
    if tail:
        command.extend(["--tail", tail])
    completed = subprocess.run(command, check=False, capture_output=True, text=True)
    if completed.returncode != 0:
        raise RuntimeError(
            f"surface scaling worker failed ({mode}): {completed.stderr.strip() or completed.stdout.strip()}"
        )
    return json.loads(completed.stdout)


def _file_snapshot(path: Path) -> dict:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    stat = path.stat()
    return {
        "size": stat.st_size,
        "mtime_ns": stat.st_mtime_ns,
        "sha256": digest.hexdigest(),
    }


def _external_exact_baseline(path: Path) -> set[str]:
    """读取 opt-in 外部 URL 的 exact identity；集合仅驻留校验进程内。"""
    exact: set[str] = set()
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for raw in handle:
            value = " ".join(raw.strip().splitlines())
            if value and not value.startswith("#"):
                exact.add(value)
    return exact


def _verify_external_index(repo: Path, target: str, expected: set[str]) -> dict:
    """逐行核对 external exact URL 全集，不把任何 URL 写入输出。"""
    remaining = set(expected)
    unexpected = 0
    duplicate_rows = 0
    seen_rows = 0
    for row in iter_surface_index(repo, target):
        seen_rows += 1
        value = str(row.get("url") or "")
        if value in remaining:
            remaining.remove(value)
        elif value in expected:
            duplicate_rows += 1
        else:
            unexpected += 1
    return {
        "expected_exact_unique": len(expected),
        "index_rows": seen_rows,
        "missing": len(remaining),
        "unexpected": unexpected,
        "duplicate_rows": duplicate_rows,
        "exact_identity_match": not remaining and not unexpected and not duplicate_rows,
    }


def _validate(
    *,
    urls: int,
    legacy_inventory_mib: int,
    max_finalize_seconds: float,
    max_bootstrap_seconds: float,
    max_rss_mib: float,
    external_with_params: str,
    external_inventory: str,
    external_target: str,
) -> dict:
    failures: list[str] = []
    with tempfile.TemporaryDirectory(prefix="ccst-surface-scale-") as temp_name:
        repo = Path(temp_name)
        target = external_target if external_with_params else "scale.test"
        external_snapshots: dict[str, tuple[Path, dict]] = {}
        external_exact: set[str] | None = None
        if external_with_params:
            source = Path(external_with_params).resolve()
            external_snapshots["with_params"] = (source, _file_snapshot(source))
            external_exact = _external_exact_baseline(source)
            recon = repo / "recon" / target
            _write_host(recon, target)
            (recon / "urls" / "with_params.txt").symlink_to(source)
            tail = ""
            urls = sum(1 for _ in source.open("r", encoding="utf-8", errors="replace"))
        else:
            tail = _write_synthetic_surface(repo, target, urls)

        cold = _run_worker("finalize", repo, target, tail=tail)
        external_index = (
            _verify_external_index(repo, target, external_exact)
            if external_exact is not None
            else {}
        )
        warm = _run_worker("bootstrap", repo, target)

        legacy = {}
        if legacy_inventory_mib > 0:
            legacy_target = "legacy.test"
            source_params = repo / "recon" / target / "urls" / "with_params.txt"
            _write_large_legacy_inventory(
                repo,
                legacy_target,
                legacy_inventory_mib,
                source_params,
            )
            if external_inventory:
                inventory_source = Path(external_inventory).resolve()
                external_snapshots["inventory"] = (inventory_source, _file_snapshot(inventory_source))
                staged = repo / "state" / legacy_target / "observations.json"
                staged.unlink()
                staged.symlink_to(inventory_source)
            legacy = _run_worker("bootstrap", repo, legacy_target)

        unchanged = all(_file_snapshot(path) == before for path, before in external_snapshots.values())
        if cold.get("status") != "ok" or cold.get("index_status") != "valid":
            failures.append("cold surface finalizer/index did not complete")
        if cold.get("projection_status") != "valid":
            failures.append("surface projection was not published")
        index_summary = cold.get("index_summary") or {}
        if not external_with_params and index_summary.get("unique_urls") != urls:
            failures.append("synthetic exact index row count changed")
        if not external_with_params and not cold.get("tail_preserved"):
            failures.append("last high-value URL did not reach bounded output")
        if external_index and not external_index.get("exact_identity_match"):
            failures.append("external exact URL identities were not preserved")
        if external_index and index_summary.get("unique_urls") != external_index.get(
            "expected_exact_unique"
        ):
            failures.append("external exact index count differs from baseline")
        if cold.get("observation_total", 0) < index_summary.get("unique_urls", 0):
            failures.append("complete observation inventory lost indexed URL identities")
        if cold.get("observation_untouched") != cold.get("observation_total"):
            failures.append("surface refresh mutated untouched observation lifecycle")
        if warm.get("projection_status") != "valid" or warm.get("next_action") != "hunt_p1":
            failures.append("warm bootstrap did not consume exact projection")
        if warm.get("seconds", 999) > max_bootstrap_seconds:
            failures.append("warm bootstrap exceeded time budget")
        if cold.get("seconds", 999) > max_finalize_seconds:
            failures.append("cold finalizer exceeded time budget")
        if cold.get("peak_rss_mib", 999999) > max_rss_mib:
            failures.append("cold finalizer exceeded RSS budget")
        if legacy and legacy.get("next_action") != "collect_candidate_evidence":
            failures.append("priority bootstrap did not short-circuit legacy large artifacts")
        if legacy and legacy.get("seconds", 999) > max_bootstrap_seconds:
            failures.append("legacy priority bootstrap exceeded time budget")
        if not unchanged:
            failures.append("external read-only artifact changed")

        return {
            "passed": not failures,
            "failures": failures,
            "urls": urls,
            "legacy_inventory_mib": legacy_inventory_mib,
            "cold": cold,
            "warm_bootstrap": warm,
            "legacy_priority_bootstrap": legacy,
            "external_index": external_index,
            "external_source_unchanged": unchanged,
        }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Validate lossless surface scaling")
    parser.add_argument("--urls", type=int, default=300_000)
    parser.add_argument("--legacy-inventory-mib", type=int, default=192)
    parser.add_argument("--max-finalize-seconds", type=float, default=90.0)
    parser.add_argument("--max-bootstrap-seconds", type=float, default=10.0)
    parser.add_argument("--max-rss-mib", type=float, default=512.0)
    parser.add_argument("--external-with-params", default="")
    parser.add_argument("--external-inventory", default="")
    parser.add_argument("--external-target", default="scale.test")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--worker", choices=("finalize", "bootstrap"), default="")
    parser.add_argument("--repo-root", default="")
    parser.add_argument("--target", default="")
    parser.add_argument("--tail", default="")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.worker:
        print(
            json.dumps(
                _worker(args.worker, Path(args.repo_root), args.target, args.tail),
                ensure_ascii=False,
                separators=(",", ":"),
            )
        )
        return 0
    if args.urls < 1 or args.legacy_inventory_mib < 0:
        raise SystemExit("--urls must be positive and --legacy-inventory-mib non-negative")
    payload = _validate(
        urls=args.urls,
        legacy_inventory_mib=args.legacy_inventory_mib,
        max_finalize_seconds=args.max_finalize_seconds,
        max_bootstrap_seconds=args.max_bootstrap_seconds,
        max_rss_mib=args.max_rss_mib,
        external_with_params=args.external_with_params,
        external_inventory=args.external_inventory,
        external_target=args.external_target,
    )
    if args.json:
        print(json.dumps(payload, ensure_ascii=False, separators=(",", ":")))
    else:
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    return 0 if payload["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
