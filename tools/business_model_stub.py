#!/usr/bin/env python3
"""business_model_stub.py — 从 recon 产物确定性派生 business model stub（批次 B4）。

Task: 09-11-ai-capability-roadmap, batch 7 (B4).

安全设计：纯确定性派生，不调 AI、不做语义推断，只搬运结构化字段——

- 数据源全部是磁盘上的 recon 产物（``recon/<target>/`` 下的 structured JSON
  与 bounded 文本清单），从 artifacts 派生而非存储，无判断代理；
- 生成的是 **stub**：技术栈段、已观察 actor/对象段从证据搬运；业务判断段
  （app purpose / crown jewels / trust boundaries / workflows）留空并标记
  ``<!-- AI: fill from observed purpose -->``，由 AI 复核补充；
- 不存在的输入文件按"无数据"处理（该段省略），不报错；完全没有任何 recon
  产物时拒绝生成（报错退出），避免制造空壳文件冒充 business model。

新鲜度契约（与 ``commands/autopilot.md`` 的 30 天复用规则对齐）：

- 已存在 ``evidence/<target>/business_model.md`` 且 mtime 在 30 天内 → 跳过
  并提示（exit 0，status=skipped_fresh）；
- 超过 30 天或 ``--refresh`` → 覆盖重新生成。**覆盖是破坏性的**：AI 手工
  填写的业务判断段会丢失。B4 降级决策（见 implement.md 7.5）：保段回带的
  解析实现复杂度高且易错，选择了覆盖式 ``--refresh`` + 输出警告，要求先
  备份；未显式传 ``--refresh`` 时旧文件超过 30 天也只是提示、不覆盖，
  AI 必须显式选择。

机械闸门全部属于桶纪律内类别：参数/格式（explicit format）、备份上限
（bounded failsafe）；没有任何内容级闸门。
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parents[1]
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

try:
    from tools.technology_inventory import (
        INVENTORY_RELATIVE_PATH,
        component_labels,
        load_or_build_inventory,
    )
    from tools.target_paths import canonical_target_value, target_storage_key
except ImportError:  # pragma: no cover - direct tools/ execution
    from technology_inventory import (  # type: ignore
        INVENTORY_RELATIVE_PATH,
        component_labels,
        load_or_build_inventory,
    )
    from target_paths import (  # type: ignore
        canonical_target_value,
        target_storage_key,
    )


STUB_SCHEMA_VERSION = 1
FRESH_WINDOW = timedelta(days=30)
# Bounded inputs: a URL/endpoint list with hundreds of thousands of lines is a
# pipeline artifact, not a business-model observation set.
MAX_ENDPOINT_LINES = 400
AI_FILL_MARKER = "<!-- AI: fill from observed purpose -->"
DERIVED_NOTE = (
    "Stub deterministically derived from recon artifacts "
    "(technology_inventory + observed endpoint paths); no AI judgment in "
    "this section."
)

# Path-shaped endpoint observations, read as text and parsed only into
# (path, query-param) pairs — no semantic inference.
ENDPOINT_SOURCES = (
    Path("urls/api_endpoints.txt"),
    Path("urls/with_params.txt"),
    Path("urls/all.txt"),
)


class BusinessModelStubError(ValueError):
    """Pre-write rejection: missing inputs, bad arguments, or flag discipline."""


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _read_lines(path: Path, limit: int) -> list[str]:
    try:
        with path.open(encoding="utf-8", errors="replace") as handle:
            return [line.strip() for line in handle if line.strip()][:limit]
    except OSError:
        return []


def _split_target_url(url: str) -> tuple[str, str]:
    """Split a same-target URL into (path, query-string) without semantics."""
    text = str(url or "").strip()
    if "://" in text:
        _, _, text = text.partition("://")
    path, _, query = text.partition("?")
    _, _, path = path.partition("/")
    return "/" + path, query


def _observed_endpoints(repo_root: Path, recon_dir: Path) -> tuple[list[str], list[str]]:
    """Collect bounded observed endpoint paths and query parameter names.

    Reads at most ``MAX_ENDPOINT_LINES`` per source, keeps the first source
    that yields content (priority order above), and derives path + parameter
    names mechanically (no classification of what the endpoint *means*).
    """
    for relative in ENDPOINT_SOURCES:
        lines = _read_lines(recon_dir / relative, MAX_ENDPOINT_LINES)
        if not lines:
            continue
        paths: list[str] = []
        params: list[str] = []
        for line in lines:
            path, query = _split_target_url(line)
            if path and path not in paths:
                paths.append(path)
            for pair in query.split("&"):
                name = pair.partition("=")[0].strip()
                if name and name not in params:
                    params.append(name)
        return paths, params
    return [], []


def _host_labels(inventory: dict) -> list[str]:
    labels: list[str] = []
    for host in inventory.get("hosts") or []:
        if not isinstance(host, dict):
            continue
        url = str(host.get("url") or "").strip()
        status = str(host.get("status") or "").strip()
        title = str(host.get("title") or "").strip()
        if not url:
            continue
        label = url
        if title:
            label = f"{label} (title: {title})"
        if status:
            label = f"{label} [status {status}]"
        labels.append(label)
    return labels


def render_stub_markdown(
    *,
    target: str,
    inventory: dict,
    endpoints: list[str],
    params: list[str],
    generated_at: str,
) -> str:
    tech_labels = component_labels(inventory)
    host_labels = _host_labels(inventory)

    lines: list[str] = []
    lines.append(f"# Business Model / Crown Jewels — {target}")
    lines.append("")
    lines.append(f"- Generated: {generated_at} (stub, schema v{STUB_SCHEMA_VERSION})")
    lines.append(f"- {DERIVED_NOTE}")
    lines.append("")

    lines.append("## App purpose")
    lines.append("")
    lines.append(AI_FILL_MARKER)
    lines.append("")

    lines.append("## Observed technology stack")
    lines.append("")
    if tech_labels:
        for label in tech_labels:
            lines.append(f"- {label}")
        lines.append(
            f"- source: {INVENTORY_RELATIVE_PATH.as_posix()} "
            f"(fingerprint {str(inventory.get('fingerprint') or 'n/a')})"
        )
    else:
        lines.append("- no components identified by technology inventory")
    if host_labels:
        lines.append("")
        lines.append("Observed live hosts:")
        for label in host_labels:
            lines.append(f"- {label}")
    lines.append("")

    lines.append("## Observed actors / objects (evidence-derived)")
    lines.append("")
    if endpoints:
        lines.append("Observed endpoint paths (no meaning inferred):")
        for path in endpoints[:MAX_ENDPOINT_LINES]:
            lines.append(f"- {path}")
        if len(endpoints) > MAX_ENDPOINT_LINES:
            lines.append(f"- ... {len(endpoints) - MAX_ENDPOINT_LINES} more")
    else:
        lines.append("- no endpoint paths observed in recon artifacts yet")
    lines.append("")
    if params:
        lines.append("Observed query parameters:")
        for name in params:
            lines.append(f"- {name}")
    lines.append("")

    lines.append("## Crown jewels")
    lines.append("")
    lines.append(AI_FILL_MARKER)
    lines.append("")

    lines.append("## Trust boundaries")
    lines.append("")
    lines.append(AI_FILL_MARKER)
    lines.append("")

    lines.append("## Sensitive workflows")
    lines.append("")
    lines.append(AI_FILL_MARKER)
    lines.append("")

    lines.append("## First hypotheses")
    lines.append("")
    lines.append(AI_FILL_MARKER)
    lines.append("")
    return "\n".join(lines)


def generate_stub(
    *,
    target: str,
    repo_root: Path | str = BASE_DIR,
    refresh: bool = False,
    force: bool = False,
) -> dict:
    """Generate ``evidence/<target>/business_model.md`` from recon artifacts.

    ``refresh`` re-generates over an existing file (destructive for AI-filled
    sections; a warning plus the previous bytes path are returned). Without
    ``refresh`` an existing file inside the 30-day freshness window is skipped.
    ``force`` bypasses the freshness skip for CI/test regeneration.
    """
    if not str(target or "").strip():
        raise BusinessModelStubError("target is required")
    repo = Path(repo_root)
    resolved = canonical_target_value(target)
    key = target_storage_key(resolved)
    recon_dir = repo / "recon" / key
    if not recon_dir.is_dir():
        raise BusinessModelStubError(
            f"no recon artifacts for target {resolved}: {recon_dir} does not exist; "
            "run Recon first — a stub without any observed evidence would be "
            "an empty shell, not a business model"
        )
    has_recon_content = any(recon_dir.rglob("*"))
    if not has_recon_content:
        raise BusinessModelStubError(
            f"recon directory for target {resolved} is empty; "
            "run Recon first — a stub without any observed evidence would be "
            "an empty shell, not a business model"
        )

    output_path = repo / "evidence" / key / "business_model.md"
    now = _now_utc()
    result: dict = {
        "status": "",
        "target": resolved,
        "path": str(output_path),
        "repo_root": str(repo),
        "generated_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
    }

    if output_path.is_file():
        try:
            mtime = datetime.fromtimestamp(output_path.stat().st_mtime, tz=timezone.utc)
        except OSError as exc:
            raise BusinessModelStubError(f"unable to inspect existing file: {exc}") from exc
        age = now - mtime
        if refresh:
            result["refreshed"] = True
            result["previous_mtime"] = mtime.strftime("%Y-%m-%dT%H:%M:%SZ")
            result["warning"] = (
                "--refresh overwrites the file: AI-filled business-judgment "
                "sections are lost. Back up the previous file first if it "
                "contains filled sections."
            )
        elif age <= FRESH_WINDOW and not force:
            result["status"] = "skipped_fresh"
            result["age_days"] = round(age.total_seconds() / 86400, 2)
            result["hint"] = (
                "business_model.md is inside the 30-day reuse window; pass "
                "--refresh to regenerate (AI-filled sections will be lost)"
            )
            return result
        elif age > FRESH_WINDOW and not force:
            # Stale (> 30 days) but not explicitly refreshed: do not silently
            # destroy possibly AI-filled content. Tell the caller to choose.
            result["status"] = "stale_needs_refresh"
            result["age_days"] = round(age.total_seconds() / 86400, 2)
            result["hint"] = (
                "business_model.md is older than 30 days; pass --refresh to "
                "regenerate (AI-filled sections will be lost)"
            )
            return result
        if result.get("refreshed"):
            result["status"] = "refreshed"
            result["previous_mtime"] = mtime.strftime("%Y-%m-%dT%H:%M:%SZ")
            result["warning"] = (
                "stale file regenerated: AI-filled business-judgment sections from "
                "the previous file are lost"
            )
        else:
            result["status"] = "regenerated_forced"
            result["previous_mtime"] = mtime.strftime("%Y-%m-%dT%H:%M:%SZ")
    else:
        result["status"] = "generated"

    inventory = load_or_build_inventory(repo, resolved)
    endpoints, params = _observed_endpoints(repo, recon_dir)
    markdown = render_stub_markdown(
        target=resolved,
        inventory=inventory,
        endpoints=endpoints,
        params=params,
        generated_at=result["generated_at"],
    )
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(markdown, encoding="utf-8")
    result["chars"] = len(markdown)
    result["endpoint_count"] = len(endpoints)
    result["param_count"] = len(params)
    result["component_count"] = len(component_labels(inventory))
    return result


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="business_model_stub",
        description=(
            "Deterministically derive evidence/<target>/business_model.md stub "
            "from recon artifacts (technology inventory + observed endpoint "
            "paths). AI judgment sections are left empty for review; no AI or "
            "semantic inference is involved."
        ),
    )
    parser.add_argument("--target", required=True, help="canonical target (host[:port] or URL)")
    parser.add_argument("--repo-root", default=str(BASE_DIR))
    parser.add_argument(
        "--refresh",
        action="store_true",
        help=(
            "regenerate even when business_model.md exists; DESTRUCTIVE for "
            "AI-filled sections — back up first"
        ),
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help=(
            "bypass the 30-day freshness skip without the --refresh warning "
            "(intended for CI/test regeneration)"
        ),
    )
    parser.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        result = generate_stub(
            target=args.target,
            repo_root=args.repo_root,
            refresh=args.refresh,
            force=args.force,
        )
    except BusinessModelStubError as exc:
        print(f"business_model_stub error: {exc}", file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0

    status = str(result.get("status") or "")
    print(f"business_model_stub: status={status} target={result['target']}")
    print(f"- path: {result['path']}")
    if result.get("age_days") is not None:
        print(f"- age: {result['age_days']} days")
    if result.get("hint"):
        print(f"- {result['hint']}")
    if result.get("warning"):
        print(f"- WARNING: {result['warning']}")
    if status in {"generated", "refreshed"}:
        print(
            f"- endpoints observed: {result.get('endpoint_count', 0)}; "
            f"components: {result.get('component_count', 0)}"
        )
        print("- AI judgment sections are left empty; review and fill them")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
