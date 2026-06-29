"""Request smuggling 专项执行规格。

第一版只沉淀“执行前需要什么发送能力”和“什么证据类型可接受”，
不在这里内置高频 payload 矩阵，避免把知识层变成失控扫描器。
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from enum import Enum
import json

try:
    from tools.sender_semantics import (
        CAP_BYTE_EXACT,
        CAP_CONFLICTING_LENGTH,
        CAP_CONNECTION_REUSE,
        CAP_HTTP2,
        CAP_MALFORMED_HEADERS,
        CAP_PARTIAL_BODY,
        SenderProfile,
        select_sender,
    )
except ImportError:  # pragma: no cover - 支持从 tools/ 目录直接运行
    from sender_semantics import (  # type: ignore
        CAP_BYTE_EXACT,
        CAP_CONFLICTING_LENGTH,
        CAP_CONNECTION_REUSE,
        CAP_HTTP2,
        CAP_MALFORMED_HEADERS,
        CAP_PARTIAL_BODY,
        SenderProfile,
        select_sender,
    )


class SmugglingEvidence(str, Enum):
    TIMING_DIFFERENTIAL = "timing_differential"
    QUEUE_POISONING = "queue_poisoning"
    MALFORMED_METHOD = "malformed_method"
    SENTINEL_404 = "sentinel_404"
    RESPONSE_QUEUE_CAPTURE = "response_queue_capture"
    HEADER_GRAFT = "response_header_graft"
    VICTIM_DELIVERY = "victim_delivery"


@dataclass(frozen=True)
class SmugglingProbeSpec:
    """一个 smuggling 变体的执行前置条件和证据出口。"""

    variant: str
    required_capabilities: frozenset[str]
    evidence: tuple[SmugglingEvidence, ...]
    notes: tuple[str, ...] = ()

    def choose_sender(self, *, local_only: bool = True) -> SenderProfile | None:
        return select_sender(self.required_capabilities, local_only=local_only)


SMUGGLING_PROBE_SPECS: tuple[SmugglingProbeSpec, ...] = (
    SmugglingProbeSpec(
        variant="CL.TE",
        required_capabilities=frozenset(
            {CAP_BYTE_EXACT, CAP_CONFLICTING_LENGTH, CAP_CONNECTION_REUSE, CAP_PARTIAL_BODY}
        ),
        evidence=(
            SmugglingEvidence.TIMING_DIFFERENTIAL,
            SmugglingEvidence.MALFORMED_METHOD,
            SmugglingEvidence.SENTINEL_404,
            SmugglingEvidence.QUEUE_POISONING,
        ),
        notes=("必须确认 sender 没有重算 Content-Length 或合并 Transfer-Encoding。",),
    ),
    SmugglingProbeSpec(
        variant="TE.CL",
        required_capabilities=frozenset(
            {CAP_BYTE_EXACT, CAP_CONFLICTING_LENGTH, CAP_CONNECTION_REUSE, CAP_PARTIAL_BODY}
        ),
        evidence=(
            SmugglingEvidence.TIMING_DIFFERENTIAL,
            SmugglingEvidence.MALFORMED_METHOD,
            SmugglingEvidence.SENTINEL_404,
            SmugglingEvidence.QUEUE_POISONING,
        ),
        notes=("必须保留 chunk 边界和冲突 Content-Length。",),
    ),
    SmugglingProbeSpec(
        variant="TE obfuscation",
        required_capabilities=frozenset(
            {CAP_BYTE_EXACT, CAP_MALFORMED_HEADERS, CAP_CONNECTION_REUSE, CAP_PARTIAL_BODY}
        ),
        evidence=(
            SmugglingEvidence.TIMING_DIFFERENTIAL,
            SmugglingEvidence.MALFORMED_METHOD,
            SmugglingEvidence.SENTINEL_404,
        ),
        notes=("需要发送器允许 header 名称、空白和重复 header 的非规范形态。",),
    ),
    SmugglingProbeSpec(
        variant="0.CL",
        required_capabilities=frozenset(
            {CAP_BYTE_EXACT, CAP_CONFLICTING_LENGTH, CAP_CONNECTION_REUSE, CAP_PARTIAL_BODY}
        ),
        evidence=(
            SmugglingEvidence.MALFORMED_METHOD,
            SmugglingEvidence.SENTINEL_404,
            SmugglingEvidence.QUEUE_POISONING,
            SmugglingEvidence.VICTIM_DELIVERY,
        ),
        notes=("重点验证后端连接池影响，不能只看攻击者自己的单次响应。",),
    ),
    SmugglingProbeSpec(
        variant="H2.CL",
        required_capabilities=frozenset({CAP_HTTP2, CAP_BYTE_EXACT, CAP_CONFLICTING_LENGTH}),
        evidence=(
            SmugglingEvidence.SENTINEL_404,
            SmugglingEvidence.QUEUE_POISONING,
            SmugglingEvidence.VICTIM_DELIVERY,
        ),
        notes=("当前项目没有内置 H2 低层 sender；需要外部 Burp/Turbo Intruder 或后续 H2 实现。",),
    ),
    SmugglingProbeSpec(
        variant="H2 CRLF header injection",
        required_capabilities=frozenset({CAP_HTTP2, CAP_BYTE_EXACT, CAP_MALFORMED_HEADERS}),
        evidence=(
            SmugglingEvidence.HEADER_GRAFT,
            SmugglingEvidence.SENTINEL_404,
            SmugglingEvidence.RESPONSE_QUEUE_CAPTURE,
        ),
        notes=("必须确认 H2 客户端没有过滤 CRLF header value。",),
    ),
)


def get_probe_spec(variant: str) -> SmugglingProbeSpec:
    normalized = (variant or "").strip().lower()
    for spec in SMUGGLING_PROBE_SPECS:
        if spec.variant.lower() == normalized:
            return spec
    raise KeyError(f"unknown smuggling variant: {variant}")


def summarize_probe_specs(*, local_only: bool = True) -> list[dict]:
    rows = []
    for spec in SMUGGLING_PROBE_SPECS:
        sender = spec.choose_sender(local_only=local_only)
        rows.append(
            {
                "variant": spec.variant,
                "required_capabilities": sorted(spec.required_capabilities),
                "evidence": [item.value for item in spec.evidence],
                "selected_sender": sender.name if sender else "",
                "notes": list(spec.notes),
            }
        )
    return rows


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Describe request smuggling execution requirements.")
    parser.add_argument("--summary", action="store_true", help="List all smuggling probe specs.")
    parser.add_argument("--variant", default="", help="Show one variant, e.g. CL.TE, TE.CL, 0.CL, H2.CL.")
    parser.add_argument("--include-external", action="store_true", help="Allow external/non-local sender routes.")
    args = parser.parse_args(argv)

    local_only = not args.include_external
    if args.variant:
        spec = get_probe_spec(args.variant)
        sender = spec.choose_sender(local_only=local_only)
        payload = {
            "variant": spec.variant,
            "required_capabilities": sorted(spec.required_capabilities),
            "evidence": [item.value for item in spec.evidence],
            "selected_sender": sender.name if sender else "",
            "notes": list(spec.notes),
        }
    else:
        payload = {"smuggling_probe_specs": summarize_probe_specs(local_only=local_only)}

    print(json.dumps(payload, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
