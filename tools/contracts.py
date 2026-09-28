#!/usr/bin/env python3
"""Shared cross-owner contracts (stage-two #9).

跨 owner 不变量集中声明。任何一方改契约，另一方 import 同一常量——编译期可见。
这是 validate↔queue 集成缺口（藏两轮才暴露）的根治：契约不再散落在各 owner
的私有副本里。只依赖标准库（纯常量/纯函数），不引入业务模块依赖。
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any

# --- Queue ↔ Checkpoint：激活字段与版本 ------------------------------------
# ACTIVATION_REQUIRED_CLAIM_FIELDS 已随 16 字段必填闸退役（2026-09-14
# dumb-queue refactor）：claim 是显式 --id 写入 + 六项机械写时不变量，
# 不再有需要共享的 claim schema。

# --- validate ↔ queue：终态契约 --------------------------------------------
# validate.py 的 canonical finding 终态与 queue resolve 的允许状态必须使用
# 同一集合，否则 validate 归档后 queue 还能把动作复活。
VALIDATE_TERMINAL_FINDING_STATES = frozenset({
    "validated",
    "rejected",
    "duplicate",
})

# --- checkpoint ↔ queue：锁序 ----------------------------------------------
# 所有同时持有两把锁的路径必须按此顺序获取，防死锁。
CHECKPOINT_QUEUE_LOCK_ORDER = ("checkpoint_witness_lock", "queue_mutation_lock")

# --- ledger ↔ runner：红线事件 ---------------------------------------------
# evidence_ledger 归档为 blocked_redline 的事件结果（红线三道闸的第三道：
# post-hoc 重写），runner/validate 不得将其当 tested_clean 消费。
LEDGER_REDLINE_EVENTS = frozenset({
    "blocked_redline",
})

# --- runner ↔ witness/report/validate：operation ID 契约 --------------------
# 纯数据/哈希函数：artifact 绑定 → 稳定 operation ID。原定义在
# validation_runner（Executor），但 Parser/Witness/Report 都要复算同一 ID
# 来对账证据——纯函数上移到共享契约后，证据消费方不再反向依赖发请求的
# 执行器（2026-09-12 优化评审 P1）。schema/operation ID/旧导出全部不变。


def artifact_digest_material(bindings: list[dict[str, Any]]) -> list[dict[str, str]]:
    """Return path-independent artifact identity for operation hashing."""
    material = []
    for binding in bindings:
        if not isinstance(binding, dict):
            continue
        kind = str(binding.get("kind") or "").strip().lower()
        digest = str(binding.get("sha256") or "").strip().lower()
        # Only wire request/response artifacts define an operation. Derived
        # diff/identity files often contain per-run paths and would break
        # replay idempotency without adding evidence strength.
        if kind and digest and (
            kind == "request"
            or kind.endswith("_request")
            or kind == "response"
            or kind.endswith("_response")
        ):
            material.append({"kind": kind, "sha256": digest})
    return sorted(material, key=lambda item: (item["kind"], item["sha256"]))


def runner_operation_id(material: dict[str, Any]) -> str:
    encoded = json.dumps(material, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
    return f"runner:{hashlib.sha256(encoded.encode('utf-8')).hexdigest()[:24]}"


# Wire-fact vocabulary: the complete set of mechanically checkable facts the
# AI may declare in ``expected``. The runner knows these predicates over raw
# replay observations; it does NOT know vulnerability classes. Any category
# (SQLi, NoSQLi, SSTI, IDOR, missing-auth, ...) uses the same vocabulary.
WIRE_FACT_NAMES = frozenset({
    "error_marker_variant_only",   # variant body shows a DB/parser error marker, baseline does not
    "count_delta_positive",        # variant JSON count is greater than baseline
    "count_delta_negative",        # variant JSON count is smaller than baseline
    "fields_added",                # variant response added JSON fields
    "fields_removed",              # variant response removed JSON fields
    "body_length_delta",           # material body-length difference beyond noise threshold
    "status_delta",                # status codes differ between the sides
    "material_diff_any",           # any material response difference
    "identical_success_pair",      # same successful status and complete retained response body
    "both_sides_rejected",         # same rejected status and complete retained response body
    "stable_timing_delta",         # variant consistently slower than baseline across repeats
    "distinct_bodies",             # baseline and variant body bytes differ (no threshold)
})
# Needle facts take the form name::<literal substring>; the AI supplies the
# needle (judgment), the runner verifies presence mechanically (reconciliation).
WIRE_NEEDLE_FACT_NAMES = frozenset({
    "variant_body_contains",       # needle appears in EVERY variant body
    "baseline_body_lacks",         # needle appears in NO baseline body and EVERY variant body
})


# Shared validation input schema; consumers never import the validation CLI.
MACHINE_DECISION_SCHEMA_VERSION = 2
SEVEN_QUESTION_DEFINITIONS = (
    ("q1_replayable_now", "Can I demonstrate this step-by-step right now?"),
    ("q2_impact_demonstrated", "Is the impact clearly demonstrated?"),
    ("q3_target_context", "Is the vulnerable asset tied to the supplied target context?"),
    ("q4_attacker_access", "Does it avoid privileged access an attacker cannot get?"),
    ("q5_not_known_behavior", "Is this not known or documented behavior?"),
    ("q6_impact_beyond_possible", "Can impact be proved beyond technically possible?"),
    ("q7_not_never_submit", "Is this not on the never-submit list unless chained?"),
)


SENSITIVE_OBSERVATION_VALUE_RE = re.compile(
    r"\b(?:authorization|cookie|set-cookie|x-api-key)\b\s*[\"']?\s*[:=]\s*[\"']?\s*\S+|"
    r"\bbearer\s+[A-Za-z0-9._~+/=-]{3,}|"
    r"\b(?:(?:access|id|refresh)[_-]?token|token|password|api[-_ ]?key)\b"
    r"\s*[\"']?\s*[:=]\s*[\"']?\s*\S+",
    re.I,
)


def validate_observed_difference(value: Any) -> str:
    """Bound public observation prose and reject credential/header values."""
    text = re.sub(r"\s+", " ", str(value or "").strip())
    if not text:
        raise ValueError("Action Queue depth contract requires last_outcome.observed_difference")
    if len(text) > 500:
        raise ValueError("Action Queue depth contract last_outcome.observed_difference exceeds 500 characters")
    if SENSITIVE_OBSERVATION_VALUE_RE.search(text):
        raise ValueError("Action Queue observed difference cannot contain credential or header values")
    return text
