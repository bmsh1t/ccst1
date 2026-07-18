"""Bounded Surface frontiers 与 materialized legacy 排序的等价性。"""

from __future__ import annotations

import random

from tools.surface import (
    _SurfaceCandidateFrontiers,
    _build_review_pool,
)


def _candidate(index: int, score: int, category: int) -> dict:
    item = {
        "url": f"https://target.com/items/{index}",
        "score": score,
        "score_breakdown": [],
        "reasons": [f"candidate-{index}"],
        "suggested": "review",
    }
    if category & 1:
        item["evidence_convergence"] = ["browser", "js"]
    if category & 2:
        item["browser_observed"] = True
    if category & 4:
        item["js_intel_observed"] = True
    if category & 8:
        item["scanner_findings"] = [{"id": f"F-{index}"}]
    if category & 16:
        item["target_memory_hits"] = [{"text": "continue"}]
    if category & 32:
        item["score_breakdown"] = [{"source": "attack_value", "score": 2}]
    return item


def test_frontiers_match_materialized_sort_for_scores_ties_and_overlaps():
    rng = random.Random(20260714)
    candidates = [
        _candidate(index, rng.randint(-4, 24), rng.randint(0, 63))
        for index in range(2500)
    ]
    materialized = sorted(candidates, key=lambda item: item["score"], reverse=True)
    expected_p1 = [item for item in materialized if item["score"] >= 8][:8]
    expected_p2 = [item for item in materialized if 3 <= item["score"] < 8][:8]
    expected_review = _build_review_pool(materialized)

    frontiers = _SurfaceCandidateFrontiers(set())
    for sequence, item in enumerate(candidates):
        frontiers.add(item, sequence)

    actual_p1 = [item for _sequence, item in frontiers.p1.values()]
    actual_p2 = [item for _sequence, item in frontiers.p2.values()]
    actual_review = _build_review_pool(frontiers.review_candidates())
    assert [item["url"] for item in actual_p1] == [item["url"] for item in expected_p1]
    assert [item["url"] for item in actual_p2] == [item["url"] for item in expected_p2]
    assert [
        (item["url"], item["score"], item["review_reason"])
        for item in actual_review
    ] == [
        (item["url"], item["score"], item["review_reason"])
        for item in expected_review
    ]


def test_frontier_keeps_first_seen_order_for_equal_scores():
    candidates = [_candidate(index, 9, 32) for index in range(100)]
    frontiers = _SurfaceCandidateFrontiers(set())
    for sequence, item in enumerate(candidates):
        frontiers.add(item, sequence)

    assert [item["url"] for _sequence, item in frontiers.p1.values()] == [
        item["url"] for item in candidates[:8]
    ]
