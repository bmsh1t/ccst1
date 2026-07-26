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


def test_review_pool_reserves_high_value_categories_before_source_flood():
    noisy = [
        {
            "url": f"https://target.com/search?page={index}",
            "score": 20 - index,
            "evidence_convergence": ["browser", "js"],
            "score_breakdown": [],
        }
        for index in range(20)
    ]
    critical = {
        "url": "https://target.com/admin/payments/upload?account_id=1",
        "score": 100,
        "score_breakdown": [{"source": "attack_value", "score": 20}],
    }

    pool = _build_review_pool([*noisy, critical])

    assert len(pool) == 16
    assert critical["url"] in [item["url"] for item in pool]
    selected = next(item for item in pool if item["url"] == critical["url"])
    assert selected["review_reason"] == "high-value category: admin/payment/upload/file"

    frontiers = _SurfaceCandidateFrontiers(set())
    for sequence, item in enumerate(noisy):
        frontiers.add(item, sequence)
    low_score_category = {**critical, "score": -10}
    frontiers.add(low_score_category, len(noisy))

    bounded_pool = _build_review_pool(frontiers.review_candidates())
    assert low_score_category["url"] in [item["url"] for item in bounded_pool]


def test_review_pool_reserves_at_most_two_neutral_new_observation_representatives():
    candidates = [
        {**_candidate(index, 0, 0), "new_observation": True}
        for index in range(3)
    ]

    pool = _build_review_pool(candidates)

    assert [item["url"] for item in pool] == [item["url"] for item in candidates[:2]]
    assert all(item["review_reason"] == "top advisory score (low-evidence fallback)" for item in pool)
    assert all(not item["score_breakdown"] for item in pool)


def test_review_pool_labels_dom_surface_as_client_side_before_incidental_file_words():
    item = {
        "url": "https://target.com/reflected/url/css_import?q=a",
        "score": 4,
        "score_breakdown": [{"source": "attack_value", "score": 2}],
    }

    selected = _build_review_pool([item])[0]

    assert selected["review_reason"] == "high-value category: client-side/file"
