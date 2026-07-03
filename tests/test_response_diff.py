"""Tests for response_diff validation helpers."""

from response_diff import diff_responses, snapshot_response


def test_response_diff_extracts_json_count_and_fields():
    snapshot = snapshot_response(
        200,
        {"Content-Type": "application/json"},
        '{"status":"success","data":[{"id":1,"email":"a@example.test"},{"id":2,"role":"user"}]}',
    )

    assert snapshot["status"] == 200
    assert snapshot["json_valid"] is True
    assert snapshot["json_count"] == 2
    assert snapshot["json_fields"] == ["email", "id", "role"]


def test_response_diff_reports_material_result_count_delta():
    diff = diff_responses(
        baseline_status=200,
        baseline_headers={"Content-Type": "application/json"},
        baseline_body='{"data":[{"id":1}]}',
        variant_status=200,
        variant_headers={"Content-Type": "application/json"},
        variant_body='{"data":[{"id":1},{"id":2},{"id":3}]}',
    )

    assert diff["diff"]["changed_any"] is True
    assert diff["diff"]["changed"]["json_count"] is True
    assert diff["diff"]["json_count"]["delta"] == 2
    assert "json_count 1 -> 3" in diff["diff"]["summary"]
