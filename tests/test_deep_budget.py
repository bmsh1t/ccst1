import pytest

from tools.deep_budget import project_budget


def test_project_budget_keeps_legacy_budget_when_adaptive_is_off():
    result = project_budget(
        5,
        maximum=40,
        url_count=80,
        parameter_count=30,
        response_variance=5,
        high_value_evidence=4,
    )
    assert result["budget"] == 5
    assert result["adaptive"] is False
    assert result["partial_on_exhaustion"] is True


def test_project_budget_expands_but_stays_bounded():
    result = project_budget(
        5,
        maximum=20,
        url_count=80,
        parameter_count=30,
        response_variance=5,
        high_value_evidence=4,
        adaptive=True,
    )
    assert result["budget"] == 20
    assert result["reasons"] == [
        "broad URL surface",
        "parameter density",
        "response variance",
        "high-value evidence",
    ]


@pytest.mark.parametrize(
    "kwargs",
    [
        {"base": 0},
        {"base": 5, "minimum": 10, "maximum": 5},
        {"base": 10, "maximum": 5},
    ],
)
def test_project_budget_rejects_invalid_bounds(kwargs):
    with pytest.raises(ValueError):
        project_budget(**kwargs)
