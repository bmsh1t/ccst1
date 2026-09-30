"""Protected Checkpoint compatibility must not recreate object inference."""
from tools.case_state_seed import build_case_state_seed


def test_retired_seed_does_not_read_or_write(tmp_path):
    before = list(tmp_path.iterdir())
    assert build_case_state_seed(tmp_path, 'fixture.test') == {
        'status': 'retired', 'suggested_objects': []}
    assert list(tmp_path.iterdir()) == before
