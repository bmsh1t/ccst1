"""Deep-JS acquisition preserves selection order without filename scoring."""
import pytest
from tools.deep_js_packer import select_bundle_urls


def test_bundle_order_scope_and_budget(tmp_path):
    candidates = tmp_path / 'candidates.txt'
    first = 'https://fixture.test/z.js'
    second = 'https://fixture.test/runtime-main-app.js'
    original = f'not-a-url\nhttps://other.test/main.js\n{first}\n{first}\n{second}\n'
    candidates.write_text(original)
    assert select_bundle_urls('fixture.test', candidates, max_bundles=1) == [first]
    assert select_bundle_urls('fixture.test', candidates, explicit_urls=[second, first], max_bundles=2) == [second, first]
    assert candidates.read_text() == original
    with pytest.raises(ValueError, match='outside target scope'):
        select_bundle_urls('fixture.test', candidates, explicit_urls=['https://other.test/main.js'])
    with pytest.raises(ValueError, match='at most'):
        select_bundle_urls('fixture.test', candidates, explicit_urls=[first, second], max_bundles=1)
    candidates.write_text('')
    assert select_bundle_urls('fixture.test', candidates) == []
