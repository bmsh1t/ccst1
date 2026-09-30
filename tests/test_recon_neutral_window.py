from tools.recon_candidates import build_js_deep_candidates


def test_js_window_preserves_input_order_and_full_source(tmp_path):
    src, dst = tmp_path / 'all', tmp_path / 'window'
    src.write_text('z.js\nauth.js\nlast.js\n')
    result = build_js_deep_candidates(src, dst, limit=1)
    assert dst.read_text() == 'z.js\n'
    assert result['remaining'] == 2
    assert result['expansion_ref'] == str(src.resolve())
    assert src.read_text() == 'z.js\nauth.js\nlast.js\n'
