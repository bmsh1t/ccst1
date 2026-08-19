from tools.target_paths import compact_url


def test_compact_url_redacts_long_query_values_and_is_bounded():
    raw = "https://target.example/api/search?token=" + ("SECRET" * 500) + "&page=2"

    preview = compact_url(raw)

    assert len(preview) <= 240
    assert "SECRET" not in preview
    assert "token=..." in preview
    assert "url_len=" in preview
    assert "sha256=" in preview
    assert compact_url(raw) == preview


def test_compact_url_keeps_short_urls_exact():
    raw = "https://target.example/api/search?q=one"

    assert compact_url(raw) == raw


def test_compact_url_drops_userinfo_from_long_preview():
    raw = "https://user:SECRET@target.example/api/search?query=" + ("x" * 400)

    preview = compact_url(raw)

    assert "SECRET" not in preview
    assert "user@" not in preview
    assert "target.example" in preview
