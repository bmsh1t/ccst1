"""高价值软信号的词边界与结构化输入契约。"""

from tools.high_value_signals import classify_high_value_signal


def test_short_tokens_do_not_match_inside_hostname_or_ordinary_words():
    hostname_noise = classify_high_value_signal(
        path="/articles/search?q=security",
        evidence="https://source-social-abcdomain.example/articles/search?q=security",
    )

    assert "rce" not in hostname_noise.classes
    assert "ci" not in hostname_noise.classes
    assert "cd" not in hostname_noise.classes


def test_short_tokens_still_match_explicit_segments_and_words():
    path_signal = classify_high_value_signal(path="/ci/builds")
    evidence_signal = classify_high_value_signal(evidence="confirmed RCE candidate")

    assert "ci" in path_signal.classes
    assert "rce" in evidence_signal.classes


def test_dom_and_reflected_routes_are_client_side_without_sessionstorage_auth_noise():
    dom = classify_high_value_signal(
        path="/dom/toxicdom/external/sessionStorage/array/eval"
    )
    reflected = classify_high_value_signal(path="/reflected/url/css_import")

    assert "xss" in dom.classes
    assert "auth" not in dom.classes
    assert "xss" in reflected.classes
