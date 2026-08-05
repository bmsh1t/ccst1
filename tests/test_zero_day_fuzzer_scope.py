from tools import zero_day_fuzzer
from tools.auth_session import AuthSession
from tools.scope_context import ScopeContext


def test_zero_day_requests_are_scope_and_auth_gated(monkeypatch, tmp_path):
    calls = []

    def fake_curl(url, method="GET", headers=None, data=None, timeout=10):
        calls.append((url, method, headers))
        return 200, "HTTP/1.1 200 OK\r\n", "ok"

    monkeypatch.setattr(zero_day_fuzzer, "curl_request", fake_curl)
    context = ScopeContext(
        root_target="target.example",
        out_of_scope=["admin.target.example"],
    )
    session = AuthSession(["Cookie: session=secret"], target="target.example")
    fuzzer = zero_day_fuzzer.ZeroDayFuzzer(
        "https://target.example",
        findings_dir=tmp_path,
        scope_target="target.example",
        scope_context=context,
        auth_session=session,
        max_requests=2,
    )

    assert fuzzer.request("https://admin.target.example") == (None, None, None)
    assert fuzzer.request("https://target.example/api")[0] == 200
    assert calls[0][2] == {"Cookie": "session=secret"}
    assert fuzzer.request("https://target.example/api/2")[0] == 200
    assert fuzzer.request("https://target.example/api/3") == (None, None, None)
    assert len(calls) == 2
    assert fuzzer.blocked_count == 1
