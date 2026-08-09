"""Regression tests for HackerOne duplicate-search query construction."""

import json

from tools import validate
from tools.graphql_utils import escape_graphql_string


class _Response:
    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self) -> bytes:
        return b'{"data":{"hacktivity_items":{"nodes":[]}}}'


def test_hackerone_dup_query_escapes_operator_inputs(monkeypatch) -> None:
    captured: dict[str, bytes] = {}

    def fake_urlopen(request, **_kwargs):
        captured["data"] = request.data
        return _Response()

    monkeypatch.setattr(validate.urllib.request, "urlopen", fake_urlopen)
    program = 'program" } } break'
    keyword = 'x\\\nquery'

    assert validate.check_h1_dups(program, keyword) == []

    query = json.loads(captured["data"])["query"]
    assert f'_eq: "{escape_graphql_string(program)}"' in query
    assert f'_icontains: "{escape_graphql_string(keyword)}"' in query
