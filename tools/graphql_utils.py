"""Small helpers for safely embedding values in GraphQL string literals."""

import json


def escape_graphql_string(value: str) -> str:
    """Return ``value`` escaped for the inside of a GraphQL string literal."""
    return json.dumps(value, ensure_ascii=False)[1:-1]
