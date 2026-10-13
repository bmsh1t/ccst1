ROWS = {
    "item-a": {"id": "item-a", "tenant": "A", "value": "synthetic A value"},
    "item-b": {"id": "item-b", "tenant": "B", "value": "synthetic B value"},
}

def lookup_key(key, actor=None):
    row = ROWS.get(key)
    if row and actor is not None and row["tenant"] != actor["tenant"]:
        raise PermissionError("tenant mismatch")
    return dict(row) if row else None
