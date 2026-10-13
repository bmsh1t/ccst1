ROWS = {
    "item-a": {"id": "item-a", "tenant": "A", "value": "synthetic A value"},
    "item-b": {"id": "item-b", "tenant": "B", "value": "synthetic B value"},
}

def lookup_key(key):
    row = ROWS.get(key)
    return dict(row) if row else None
