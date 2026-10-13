from storage import lookup_key

def export_one(actor, key):
    return lookup_key(key, actor=actor)

def disconnected_debug_export(key):
    return lookup_key(key)
