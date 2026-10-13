SESSIONS = {"synthetic-session-a": {"tenant": "A", "actor_id": "a-7"}}

def authenticate(session):
    actor = SESSIONS.get(session)
    return dict(actor) if actor else None
