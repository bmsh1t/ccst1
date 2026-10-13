from urllib.parse import unquote
from authorization import authenticate
from services import export_one

ROUTES = {("GET", "/exports/item"): export_one}

def dispatch(request):
    handler = ROUTES.get((request["method"], request["path"]))
    if handler is None:
        return {"status": 404, "body": None}
    actor = authenticate(request.get("session"))
    if actor is None:
        return {"status": 401, "body": None}
    item_key = unquote(request["query"]["item"].strip())
    try:
        return {"status": 200, "body": handler(actor, item_key)}
    except PermissionError:
        return {"status": 403, "body": None}
