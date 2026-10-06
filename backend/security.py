"""API-key authentication, role-based authorization and a small in-memory rate limiter."""
import hmac
import time
from collections import defaultdict, deque
from functools import wraps

from flask import current_app, jsonify, request

_hits = defaultdict(deque)


def _role_for(key):
    cfg = current_app.config
    if key and hmac.compare_digest(key, cfg["ADMIN_KEY"]):
        return "admin"
    if key and hmac.compare_digest(key, cfg["ANALYST_KEY"]):
        return "analyst"
    return None


def require_role(role):
    """role='analyst' lets analysts AND admins in; role='admin' is admins only (e.g. editing rules)."""
    def deco(fn):
        @wraps(fn)
        def wrapper(*a, **kw):
            if current_app.config["AUTH_ENABLED"]:
                got = _role_for(request.headers.get("X-API-Key", ""))
                if got is None:
                    return jsonify(error="authentication required (X-API-Key)"), 401
                if role == "admin" and got != "admin":
                    return jsonify(error="admin role required"), 403
            return fn(*a, **kw)
        return wrapper
    return deco


def rate_limited(fn):
    @wraps(fn)
    def wrapper(*a, **kw):
        limit = current_app.config["RATE_LIMIT"]
        q, now = _hits[request.remote_addr], time.time()
        while q and now - q[0] > 60:
            q.popleft()
        if len(q) >= limit:
            return jsonify(error="rate limit exceeded"), 429
        q.append(now)
        return fn(*a, **kw)
    return wrapper
