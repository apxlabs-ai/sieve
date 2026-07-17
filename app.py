#!/usr/bin/env python3
"""
Sieve — a tiny API used as a local/CI smoke-test target for Niro
(https://github.com/apxlabs-ai/niro), the AI penetration tester.

⚠️  Do NOT deploy Sieve or expose it to the internet. It is deliberately weak
    and exists only for local or CI testing — run it on localhost, nowhere else.

NOTE (production): the session store (TOKENS) and the login failed-attempt
counter (FAILED_ATTEMPTS) below are in-process dicts. That is fine for this
single-process demo, but a real deployment must back both with a shared store
(e.g. Redis) so sessions and lockout state survive restarts and are consistent
across multiple app instances. Passwords are also still seeded in plaintext for
demo simplicity; production must store password hashes only.
"""
import secrets
import time

from flask import Flask, request, jsonify

app = Flask(__name__)

# Seeded, in-memory "database" — no persistence, instant start.
USERS = {
    "alice": {"id": 1, "password": "alice-pw", "email": "alice@sieve.test", "balance": 100,  "admin": False},
    "bob":   {"id": 2, "password": "bob-pw",   "email": "bob@sieve.test",   "balance": 8400, "admin": False},
    "admin": {"id": 3, "password": "admin-pw", "email": "admin@sieve.test", "balance": 0,    "admin": True},
}

# token -> {"username": str, "issued_at": float}. Tokens are random and expire.
TOKENS = {}
SESSION_TTL_SECONDS = 3600  # tokens stop working an hour after they are issued.

# Per-username failed-login tracking for temporary lockout.
FAILED_ATTEMPTS = {}  # username -> (count, first_failure_ts)
MAX_FAILED_ATTEMPTS = 5
LOCKOUT_SECONDS = 300


def _current_user():
    """Resolve the authenticated user from the bearer token, or None.

    Enforces the session TTL: an expired token is discarded and treated as
    unauthenticated. Returns the USERS record (with its username) or None.
    """
    token = request.headers.get("Authorization", "").removeprefix("Bearer ").strip()
    session = TOKENS.get(token)
    if session is None:
        return None
    if time.time() - session["issued_at"] > SESSION_TTL_SECONDS:
        TOKENS.pop(token, None)
        return None
    username = session["username"]
    user = USERS.get(username)
    if user is None:
        return None
    return {**user, "username": username}


@app.get("/")
def index():
    return jsonify(
        name="Sieve",
        warning="INTENTIONALLY VULNERABLE - localhost/CI smoke-test target only. Do not deploy.",
        endpoints=["POST /login", "POST /logout", "GET /accounts/<id>", "GET /admin/users"],
    )


@app.post("/login")
def login():
    body = request.get_json(force=True, silent=True) or {}
    username = body.get("username")
    now = time.time()

    # Temporary per-account lockout after repeated failures — blocks unthrottled
    # password guessing (and rejects even a correct password while locked).
    count, since = FAILED_ATTEMPTS.get(username, (0, now))
    if count >= MAX_FAILED_ATTEMPTS and now - since < LOCKOUT_SECONDS:
        return jsonify(error="account temporarily locked, try again later"), 429

    user = USERS.get(username)
    if user and user["password"] == body.get("password"):
        FAILED_ATTEMPTS.pop(username, None)
        # Invalidate any prior session for this user so old tokens die on re-login.
        for old_token, session in list(TOKENS.items()):
            if session["username"] == username:
                TOKENS.pop(old_token, None)
        # Cryptographically random, unguessable token — not derivable from the id.
        token = secrets.token_urlsafe(32)
        TOKENS[token] = {"username": username, "issued_at": now}
        return jsonify(token=token)

    # Record the failure, resetting the window if the previous lockout expired.
    if now - since >= LOCKOUT_SECONDS:
        count, since = 0, now
    FAILED_ATTEMPTS[username] = (count + 1, since)
    return jsonify(error="invalid credentials"), 401


@app.post("/logout")
def logout():
    token = request.headers.get("Authorization", "").removeprefix("Bearer ").strip()
    TOKENS.pop(token, None)
    return "", 204


# Return account details for the given id. A valid bearer token is required, and
# a non-admin user may only read their own account (admins may read any).
@app.get("/accounts/<int:account_id>")
def account(account_id):
    requester = _current_user()
    if requester is None:
        return jsonify(error="unauthorized"), 401
    if not requester["admin"] and requester["id"] != account_id:
        return jsonify(error="forbidden"), 403
    for username, user in USERS.items():
        if user["id"] == account_id:
            return jsonify(id=user["id"], username=username, email=user["email"], balance=user["balance"])
    return jsonify(error="not found"), 404


# Return the full user directory — admins only, and never with passwords.
@app.get("/admin/users")
def admin_users():
    requester = _current_user()
    if requester is None:
        return jsonify(error="unauthorized"), 401
    if not requester["admin"]:
        return jsonify(error="forbidden"), 403
    safe_users = {
        username: {k: v for k, v in user.items() if k != "password"}
        for username, user in USERS.items()
    }
    return jsonify(users=safe_users)


if __name__ == "__main__":
    # 0.0.0.0 so it is reachable from the pentest container; port 5000.
    app.run(host="0.0.0.0", port=5000)
