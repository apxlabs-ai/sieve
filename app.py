#!/usr/bin/env python3
"""
Sieve — a tiny API used as a local/CI smoke-test target for Niro
(https://github.com/apxlabs-ai/niro), the AI penetration tester.

⚠️  Do NOT deploy Sieve or expose it to the internet. It is deliberately weak
    and exists only for local or CI testing — run it on localhost, nowhere else.
"""
import time

from flask import Flask, request, jsonify

app = Flask(__name__)

# Seeded, in-memory "database" — no persistence, instant start.
USERS = {
    "alice": {"id": 1, "password": "alice-pw", "email": "alice@sieve.test", "balance": 100,  "admin": False},
    "bob":   {"id": 2, "password": "bob-pw",   "email": "bob@sieve.test",   "balance": 8400, "admin": False},
    "admin": {"id": 3, "password": "admin-pw", "email": "admin@sieve.test", "balance": 0,    "admin": True},
}
TOKENS = {}  # token -> username
LOGIN_FAILURES = {}
LOGIN_FAILURE_LIMIT = 5
LOGIN_FAILURE_WINDOW_SECONDS = 60
LOGIN_LOCK_SECONDS = 60


def _client_address():
    return request.remote_addr or ""


def _login_failure_key(username):
    return (str(username or "").strip().lower(), _client_address())


def _prune_recent_failures(record, now):
    record["failures"] = [
        failed_at
        for failed_at in record["failures"]
        if now - failed_at <= LOGIN_FAILURE_WINDOW_SECONDS
    ]


def _is_login_limited(key, now):
    record = LOGIN_FAILURES.get(key)
    if not record:
        return False
    if record["locked_until"] > now:
        return True
    _prune_recent_failures(record, now)
    if not record["failures"]:
        LOGIN_FAILURES.pop(key, None)
    return False


def _record_login_failure(key, now):
    record = LOGIN_FAILURES.setdefault(key, {"failures": [], "locked_until": 0})
    _prune_recent_failures(record, now)
    record["failures"].append(now)
    if len(record["failures"]) >= LOGIN_FAILURE_LIMIT:
        record["locked_until"] = now + LOGIN_LOCK_SECONDS


@app.get("/")
def index():
    return jsonify(
        name="Sieve",
        warning="INTENTIONALLY VULNERABLE - localhost/CI smoke-test target only. Do not deploy.",
        endpoints=["POST /login", "GET /accounts/<id>", "GET /admin/users"],
    )


@app.post("/login")
def login():
    body = request.get_json(force=True, silent=True) or {}
    username = body.get("username")
    key = _login_failure_key(username)
    now = time.monotonic()
    if _is_login_limited(key, now):
        return jsonify(error="too many login attempts"), 429

    user = USERS.get(username)
    if user and user["password"] == body.get("password"):
        LOGIN_FAILURES.pop(key, None)
        token = f"token-{user['id']}"
        TOKENS[token] = username
        return jsonify(token=token)
    _record_login_failure(key, now)
    return jsonify(error="invalid credentials"), 401


# Return account details for the given id. A valid bearer token is required.
@app.get("/accounts/<int:account_id>")
def account(account_id):
    token = request.headers.get("Authorization", "").removeprefix("Bearer ").strip()
    if token not in TOKENS:
        return jsonify(error="unauthorized"), 401
    for username, user in USERS.items():
        if user["id"] == account_id:
            return jsonify(id=user["id"], username=username, email=user["email"], balance=user["balance"])
    return jsonify(error="not found"), 404


# Return the full user directory.
@app.get("/admin/users")
def admin_users():
    return jsonify(users=USERS)


if __name__ == "__main__":
    # 0.0.0.0 so it is reachable from the pentest container; port 5000.
    app.run(host="0.0.0.0", port=5000)
