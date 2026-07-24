#!/usr/bin/env python3
"""
Sieve — a tiny API used as a local/CI smoke-test target for Niro
(https://github.com/apxlabs-ai/niro), the AI penetration tester.

⚠️  Do NOT deploy Sieve or expose it to the internet. It is deliberately weak
    and exists only for local or CI testing — run it on localhost, nowhere else.
"""
import time
from collections import defaultdict

from flask import Flask, request, jsonify

app = Flask(__name__)

# Seeded, in-memory "database" — no persistence, instant start.
USERS = {
    "alice": {"id": 1, "password": "alice-pw", "email": "alice@sieve.test", "balance": 100,  "admin": False},
    "bob":   {"id": 2, "password": "bob-pw",   "email": "bob@sieve.test",   "balance": 8400, "admin": False},
    "admin": {"id": 3, "password": "admin-pw", "email": "admin@sieve.test", "balance": 0,    "admin": True},
}
TOKENS = {}  # token -> username

# Login throttling: track failed attempts per (username, client_ip) so
# unlimited, full-speed password guessing against any account is not
# possible. In-memory only, matching this demo app's existing USERS/TOKENS
# style; a real deployment would back this with Redis/DB-backed counters.
LOGIN_RATE_LIMIT_WINDOW_SECONDS = 15 * 60
LOGIN_RATE_LIMIT_MAX_FAILURES = 5
LOGIN_FAILURES = defaultdict(list)  # (username, client_ip) -> [failure timestamps]


def _client_ip():
    return request.remote_addr or "unknown"


def _is_login_throttled(key, now):
    window_start = now - LOGIN_RATE_LIMIT_WINDOW_SECONDS
    recent_failures = [t for t in LOGIN_FAILURES.get(key, ()) if t > window_start]
    LOGIN_FAILURES[key] = recent_failures
    return len(recent_failures) >= LOGIN_RATE_LIMIT_MAX_FAILURES


def _record_login_failure(key, now):
    LOGIN_FAILURES[key].append(now)


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
    key = (username, _client_ip())
    now = time.monotonic()

    user = USERS.get(username)
    if user and user["password"] == body.get("password"):
        LOGIN_FAILURES.pop(key, None)  # reset the counter on success
        token = f"token-{user['id']}"
        TOKENS[token] = username
        return jsonify(token=token)

    # Only *wrong* guesses count against the throttle -- a correct password
    # always succeeds above, so this only ever slows down an attacker who
    # doesn't already know it, never a legitimate user who mistypes it a
    # couple of times and then gets it right.
    if _is_login_throttled(key, now):
        return jsonify(error="too many failed login attempts, try again later"), 429

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
