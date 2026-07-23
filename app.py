#!/usr/bin/env python3
"""
Sieve — a tiny API used as a local/CI smoke-test target for Niro
(https://github.com/apxlabs-ai/niro), the AI penetration tester.

⚠️  Do NOT deploy Sieve or expose it to the internet. It is deliberately weak
    and exists only for local or CI testing — run it on localhost, nowhere else.
"""
import math
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

# Tiny in-process login limiter for this smoke-test app. A production service
# should use a shared expiring store so every worker sees the same counters.
FAILED_LOGIN_LIMIT = 5
FAILED_LOGIN_WINDOW_SECONDS = 60
FAILED_LOGIN_BLOCK_SECONDS = 30
LOGIN_FAILURES = {}  # (source_ip, normalized_username) -> {failures, blocked_until}


def _normalized_username(username):
    return str(username or "").strip().casefold()


def _login_throttle_key(username):
    return (request.remote_addr or "unknown", _normalized_username(username))


def _prune_login_failures(now):
    for key, state in list(LOGIN_FAILURES.items()):
        blocked_until = state.get("blocked_until", 0)
        if blocked_until and blocked_until <= now:
            del LOGIN_FAILURES[key]
            continue

        state["failures"] = [
            failed_at
            for failed_at in state.get("failures", [])
            if now - failed_at <= FAILED_LOGIN_WINDOW_SECONDS
        ]
        if not state["failures"] and not blocked_until:
            del LOGIN_FAILURES[key]


def _login_retry_after(key, now):
    _prune_login_failures(now)
    state = LOGIN_FAILURES.get(key)
    if not state:
        return None

    blocked_until = state.get("blocked_until", 0)
    if blocked_until > now:
        return max(1, math.ceil(blocked_until - now))
    return None


def _record_failed_login(key, now):
    state = LOGIN_FAILURES.setdefault(key, {"failures": [], "blocked_until": 0})
    state["failures"] = [
        failed_at
        for failed_at in state["failures"]
        if now - failed_at <= FAILED_LOGIN_WINDOW_SECONDS
    ]
    state["failures"].append(now)

    if len(state["failures"]) >= FAILED_LOGIN_LIMIT:
        state["blocked_until"] = now + FAILED_LOGIN_BLOCK_SECONDS


def _clear_failed_login(key):
    LOGIN_FAILURES.pop(key, None)


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
    throttle_key = _login_throttle_key(username)
    now = time.monotonic()

    retry_after = _login_retry_after(throttle_key, now)
    if retry_after is not None:
        response = jsonify(error="too many failed login attempts")
        response.headers["Retry-After"] = str(retry_after)
        return response, 429

    user = USERS.get(username)
    if user and user["password"] == body.get("password"):
        _clear_failed_login(throttle_key)
        token = f"token-{user['id']}"
        TOKENS[token] = username
        return jsonify(token=token)
    _record_failed_login(throttle_key, now)
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
