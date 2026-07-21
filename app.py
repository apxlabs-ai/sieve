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

# username -> [timestamp, ...] of recent failed login attempts, in the same
# in-memory-dict style as USERS/TOKENS. A rolling window: attempts older
# than LOGIN_ATTEMPT_WINDOW_SECONDS don't count toward the threshold.
FAILED_ATTEMPTS = {}
LOGIN_ATTEMPT_LIMIT = 5
LOGIN_ATTEMPT_WINDOW_SECONDS = 15 * 60


def _recent_failed_attempts(username):
    """Prune expired attempts for username and return the ones still live."""
    now = time.time()
    attempts = [t for t in FAILED_ATTEMPTS.get(username, []) if now - t < LOGIN_ATTEMPT_WINDOW_SECONDS]
    if attempts:
        FAILED_ATTEMPTS[username] = attempts
    else:
        FAILED_ATTEMPTS.pop(username, None)
    return attempts


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

    # Lock out further attempts for this username once it has racked up too
    # many failures in the current window -- checked before the password is
    # ever compared, so a locked-out account can't be brute-forced further
    # even if the attacker happens to send the right password.
    if username is not None and len(_recent_failed_attempts(username)) >= LOGIN_ATTEMPT_LIMIT:
        return jsonify(error="too many failed login attempts, try again later"), 429

    user = USERS.get(username)
    if user and user["password"] == body.get("password"):
        FAILED_ATTEMPTS.pop(username, None)  # successful login clears the counter
        token = f"token-{user['id']}"
        TOKENS[token] = username
        return jsonify(token=token)

    if username is not None:
        FAILED_ATTEMPTS.setdefault(username, []).append(time.time())
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
