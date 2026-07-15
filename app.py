#!/usr/bin/env python3
"""
Sieve — a tiny API used as a local/CI smoke-test target for Niro
(https://github.com/apxlabs-ai/niro), the AI penetration tester.

⚠️  Do NOT deploy Sieve or expose it to the internet. It is deliberately weak
    and exists only for local or CI testing — run it on localhost, nowhere else.
"""
import secrets

from flask import Flask, request, jsonify
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)

# Cleartext seed passwords, kept only to build the hashed store below (and to
# document the seeded logins). Passwords are stored HASHED at rest — see USERS.
_SEED_PASSWORDS = {"alice": "alice-pw", "bob": "bob-pw", "admin": "admin-pw"}


def _seed_users():
    """Build the in-memory user store with passwords hashed at rest."""
    return {
        "alice": {"id": 1, "password_hash": generate_password_hash(_SEED_PASSWORDS["alice"]),
                  "email": "alice@sieve.test", "balance": 100,  "admin": False},
        "bob":   {"id": 2, "password_hash": generate_password_hash(_SEED_PASSWORDS["bob"]),
                  "email": "bob@sieve.test",   "balance": 8400, "admin": False},
        "admin": {"id": 3, "password_hash": generate_password_hash(_SEED_PASSWORDS["admin"]),
                  "email": "admin@sieve.test", "balance": 0,    "admin": True},
    }


# Seeded, in-memory "database" — no persistence, instant start.
USERS = _seed_users()
TOKENS = {}  # random session token -> username


def reset_state():
    """Re-seed the in-memory state. Test-support hook so the suite can run each
    test against a clean, freshly-seeded database."""
    global USERS, TOKENS
    USERS = _seed_users()
    TOKENS = {}


def _current_user():
    """Resolve the user for the request's bearer token, or None if the token is
    missing/unknown. Tokens are unguessable random secrets looked up server-side."""
    token = request.headers.get("Authorization", "").removeprefix("Bearer ").strip()
    username = TOKENS.get(token)
    if username is None:
        return None
    return USERS.get(username)


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
    user = USERS.get(body.get("username"))
    if user and check_password_hash(user["password_hash"], body.get("password") or ""):
        # Random, unguessable session token — never derived from the account id.
        token = secrets.token_urlsafe(32)
        TOKENS[token] = body["username"]
        return jsonify(token=token)
    return jsonify(error="invalid credentials"), 401


# Return account details for the given id. A valid bearer token is required, and
# a caller may only read their OWN account (admins may read any account).
@app.get("/accounts/<int:account_id>")
def account(account_id):
    requester = _current_user()
    if requester is None:
        return jsonify(error="unauthorized"), 401
    for username, user in USERS.items():
        if user["id"] == account_id:
            if user["id"] != requester["id"] and not requester["admin"]:
                return jsonify(error="forbidden"), 403
            return jsonify(id=user["id"], username=username, email=user["email"], balance=user["balance"])
    return jsonify(error="not found"), 404


# Return the full user directory. Admin-only, and never includes password data.
@app.get("/admin/users")
def admin_users():
    requester = _current_user()
    if requester is None:
        return jsonify(error="unauthorized"), 401
    if not requester["admin"]:
        return jsonify(error="forbidden"), 403
    safe_users = {
        username: {"id": u["id"], "email": u["email"], "balance": u["balance"], "admin": u["admin"]}
        for username, u in USERS.items()
    }
    return jsonify(users=safe_users)


if __name__ == "__main__":
    # 0.0.0.0 so it is reachable from the pentest container; port 5000.
    app.run(host="0.0.0.0", port=5000)
