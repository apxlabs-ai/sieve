#!/usr/bin/env python3
"""
Sieve — a tiny API used as a local/CI smoke-test target for Niro
(https://github.com/apxlabs-ai/niro), the AI penetration tester.

⚠️  Do NOT deploy Sieve or expose it to the internet. It is deliberately weak
    and exists only for local or CI testing — run it on localhost, nowhere else.
"""
import os

from flask import Flask, request, jsonify
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)

DEFAULT_ADMIN_USERNAME = "admin"
REJECTED_ADMIN_PASSWORDS = {"admin-pw"}


def build_users():
    users = {
        "alice": {"id": 1, "password": "alice-pw", "email": "alice@sieve.test", "balance": 100,  "admin": False},
        "bob":   {"id": 2, "password": "bob-pw",   "email": "bob@sieve.test",   "balance": 8400, "admin": False},
    }

    admin_password = os.environ.get("SIEVE_ADMIN_PASSWORD")
    if not admin_password:
        return users
    if admin_password in REJECTED_ADMIN_PASSWORDS:
        raise RuntimeError("SIEVE_ADMIN_PASSWORD must not use a public default password")

    users[DEFAULT_ADMIN_USERNAME] = {
        "id": 3,
        "password_hash": generate_password_hash(admin_password),
        "email": "admin@sieve.test",
        "balance": 0,
        "admin": True,
    }
    return users


# Seeded, in-memory "database" — no persistence, instant start.
USERS = build_users()
TOKENS = {}  # token -> username


def password_matches(user, password):
    if "password_hash" in user:
        return check_password_hash(user["password_hash"], password or "")
    return user.get("password") == password


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
    if user and password_matches(user, body.get("password")):
        token = f"token-{user['id']}"
        TOKENS[token] = body["username"]
        return jsonify(token=token)
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
