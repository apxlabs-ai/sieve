"""Regression tests for GET /admin/users authorization.

Invariant under test:
  The full user directory — including every user's password — must NOT be
  reachable by an unauthenticated visitor or by an authenticated non-admin
  user, and no password field may ever appear in the response body.

The scenario mirrors the proof-of-concept actors (an unauthenticated caller,
a standard non-admin user, and a legitimate admin) but recreates them with the
app's own in-memory USERS/TOKENS rather than reading any live-target fixtures.
Passwords below are local test fixtures, not real credentials.
"""
import json
from copy import deepcopy

import pytest

import app as sieve


@pytest.fixture
def client():
    sieve.app.config["TESTING"] = True
    # Snapshot the module-level state before mutating it, and restore it on
    # teardown. app.USERS / app.TOKENS are shared globals; without this, the
    # actors seeded below (and their local test passwords) would leak into any
    # other test file that imports the same module and relies on the original
    # seeded users.
    saved_users = deepcopy(sieve.USERS)
    saved_tokens = deepcopy(sieve.TOKENS)
    # Recreate a deterministic, known set of actors: two standard users and one
    # admin, matching the roles the PoC exercised (standard user + admin).
    sieve.USERS.clear()
    sieve.USERS.update(
        {
            "alice": {"id": 1, "password": "alice-secret", "email": "alice@sieve.test", "balance": 100, "admin": False},
            "bob": {"id": 2, "password": "bob-secret", "email": "bob@sieve.test", "balance": 8400, "admin": False},
            "admin": {"id": 3, "password": "admin-secret", "email": "admin@sieve.test", "balance": 0, "admin": True},
        }
    )
    sieve.TOKENS.clear()
    try:
        with sieve.app.test_client() as c:
            yield c
    finally:
        sieve.USERS.clear()
        sieve.USERS.update(saved_users)
        sieve.TOKENS.clear()
        sieve.TOKENS.update(saved_tokens)


def _login(client, username, password):
    resp = client.post("/login", json={"username": username, "password": password})
    assert resp.status_code == 200, f"login for {username} failed: {resp.status_code} {resp.data!r}"
    return resp.get_json()["token"]


def _assert_no_passwords(body_text):
    """No password field and no seeded password value may appear anywhere."""
    assert "password" not in body_text, "response leaked a 'password' field"
    for secret in ("alice-secret", "bob-secret", "admin-secret"):
        assert secret not in body_text, f"response leaked a plaintext password ({secret})"


def test_positive_control_auth_baseline_healthy(client):
    # /accounts/<id> with no auth is rejected -> proves the auth baseline is
    # healthy, so a failure below is this specific bug, not a broken setup.
    resp = client.get("/accounts/1")
    assert resp.status_code == 401


def test_admin_users_rejects_unauthenticated(client):
    resp = client.get("/admin/users")
    assert resp.status_code in (401, 403), (
        f"unauthenticated GET /admin/users returned {resp.status_code}; "
        f"directory must not be served without an admin token"
    )
    _assert_no_passwords(resp.get_data(as_text=True))


def test_admin_users_rejects_non_admin(client):
    token = _login(client, "alice", "alice-secret")
    resp = client.get("/admin/users", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code in (401, 403), (
        f"non-admin GET /admin/users returned {resp.status_code}; "
        f"directory must not be served to a non-admin user"
    )
    _assert_no_passwords(resp.get_data(as_text=True))


def test_admin_users_allows_admin_without_leaking_passwords(client):
    # Legitimate control: a real admin still gets the directory (the fix must
    # not break the intended feature), but never any password field.
    token = _login(client, "admin", "admin-secret")
    resp = client.get("/admin/users", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    users = json.loads(body)["users"]
    assert set(users.keys()) == {"alice", "bob", "admin"}
    _assert_no_passwords(body)
