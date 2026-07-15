#!/usr/bin/env python3
"""
Security regression tests for Sieve's auth / authorization model.

These run against the Flask app via its test client (no live server, no Docker),
so they are self-contained and CI-runnable. Each test encodes a security
invariant that must hold on every request path:

  * /admin/users     — requires a valid token AND admin role, and never leaks
                       the stored password field.
  * session tokens   — are unguessable random secrets, not derived from the
                       public sequential account id.
  * /accounts/<id>   — a caller may only read their OWN account (admins may
                       read any); cross-account reads by a non-admin are denied.

Every test also keeps a *legitimate* control green, so a failure points at the
broken invariant rather than a broken test setup.
"""
import re

import pytest

import app as sieve


# Seeded login credentials (mirrors the app's seeded USERS table). These are the
# cleartext passwords a user types at login; the app is expected to store only a
# hash of them at rest.
CREDS = {
    "alice": "alice-pw",
    "bob": "bob-pw",
    "admin": "admin-pw",
}


@pytest.fixture
def client():
    """A fresh test client with a clean, freshly-seeded in-memory state.

    The app keeps USERS/TOKENS in module globals that mutate across requests, so
    we re-seed before each test to keep tests independent and order-agnostic.
    """
    sieve.reset_state()
    sieve.app.config.update(TESTING=True)
    with sieve.app.test_client() as c:
        yield c


def login(client, username):
    resp = client.post("/login", json={"username": username, "password": CREDS[username]})
    assert resp.status_code == 200, f"login for {username} failed: {resp.status_code} {resp.data!r}"
    return resp.get_json()["token"]


# --------------------------------------------------------------------------- #
# Baseline / control: the seeded users must still authenticate after hashing.
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("username", ["alice", "bob", "admin"])
def test_seeded_users_can_still_log_in(client, username):
    """Password hashing at rest must not break existing credentials."""
    resp = client.post("/login", json={"username": username, "password": CREDS[username]})
    assert resp.status_code == 200
    assert "token" in resp.get_json()


def test_wrong_password_is_rejected(client):
    resp = client.post("/login", json={"username": "alice", "password": "not-the-password"})
    assert resp.status_code == 401


# --------------------------------------------------------------------------- #
# Finding: session tokens are forgeable from the public sequential account id.
# Invariant: tokens are unguessable random secrets, not `token-<id>`.
# --------------------------------------------------------------------------- #

def test_token_is_not_derived_from_account_id(client):
    """An issued token must not equal `token-<id>` and must carry real entropy."""
    token = login(client, "alice")  # alice is account id 1
    assert token != "token-1", "token is derived from the public account id (forgeable)"
    assert not re.fullmatch(r"token-\d+", token), (
        f"token {token!r} follows the guessable token-<id> scheme"
    )
    # A random URL-safe secret is long; require meaningful entropy.
    assert len(token) >= 24, f"token {token!r} is too short to be an unguessable secret"


def test_forged_sequential_token_is_rejected(client):
    """A token synthesized from a public id (token-2 / token-3) — never issued to
    the caller — must be rejected, with no prior login as the victim."""
    for victim_id in (2, 3):
        forged = f"token-{victim_id}"
        resp = client.get(f"/accounts/{victim_id}", headers={"Authorization": f"Bearer {forged}"})
        assert resp.status_code == 401, (
            f"forged token {forged!r} was accepted ({resp.status_code}) — tokens are guessable"
        )


def test_random_unminted_token_is_rejected(client):
    """Control: an arbitrary never-issued token is rejected (auth check is healthy)."""
    resp = client.get("/accounts/1", headers={"Authorization": "Bearer totally-made-up-token"})
    assert resp.status_code == 401


# --------------------------------------------------------------------------- #
# Finding: horizontal + vertical IDOR on GET /accounts/<id>.
# Invariant: a caller reads only their own account; admins may read any.
# --------------------------------------------------------------------------- #

def test_user_can_read_own_account(client):
    """Control: the legitimate case must stay green."""
    token = login(client, "alice")
    resp = client.get("/accounts/1", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["email"] == "alice@sieve.test"
    assert "password" not in body


def test_no_token_read_is_unauthorized(client):
    resp = client.get("/accounts/1")
    assert resp.status_code == 401


def test_non_admin_cannot_read_other_account(client):
    """alice's own token must not read bob's or admin's account (horizontal +
    vertical IDOR)."""
    token = login(client, "alice")  # id 1
    for victim_id in (2, 3):
        resp = client.get(f"/accounts/{victim_id}", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 403, (
            f"alice's token read /accounts/{victim_id} -> {resp.status_code} "
            f"(expected 403): {resp.get_json()}"
        )


def test_reciprocal_cross_account_denied(client):
    """bob's own token must not read alice's account either."""
    token = login(client, "bob")  # id 2
    resp = client.get("/accounts/1", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 403


def test_admin_may_read_any_account(client):
    """Admin carve-out: an admin token may read any account."""
    token = login(client, "admin")  # id 3
    resp = client.get("/accounts/1", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200
    assert resp.get_json()["email"] == "alice@sieve.test"


# --------------------------------------------------------------------------- #
# Finding: /admin/users has no auth and leaks every plaintext password.
# Invariant: requires valid token (401 else) + admin role (403 else); never
# serializes any password field.
# --------------------------------------------------------------------------- #

def test_admin_users_requires_token(client):
    resp = client.get("/admin/users")
    assert resp.status_code == 401
    assert b"password" not in resp.data


def test_admin_users_rejects_invalid_token(client):
    resp = client.get("/admin/users", headers={"Authorization": "Bearer garbage-invalid-token"})
    assert resp.status_code == 401
    assert b"password" not in resp.data


def test_admin_users_forbidden_for_non_admin(client):
    token = login(client, "alice")
    resp = client.get("/admin/users", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 403
    assert b"password" not in resp.data


def test_admin_users_never_leaks_passwords_even_for_admin(client):
    token = login(client, "admin")
    resp = client.get("/admin/users", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200
    # No password field may appear anywhere in the serialized directory.
    assert b"password" not in resp.data
    users = resp.get_json()["users"]
    for entry in users.values():
        assert "password" not in entry
