"""
Regression tests for Sieve's admin user-directory endpoint (app.py).

Invariant under test: the full user directory route (GET /admin/users) must
require an authenticated administrator session and must not return plaintext
passwords to anyone, including anonymous requests.

Uses Flask's own test client against the app object directly -- no
network/docker required -- and resets the in-memory TOKENS store between
tests so cases don't leak state into each other.
"""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import app as app_module  # noqa: E402


@pytest.fixture
def client():
    app_module.app.config["TESTING"] = True
    # The app keeps its "database" as module-level dicts with no reset hook;
    # clear sessions between tests so one test's tokens can't leak into another.
    app_module.TOKENS.clear()
    with app_module.app.test_client() as c:
        yield c
    app_module.TOKENS.clear()


def login(client, username, password):
    resp = client.post("/login", json={"username": username, "password": password})
    assert resp.status_code == 200, f"setup failed logging in as {username}: {resp.status_code} {resp.get_json()}"
    return resp.get_json()["token"]


def get_admin_users(client, token=None):
    headers = {}
    if token is not None:
        headers["Authorization"] = f"Bearer {token}"
    return client.get("/admin/users", headers=headers)


# --- Auth is required at all ----------------------------------------------


def test_anonymous_request_is_rejected(client):
    """Attack: a completely unauthenticated caller (no Authorization header
    at all) must never get the user directory."""
    resp = get_admin_users(client)
    assert resp.status_code in (401, 403), (
        f"anonymous GET /admin/users must be rejected, got {resp.status_code} {resp.get_json()}"
    )


def test_garbage_token_is_rejected(client):
    """A token that was never issued must not authenticate."""
    resp = get_admin_users(client, token="not-a-real-token")
    assert resp.status_code in (401, 403), (
        f"unissued token must be rejected, got {resp.status_code} {resp.get_json()}"
    )


# --- A valid, non-admin session must still be refused ----------------------


def test_non_admin_token_is_forbidden(client):
    """Attack: a legitimately issued, valid bearer token belonging to a
    non-admin user must not read the admin directory. This is the case the
    naive 'any valid token' check would miss."""
    alice_token = login(client, "alice", "alice-pw")
    resp = get_admin_users(client, token=alice_token)
    assert resp.status_code == 403, (
        f"a valid non-admin token must be forbidden from /admin/users, got {resp.status_code} {resp.get_json()}"
    )


# --- Positive control: a real admin session must work ----------------------


def test_admin_token_can_read_directory(client):
    """Positive control: must stay green throughout -- proves the auth
    plumbing itself is healthy, isolating the failures above to the missing
    checks rather than a broken environment/fixture."""
    admin_token = login(client, "admin", "admin-pw")
    resp = get_admin_users(client, token=admin_token)
    assert resp.status_code == 200, (
        f"a valid admin token must be able to read /admin/users, got {resp.status_code} {resp.get_json()}"
    )
    body = resp.get_json()
    assert "alice" in body["users"]
    assert "bob" in body["users"]
    assert "admin" in body["users"]


# --- Passwords must never be serialized, even to a real admin --------------


def test_directory_never_includes_plaintext_passwords(client):
    """Even a legitimate admin caller must never receive the raw `password`
    field for any account -- the leak is in the serialization, not just the
    access control."""
    admin_token = login(client, "admin", "admin-pw")
    resp = get_admin_users(client, token=admin_token)
    assert resp.status_code == 200
    body = resp.get_json()
    for username, record in body["users"].items():
        assert "password" not in record, (
            f"admin directory response must never include a plaintext password field, "
            f"but {username!r}'s record did: {record!r}"
        )
