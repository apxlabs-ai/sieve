"""
Regression test for: GET /admin/users must require an authenticated admin,
and must never include plaintext passwords in its response.

Root cause (fixed in app.py's admin_users() handler): the handler performed
no authentication or authorization check at all -- it serialized the raw
USERS dict (including every user's plaintext password and admin flag)
verbatim to any caller, unauthenticated or not.

Invariant asserted here:
  - an unauthenticated caller is rejected (401), not served the user list;
  - a logged-in, non-admin user is rejected (403), not served the user list;
  - a logged-in admin can read the directory (positive control), but the
    response never contains a "password" field for any user.
"""
import pytest

import app as sieve_app


@pytest.fixture
def client():
    sieve_app.app.config["TESTING"] = True
    # Fresh session-token state per test so tests don't leak into each other.
    sieve_app.TOKENS.clear()
    with sieve_app.app.test_client() as c:
        yield c


def login(client, username, password):
    resp = client.post("/login", json={"username": username, "password": password})
    assert resp.status_code == 200, f"login as {username!r} failed: {resp.status_code} {resp.get_json()}"
    return resp.get_json()["token"]


def get_admin_users(client, token=None):
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    return client.get("/admin/users", headers=headers)


def test_unauthenticated_request_is_rejected(client):
    resp = get_admin_users(client)
    assert resp.status_code in (401, 403), (
        f"unauthenticated GET /admin/users returned {resp.status_code} "
        f"{resp.get_json()} (expected 401/403, and no user data)"
    )


def test_non_admin_user_is_rejected(client):
    alice_token = login(client, "alice", "alice-pw")

    resp = get_admin_users(client, alice_token)
    assert resp.status_code == 403, (
        f"alice's (non-admin) token read /admin/users: {resp.status_code} "
        f"{resp.get_json()} (expected 403)"
    )


def test_admin_can_read_directory_without_passwords(client):
    # Positive control: a logged-in admin must still be able to use the
    # endpoint. If this fails, the fix over-restricted the route rather than
    # just closing the auth hole.
    admin_token = login(client, "admin", "admin-pw")

    resp = get_admin_users(client, admin_token)
    assert resp.status_code == 200
    users = resp.get_json()["users"]
    assert set(users) == {"alice", "bob", "admin"}

    for username, record in users.items():
        assert "password" not in record, (
            f"response for {username!r} still leaks a password field: {record}"
        )
