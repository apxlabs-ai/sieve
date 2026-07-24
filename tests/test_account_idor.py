"""
Regression test for: GET /accounts/<id> must only return the caller's own
account, never another user's — including the admin's.

Root cause (fixed in app.py's account() handler): the handler checked only
that the bearer token was *some* valid, logged-in token; it never resolved
the token to its owning user and compared that user's id against the
requested account_id. Any authenticated user could therefore read any other
user's account record (a classic IDOR / BOLA).

Invariant asserted here: a logged-in, non-admin user can read their own
account (positive control) but is rejected (403) when requesting any other
user's account id — in both directions (alice -> bob, bob -> alice) and
against the admin account.
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


def get_account(client, account_id, token):
    return client.get(f"/accounts/{account_id}", headers={"Authorization": f"Bearer {token}"})


def test_user_can_read_own_account(client):
    # Positive control: alice reading her own account must succeed. If this
    # fails, the environment/harness is broken, not the invariant under test.
    alice_token = login(client, "alice", "alice-pw")
    resp = get_account(client, 1, alice_token)
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["username"] == "alice"
    assert body["email"] == "alice@sieve.test"


def test_user_cannot_read_another_users_account(client):
    alice_token = login(client, "alice", "alice-pw")

    resp = get_account(client, 2, alice_token)  # bob's account
    assert resp.status_code == 403, (
        f"alice's token read bob's account: {resp.status_code} {resp.get_json()} "
        "(expected 403)"
    )


def test_user_cannot_read_admin_account(client):
    alice_token = login(client, "alice", "alice-pw")

    resp = get_account(client, 3, alice_token)  # admin's account
    assert resp.status_code == 403, (
        f"alice's token read admin's account: {resp.status_code} {resp.get_json()} "
        "(expected 403)"
    )


def test_cross_account_access_is_blocked_in_both_directions(client):
    bob_token = login(client, "bob", "bob-pw")

    resp = get_account(client, 1, bob_token)  # alice's account
    assert resp.status_code == 403, (
        f"bob's token read alice's account: {resp.status_code} {resp.get_json()} "
        "(expected 403)"
    )


def test_admin_can_read_other_users_accounts(client):
    # Privileged lookups are still intended to work: an admin's token may
    # resolve any account id, unlike an ordinary user's.
    admin_token = login(client, "admin", "admin-pw")

    resp = get_account(client, 1, admin_token)  # alice's account
    assert resp.status_code == 200
    assert resp.get_json()["username"] == "alice"
