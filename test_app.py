"""
Regression tests for the Sieve smoke-test app's auth/session hardening.

Each test asserts a security *invariant* (not a weak "returns 200"), and each is
paired with a legitimate-request control so a red failure proves the invariant is
violated rather than the test setup being broken.

The app keeps state in module-level dicts (USERS/TOKENS/FAILED_ATTEMPTS), so we
reset that mutable state before every test to keep tests independent.
"""
import importlib

import pytest

import app as app_module


@pytest.fixture(autouse=True)
def reset_state():
    """Reset the in-memory session/attempt state before each test."""
    # Re-import fresh module state to avoid cross-test leakage.
    importlib.reload(app_module)
    yield


@pytest.fixture
def client():
    app_module.app.config.update(TESTING=True)
    return app_module.app.test_client()


def login(client, username, password):
    return client.post("/login", json={"username": username, "password": password})


# ----------------------------------------------------------------------------
# TC-C9B9C9CB (CRITICAL): unauthenticated full user-directory disclosure.
# Invariant: unauthenticated visitors and non-admin users must not retrieve the
# full user directory, and plaintext passwords must never be returned.
# ----------------------------------------------------------------------------
def test_admin_users_rejects_unauthenticated(client):
    resp = client.get("/admin/users")
    assert resp.status_code in (401, 403), resp.get_data(as_text=True)
    assert b"password" not in resp.data


def test_admin_users_rejects_garbage_token(client):
    resp = client.get("/admin/users", headers={"Authorization": "Bearer garbage"})
    assert resp.status_code in (401, 403)
    assert b"password" not in resp.data


def test_admin_users_rejects_non_admin_user(client):
    token = login(client, "alice", "alice-pw").get_json()["token"]
    resp = client.get("/admin/users", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 403, resp.get_data(as_text=True)


def test_admin_users_allows_admin_but_never_leaks_passwords(client):
    """Control: the legitimate admin path succeeds, proving the guard is specific."""
    token = login(client, "admin", "admin-pw").get_json()["token"]
    resp = client.get("/admin/users", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200, resp.get_data(as_text=True)
    body = resp.get_json()
    assert "users" in body
    # Even for a legitimate admin, plaintext passwords must never be returned.
    for record in body["users"].values():
        assert "password" not in record


# ----------------------------------------------------------------------------
# TC-3D24B629 (CRITICAL): predictable tokens derived from account id.
# Invariant: a token must not be derivable from an account id; a fabricated
# "token-<id>" must never authenticate.
# ----------------------------------------------------------------------------
def test_forged_predictable_token_is_rejected(client):
    # Attacker never logged in; forges the old predictable token for bob (id=2).
    resp = client.get("/accounts/2", headers={"Authorization": "Bearer token-2"})
    assert resp.status_code == 401, resp.get_data(as_text=True)


def test_forged_predictable_admin_token_is_rejected(client):
    resp = client.get("/accounts/3", headers={"Authorization": "Bearer token-3"})
    assert resp.status_code == 401, resp.get_data(as_text=True)


def test_issued_token_is_not_derivable_from_id(client):
    """Control: a real login yields a working, unguessable token."""
    token = login(client, "alice", "alice-pw").get_json()["token"]
    # Token must not be the predictable "token-<id>" form.
    assert token != "token-1"
    assert not token.startswith("token-")
    assert len(token) >= 20
    # And it must actually work on alice's own account.
    resp = client.get("/accounts/1", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200


# ----------------------------------------------------------------------------
# TC-E6D858BE (HIGH): IDOR/BOLA on GET /accounts/<id>.
# Invariant: a non-admin may read only their own account; admins may read others.
# ----------------------------------------------------------------------------
def test_non_admin_cannot_read_other_account(client):
    token = login(client, "alice", "alice-pw").get_json()["token"]
    resp = client.get("/accounts/2", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code in (403, 404), resp.get_data(as_text=True)
    assert b"bob@sieve.test" not in resp.data


def test_non_admin_cannot_read_admin_account(client):
    token = login(client, "bob", "bob-pw").get_json()["token"]
    resp = client.get("/accounts/3", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code in (403, 404)
    assert b"admin@sieve.test" not in resp.data


def test_user_can_read_own_account(client):
    """Control: reading your own account still works."""
    token = login(client, "alice", "alice-pw").get_json()["token"]
    resp = client.get("/accounts/1", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200
    assert resp.get_json()["email"] == "alice@sieve.test"


def test_admin_can_read_other_account(client):
    """Control: the admin allow-path can read another user's account."""
    token = login(client, "admin", "admin-pw").get_json()["token"]
    resp = client.get("/accounts/1", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200
    assert resp.get_json()["email"] == "alice@sieve.test"


# ----------------------------------------------------------------------------
# TC-C2925A62 (MEDIUM): no logout / permanent reused token.
# Invariant: a user can end their session (token stops working), and repeated
# logins do not silently reuse the same permanent token.
# ----------------------------------------------------------------------------
def test_logout_invalidates_token(client):
    token = login(client, "alice", "alice-pw").get_json()["token"]
    headers = {"Authorization": f"Bearer {token}"}
    # Control: token works before logout.
    assert client.get("/accounts/1", headers=headers).status_code == 200
    # Logout invalidates it.
    logout = client.post("/logout", headers=headers)
    assert logout.status_code in (200, 204), logout.get_data(as_text=True)
    # Token no longer works.
    assert client.get("/accounts/1", headers=headers).status_code == 401


def test_relogin_issues_a_fresh_token(client):
    first = login(client, "alice", "alice-pw").get_json()["token"]
    second = login(client, "alice", "alice-pw").get_json()["token"]
    assert first != second, "repeated logins reused the same permanent token"


# ----------------------------------------------------------------------------
# TC-63C5C905 (MEDIUM): no login lockout / rate limiting.
# Invariant: the login endpoint must not allow unlimited unthrottled guessing;
# after enough failures the account is temporarily locked (429).
# ----------------------------------------------------------------------------
def test_repeated_failures_trigger_lockout(client):
    # Burst of wrong-password attempts.
    saw_lockout = False
    for i in range(20):
        resp = login(client, "alice", f"guess-{i}")
        if resp.status_code == 429:
            saw_lockout = True
            break
        assert resp.status_code == 401
    assert saw_lockout, "no lockout (429) after repeated failed logins"


def test_lockout_blocks_even_correct_password(client):
    for i in range(20):
        resp = login(client, "alice", f"guess-{i}")
        if resp.status_code == 429:
            break
    # Even the correct password must be rejected while locked out.
    resp = login(client, "alice", "alice-pw")
    assert resp.status_code == 429, resp.get_data(as_text=True)


def test_lockout_is_per_username(client):
    """Control: locking alice must not lock bob (proves the counter is per-account)."""
    for i in range(20):
        if login(client, "alice", f"guess-{i}").status_code == 429:
            break
    # Bob has no failures and logs in normally.
    resp = login(client, "bob", "bob-pw")
    assert resp.status_code == 200, resp.get_data(as_text=True)
