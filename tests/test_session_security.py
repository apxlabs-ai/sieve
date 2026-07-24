"""
Regression tests for Sieve's session/auth mechanism (app.py).

Invariant under test (shared root cause across two findings):

  1. A session token must be cryptographically unguessable -- it must not be
     a deterministic function of public data (the account's own sequential
     integer id), so nobody can compute another account's token without its
     password.
  2. GET /accounts/<id> must bind the presented token to its *owning* user:
     a valid-but-foreign token (legitimately issued to a different, lower or
     equal privileged user) must never be able to read another account's
     record. Only the token's own owner (by id) may read that account.

Both checks use Flask's own test client against the app object directly --
no network/docker required -- and reset the in-memory TOKENS store between
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


def get_account(client, account_id, token=None):
    headers = {}
    if token is not None:
        headers["Authorization"] = f"Bearer {token}"
    return client.get(f"/accounts/{account_id}", headers=headers)


# --- Root cause 1: predictable token generation --------------------------


def test_login_token_is_not_the_predictable_id_pattern(client):
    """The old vulnerable code issued token = f"token-{user['id']}". A
    cryptographically random token must never match that guessable shape."""
    alice_token = login(client, "alice", "alice-pw")
    bob_token = login(client, "bob", "bob-pw")
    admin_token = login(client, "admin", "admin-pw")

    assert alice_token != "token-1", "alice's token must not be the predictable token-<id> value"
    assert bob_token != "token-2", "bob's token must not be the predictable token-<id> value"
    assert admin_token != "token-3", "admin's token must not be the predictable token-<id> value"

    # Guard against a trivial variant (e.g. a fixed prefix + id) rather than
    # true per-login randomness.
    assert len(alice_token) >= 20, "token should have real cryptographic entropy, not a short deterministic id"


def test_login_token_is_unique_per_login_not_derived_from_id(client):
    """Logging in twice as the same user must not yield the same token
    twice in a row from a deterministic formula seeded only by the id."""
    first = login(client, "alice", "alice-pw")
    second = login(client, "alice", "alice-pw")
    assert first != second, "each login must mint a fresh random token, not a deterministic function of user id"


def test_forged_predictable_token_is_rejected(client):
    """Attack A: without ever authenticating as bob or admin, an attacker
    who can see the sequential integer id in /accounts/<id> URLs must not
    be able to compute a working token for that account."""
    # Establish a healthy baseline: a real login for a different account works.
    login(client, "alice", "alice-pw")

    resp = get_account(client, 2, token="token-2")  # forged bob token, never issued
    assert resp.status_code in (401, 403), (
        f"forged token 'token-2' (never issued to bob) must be rejected, got {resp.status_code} {resp.get_json()}"
    )

    resp = get_account(client, 3, token="token-3")  # forged admin token, never issued
    assert resp.status_code in (401, 403), (
        f"forged token 'token-3' (never issued to admin) must be rejected, got {resp.status_code} {resp.get_json()}"
    )


# --- Root cause 2: missing token-to-account ownership binding ------------


def test_account_owner_can_read_own_account(client):
    """Positive control: must stay green throughout -- proves the auth
    plumbing itself is healthy, isolating failures below to the missing
    ownership check rather than a broken environment/fixture."""
    alice_token = login(client, "alice", "alice-pw")
    resp = get_account(client, 1, token=alice_token)
    assert resp.status_code == 200
    assert resp.get_json()["username"] == "alice"


def test_token_is_not_bound_to_a_foreign_account(client):
    """Attack B: a token legitimately issued to a low-privilege user must
    not read a *different* user's account, including the admin account."""
    alice_token = login(client, "alice", "alice-pw")

    resp = get_account(client, 2, token=alice_token)  # bob's account
    assert resp.status_code == 403, (
        f"alice's own legitimate token must not read bob's account (/accounts/2), "
        f"got {resp.status_code} {resp.get_json()}"
    )

    resp = get_account(client, 3, token=alice_token)  # admin's account
    assert resp.status_code == 403, (
        f"alice's own legitimate token must not read admin's account (/accounts/3), "
        f"got {resp.status_code} {resp.get_json()}"
    )


def test_token_ownership_check_is_symmetric(client):
    """Reverse direction: bob's token must not read alice's account either --
    the check must be a real equality on the owner, not a one-off special case."""
    bob_token = login(client, "bob", "bob-pw")
    resp = get_account(client, 1, token=bob_token)
    assert resp.status_code == 403, (
        f"bob's token must not read alice's account (/accounts/1), got {resp.status_code} {resp.get_json()}"
    )
    # Bob can still read his own account -- the fix must not be overly broad.
    resp = get_account(client, 2, token=bob_token)
    assert resp.status_code == 200
    assert resp.get_json()["username"] == "bob"


def test_missing_or_garbage_token_is_rejected(client):
    """Baseline negative control: an unissued token must never authenticate."""
    resp = get_account(client, 1, token="not-a-real-token")
    assert resp.status_code in (401, 403)

    resp = get_account(client, 1, token=None)
    assert resp.status_code in (401, 403)
