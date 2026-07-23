"""
Regression tests for session-token unguessability.

Security invariant under test:
    An attacker who does not know a user's password must NOT be able to obtain
    a valid, working session token for that user's account.

The login handler must mint an unguessable, server-issued secret — never a
deterministic function of a public/enumerable field such as the numeric user id.
These tests drive the app in-process with Flask's test client and reset the
in-memory token store between cases so each starts from a clean baseline.
"""
import re

import pytest

import app as sieve


@pytest.fixture
def client():
    sieve.TOKENS.clear()
    sieve.app.config["TESTING"] = True
    with sieve.app.test_client() as c:
        yield c
    sieve.TOKENS.clear()


def _login(client, username, password):
    return client.post("/login", json={"username": username, "password": password})


def test_legitimate_login_can_read_own_account(client):
    """Baseline (green control): a real login yields a token that works."""
    resp = _login(client, "alice", "alice-pw")
    assert resp.status_code == 200
    token = resp.get_json()["token"]

    acct = client.get("/accounts/1", headers={"Authorization": f"Bearer {token}"})
    assert acct.status_code == 200
    assert acct.get_json()["username"] == "alice"


def test_undefined_token_is_rejected(client):
    """Baseline (green control): an unknown token is refused — auth check is live."""
    acct = client.get(
        "/accounts/1", headers={"Authorization": "Bearer token-999999"}
    )
    assert acct.status_code == 401


def test_forged_token_from_public_id_is_rejected(client):
    """
    Core invariant: after a victim logs in, an attacker who knows only the
    victim's public numeric id (and no password) must NOT be able to forge a
    working token by the formula `token-<id>`.
    """
    # Precondition: victim performs her own legitimate login (the only password
    # use; it is the victim's own). This populates the token store as normal.
    assert _login(client, "alice", "alice-pw").status_code == 200

    # Attack: forge the token from the public id alone. No password is sent.
    forged = "token-1"
    acct = client.get(
        "/accounts/1", headers={"Authorization": f"Bearer {forged}"}
    )
    assert acct.status_code == 401, (
        "guessable token derived from the public user id was accepted — "
        "account takeover without a password"
    )


def test_issued_token_is_not_derivable_from_user_id(client):
    """
    The issued token must not be the predictable `token-<id>` string, and must
    carry real entropy (high-entropy, url-safe secret), so it cannot be guessed.
    """
    resp = _login(client, "bob", "bob-pw")
    assert resp.status_code == 200
    token = resp.get_json()["token"]

    # Must not be the deterministic formula for bob (id=2) or any small id.
    assert not re.fullmatch(r"token-\d+", token), (
        f"issued token {token!r} is a deterministic function of the user id"
    )
    # Must be a substantial, high-entropy secret.
    assert len(token) >= 32, f"issued token {token!r} is too short to be unguessable"
