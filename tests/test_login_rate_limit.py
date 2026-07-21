"""Regression tests for POST /login rate limiting / lockout.

Invariant under test (see the security finding this closes):
  The login endpoint must not allow unlimited, unthrottled password
  guessing against a known username. After a bounded number of failed
  attempts in a rolling window, the endpoint must start rejecting further
  attempts (429) instead of comparing the password again -- while
  legitimate logins that stay under that budget, and logins for other
  usernames, are unaffected, and a successful login clears the count.

The vulnerable implementation did a bare in-memory dict lookup and string
comparison with no attempt counter, no delay, and no lockout state: every
failed attempt returned a plain 401 forever, so an attacker could run
unlimited automated credential-stuffing against any account (including
admin) at hundreds of requests/second.
"""
import pytest

import app as app_module


@pytest.fixture
def client():
    app_module.app.config["TESTING"] = True
    # Module-level state is shared across tests; isolate it per test.
    app_module.TOKENS.clear()
    if hasattr(app_module, "FAILED_ATTEMPTS"):
        app_module.FAILED_ATTEMPTS.clear()
    with app_module.app.test_client() as c:
        yield c
    app_module.TOKENS.clear()
    if hasattr(app_module, "FAILED_ATTEMPTS"):
        app_module.FAILED_ATTEMPTS.clear()


def login(client, username, password):
    return client.post("/login", json={"username": username, "password": password})


def test_burst_of_wrong_passwords_gets_throttled(client):
    # Positive control: a legitimate login for an unrelated account succeeds
    # normally before the burst -- proves the app/environment is healthy.
    control = login(client, "bob", "bob-pw")
    assert control.status_code == 200

    # Attack: a burst of wrong-password guesses against a known username
    # ("alice"), well past any reasonable per-window threshold.
    statuses = [login(client, "alice", f"wrong-guess-{i}").status_code for i in range(20)]

    assert all(s in (401, 429) for s in statuses), (
        f"unexpected status codes during guessing burst: {statuses}"
    )
    assert 429 in statuses, (
        "endpoint never throttled/locked out a 20-attempt wrong-password "
        f"burst against a known username -- unlimited guessing is possible. "
        f"statuses observed: {statuses}"
    )
    # Once locked out, the correct password must not be accepted either --
    # that's what makes the lockout real, not decorative.
    locked = login(client, "alice", "alice-pw")
    assert locked.status_code == 429, (
        f"account should be locked out even for the correct password, got "
        f"{locked.status_code}: {locked.get_json()}"
    )


def test_legitimate_login_under_threshold_still_works(client):
    # A handful of wrong guesses (well under the lockout threshold),
    # followed by the correct password, must succeed like today -- the
    # fix must not punish normal typo-and-retry user behavior.
    for i in range(3):
        resp = login(client, "alice", f"typo-{i}")
        assert resp.status_code == 401

    resp = login(client, "alice", "alice-pw")
    assert resp.status_code == 200, (
        f"legitimate login was blocked despite being under the lockout "
        f"threshold: {resp.status_code} {resp.get_json()}"
    )
    assert "token" in resp.get_json()


def test_lockout_is_scoped_to_the_targeted_username(client):
    # Hammering "alice" must not lock out "bob" -- the counter is keyed per
    # account, not a single global switch that DoSes every user at once.
    for i in range(20):
        login(client, "alice", f"wrong-guess-{i}")

    resp = login(client, "bob", "bob-pw")
    assert resp.status_code == 200, (
        f"unrelated account 'bob' was collateral damage from 'alice' being "
        f"guessed against: {resp.status_code} {resp.get_json()}"
    )


def test_successful_login_resets_the_failure_counter(client):
    # Fail a few times, then log in correctly -- this must clear the
    # counter so the next handful of failures doesn't carry over stale
    # count from before the successful login.
    for i in range(3):
        login(client, "alice", f"typo-{i}")
    good = login(client, "alice", "alice-pw")
    assert good.status_code == 200

    # A few more failures right after a successful login should still be
    # treated as a fresh window, not instantly locked out from leftover
    # count.
    resp = login(client, "alice", "another-typo")
    assert resp.status_code == 401, (
        f"failure counter was not reset by the prior successful login: "
        f"{resp.status_code} {resp.get_json()}"
    )
