"""
Regression tests for Sieve's login throttling (app.py).

Invariant under test: the login endpoint must limit or slow repeated failed
password attempts for a given account instead of allowing unlimited, instant
guesses -- after a small, fixed number of consecutive failures for the same
(username, client IP), the server must reject further attempts with 429
until the window resets or the failure counter is cleared by a success.

Uses Flask's own test client against the app object directly -- no
network/docker required -- and resets the in-memory TOKENS/LOGIN_FAILURES
stores between tests so cases don't leak state into each other.
"""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import app as app_module  # noqa: E402


def _reset_throttle_state():
    # LOGIN_FAILURES only exists once the throttle fix is in place; on the
    # unfixed code there is no throttle state to reset at all, which is
    # itself part of what these tests are demonstrating.
    failures = getattr(app_module, "LOGIN_FAILURES", None)
    if failures is not None:
        failures.clear()


@pytest.fixture
def client():
    app_module.app.config["TESTING"] = True
    # The app keeps its "database" and throttle state as module-level dicts
    # with no reset hook; clear them between tests so one test's failed
    # attempts (or sessions) can't leak into another.
    app_module.TOKENS.clear()
    _reset_throttle_state()
    with app_module.app.test_client() as c:
        yield c
    app_module.TOKENS.clear()
    _reset_throttle_state()


def attempt_login(client, username, password):
    return client.post("/login", json={"username": username, "password": password})


def login(client, username, password):
    resp = attempt_login(client, username, password)
    assert resp.status_code == 200, f"setup failed logging in as {username}: {resp.status_code} {resp.get_json()}"
    return resp.get_json()["token"]


# --- Positive control -------------------------------------------------------


def test_correct_credentials_still_authenticate(client):
    """Positive control: must stay green throughout -- proves the login
    plumbing itself is healthy, isolating the failures below to the missing
    throttle rather than a broken environment/fixture."""
    resp = attempt_login(client, "alice", "alice-pw")
    assert resp.status_code == 200
    assert "token" in resp.get_json()


# --- Attack: unlimited, full-speed password guessing -----------------------


def test_repeated_failed_logins_are_throttled_with_429(client):
    """Attack: the PoC's scenario -- 25 rapid wrong-password guesses against
    the same account. The old code answered every single one with a plain
    401 and no throttling at all. A properly defended server must start
    rejecting further guesses with 429 well before 25 attempts."""
    statuses = []
    for i in range(25):
        resp = attempt_login(client, "alice", f"wrong-guess-{i}")
        statuses.append(resp.status_code)

    assert 429 in statuses, (
        f"expected the server to eventually respond 429 to repeated failed "
        f"login guesses against the same account, but saw only: {sorted(set(statuses))}"
    )
    # Once throttled, it must stay throttled for the rest of the burst --
    # not flip back to 401 (which would mean the counter isn't sticky).
    first_429 = statuses.index(429)
    assert all(s == 429 for s in statuses[first_429:]), (
        "once throttled, subsequent attempts in the same window must also be 429, "
        f"got: {statuses[first_429:]}"
    )


def test_correct_password_still_works_after_wrong_guesses_are_throttled(client):
    """The throttle must slow down *guessing*, not lock the legitimate user
    out of their own account: once wrong guesses trip the 429, the correct
    password (which only its rightful owner knows) must still authenticate
    immediately -- matching the PoC's positive control, which treats a
    still-broken login after the burst as an environment failure, not a
    pass."""
    for i in range(10):
        attempt_login(client, "alice", f"wrong-guess-{i}")

    resp = attempt_login(client, "alice", "alice-pw")
    assert resp.status_code == 200, (
        f"the correct password must still authenticate after a burst of "
        f"unrelated wrong guesses was throttled, got {resp.status_code} {resp.get_json()}"
    )
    assert "token" in resp.get_json()


def test_throttle_is_scoped_per_account_not_global(client):
    """Failed guesses against one account must not lock out an unrelated
    account on the same client -- the throttle is keyed per (username, ip),
    not a single global switch that would itself be a denial-of-service
    vector against every other user."""
    for i in range(10):
        attempt_login(client, "alice", f"wrong-guess-{i}")

    resp = attempt_login(client, "bob", "bob-pw")
    assert resp.status_code == 200, (
        f"bob's correct login must not be affected by alice's throttled failures, "
        f"got {resp.status_code} {resp.get_json()}"
    )


def test_successful_login_resets_the_failure_counter(client):
    """A handful of failures below the threshold, followed by a success,
    must clear the counter -- a legitimate user who fat-fingers their
    password a couple of times and then gets it right should not be
    penalized on their next mistake as if the earlier ones still counted."""
    for i in range(3):
        attempt_login(client, "alice", f"wrong-guess-{i}")

    resp = login(client, "alice", "alice-pw")
    assert resp

    # Same small number of failures again -- if the counter had not been
    # reset by the success above, this would already be at/over threshold.
    statuses = []
    for i in range(3):
        statuses.append(attempt_login(client, "alice", f"wrong-guess-again-{i}").status_code)
    assert 429 not in statuses, (
        f"failure counter must have been reset by the intervening success, "
        f"but got throttled again after only 3 more failures: {statuses}"
    )
