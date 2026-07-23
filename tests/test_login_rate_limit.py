import unittest

import app as sieve


class LoginRateLimitTest(unittest.TestCase):
    def setUp(self):
        sieve.TOKENS.clear()
        if hasattr(sieve, "LOGIN_FAILURES"):
            sieve.LOGIN_FAILURES.clear()
        sieve.app.config.update(TESTING=True)
        self.client = sieve.app.test_client()

    def login(self, username, password, remote_addr="203.0.113.10"):
        return self.client.post(
            "/login",
            json={"username": username, "password": password},
            environ_overrides={"REMOTE_ADDR": remote_addr},
        )

    def test_repeated_invalid_guesses_are_rate_limited(self):
        initial_valid = self.login("alice", "alice-pw")
        self.assertEqual(initial_valid.status_code, 200)
        self.assertIn("token", initial_valid.get_json())

        limited_response = None
        for attempt in range(1, 13):
            response = self.login("alice", f"tc271fa8c2-invalid-{attempt}")
            if response.status_code == 429:
                limited_response = response
                break
            self.assertEqual(response.status_code, 401)

        self.assertIsNotNone(
            limited_response,
            "login accepted twelve invalid guesses without a bounded response",
        )
        self.assertIn("too many", limited_response.get_json()["error"].lower())

        locked_valid = self.login("alice", "alice-pw")
        self.assertEqual(locked_valid.status_code, 429)

        unaffected_user = self.login("bob", "bob-pw")
        self.assertEqual(unaffected_user.status_code, 200)
        self.assertIn("token", unaffected_user.get_json())


if __name__ == "__main__":
    unittest.main()
