import unittest

import app as sieve


class LoginThrottleTest(unittest.TestCase):
    def setUp(self):
        sieve.TOKENS.clear()
        if hasattr(sieve, "LOGIN_FAILURES"):
            sieve.LOGIN_FAILURES.clear()
        self.client = sieve.app.test_client()

    def login(self, username, password, source_ip="203.0.113.10"):
        return self.client.post(
            "/login",
            json={"username": username, "password": password},
            environ_base={"REMOTE_ADDR": source_ip},
        )

    def test_repeated_failed_logins_trigger_bounded_throttle(self):
        positive_control = self.login("alice", "alice-pw")
        self.assertEqual(positive_control.status_code, 200)

        responses = [
            self.login("alice", "rate-limit-test-invalid")
            for _ in range(15)
        ]
        statuses = [response.status_code for response in responses]

        first_failure = responses[0]
        self.assertEqual(first_failure.status_code, 401)
        self.assertEqual(first_failure.get_json(), {"error": "invalid credentials"})

        self.assertIn(
            429,
            statuses,
            f"expected a 429 throttle within 15 failed attempts, got {statuses}",
        )
        throttled = responses[statuses.index(429)]
        self.assertIn("Retry-After", throttled.headers)

    def test_successful_login_clears_previous_failures(self):
        for _ in range(3):
            response = self.login("alice", "rate-limit-test-invalid")
            self.assertEqual(response.status_code, 401)

        valid_response = self.login("alice", "alice-pw")
        self.assertEqual(valid_response.status_code, 200)

        response = self.login("alice", "rate-limit-test-invalid")
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.get_json(), {"error": "invalid credentials"})


if __name__ == "__main__":
    unittest.main()
