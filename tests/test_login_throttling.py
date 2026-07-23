import unittest

import app as sieve


class LoginThrottlingTest(unittest.TestCase):
    def setUp(self):
        self.client = sieve.app.test_client()
        sieve.TOKENS.clear()
        getattr(sieve, "LOGIN_FAILURES", {}).clear()

    def login(self, username, password):
        return self.client.post(
            "/login",
            json={"username": username, "password": password},
        )

    def test_repeated_failed_login_attempts_temporarily_lock_account(self):
        control_username = "bob"
        control_password = sieve.USERS[control_username]["password"]
        target_username = "alice"
        target_password = sieve.USERS[target_username]["password"]

        bob_response = self.login(control_username, control_password)
        self.assertEqual(bob_response.status_code, 200)
        self.assertIn("token", bob_response.get_json())

        alice_response = self.login(target_username, target_password)
        self.assertEqual(alice_response.status_code, 200)
        self.assertIn("token", alice_response.get_json())

        failed_statuses = []
        protective_response = None
        for index in range(15):
            response = self.login(target_username, f"wrong-password-{index}")
            failed_statuses.append(response.status_code)
            if response.status_code in {423, 429}:
                protective_response = response
                break

        self.assertIsNotNone(
            protective_response,
            f"expected a lockout/throttle response within 15 failures, got {failed_statuses}",
        )

        bob_control = self.login(control_username, control_password)
        self.assertEqual(bob_control.status_code, 200)
        self.assertIn("token", bob_control.get_json())

        locked_alice = self.login(target_username, target_password)
        self.assertIn(locked_alice.status_code, {423, 429})


if __name__ == "__main__":
    unittest.main()
