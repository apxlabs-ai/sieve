import unittest

import app as sieve_app


class LoginTokenTests(unittest.TestCase):
    def setUp(self):
        sieve_app.TOKENS.clear()
        self.client = sieve_app.app.test_client()

    def login_bob(self):
        response = self.client.post(
            "/login",
            json={"username": "bob", "password": "bob-pw"},
        )
        self.assertEqual(response.status_code, 200)
        token = response.get_json()["token"]
        self.assertTrue(token)
        return token

    def get_bob_account(self, token):
        return self.client.get(
            "/accounts/2",
            headers={"Authorization": f"Bearer {token}"},
        )

    def test_derived_account_id_token_is_rejected_after_login(self):
        issued_token = self.login_bob()

        legitimate_response = self.get_bob_account(issued_token)
        self.assertEqual(legitimate_response.status_code, 200)
        self.assertEqual(legitimate_response.get_json()["username"], "bob")

        guessed_response = self.get_bob_account("token-2")
        self.assertEqual(guessed_response.status_code, 401)
        self.assertEqual(guessed_response.get_json(), {"error": "unauthorized"})

    def test_each_successful_login_issues_a_distinct_usable_token(self):
        first_token = self.login_bob()
        second_token = self.login_bob()

        self.assertNotEqual(first_token, second_token)

        for token in (first_token, second_token):
            response = self.get_bob_account(token)
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.get_json()["username"], "bob")


if __name__ == "__main__":
    unittest.main()
