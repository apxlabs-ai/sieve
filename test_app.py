import unittest
from unittest import mock

import app as sieve


class BearerTokenTests(unittest.TestCase):
    def setUp(self):
        sieve.TOKENS.clear()
        self.client = sieve.app.test_client()

    def login(self, username, password):
        response = self.client.post(
            "/login",
            json={"username": username, "password": password},
        )
        self.assertEqual(response.status_code, 200, response.get_data(as_text=True))
        payload = response.get_json()
        self.assertIn("token", payload)
        return payload["token"]

    def get_account(self, account_id, token):
        return self.client.get(
            f"/accounts/{account_id}",
            headers={"Authorization": f"Bearer {token}"},
        )

    def test_guessing_user_id_derived_bearer_token_does_not_grant_access(self):
        with mock.patch(
            "secrets.token_urlsafe",
            side_effect=["opaque-alice-token", "opaque-bob-token"],
        ):
            alice_token = self.login("alice", "alice-pw")
            alice_response = self.get_account(1, alice_token)
            self.assertEqual(
                alice_response.status_code,
                200,
                alice_response.get_data(as_text=True),
            )
            self.assertEqual(alice_response.get_json()["username"], "alice")

            unknown_response = self.get_account(2, "token-999")
            self.assertEqual(
                unknown_response.status_code,
                401,
                unknown_response.get_data(as_text=True),
            )

            bob_token = self.login("bob", "bob-pw")
            bob_response = self.get_account(2, bob_token)
            self.assertEqual(
                bob_response.status_code,
                200,
                bob_response.get_data(as_text=True),
            )
            self.assertEqual(bob_response.get_json()["username"], "bob")

            guessed_response = self.get_account(2, "token-2")
            self.assertEqual(
                guessed_response.status_code,
                401,
                guessed_response.get_data(as_text=True),
            )


if __name__ == "__main__":
    unittest.main()
