import unittest

from app import TOKENS, app


class AccountAuthorizationTest(unittest.TestCase):
    def setUp(self):
        TOKENS.clear()
        self.client = app.test_client()

    def login(self, username, password):
        response = self.client.post(
            "/login",
            json={"username": username, "password": password},
        )
        self.assertEqual(response.status_code, 200)
        token = response.get_json()["token"]
        self.assertTrue(token)
        return token

    def auth_header(self, token):
        return {"Authorization": f"Bearer {token}"}

    def test_account_holder_cannot_read_another_account(self):
        alice_token = self.login("alice", "alice-pw")
        bob_token = self.login("bob", "bob-pw")

        alice_account = self.client.get("/accounts/1", headers=self.auth_header(alice_token))
        self.assertEqual(alice_account.status_code, 200)
        self.assertEqual(alice_account.get_json()["username"], "alice")

        bob_account = self.client.get("/accounts/2", headers=self.auth_header(bob_token))
        self.assertEqual(bob_account.status_code, 200)
        self.assertEqual(bob_account.get_json()["username"], "bob")

        invalid_token = self.client.get("/accounts/2", headers=self.auth_header("invalid-token"))
        self.assertEqual(invalid_token.status_code, 401)

        cross_account = self.client.get("/accounts/2", headers=self.auth_header(alice_token))
        self.assertIn(
            cross_account.status_code,
            {403, 404},
            (
                "cross-account request should be denied, not return another user's "
                f"account details: status={cross_account.status_code} body={cross_account.get_json()}"
            ),
        )


if __name__ == "__main__":
    unittest.main()
