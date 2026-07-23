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
        return {"Authorization": f"Bearer {token}"}

    def test_account_holder_cannot_read_another_account_record(self):
        alice_headers = self.login("alice", "alice-pw")

        own_response = self.client.get("/accounts/1", headers=alice_headers)
        self.assertEqual(own_response.status_code, 200)
        self.assertEqual(own_response.get_json()["username"], "alice")

        for account_id in (2, 3):
            with self.subTest(account_id=account_id):
                other_response = self.client.get(
                    f"/accounts/{account_id}",
                    headers=alice_headers,
                )

                self.assertEqual(other_response.status_code, 403)


if __name__ == "__main__":
    unittest.main()
