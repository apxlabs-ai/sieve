import unittest

from app import TOKENS, app


class LoginSecurityTest(unittest.TestCase):
    def setUp(self):
        TOKENS.clear()
        self.client = app.test_client()

    def test_public_default_admin_credentials_are_rejected(self):
        standard_login = self.client.post(
            "/login", json={"username": "alice", "password": "alice-pw"}
        )
        self.assertEqual(standard_login.status_code, 200)
        self.assertIn("token", standard_login.get_json())

        wrong_admin_login = self.client.post(
            "/login", json={"username": "admin", "password": "not-admin-pw"}
        )
        self.assertEqual(wrong_admin_login.status_code, 401)

        default_admin_login = self.client.post(
            "/login", json={"username": "admin", "password": "admin-pw"}
        )
        self.assertEqual(default_admin_login.status_code, 401)
        self.assertEqual(
            default_admin_login.get_json(), {"error": "invalid credentials"}
        )


if __name__ == "__main__":
    unittest.main()
