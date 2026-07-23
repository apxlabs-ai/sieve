import unittest

import app as sieve


class AdminUsersSecurityTest(unittest.TestCase):
    def setUp(self):
        sieve.TOKENS.clear()
        self.client = sieve.app.test_client()

    def login(self, username):
        password = sieve.USERS[username]["password"]
        response = self.client.post(
            "/login",
            json={"username": username, "password": password},
        )
        self.assertEqual(response.status_code, 200)
        return response.get_json()["token"]

    def assert_no_password_fields(self, value):
        if isinstance(value, dict):
            self.assertNotIn("password", value)
            for child in value.values():
                self.assert_no_password_fields(child)
        elif isinstance(value, list):
            for child in value:
                self.assert_no_password_fields(child)

    def test_admin_directory_requires_admin_token(self):
        admin_token = self.login("admin")
        alice_token = self.login("alice")

        admin_response = self.client.get(
            "/admin/users",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        self.assertEqual(admin_response.status_code, 200)

        anonymous_response = self.client.get("/admin/users")
        self.assertEqual(anonymous_response.status_code, 401)

        standard_user_response = self.client.get(
            "/admin/users",
            headers={"Authorization": f"Bearer {alice_token}"},
        )
        self.assertEqual(standard_user_response.status_code, 403)

    def test_admin_directory_omits_password_fields(self):
        admin_token = self.login("admin")

        response = self.client.get(
            "/admin/users",
            headers={"Authorization": f"Bearer {admin_token}"},
        )

        self.assertEqual(response.status_code, 200)
        self.assert_no_password_fields(response.get_json())

    def test_admin_directory_response_is_not_stored(self):
        admin_token = self.login("admin")

        response = self.client.get(
            "/admin/users",
            headers={"Authorization": f"Bearer {admin_token}"},
        )

        self.assertEqual(response.status_code, 200)
        directives = {
            part.strip().lower().split("=", 1)[0]
            for part in response.headers.get("Cache-Control", "").split(",")
            if part.strip()
        }
        self.assertIn("no-store", directives)
        self.assertIn("private", directives)


if __name__ == "__main__":
    unittest.main()
