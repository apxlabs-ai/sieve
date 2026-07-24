import unittest

import app as sieve


class AdminUsersTest(unittest.TestCase):
    def setUp(self):
        sieve.TOKENS.clear()
        self.client = sieve.app.test_client()

    def login(self, username, password):
        response = self.client.post(
            "/login",
            json={"username": username, "password": password},
        )
        self.assertEqual(response.status_code, 200)
        return response.get_json()["token"]

    def assert_no_passwords(self, users):
        self.assertIsInstance(users, dict)
        for username, user in users.items():
            with self.subTest(username=username):
                self.assertNotIn("password", user)

    def test_admin_users_denies_unauthenticated_callers(self):
        response = self.client.get("/admin/users")

        self.assertEqual(response.status_code, 401)
        self.assertNotIn("users", response.get_json())

    def test_admin_users_denies_non_admin_callers(self):
        token = self.login("alice", "alice-pw")

        response = self.client.get(
            "/admin/users",
            headers={"Authorization": f"Bearer {token}"},
        )

        self.assertEqual(response.status_code, 403)
        self.assertNotIn("users", response.get_json())

    def test_admin_users_allows_admin_without_password_fields(self):
        token = self.login("admin", "admin-pw")

        response = self.client.get(
            "/admin/users",
            headers={"Authorization": f"Bearer {token}"},
        )

        self.assertEqual(response.status_code, 200)
        users = response.get_json()["users"]
        self.assertEqual(set(users), {"admin", "alice", "bob"})
        self.assert_no_passwords(users)


if __name__ == "__main__":
    unittest.main()
