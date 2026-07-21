import unittest

import app as sieve

try:
    from werkzeug.security import generate_password_hash
except ImportError:  # pragma: no cover - only relevant outside the app runtime
    generate_password_hash = None


TEST_PASSWORDS = {
    "alice": "alice-admin-directory-test-password",
    "admin": "admin-directory-test-password",
}


def set_user_password(username, password):
    user = sieve.USERS[username]
    if "password_hash" in user:
        user["password_hash"] = generate_password_hash(password)
        user.pop("password", None)
    else:
        user["password"] = password


class AdminUsersTestCase(unittest.TestCase):
    def setUp(self):
        sieve.TOKENS.clear()
        for username, password in TEST_PASSWORDS.items():
            set_user_password(username, password)
        self.client = sieve.app.test_client()

    def login(self, username, password):
        response = self.client.post(
            "/login",
            json={"username": username, "password": password},
        )
        self.assertEqual(response.status_code, 200)
        return response.get_json()["token"]

    def test_admin_directory_rejects_unauthenticated_requests(self):
        response = self.client.get("/admin/users")

        self.assertIn(response.status_code, (401, 403))
        body = response.get_json()
        self.assertNotIn("users", body)

    def test_admin_directory_rejects_non_admin_users(self):
        token = self.login("alice", TEST_PASSWORDS["alice"])

        response = self.client.get(
            "/admin/users",
            headers={"Authorization": f"Bearer {token}"},
        )

        self.assertEqual(response.status_code, 403)
        body = response.get_json()
        self.assertNotIn("users", body)

    def test_admin_directory_omits_passwords_for_admin_users(self):
        token = self.login("admin", TEST_PASSWORDS["admin"])

        response = self.client.get(
            "/admin/users",
            headers={"Authorization": f"Bearer {token}"},
        )

        self.assertEqual(response.status_code, 200)
        users = response.get_json()["users"]
        self.assertEqual(set(users), {"alice", "bob", "admin"})
        for user in users.values():
            self.assertEqual(set(user), {"id", "email", "balance", "admin"})
            self.assertNotIn("password", user)


if __name__ == "__main__":
    unittest.main()
