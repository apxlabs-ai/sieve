import unittest

from app import app


def password_paths(value, path="$"):
    paths = []
    if isinstance(value, dict):
        for key, child in value.items():
            child_path = f"{path}.{key}"
            if key == "password":
                paths.append(child_path)
            paths.extend(password_paths(child, child_path))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            paths.extend(password_paths(child, f"{path}[{index}]"))
    return paths


class AdminUsersSecurityTest(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()

    def test_user_directory_does_not_disclose_password_fields(self):
        login = self.client.post(
            "/login",
            json={"username": "alice", "password": "alice-pw"},
        )
        self.assertEqual(login.status_code, 200)
        token = login.get_json()["token"]

        account = self.client.get(
            "/accounts/1",
            headers={"Authorization": f"Bearer {token}"},
        )
        self.assertEqual(account.status_code, 200)
        account_body = account.get_json()
        self.assertEqual(account_body["username"], "alice")
        self.assertEqual(account_body["email"], "alice@sieve.test")
        self.assertEqual(password_paths(account_body), [])

        directory = self.client.get("/admin/users")
        self.assertEqual(directory.status_code, 200)
        self.assertEqual(password_paths(directory.get_json()), [])


if __name__ == "__main__":
    unittest.main()
