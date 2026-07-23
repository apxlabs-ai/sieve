import json
import unittest

from app import TOKENS, app


def assert_invalid_credentials(test_case, response):
    test_case.assertEqual(response.status_code, 401)
    test_case.assertEqual(response.content_type, "application/json")
    test_case.assertEqual(response.get_json(), {"error": "invalid credentials"})


class LoginTestCase(unittest.TestCase):
    def setUp(self):
        TOKENS.clear()
        self.client = app.test_client()

    def tearDown(self):
        TOKENS.clear()

    def assert_login_baseline(self):
        valid = self.client.post("/login", json={"username": "alice", "password": "alice-pw"})
        self.assertEqual(valid.status_code, 200)
        self.assertEqual(valid.content_type, "application/json")
        self.assertEqual(valid.get_json()["token"], "token-1")

        invalid = self.client.post("/login", json={"username": "alice", "password": "wrong"})
        assert_invalid_credentials(self, invalid)

    def test_login_rejects_json_scalar_bodies_with_controlled_response(self):
        self.assert_login_baseline()

        for payload in ("x", True, 1):
            with self.subTest(payload=payload):
                response = self.client.post(
                    "/login",
                    data=json.dumps(payload),
                    content_type="application/json",
                )

                assert_invalid_credentials(self, response)


if __name__ == "__main__":
    unittest.main()
