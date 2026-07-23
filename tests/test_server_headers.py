import json
import os
import re
import socket
import subprocess
import sys
import textwrap
import time
import unittest
from pathlib import Path
from urllib import error, parse, request


ROOT = Path(__file__).resolve().parents[1]
VERSIONED_INTERNAL_SERVER = re.compile(r"\b(?:Werkzeug|Python)/\d+(?:\.\d+)*\b")


def unused_local_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def request_json(base_url, method, path, body=None):
    data = None
    headers = {}
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        headers["Content-Type"] = "application/json"

    req = request.Request(
        parse.urljoin(base_url + "/", path.lstrip("/")),
        data=data,
        headers=headers,
        method=method,
    )
    try:
        with request.urlopen(req, timeout=2) as response:
            return response.status, response.headers, response.read().decode("utf-8")
    except error.HTTPError as exc:
        try:
            return exc.code, exc.headers, exc.read().decode("utf-8")
        finally:
            exc.close()


class PublicServerHeaderTest(unittest.TestCase):
    def setUp(self):
        self.port = unused_local_port()
        self.base_url = f"http://127.0.0.1:{self.port}"
        server_code = textwrap.dedent(
            """
            import os
            import app

            port = int(os.environ["SIEVE_TEST_PORT"])
            run_server = getattr(app, "run_server", None)
            if run_server is None:
                app.app.run(host="127.0.0.1", port=port)
            else:
                run_server(host="127.0.0.1", port=port)
            """
        )
        env = os.environ.copy()
        env["SIEVE_TEST_PORT"] = str(self.port)
        env["PYTHONUNBUFFERED"] = "1"
        self.server = subprocess.Popen(
            [sys.executable, "-c", server_code],
            cwd=ROOT,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        self.addCleanup(self.stop_server)
        self.wait_for_server()

    def stop_server(self):
        if self.server.poll() is None:
            self.server.terminate()
            try:
                self.server.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.server.kill()
                self.server.wait(timeout=5)

    def wait_for_server(self):
        deadline = time.time() + 10
        last_error = None
        while time.time() < deadline:
            if self.server.poll() is not None:
                stdout, stderr = self.server.communicate()
                self.fail(
                    "server exited during startup\n"
                    f"stdout:\n{stdout}\n"
                    f"stderr:\n{stderr}"
                )
            try:
                request_json(self.base_url, "GET", "/")
                return
            except Exception as exc:
                last_error = exc
                time.sleep(0.1)
        self.fail(f"server did not start: {last_error}")

    def assert_response_has_no_versioned_server_header(
        self, response_name, status, headers, raw_body, expected_status, expected_field
    ):
        self.assertEqual(status, expected_status, response_name)
        body = json.loads(raw_body)
        key, expected_value = expected_field
        self.assertEqual(body.get(key), expected_value, response_name)

        leaked = [
            header
            for header in headers.get_all("Server", [])
            if VERSIONED_INTERNAL_SERVER.search(header)
        ]
        self.assertEqual(
            [],
            leaked,
            f"{response_name} leaked precise internal server versions",
        )

    def test_public_success_and_error_responses_do_not_disclose_versions(self):
        cases = [
            (
                "GET /",
                request_json(self.base_url, "GET", "/"),
                200,
                ("name", "Sieve"),
            ),
            (
                "POST /login invalid credentials",
                request_json(
                    self.base_url,
                    "POST",
                    "/login",
                    {"email": "invalid@example.test", "password": "bad"},
                ),
                401,
                ("error", "invalid credentials"),
            ),
        ]

        for response_name, response, expected_status, expected_field in cases:
            with self.subTest(response_name=response_name):
                self.assert_response_has_no_versioned_server_header(
                    response_name,
                    *response,
                    expected_status,
                    expected_field,
                )


if __name__ == "__main__":
    unittest.main()
