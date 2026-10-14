import json
import hashlib
import http.client
import sqlite3
import tempfile
import threading
import unittest
from contextlib import closing
from http.server import ThreadingHTTPServer
from pathlib import Path
from urllib.parse import quote, urlencode

from app import (
    MAX_FILE_BYTES,
    PASSWORD_ITERATIONS,
    confined_storage_path,
    initialize_database,
    make_handler,
)


class NotesAppTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.database_path = str(Path(self.temp_dir.name) / "test.sqlite3")
        self.files_directory = str(Path(self.temp_dir.name) / "user_files")
        initialize_database(self.database_path)
        self.server = ThreadingHTTPServer(
            ("127.0.0.1", 0),
            make_handler(
                self.database_path,
                self.files_directory,
                application_root=self.temp_dir.name,
            ),
        )
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.client = http.client.HTTPConnection("127.0.0.1", self.server.server_port)
        self.cookie = None

    def tearDown(self):
        self.client.close()
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()
        self.temp_dir.cleanup()

    def request(self, method, path, data=None, json_body=False, csrf_token=None):
        headers = {}
        if self.cookie:
            headers["Cookie"] = self.cookie
        if csrf_token:
            headers["X-CSRF-Token"] = csrf_token
        if data is not None:
            if json_body:
                headers["Content-Type"] = "application/json"
                body = json.dumps(data)
            else:
                headers["Content-Type"] = "application/x-www-form-urlencoded"
                body = urlencode(data)
        else:
            body = None
        self.client.request(method, path, body=body, headers=headers)
        response = self.client.getresponse()
        content = response.read().decode("utf-8")
        set_cookie = response.getheader("Set-Cookie")
        if set_cookie:
            self.cookie = set_cookie.split(";", 1)[0]
        return response.status, response.getheader("Location"), content

    def extract_csrf_token(self, content):
        marker = 'name="csrf_token" value="'
        prefix, separator, remainder = content.partition(marker)
        self.assertTrue(separator, "CSRF token input should be present")
        return remainder.split('"', 1)[0]

    def csrf_token(self, path="/register"):
        status, _, content = self.request("GET", path)
        self.assertEqual(status, 200)
        return self.extract_csrf_token(content)

    def logout(self):
        csrf_token = self.csrf_token("/notes")
        return self.request("POST", "/logout", {"csrf_token": csrf_token})

    def api_csrf_token(self):
        status, _, content = self.request("GET", "/api/files")
        self.assertEqual(status, 200)
        return json.loads(content)["csrf_token"]

    def register(self, email, password="correct-horse"):
        token = self.csrf_token()
        return self.request("POST", "/register", {
            "csrf_token": token, "email": email, "password": password,
        })

    def login(self, email, password):
        token = self.csrf_token("/login")
        return self.request("POST", "/login", {
            "csrf_token": token, "email": email, "password": password,
        })

    def test_user_can_log_in_after_logging_out(self):
        self.register("alice@example.com")
        status, location, _ = self.logout()
        self.assertEqual((status, location), (303, "/login"))

        status, location, _ = self.login("alice@example.com", "correct-horse")
        self.assertEqual((status, location), (303, "/notes"))
        status, _, content = self.request("GET", "/notes")
        self.assertEqual(status, 200)
        self.assertIn("alice@example.com", content)

    def test_register_logs_user_in_and_saves_note(self):
        status, location, _ = self.register("alice@example.com")
        self.assertEqual((status, location), (303, "/notes"))
        status, _, content = self.request("GET", "/notes")
        self.assertEqual(status, 200)
        self.assertIn("alice@example.com", content)

        token = self.extract_csrf_token(content)
        status, location, _ = self.request("POST", "/notes", {
            "csrf_token": token, "body": "private note",
        })
        self.assertEqual((status, location), (303, "/notes"))
        _, _, content = self.request("GET", "/notes")
        self.assertIn("private note", content)

    def test_only_owner_can_view_a_note(self):
        self.register("alice@example.com")
        status, _, content = self.request("GET", "/notes")
        csrf = self.extract_csrf_token(content)
        self.request("POST", "/notes", {"csrf_token": csrf, "body": "Alice's secret"})

        self.logout()
        status, location, _ = self.register("bob@example.com")
        self.assertEqual((status, location), (303, "/notes"))
        status, _, content = self.request("GET", "/notes")
        self.assertEqual(status, 200)
        self.assertNotIn("Alice's secret", content)

    def test_login_rejects_wrong_password(self):
        self.register("alice@example.com")
        self.logout()
        status, _, content = self.login("alice@example.com", "incorrect")
        self.assertEqual(status, 401)
        self.assertIn("正しくありません", content)

    def test_rejects_short_password(self):
        status, _, content = self.register("alice@example.com", "short")
        self.assertEqual(status, 400)
        self.assertIn("8〜128文字", content)

    def test_password_requires_at_least_eight_characters(self):
        status, location, _ = self.register("eight@example.com", "12345678")
        self.assertEqual((status, location), (303, "/notes"))

        status, _, content = self.register("seven@example.com", "1234567")
        self.assertEqual(status, 400)
        self.assertIn("8〜128文字", content)

    def test_passwords_are_stored_as_salted_hashes_not_plaintext(self):
        password = "same-dummy-password"
        self.register("alice@example.com", password)
        self.register("bob@example.com", password)

        with closing(sqlite3.connect(self.database_path)) as connection:
            credentials = connection.execute(
                "SELECT password_salt, password_hash FROM users ORDER BY email"
            ).fetchall()

        self.assertEqual(len(credentials), 2)
        for salt, password_hash in credentials:
            self.assertEqual(len(salt), 16)
            self.assertNotEqual(password_hash, password.encode("utf-8"))
            self.assertEqual(
                password_hash,
                hashlib.pbkdf2_hmac(
                    "sha256", password.encode("utf-8"), salt, PASSWORD_ITERATIONS
                ),
            )
        self.assertNotEqual(credentials[0][0], credentials[1][0])
        self.assertNotEqual(credentials[0][1], credentials[1][1])

    def test_requires_csrf_token(self):
        status, _, content = self.request("GET", "/register")
        self.assertEqual(status, 200)
        status, _, _ = self.request("POST", "/register", {
            "email": "alice@example.com", "password": "correct-horse",
        })
        self.assertEqual(status, 403)

    def test_unauthenticated_user_cannot_view_notes(self):
        status, location, _ = self.request("GET", "/notes")
        self.assertEqual((status, location), (303, "/login"))

    def test_note_content_is_html_escaped(self):
        self.register("alice@example.com")
        _, _, content = self.request("GET", "/notes")
        csrf = self.extract_csrf_token(content)
        self.request("POST", "/notes", {"csrf_token": csrf, "body": "<script>alert(1)</script>"})
        _, _, content = self.request("GET", "/notes")
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", content)
        self.assertNotIn("<script>alert(1)</script>", content)

    def test_file_api_supports_create_list_read_update_and_delete(self):
        self.register("alice@example.com")
        csrf_token = self.api_csrf_token()

        status, _, content = self.request(
            "POST",
            "/api/files",
            {"name": "メモ.txt", "content": "最初の内容"},
            json_body=True,
            csrf_token=csrf_token,
        )
        self.assertEqual(status, 201)
        self.assertEqual(json.loads(content)["name"], "メモ.txt")

        status, _, content = self.request("GET", "/api/files")
        self.assertEqual(status, 200)
        listing = json.loads(content)
        self.assertEqual([file["name"] for file in listing["files"]], ["メモ.txt"])
        self.assertEqual(listing["files"][0]["size"], len("最初の内容".encode("utf-8")))

        status, _, content = self.request("GET", "/api/files/" + quote("メモ.txt"))
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(content)["content"], "最初の内容")

        status, _, content = self.request(
            "PUT",
            "/api/files/" + quote("メモ.txt"),
            {"content": "更新済み"},
            json_body=True,
            csrf_token=csrf_token,
        )
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(content)["size"], len("更新済み".encode("utf-8")))
        _, _, content = self.request("GET", "/api/files/" + quote("メモ.txt"))
        self.assertEqual(json.loads(content)["content"], "更新済み")

        status, _, content = self.request(
            "DELETE", "/api/files/" + quote("メモ.txt"), csrf_token=csrf_token
        )
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(content)["deleted"], "メモ.txt")
        status, _, _ = self.request("GET", "/api/files/" + quote("メモ.txt"))
        self.assertEqual(status, 404)

    def test_file_api_requires_login_and_csrf_for_changes(self):
        status, _, content = self.request("GET", "/api/files")
        self.assertEqual(status, 401)
        self.assertIn("error", json.loads(content))

        self.register("alice@example.com")
        status, _, _ = self.request(
            "POST",
            "/api/files",
            {"name": "memo.txt", "content": "private"},
            json_body=True,
        )
        self.assertEqual(status, 403)

    def test_file_api_keeps_each_users_files_private(self):
        self.register("alice@example.com")
        csrf_token = self.api_csrf_token()
        status, _, _ = self.request(
            "POST",
            "/api/files",
            {"name": "secret.txt", "content": "Alice's private file"},
            json_body=True,
            csrf_token=csrf_token,
        )
        self.assertEqual(status, 201)
        self.logout()

        self.register("bob@example.com")
        status, _, content = self.request("GET", "/api/files")
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(content)["files"], [])
        status, _, _ = self.request("GET", "/api/files/secret.txt")
        self.assertEqual(status, 404)

    def test_file_api_rejects_path_traversal_and_duplicate_creation(self):
        self.register("alice@example.com")
        csrf_token = self.api_csrf_token()

        status, _, _ = self.request(
            "POST",
            "/api/files",
            {"name": "safe.txt", "content": "safe"},
            json_body=True,
            csrf_token=csrf_token,
        )
        self.assertEqual(status, 201)
        status, _, _ = self.request(
            "POST",
            "/api/files",
            {"name": "safe.txt", "content": "overwrite"},
            json_body=True,
            csrf_token=csrf_token,
        )
        self.assertEqual(status, 409)

        traversal_path = "/api/files/" + quote("../outside.txt", safe="")
        status, _, _ = self.request("GET", traversal_path)
        self.assertEqual(status, 400)
        self.assertFalse((Path(self.files_directory).parent / "outside.txt").exists())

    def test_file_api_rejects_oversized_content_and_invalid_json(self):
        self.register("alice@example.com")
        csrf_token = self.api_csrf_token()

        status, _, _ = self.request(
            "POST",
            "/api/files",
            {"name": "large.txt", "content": "x" * (MAX_FILE_BYTES + 1)},
            json_body=True,
            csrf_token=csrf_token,
        )
        self.assertEqual(status, 400)

        status, _, _ = self.request(
            "POST",
            "/api/files",
            ["not", "an", "object"],
            json_body=True,
            csrf_token=csrf_token,
        )
        self.assertEqual(status, 400)

    def test_file_api_cannot_read_files_outside_its_storage_directory(self):
        self.register("alice@example.com")

        status, _, _ = self.request("GET", "/api/files/key.txt")
        self.assertEqual(status, 404)

        status, _, _ = self.request("GET", "/api/files/" + quote("../../key.txt", safe=""))
        self.assertEqual(status, 400)

    def test_file_storage_path_must_stay_inside_application_directory(self):
        app_root = Path(self.temp_dir.name).resolve()

        with self.assertRaises(ValueError):
            confined_storage_path(app_root, app_root.parent / "outside-files")

        with self.assertRaises(ValueError):
            confined_storage_path(app_root, app_root)

        self.assertEqual(
            confined_storage_path(app_root, "safe-files"),
            app_root / "safe-files",
        )

    def test_file_storage_rejects_symlink_to_outside_directory(self):
        app_root = Path(self.temp_dir.name).resolve()
        outside_directory = Path(self.temp_dir.name).parent / (
            Path(self.temp_dir.name).name + "-outside"
        )
        outside_directory.mkdir()
        link = app_root / "linked-files"
        try:
            link.symlink_to(outside_directory, target_is_directory=True)
        except (OSError, NotImplementedError):
            self.skipTest("Directory symlink creation is not available")

        try:
            with self.assertRaises(ValueError):
                confined_storage_path(app_root, "linked-files")
        finally:
            link.unlink()
            outside_directory.rmdir()


if __name__ == "__main__":
    unittest.main()
