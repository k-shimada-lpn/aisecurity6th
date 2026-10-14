from __future__ import annotations

import hashlib
import html
import hmac
import json
import os
import re
import secrets
import sqlite3
import tempfile
import threading
import time
from contextlib import contextmanager
from http import HTTPStatus
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Iterator
from urllib.parse import parse_qs, unquote, urlsplit


PASSWORD_ITERATIONS = 310_000
SESSION_LIFETIME = 12 * 60 * 60
MAX_REQUEST_BYTES = 64 * 1024
MAX_NOTE_LENGTH = 5_000
MAX_FILE_BYTES = 1024 * 1024
MAX_FILES_PER_USER = 100
MAX_USER_STORAGE_BYTES = 10 * MAX_FILE_BYTES
EMAIL_PATTERN = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
INVALID_FILE_NAME = re.compile(r'[<>:"/\\|?*\x00-\x1f]')
WINDOWS_RESERVED_NAMES = {
    "CON", "PRN", "AUX", "NUL",
    *(f"COM{number}" for number in range(1, 10)),
    *(f"LPT{number}" for number in range(1, 10)),
}
COOKIE_SECURE = os.environ.get("COOKIE_SECURE") == "1"
FILE_STORAGE_LOCK = threading.RLock()


def confined_storage_path(application_root: Path, configured_path: str | Path) -> Path:
    root = application_root.resolve()
    configured = Path(configured_path)
    candidate = Path(os.path.abspath(configured if configured.is_absolute() else root / configured))
    try:
        relative_path = candidate.relative_to(root)
    except ValueError as error:
        raise ValueError("File storage must be inside the application directory") from error
    if not relative_path.parts:
        raise ValueError("File storage must use a dedicated subdirectory")

    current = root
    for part in relative_path.parts:
        current /= part
        if current.is_symlink():
            raise ValueError("File storage cannot contain symbolic links")

    resolved = candidate.resolve()
    try:
        resolved.relative_to(root)
    except ValueError as error:
        raise ValueError("File storage must resolve inside the application directory") from error
    if resolved == root:
        raise ValueError("File storage must use a dedicated subdirectory")
    return candidate


@contextmanager
def connect_database(database_path: str) -> Iterator[sqlite3.Connection]:
    connection = sqlite3.connect(database_path, timeout=10)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    try:
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def initialize_database(database_path: str) -> None:
    if database_path != ":memory:":
        Path(database_path).parent.mkdir(parents=True, exist_ok=True)
    with connect_database(database_path) as connection:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                email TEXT NOT NULL UNIQUE,
                password_salt BLOB NOT NULL,
                password_hash BLOB NOT NULL,
                created_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS sessions (
                token_hash TEXT PRIMARY KEY,
                user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                csrf_token TEXT NOT NULL,
                expires_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS notes (
                id INTEGER PRIMARY KEY,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                body TEXT NOT NULL,
                created_at INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS notes_user_created
                ON notes(user_id, created_at DESC, id DESC);
            """
        )


def password_digest(password: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, PASSWORD_ITERATIONS
    )


def page(title: str, content: str) -> str:
    return f"""<!doctype html>
<html lang="ja">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{html.escape(title)} - マイメモ</title>
  <style>
    :root {{ color-scheme: light; font-family: system-ui, sans-serif; background: #f4f6fb; color: #1b2430; }}
    body {{ max-width: 680px; margin: 3rem auto; padding: 0 1rem; }}
    main {{ background: white; border: 1px solid #dce2eb; border-radius: 12px; padding: 1.5rem; }}
    h1 {{ margin-top: 0; font-size: 1.7rem; }}
    label {{ display: block; margin: 1rem 0 .35rem; font-weight: 600; }}
    input, textarea {{ box-sizing: border-box; width: 100%; padding: .7rem; border: 1px solid #aab4c2; border-radius: 6px; font: inherit; }}
    textarea {{ min-height: 8rem; resize: vertical; }}
    button {{ margin-top: 1rem; padding: .65rem 1rem; border: 0; border-radius: 6px; background: #2457c5; color: white; font: inherit; cursor: pointer; }}
    a {{ color: #2457c5; }}
    .error {{ padding: .75rem; background: #fff1f0; border: 1px solid #e4a8a3; border-radius: 6px; }}
    .note {{ padding: 1rem 0; border-bottom: 1px solid #e4e8ef; white-space: pre-wrap; overflow-wrap: anywhere; }}
    .muted {{ color: #596579; font-size: .9rem; }}
    nav {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 1rem; }}
    nav form {{ margin: 0; }}
    nav button {{ margin: 0; background: #596579; }}
  </style>
</head>
<body><main>{content}</main></body>
</html>"""


def make_handler(
    database_path: str,
    files_directory: str | Path = "user_files",
    *,
    application_root: str | Path | None = None,
) -> type[BaseHTTPRequestHandler]:
    app_root = Path(application_root or Path(__file__).resolve().parent).resolve()
    storage_root = confined_storage_path(app_root, files_directory)

    class NotesHandler(BaseHTTPRequestHandler):
        server_version = "PersonalNotes"

        def _headers(self) -> None:
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header(
                "Content-Security-Policy",
                "default-src 'none'; style-src 'unsafe-inline'; "
                "form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
            )

        def _send(self, status: int, body: str = "", content_type: str = "text/html; charset=utf-8",
                  cookie: str | None = None) -> None:
            encoded = body.encode("utf-8")
            self.send_response(status)
            self._headers()
            self.send_header("Content-Type", content_type)
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(encoded)))
            if cookie:
                self.send_header("Set-Cookie", cookie)
            self.end_headers()
            self.wfile.write(encoded)

        def _json(self, status: int, payload: dict, cookie: str | None = None) -> None:
            self._send(
                status,
                json.dumps(payload, ensure_ascii=False),
                "application/json; charset=utf-8",
                cookie,
            )

        def _cookie_header(self, token: str, max_age: int = SESSION_LIFETIME) -> str:
            secure = "; Secure" if COOKIE_SECURE else ""
            return (
                f"session={token}; Path=/; HttpOnly; SameSite=Lax; "
                f"Max-Age={max_age}{secure}"
            )

        def _new_session(self, user_id: int | None) -> tuple[dict, str]:
            token = secrets.token_urlsafe(32)
            token_hash = hashlib.sha256(token.encode()).hexdigest()
            csrf_token = secrets.token_urlsafe(32)
            expires_at = int(time.time()) + SESSION_LIFETIME
            with connect_database(database_path) as connection:
                connection.execute(
                    "INSERT INTO sessions(token_hash, user_id, csrf_token, expires_at) "
                    "VALUES (?, ?, ?, ?)",
                    (token_hash, user_id, csrf_token, expires_at),
                )
            return {
                "token_hash": token_hash,
                "user_id": user_id,
                "csrf_token": csrf_token,
                "expires_at": expires_at,
            }, self._cookie_header(token)

        def _get_session(self) -> tuple[dict, str | None]:
            cookie = SimpleCookie()
            try:
                cookie.load(self.headers.get("Cookie", ""))
            except Exception:
                cookie = SimpleCookie()
            morsel = cookie.get("session")
            if morsel:
                token_hash = hashlib.sha256(morsel.value.encode()).hexdigest()
                with connect_database(database_path) as connection:
                    row = connection.execute(
                        "SELECT s.token_hash, s.user_id, s.csrf_token, s.expires_at, u.email "
                        "FROM sessions s LEFT JOIN users u ON u.id = s.user_id "
                        "WHERE s.token_hash = ?",
                        (token_hash,),
                    ).fetchone()
                    if row and row["expires_at"] > int(time.time()):
                        return dict(row), None
                    connection.execute("DELETE FROM sessions WHERE expires_at <= ?", (int(time.time()),))
            session, cookie_header = self._new_session(None)
            return session, cookie_header

        def _render(self, status: int, title: str, content: str,
                    cookie: str | None = None) -> None:
            self._send(status, page(title, content), cookie=cookie)

        def _redirect(self, location: str, cookie: str | None = None) -> None:
            self.send_response(HTTPStatus.SEE_OTHER)
            self._headers()
            self.send_header("Location", location)
            if cookie:
                self.send_header("Set-Cookie", cookie)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def _form(self) -> dict[str, str] | None:
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                return None
            if length < 0 or length > MAX_REQUEST_BYTES:
                return None
            if self.headers.get_content_type() != "application/x-www-form-urlencoded":
                return None
            try:
                values = parse_qs(
                    self.rfile.read(length).decode("utf-8"), keep_blank_values=True,
                    strict_parsing=True, max_num_fields=10,
                )
            except (UnicodeDecodeError, ValueError):
                return None
            if any(len(items) != 1 for items in values.values()):
                return None
            return {key: items[0] for key, items in values.items()}

        def _json_form(self) -> tuple[dict | None, int | None]:
            try:
                length = int(self.headers.get("Content-Length", ""))
            except ValueError:
                return None, HTTPStatus.BAD_REQUEST
            if length < 0:
                return None, HTTPStatus.BAD_REQUEST
            if self.headers.get("Transfer-Encoding"):
                self.close_connection = True
                return None, HTTPStatus.BAD_REQUEST
            if length > MAX_FILE_BYTES + 4096:
                self.close_connection = True
                return None, HTTPStatus.REQUEST_ENTITY_TOO_LARGE
            try:
                body = self.rfile.read(length)
                if self.headers.get_content_type() != "application/json":
                    return None, HTTPStatus.BAD_REQUEST
                payload = json.loads(body.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                return None, HTTPStatus.BAD_REQUEST
            if not isinstance(payload, dict):
                return None, HTTPStatus.BAD_REQUEST
            return payload, None

        def _csrf_valid(self, form: dict[str, str], session: dict) -> bool:
            supplied = form.get("csrf_token", "")
            return hmac.compare_digest(supplied, session["csrf_token"])

        def _file_name(self, name: str) -> str | None:
            try:
                encoded_name = name.encode("utf-8")
            except UnicodeEncodeError:
                return None
            if (
                not name
                or name in {".", ".."}
                or len(encoded_name) > 255
                or name.endswith((" ", "."))
                or INVALID_FILE_NAME.search(name)
                or Path(name).name != name
                or name.split(".", 1)[0].upper() in WINDOWS_RESERVED_NAMES
            ):
                return None
            return name

        def _user_files_directory(self, user_id: int) -> Path:
            confined_storage_path(app_root, storage_root)
            storage_root.mkdir(parents=True, exist_ok=True)
            user_directory = storage_root / str(user_id)
            user_directory.mkdir(exist_ok=True)
            resolved_directory = user_directory.resolve()
            if user_directory.is_symlink() or resolved_directory.parent != storage_root:
                raise OSError("User storage directory is outside the configured root")
            return resolved_directory

        def _file_path(self, user_directory: Path, name: str) -> Path | None:
            safe_name = self._file_name(name)
            if safe_name is None:
                return None
            path = user_directory / safe_name
            if path.is_symlink() or path.resolve().parent != user_directory:
                return None
            return path

        def _api_error(self, status: int, message: str, cookie: str | None = None) -> None:
            self._json(status, {"error": message}, cookie)

        def _api_authenticated(self, session: dict, cookie: str | None) -> bool:
            if session["user_id"]:
                return True
            self._api_error(HTTPStatus.UNAUTHORIZED, "ログインが必要です。", cookie)
            return False

        def _api_csrf_valid(self, session: dict) -> bool:
            supplied = self.headers.get("X-CSRF-Token", "")
            if hmac.compare_digest(supplied, session["csrf_token"]):
                return True
            self._api_error(HTTPStatus.FORBIDDEN, "CSRFトークンが正しくありません。")
            return False

        def _api_file_content(self, payload: dict) -> tuple[str, bytes] | None:
            name = payload.get("name")
            content = payload.get("content")
            if not isinstance(name, str) or self._file_name(name) is None:
                return None
            if not isinstance(content, str):
                return None
            try:
                encoded_content = content.encode("utf-8")
            except UnicodeEncodeError:
                return None
            if len(encoded_content) > MAX_FILE_BYTES:
                return None
            return name, encoded_content

        def _api_storage_available(self, user_directory: Path, content: bytes, replacing: Path | None = None) -> bool:
            entries = [
                entry for entry in user_directory.iterdir()
                if entry.is_file() and not entry.is_symlink()
            ]
            file_count = len(entries)
            used_bytes = sum(entry.stat().st_size for entry in entries)
            if replacing and replacing.exists():
                file_count -= 1
                used_bytes -= replacing.stat().st_size
            return (
                file_count < MAX_FILES_PER_USER
                and used_bytes + len(content) <= MAX_USER_STORAGE_BYTES
            )

        def _api_list_files(self, session: dict, cookie: str | None) -> None:
            try:
                with FILE_STORAGE_LOCK:
                    user_directory = self._user_files_directory(session["user_id"])
                    files = [
                        {"name": entry.name, "size": entry.stat().st_size}
                        for entry in sorted(user_directory.iterdir(), key=lambda item: item.name)
                        if entry.is_file() and not entry.is_symlink()
                    ]
            except OSError:
                self._api_error(HTTPStatus.INTERNAL_SERVER_ERROR, "ファイル一覧を取得できません。", cookie)
                return
            self._json(
                HTTPStatus.OK,
                {"files": files, "csrf_token": session["csrf_token"]},
                cookie,
            )

        def _api_create_file(self, session: dict, payload: dict, cookie: str | None) -> None:
            file_data = self._api_file_content(payload)
            if file_data is None:
                self._api_error(
                    HTTPStatus.BAD_REQUEST,
                    "nameと文字列contentを指定してください（ファイル上限1 MiB）。",
                    cookie,
                )
                return
            name, content = file_data
            try:
                with FILE_STORAGE_LOCK:
                    user_directory = self._user_files_directory(session["user_id"])
                    path = self._file_path(user_directory, name)
                    if path is None:
                        self._api_error(HTTPStatus.BAD_REQUEST, "ファイル名が不正です。", cookie)
                        return
                    if path.exists():
                        self._api_error(HTTPStatus.CONFLICT, "同じ名前のファイルが存在します。", cookie)
                        return
                    if not self._api_storage_available(user_directory, content):
                        self._api_error(HTTPStatus.INSUFFICIENT_STORAGE, "保存容量の上限を超えます。", cookie)
                        return
                    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                    with os.fdopen(descriptor, "wb") as file:
                        file.write(content)
            except OSError:
                self._api_error(HTTPStatus.INTERNAL_SERVER_ERROR, "ファイルを作成できません。", cookie)
                return
            self._json(HTTPStatus.CREATED, {"name": name, "size": len(content)}, cookie)

        def _api_read_file(self, session: dict, name: str, cookie: str | None) -> None:
            try:
                with FILE_STORAGE_LOCK:
                    user_directory = self._user_files_directory(session["user_id"])
                    path = self._file_path(user_directory, name)
                    if path is None:
                        self._api_error(HTTPStatus.BAD_REQUEST, "ファイル名が不正です。", cookie)
                        return
                    if not path.is_file():
                        self._api_error(HTTPStatus.NOT_FOUND, "ファイルが見つかりません。", cookie)
                        return
                    content = path.read_bytes()
            except OSError:
                self._api_error(HTTPStatus.INTERNAL_SERVER_ERROR, "ファイルを読み取れません。", cookie)
                return
            if len(content) > MAX_FILE_BYTES:
                self._api_error(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, "ファイルサイズの上限を超えています。", cookie)
                return
            try:
                text = content.decode("utf-8")
            except UnicodeDecodeError:
                self._api_error(HTTPStatus.UNSUPPORTED_MEDIA_TYPE, "UTF-8テキストではありません。", cookie)
                return
            self._json(HTTPStatus.OK, {"name": name, "content": text}, cookie)

        def _api_update_file(self, session: dict, name: str, payload: dict, cookie: str | None) -> None:
            content = payload.get("content")
            if not isinstance(content, str):
                self._api_error(HTTPStatus.BAD_REQUEST, "文字列contentを指定してください。", cookie)
                return
            try:
                encoded_content = content.encode("utf-8")
            except UnicodeEncodeError:
                self._api_error(HTTPStatus.BAD_REQUEST, "contentをUTF-8に変換できません。", cookie)
                return
            if len(encoded_content) > MAX_FILE_BYTES:
                self._api_error(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, "ファイルサイズの上限は1 MiBです。", cookie)
                return
            temporary_path: Path | None = None
            try:
                with FILE_STORAGE_LOCK:
                    user_directory = self._user_files_directory(session["user_id"])
                    path = self._file_path(user_directory, name)
                    if path is None:
                        self._api_error(HTTPStatus.BAD_REQUEST, "ファイル名が不正です。", cookie)
                        return
                    if not path.is_file():
                        self._api_error(HTTPStatus.NOT_FOUND, "ファイルが見つかりません。", cookie)
                        return
                    if not self._api_storage_available(user_directory, encoded_content, path):
                        self._api_error(HTTPStatus.INSUFFICIENT_STORAGE, "保存容量の上限を超えます。", cookie)
                        return
                    descriptor, temporary_name = tempfile.mkstemp(dir=user_directory, prefix=".upload-")
                    temporary_path = Path(temporary_name)
                    with os.fdopen(descriptor, "wb") as file:
                        file.write(encoded_content)
                    os.replace(temporary_path, path)
            except OSError:
                self._api_error(HTTPStatus.INTERNAL_SERVER_ERROR, "ファイルを更新できません。", cookie)
                return
            finally:
                if temporary_path is not None:
                    temporary_path.unlink(missing_ok=True)
            self._json(HTTPStatus.OK, {"name": name, "size": len(encoded_content)}, cookie)

        def _api_delete_file(self, session: dict, name: str, cookie: str | None) -> None:
            try:
                with FILE_STORAGE_LOCK:
                    user_directory = self._user_files_directory(session["user_id"])
                    path = self._file_path(user_directory, name)
                    if path is None:
                        self._api_error(HTTPStatus.BAD_REQUEST, "ファイル名が不正です。", cookie)
                        return
                    if not path.is_file():
                        self._api_error(HTTPStatus.NOT_FOUND, "ファイルが見つかりません。", cookie)
                        return
                    path.unlink()
            except OSError:
                self._api_error(HTTPStatus.INTERNAL_SERVER_ERROR, "ファイルを削除できません。", cookie)
                return
            self._json(HTTPStatus.OK, {"deleted": name}, cookie)

        def _dispatch_files_api(self, session: dict, cookie: str | None) -> bool:
            path = urlsplit(self.path).path
            if path != "/api/files" and not path.startswith("/api/files/"):
                return False
            if not self._api_authenticated(session, cookie):
                return True

            if path == "/api/files":
                if self.command == "GET":
                    self._api_list_files(session, cookie)
                    return True
                if self.command != "POST":
                    self._api_error(HTTPStatus.METHOD_NOT_ALLOWED, "このAPIではGETとPOSTを使用できます。", cookie)
                    return True
                payload, error_status = self._json_form()
                if error_status == HTTPStatus.REQUEST_ENTITY_TOO_LARGE:
                    self._api_error(error_status, "リクエストサイズの上限を超えています。", cookie)
                    return True
                if payload is None:
                    self._api_error(HTTPStatus.BAD_REQUEST, "正しいJSONリクエストが必要です。", cookie)
                    return True
                if not self._api_csrf_valid(session):
                    return True
                self._api_create_file(session, payload, cookie)
                return True

            encoded_name = path.removeprefix("/api/files/")
            try:
                name = unquote(encoded_name, errors="strict")
            except UnicodeDecodeError:
                self._api_error(HTTPStatus.BAD_REQUEST, "ファイル名が不正です。", cookie)
                return True
            if not name or "/" in name:
                self._api_error(HTTPStatus.BAD_REQUEST, "ファイル名が不正です。", cookie)
                return True

            if self.command == "GET":
                self._api_read_file(session, name, cookie)
            elif self.command == "PUT":
                payload, error_status = self._json_form()
                if error_status == HTTPStatus.REQUEST_ENTITY_TOO_LARGE:
                    self._api_error(error_status, "リクエストサイズの上限を超えています。", cookie)
                    return True
                if payload is None:
                    self._api_error(HTTPStatus.BAD_REQUEST, "正しいJSONリクエストが必要です。", cookie)
                    return True
                if not self._api_csrf_valid(session):
                    return True
                self._api_update_file(session, name, payload, cookie)
            elif self.command == "DELETE":
                try:
                    length = int(self.headers.get("Content-Length", "0"))
                except ValueError:
                    self.close_connection = True
                    self._api_error(HTTPStatus.BAD_REQUEST, "Content-Lengthが不正です。", cookie)
                    return True
                if length < 0 or length > MAX_FILE_BYTES + 4096 or self.headers.get("Transfer-Encoding"):
                    self.close_connection = True
                    self._api_error(HTTPStatus.BAD_REQUEST, "DELETEリクエストに本文は指定できません。", cookie)
                    return True
                if length:
                    self.rfile.read(length)
                    self._api_error(HTTPStatus.BAD_REQUEST, "DELETEリクエストに本文は指定できません。", cookie)
                    return True
                if not self._api_csrf_valid(session):
                    return True
                self._api_delete_file(session, name, cookie)
            else:
                self._api_error(HTTPStatus.METHOD_NOT_ALLOWED, "このAPIではGET、PUT、DELETEを使用できます。", cookie)
            return True

        def _auth_form(self, session: dict, mode: str, message: str = "",
                       status: int = HTTPStatus.OK, cookie: str | None = None) -> None:
            register = mode == "register"
            title = "ユーザー登録" if register else "ログイン"
            action = "/register" if register else "/login"
            description = (
                '<label for="email">メールアドレス</label>'
                '<input id="email" name="email" type="email" maxlength="254" required autocomplete="email">'
                '<label for="password">パスワード（8文字以上）</label>'
                '<input id="password" name="password" type="password" minlength="8" maxlength="128" required '
                f'autocomplete="{"new-password" if register else "current-password"}">'
            )
            link = (
                '<p>アカウントをお持ちですか？ <a href="/login">ログイン</a></p>'
                if register else
                '<p>初めての方は <a href="/register">ユーザー登録</a></p>'
            )
            alert = f'<p class="error">{html.escape(message)}</p>' if message else ""
            content = (
                f"<h1>{title}</h1>{alert}<form method=\"post\" action=\"{action}\">"
                f'<input type="hidden" name="csrf_token" value="{html.escape(session["csrf_token"])}">'
                f"{description}<button type=\"submit\">{title}</button></form>{link}"
            )
            self._render(status, title, content, cookie)

        def _notes_content(self, session: dict) -> str:
            with connect_database(database_path) as connection:
                notes = connection.execute(
                    "SELECT body, created_at FROM notes WHERE user_id = ? "
                    "ORDER BY created_at DESC, id DESC",
                    (session["user_id"],),
                ).fetchall()
            rendered_notes = "".join(
                '<article class="note"><p>'
                + html.escape(note["body"])
                + '</p><span class="muted">'
                + time.strftime("%Y-%m-%d %H:%M", time.localtime(note["created_at"]))
                + "</span></article>"
                for note in notes
            ) or '<p class="muted">メモはまだありません。</p>'
            csrf_input = (
                '<input type="hidden" name="csrf_token" '
                f'value="{html.escape(session["csrf_token"])}">'
            )
            return (
                '<nav><strong>マイメモ</strong><span>'
                + html.escape(session.get("email") or "")
                + '</span><form method="post" action="/logout">'
                + csrf_input
                + '<button type="submit">ログアウト</button></form></nav>'
                '<h1>メモ</h1><form method="post" action="/notes">'
                + csrf_input
                + '<label for="body">新しいメモ</label>'
                + f'<textarea id="body" name="body" maxlength="{MAX_NOTE_LENGTH}" required></textarea>'
                + '<button type="submit">メモを保存</button></form><section aria-label="保存したメモ">'
                + rendered_notes
                + "</section>"
            )

        def do_GET(self) -> None:
            session, cookie = self._get_session()
            if self._dispatch_files_api(session, cookie):
                return
            if self.path == "/":
                self._redirect("/notes" if session["user_id"] else "/login", cookie)
            elif self.path == "/login":
                self._auth_form(session, "login", cookie=cookie)
            elif self.path == "/register":
                self._auth_form(session, "register", cookie=cookie)
            elif self.path == "/notes":
                if not session["user_id"]:
                    self._redirect("/login", cookie)
                    return
                self._render(HTTPStatus.OK, "マイメモ", self._notes_content(session), cookie)
            else:
                self._render(
                    HTTPStatus.NOT_FOUND, "ページが見つかりません",
                    "<h1>ページが見つかりません</h1>", cookie,
                )

        def _register(self, session: dict, form: dict[str, str], cookie: str | None) -> None:
            email = form.get("email", "").strip().lower()
            password = form.get("password", "")
            if not EMAIL_PATTERN.fullmatch(email) or len(email) > 254:
                self._auth_form(
                    session, "register", "有効なメールアドレスを入力してください。",
                    HTTPStatus.BAD_REQUEST, cookie,
                )
                return
            if len(password) < 8 or len(password) > 128:
                self._auth_form(
                    session, "register", "パスワードは8〜128文字で入力してください。",
                    HTTPStatus.BAD_REQUEST, cookie,
                )
                return

            salt = secrets.token_bytes(16)
            digest = password_digest(password, salt)
            try:
                with connect_database(database_path) as connection:
                    cursor = connection.execute(
                        "INSERT INTO users(email, password_salt, password_hash, created_at) "
                        "VALUES (?, ?, ?, ?)",
                        (email, salt, digest, int(time.time())),
                    )
                    user_id = cursor.lastrowid
            except sqlite3.IntegrityError:
                self._auth_form(
                    session, "register", "このメールアドレスは既に登録されています。",
                    HTTPStatus.CONFLICT, cookie,
                )
                return

            session_cookie = self._replace_session(session, user_id)
            self._redirect("/notes", session_cookie)

        def _login(self, session: dict, form: dict[str, str], cookie: str | None) -> None:
            email = form.get("email", "").strip().lower()
            password = form.get("password", "")
            with connect_database(database_path) as connection:
                user = connection.execute(
                    "SELECT id, password_salt, password_hash FROM users WHERE email = ?",
                    (email,),
                ).fetchone()

            if user:
                valid = hmac.compare_digest(
                    password_digest(password, user["password_salt"]), user["password_hash"]
                )
            else:
                password_digest(password[:128], b"notes-app-dummy!")
                valid = False
            if not valid:
                self._auth_form(
                    session, "login", "メールアドレスまたはパスワードが正しくありません。",
                    HTTPStatus.UNAUTHORIZED, cookie,
                )
                return

            session_cookie = self._replace_session(session, user["id"])
            self._redirect("/notes", session_cookie)

        def _save_note(self, session: dict, form: dict[str, str], cookie: str | None) -> None:
            if not session["user_id"]:
                self._redirect("/login", cookie)
                return
            body = form.get("body", "")
            if not body.strip() or len(body) > MAX_NOTE_LENGTH:
                self._render(
                    HTTPStatus.BAD_REQUEST, "メモを保存できません",
                    "<h1>メモは1〜5000文字で入力してください。</h1>"
                    '<p><a href="/notes">メモに戻る</a></p>',
                    cookie,
                )
                return
            with connect_database(database_path) as connection:
                connection.execute(
                    "INSERT INTO notes(user_id, body, created_at) VALUES (?, ?, ?)",
                    (session["user_id"], body.strip(), int(time.time())),
                )
            self._redirect("/notes", cookie)

        def _logout(self, session: dict) -> None:
            with connect_database(database_path) as connection:
                connection.execute(
                    "DELETE FROM sessions WHERE token_hash = ?", (session["token_hash"],)
                )
            self._redirect("/login", self._cookie_header("", 0))

        def do_POST(self) -> None:
            session, cookie = self._get_session()
            if self._dispatch_files_api(session, cookie):
                return
            form = self._form()
            if form is None:
                self._render(HTTPStatus.BAD_REQUEST, "不正なリクエスト", "<h1>不正なリクエストです。</h1>", cookie)
                return
            if not self._csrf_valid(form, session):
                self._render(HTTPStatus.FORBIDDEN, "リクエストを確認できません",
                             "<h1>ページを再読み込みして、もう一度お試しください。</h1>", cookie)
                return
            if self.path == "/register":
                self._register(session, form, cookie)
            elif self.path == "/login":
                self._login(session, form, cookie)
            elif self.path == "/notes":
                self._save_note(session, form, cookie)
            elif self.path == "/logout":
                self._logout(session)
            else:
                self._render(
                    HTTPStatus.NOT_FOUND, "ページが見つかりません",
                    "<h1>ページが見つかりません</h1>", cookie,
                )

        def do_PUT(self) -> None:
            session, cookie = self._get_session()
            if not self._dispatch_files_api(session, cookie):
                self._api_error(HTTPStatus.NOT_FOUND, "APIが見つかりません。", cookie)

        def do_DELETE(self) -> None:
            session, cookie = self._get_session()
            if not self._dispatch_files_api(session, cookie):
                self._api_error(HTTPStatus.NOT_FOUND, "APIが見つかりません。", cookie)

        def _replace_session(self, old_session: dict, user_id: int) -> str:
            with connect_database(database_path) as connection:
                connection.execute(
                    "DELETE FROM sessions WHERE token_hash = ?", (old_session["token_hash"],)
                )
            _, cookie = self._new_session(user_id)
            return cookie

        def log_message(self, format: str, *args: object) -> None:
            return

    return NotesHandler


def main() -> None:
    database_path = os.environ.get("APP_DB_PATH", "notes.sqlite3")
    files_directory = os.environ.get("APP_FILES_DIR", "user_files")
    host = os.environ.get("APP_HOST", "127.0.0.1")
    port = int(os.environ.get("APP_PORT", "8000"))
    initialize_database(database_path)
    server = ThreadingHTTPServer((host, port), make_handler(database_path, files_directory))
    print(f"マイメモを起動しました: http://{host}:{port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nサーバーを終了します。")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
