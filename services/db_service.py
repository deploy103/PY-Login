import sqlite3
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
import time


BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
DB_FILE = DATA_DIR / "app.db"


def get_connection():
    ensure_storage()
    connection = sqlite3.connect(DB_FILE)
    connection.row_factory = sqlite3.Row
    return connection


def ensure_storage():
    DATA_DIR.mkdir(exist_ok=True)
    with closing(sqlite3.connect(DB_FILE)) as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                username TEXT NOT NULL UNIQUE,
                birthdate TEXT NOT NULL,
                email TEXT NOT NULL UNIQUE,
                signup_path TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS activity_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                message TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS auth_failures (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT NOT NULL,
                username TEXT,
                reason TEXT NOT NULL,
                created_at INTEGER NOT NULL
            )
            """
        )
        connection.commit()


def row_to_user(row):
    if row is None:
        return None
    return {
        "id": row["id"],
        "name": row["name"],
        "username": row["username"],
        "birthdate": row["birthdate"],
        "email": row["email"],
        "path": row["signup_path"],
        "password": row["password_hash"],
        "created_at": row["created_at"],
    }


def get_user_by_email(email):
    with closing(get_connection()) as connection:
        row = connection.execute(
            "SELECT * FROM users WHERE lower(email) = lower(?)",
            (email,),
        ).fetchone()
    return row_to_user(row)


def get_user_by_username(username):
    with closing(get_connection()) as connection:
        row = connection.execute(
            "SELECT * FROM users WHERE lower(username) = lower(?)",
            (username,),
        ).fetchone()
    return row_to_user(row)


def list_users():
    with closing(get_connection()) as connection:
        rows = connection.execute(
            """
            SELECT id, name, username, birthdate, email, signup_path, created_at
            FROM users
            ORDER BY id DESC
            """
        ).fetchall()
    return [
        {
            "id": row["id"],
            "name": row["name"],
            "username": row["username"],
            "birthdate": row["birthdate"],
            "email": row["email"],
            "path": row["signup_path"],
            "created_at": row["created_at"],
        }
        for row in rows
    ]


def create_user_record(user):
    created_at = datetime.now(timezone.utc).isoformat()
    with closing(get_connection()) as connection:
        connection.execute(
            """
            INSERT INTO users (name, username, birthdate, email, signup_path, password_hash, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                user["name"],
                user["username"],
                user["birthdate"],
                user["email"],
                user["path"],
                user["password"],
                created_at,
            ),
        )
        connection.commit()


def delete_user_by_username(username):
    with closing(get_connection()) as connection:
        cursor = connection.execute(
            "DELETE FROM users WHERE lower(username) = lower(?)",
            (username,),
        )
        connection.commit()
    return cursor.rowcount > 0


def append_log(message):
    created_at = datetime.now(timezone.utc).astimezone().strftime("%Y-%m-%d %H:%M:%S %Z")
    with closing(get_connection()) as connection:
        connection.execute(
            "INSERT INTO activity_logs (message, created_at) VALUES (?, ?)",
            (message, created_at),
        )
        connection.commit()


def load_logs(limit=100):
    safe_limit = max(1, min(int(limit), 500))
    with closing(get_connection()) as connection:
        rows = connection.execute(
            """
            SELECT message, created_at
            FROM activity_logs
            ORDER BY id DESC
            LIMIT ?
            """,
            (safe_limit,),
        ).fetchall()
    return [f"[{row['created_at']}] {row['message']}" for row in rows]


def cleanup_old_auth_failures(window_seconds):
    cutoff = int(time.time()) - int(window_seconds)
    with closing(get_connection()) as connection:
        connection.execute(
            "DELETE FROM auth_failures WHERE created_at < ?",
            (cutoff,),
        )
        connection.commit()


def record_auth_failure(ip_address, username, reason):
    now = int(time.time())
    with closing(get_connection()) as connection:
        connection.execute(
            """
            INSERT INTO auth_failures (ip_address, username, reason, created_at)
            VALUES (?, ?, ?, ?)
            """,
            (ip_address, username or "", reason, now),
        )
        connection.commit()


def count_recent_auth_failures(ip_address, window_seconds):
    cleanup_old_auth_failures(window_seconds)
    cutoff = int(time.time()) - int(window_seconds)
    with closing(get_connection()) as connection:
        row = connection.execute(
            """
            SELECT COUNT(*) AS failure_count
            FROM auth_failures
            WHERE ip_address = ? AND created_at >= ?
            """,
            (ip_address, cutoff),
        ).fetchone()
    return int(row["failure_count"]) if row else 0


def count_recent_auth_failures_for_username(username, window_seconds):
    cleanup_old_auth_failures(window_seconds)
    normalized_username = (username or "").strip().lower()
    if not normalized_username:
        return 0
    cutoff = int(time.time()) - int(window_seconds)
    with closing(get_connection()) as connection:
        row = connection.execute(
            """
            SELECT COUNT(*) AS failure_count
            FROM auth_failures
            WHERE lower(username) = ? AND created_at >= ?
            """,
            (normalized_username, cutoff),
        ).fetchone()
    return int(row["failure_count"]) if row else 0


def clear_auth_failures(ip_address):
    with closing(get_connection()) as connection:
        connection.execute(
            "DELETE FROM auth_failures WHERE ip_address = ?",
            (ip_address,),
        )
        connection.commit()


def clear_auth_failures_for_username(username):
    normalized_username = (username or "").strip().lower()
    if not normalized_username:
        return
    with closing(get_connection()) as connection:
        connection.execute(
            "DELETE FROM auth_failures WHERE lower(username) = ?",
            (normalized_username,),
        )
        connection.commit()


def reset_database():
    with closing(get_connection()) as connection:
        connection.execute("DELETE FROM users")
        connection.execute("DELETE FROM activity_logs")
        connection.execute("DELETE FROM auth_failures")
        connection.commit()
