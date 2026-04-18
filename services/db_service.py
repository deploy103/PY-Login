import sqlite3
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path


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


def reset_database():
    with closing(get_connection()) as connection:
        connection.execute("DELETE FROM users")
        connection.execute("DELETE FROM activity_logs")
        connection.commit()
