import sqlite3
from pathlib import Path
from datetime import datetime


DB_FILE = Path(__file__).resolve().with_name(
    "security_analyzer.db"
)


def get_connection():
    """Create a connection to the SQLite database."""
    connection = sqlite3.connect(DB_FILE)
    connection.row_factory = sqlite3.Row
    return connection


def init_db():
    """Initialize database tables without deleting existing history."""

    with get_connection() as connection:

        connection.execute("""
            CREATE TABLE IF NOT EXISTS analysis_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                filename TEXT NOT NULL,
                analyzed_at TEXT NOT NULL,
                total_entries INTEGER NOT NULL,
                successful_logins INTEGER NOT NULL,
                failed_logins INTEGER NOT NULL,
                alert_count INTEGER NOT NULL
            )
        """)

        connection.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                full_name TEXT NOT NULL,
                email TEXT NOT NULL UNIQUE COLLATE NOCASE,
                username TEXT NOT NULL UNIQUE COLLATE NOCASE,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
        """)

        columns = connection.execute(
            "PRAGMA table_info(analysis_history)"
        ).fetchall()

        column_names = [column["name"] for column in columns]

        if "user_id" not in column_names:
            connection.execute("""
                ALTER TABLE analysis_history
                ADD COLUMN user_id INTEGER REFERENCES users(id)
            """)


def save_analysis(filename, report, user_id=None):
    """Save an analysis report."""

    analyzed_at = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    with get_connection() as connection:
        connection.execute("""
            INSERT INTO analysis_history (
                filename,
                analyzed_at,
                total_entries,
                successful_logins,
                failed_logins,
                alert_count,
                user_id
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            filename,
            analyzed_at,
            report["total_entries"],
            report["successful_logins"],
            report["failed_logins"],
            len(report["alerts"]),
            user_id
        ))


def get_history(user_id=None):
    """Get recent analysis history."""

    with get_connection() as connection:

        if user_id is None:
            rows = connection.execute("""
                SELECT *
                FROM analysis_history
                ORDER BY id DESC
                LIMIT 100
            """).fetchall()

        else:
            rows = connection.execute("""
                SELECT *
                FROM analysis_history
                WHERE user_id = ?
                ORDER BY id DESC
                LIMIT 100
            """, (user_id,)).fetchall()

        return [dict(row) for row in rows]

