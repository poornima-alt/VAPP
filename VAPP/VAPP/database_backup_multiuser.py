
import os
import sqlite3
from werkzeug.security import generate_password_hash

DATABASE = os.environ.get("VAPP_DATABASE_PATH", "vapp.db")


def get_connection(database_path=None):
    path = database_path or DATABASE
    connection = sqlite3.connect(path)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def initialize_database(database_path=None):
    connection = get_connection(database_path)

    try:
        cursor = connection.cursor()

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS security_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                source_ip TEXT,
                destination_ip TEXT,
                protocol TEXT,
                port INTEGER,
                event_type TEXT,
                description TEXT,
                severity TEXT,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS analysis_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_id INTEGER,
                threat_type TEXT,
                confidence REAL,
                risk_score REAL,
                risk_level TEXT,
                explanation TEXT,
                recommendation TEXT,
                analysed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (event_id) REFERENCES security_events(id)
            )
        """)

        connection.commit()

    finally:
        connection.close()


def create_demo_user(database_path=None):
    connection = get_connection(database_path)

    try:
        cursor = connection.cursor()

        existing_user = cursor.execute(
            "SELECT id FROM users WHERE email = ?",
            ("demo@vapp.local",)
        ).fetchone()

        if not existing_user:
            password_hash = generate_password_hash("VAPP@123")

            cursor.execute("""
                INSERT INTO users (name, email, password_hash)
                VALUES (?, ?, ?)
            """, (
                "VAPP Demo User",
                "demo@vapp.local",
                password_hash
            ))

            connection.commit()

    finally:
        connection.close()


if __name__ == "__main__":
    initialize_database()
    create_demo_user()
    print("VAPP database initialized successfully.")
