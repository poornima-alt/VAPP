import os
import sqlite3
import secrets
import string
from werkzeug.security import generate_password_hash

DATABASE = os.environ.get("VAPP_DATABASE_PATH", "vapp.db")

REGISTRATION_CODE_CHARS = string.ascii_letters + string.digits + "!@#$%&*+-_=?."

def generate_registration_code(length=None):
    """Generate a random, variable-length account reference (not a password)."""
    length = length or secrets.choice(range(14, 19))
    return "".join(secrets.choice(REGISTRATION_CODE_CHARS) for _ in range(length))


def get_connection(database_path=None):
    path = database_path or DATABASE
    connection = sqlite3.connect(path, timeout=30)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA busy_timeout = 30000")
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
                registration_code TEXT,
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
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS user_integrations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                provider TEXT NOT NULL,
                external_account TEXT,
                status TEXT NOT NULL DEFAULT 'disconnected',
                credential_ref TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(user_id, provider),
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS user_devices (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                device_name TEXT NOT NULL,
                token_hash TEXT NOT NULL UNIQUE,
                is_active INTEGER NOT NULL DEFAULT 1,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_seen TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS gmail_oauth_tokens (
                user_id INTEGER PRIMARY KEY,
                gmail_email TEXT NOT NULL,
                encrypted_credentials TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS sms_sync_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                device_id INTEGER NOT NULL,
                local_event_id TEXT NOT NULL,
                security_event_id INTEGER NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(device_id, local_event_id),
                FOREIGN KEY (device_id) REFERENCES user_devices(id)
                    ON DELETE CASCADE,
                FOREIGN KEY (security_event_id) REFERENCES security_events(id)
                    ON DELETE CASCADE
            )
        """)

    
        # Add the registration-code column to existing databases without losing users.
        user_columns = {row[1] for row in cursor.execute("PRAGMA table_info(users)").fetchall()}
        if "registration_code" not in user_columns:
            cursor.execute("ALTER TABLE users ADD COLUMN registration_code TEXT")
                # Add sender identifier for privacy-preserving Android SMS records.
        security_columns = {
            row[1] for row in cursor.execute(
                "PRAGMA table_info(security_events)"
            ).fetchall()
        }

        if "sender_identifier" not in security_columns:
            cursor.execute(
                "ALTER TABLE security_events ADD COLUMN sender_identifier TEXT"
            )
        # Backfill legacy users, then enforce uniqueness for all future registrations.
        existing_codes = {
            row[0] for row in cursor.execute(
                "SELECT registration_code FROM users WHERE registration_code IS NOT NULL"
            ).fetchall()
        }
        legacy_users = cursor.execute(
            "SELECT id FROM users WHERE registration_code IS NULL OR registration_code = ''"
        ).fetchall()
        for legacy_user in legacy_users:
            while True:
                code = generate_registration_code()
                if code not in existing_codes:
                    break
            cursor.execute(
                "UPDATE users SET registration_code = ? WHERE id = ?",
                (code, legacy_user[0])
            )
            existing_codes.add(code)
        cursor.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_users_registration_code "
            "ON users(registration_code)"
        )

        cursor.execute("CREATE INDEX IF NOT EXISTS idx_user_devices_user ON user_devices(user_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_gmail_tokens_email ON gmail_oauth_tokens(gmail_email)")
        connection.commit()
    finally:
        connection.close()


def create_demo_user(database_path=None):
    connection = get_connection(database_path)
    try:
        existing_user = connection.execute(
            "SELECT id FROM users WHERE email = ?", ("demo@vapp.local",)
        ).fetchone()
        if not existing_user:
            connection.execute(
                "INSERT INTO users (name, email, password_hash, registration_code) VALUES (?, ?, ?, ?)",
                ("VAPP Demo User", "demo@vapp.local", generate_password_hash("VAPP@123"), generate_registration_code())
            )
            connection.commit()
    finally:
        connection.close()


if __name__ == "__main__":
    initialize_database()
    create_demo_user()
    print("VAPP database initialized successfully.")
