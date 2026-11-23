import os
import sqlite3
import tempfile
from pathlib import Path

with tempfile.TemporaryDirectory() as temp:
    db_path = str(Path(temp) / "registration_test.db")
    os.environ["VAPP_DATABASE_PATH"] = db_path

    import database
    database.initialize_database()

    conn = sqlite3.connect(db_path)
    columns = [row[1] for row in conn.execute("PRAGMA table_info(users)")]

    print("Users table columns:", columns)
    print("Registration code column exists:", "registration_code" in columns)

    indexes = conn.execute("PRAGMA index_list(users)").fetchall()
    print("User table indexes:", indexes)

    print("Gmail token table exists:", bool(conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='gmail_oauth_tokens'"
    ).fetchone()))

    conn.close()
