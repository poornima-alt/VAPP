import sqlite3

conn = sqlite3.connect("file:vapp.db?mode=ro", uri=True)

users = [row[1] for row in conn.execute("PRAGMA table_info(users)")]
tables = [row[0] for row in conn.execute(
    "SELECT name FROM sqlite_master WHERE type='table'"
)]

print("Registration code column:", "registration_code" in users)
print("Unique registration-code index:", bool(conn.execute(
    "SELECT 1 FROM sqlite_master WHERE type='index' AND name='idx_users_registration_code'"
).fetchone()))
print("Gmail token table:", "gmail_oauth_tokens" in tables)
print("User count:", conn.execute("SELECT COUNT(*) FROM users").fetchone()[0])
print("Security event count:", conn.execute("SELECT COUNT(*) FROM security_events").fetchone()[0])

conn.close()
