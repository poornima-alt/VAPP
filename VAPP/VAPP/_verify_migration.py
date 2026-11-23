import sqlite3

conn = sqlite3.connect("file:vapp.db?mode=ro", uri=True)

tables = [
    row[0] for row in conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
    )
]

print("Tables:", tables)
print("Gmail token table:", "gmail_oauth_tokens" in tables)
print("Users:", conn.execute("SELECT COUNT(*) FROM users").fetchone()[0])
print("Events:", conn.execute("SELECT COUNT(*) FROM security_events").fetchone()[0])

conn.close()
