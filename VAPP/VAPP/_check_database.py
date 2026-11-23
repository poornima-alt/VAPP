import sqlite3

conn = sqlite3.connect("file:vapp.db?mode=ro", uri=True)

tables = [
    row[0] for row in conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
    )
]

print("Tables:", tables)
print("Users:", conn.execute("SELECT COUNT(*) FROM users").fetchone()[0])
print("Security events:", conn.execute("SELECT COUNT(*) FROM security_events").fetchone()[0])
print("Analysis results:", conn.execute("SELECT COUNT(*) FROM analysis_results").fetchone()[0])

exists = conn.execute(
    "SELECT 1 FROM sqlite_master WHERE type='table' AND name='gmail_oauth_tokens'"
).fetchone()

print("Gmail token table already exists:", bool(exists))
conn.close()
