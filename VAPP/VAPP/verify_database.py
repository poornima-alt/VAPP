
import os
import tempfile
import database

db_path = os.path.join(
    tempfile.gettempdir(),
    "vapp_db_check.sqlite"
)

database.initialize_database(db_path)

database.create_demo_user(db_path)
database.create_demo_user(db_path)

connection = database.get_connection(db_path)

tables = connection.execute(
    "SELECT name FROM sqlite_master WHERE type='table'"
).fetchall()

user_count = connection.execute(
    "SELECT COUNT(*) FROM users"
).fetchone()[0]

foreign_keys = connection.execute(
    "PRAGMA foreign_keys"
).fetchone()[0]

print("Tables:", [row["name"] for row in tables])
print("Demo users:", user_count)
print("Foreign keys:", foreign_keys)

connection.close()
