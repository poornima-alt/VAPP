
import os
import tempfile

os.environ["VAPP_DATABASE_PATH"] = os.path.join(
    tempfile.gettempdir(),
    "vapp_test_database.sqlite"
)

import database

database.initialize_database()
database.create_demo_user()

connection = database.get_connection()

tables = connection.execute(
    "SELECT name FROM sqlite_master WHERE type='table'"
).fetchall()

users = connection.execute(
    "SELECT COUNT(*) FROM users"
).fetchone()[0]

print("Tables:", [row["name"] for row in tables])
print("Demo users:", users)

connection.close()
print("Database initialization test: PASSED")
