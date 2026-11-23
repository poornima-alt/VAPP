
import os
import tempfile
import unittest

TEMP_DIR = tempfile.TemporaryDirectory()
TEST_DB = os.path.join(TEMP_DIR.name, "gmail_isolation.db")
os.environ["VAPP_DATABASE_PATH"] = TEST_DB

from database import get_connection, initialize_database
from gmail_monitor import ensure_tables, already_processed, mark_processed


class GmailUserIsolationTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        initialize_database(TEST_DB)
        ensure_tables()

        connection = get_connection(TEST_DB)
        try:
            connection.execute(
                "INSERT INTO users (name, email, password_hash) VALUES (?, ?, ?)",
                ("User A", "gmail-a@test.local", "test-hash")
            )
            connection.execute(
                "INSERT INTO users (name, email, password_hash) VALUES (?, ?, ?)",
                ("User B", "gmail-b@test.local", "test-hash")
            )

            rows = connection.execute(
                "SELECT id, email FROM users WHERE email IN (?, ?)",
                ("gmail-a@test.local", "gmail-b@test.local")
            ).fetchall()

            cls.users = {
                row["email"]: row["id"] for row in rows
            }
            connection.commit()
        finally:
            connection.close()

    @classmethod
    def tearDownClass(cls):
        TEMP_DIR.cleanup()

    def test_same_message_id_is_isolated_per_user(self):
        user_a = self.users["gmail-a@test.local"]
        user_b = self.users["gmail-b@test.local"]
        message_id = "same-gmail-message-id"

        self.assertFalse(already_processed(message_id, user_a))
        self.assertFalse(already_processed(message_id, user_b))

        mark_processed(message_id, user_a)

        self.assertTrue(already_processed(message_id, user_a))
        self.assertFalse(already_processed(message_id, user_b))

        mark_processed(message_id, user_b)

        self.assertTrue(already_processed(message_id, user_a))
        self.assertTrue(already_processed(message_id, user_b))

        print("PASS: Same Gmail message ID can be tracked independently.")
        print("PASS: User A processing does not affect User B.")
        print("PASS: Both users can independently record the message.")


if __name__ == "__main__":
    unittest.main(verbosity=2)
