
import os
import tempfile
import unittest

TEMP_DIR = tempfile.TemporaryDirectory()
TEST_DB = os.path.join(TEMP_DIR.name, "auth_test.db")

os.environ["VAPP_DATABASE_PATH"] = TEST_DB

from database import get_connection
import app as vapp


class AuthenticationTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        vapp.app.config["TESTING"] = True
        cls.client = vapp.app.test_client()

    def test_01_registration(self):
        response = self.client.post(
            "/signup",
            data={
                "name": "Test User",
                "email": "auth-test@example.com",
                "password": "TestPassword123!",
                "confirm_password": "TestPassword123!"
            }
        )

        self.assertEqual(response.status_code, 200)

        connection = get_connection(TEST_DB)
        user = connection.execute(
            "SELECT * FROM users WHERE email = ?",
            ("auth-test@example.com",)
        ).fetchone()
        connection.close()

        self.assertIsNotNone(user)
        self.assertNotEqual(
            user["password_hash"],
            "TestPassword123!"
        )
        print("PASS: Registration and password hashing.")

    def test_02_login(self):
        response = self.client.post(
            "/login",
            data={
                "email": "auth-test@example.com",
                "password": "TestPassword123!"
            }
        )

        self.assertEqual(response.status_code, 302)

        with self.client.session_transaction() as session:
            self.assertIn("user_id", session)
            self.assertEqual(session["user_name"], "Test User")

        print("PASS: Login and session creation.")

    def test_03_invalid_login(self):
        response = self.client.post(
            "/login",
            data={
                "email": "auth-test@example.com",
                "password": "WrongPassword123!"
            }
        )

        self.assertEqual(response.status_code, 200)

        print("PASS: Incorrect password rejected.")

    def test_04_logout(self):
        response = self.client.get("/logout")

        self.assertEqual(response.status_code, 302)

        with self.client.session_transaction() as session:
            self.assertNotIn("user_id", session)

        print("PASS: Logout clears session.")

    def test_05_duplicate_registration(self):
        response = self.client.post(
            "/signup",
            data={
                "name": "Another User",
                "email": "auth-test@example.com",
                "password": "AnotherPassword123!",
                "confirm_password": "AnotherPassword123!"
            }
        )

        self.assertEqual(response.status_code, 409)

        connection = get_connection(TEST_DB)
        count = connection.execute(
            "SELECT COUNT(*) FROM users WHERE email = ?",
            ("auth-test@example.com",)
        ).fetchone()[0]
        connection.close()

        self.assertEqual(count, 1)
        print("PASS: Duplicate registration rejected.")


if __name__ == "__main__":
    print("\n========== VAPP AUTHENTICATION VERIFICATION ==========\n")
    unittest.main(verbosity=2)
