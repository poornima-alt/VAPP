
import os
import tempfile
import unittest

TEMP_DIR = tempfile.TemporaryDirectory()
TEST_DB = os.path.join(TEMP_DIR.name, "mobile_sms_test.db")

# Set before importing the application.
os.environ["VAPP_DATABASE_PATH"] = TEST_DB

from database import get_connection
import app as vapp


class MobileSMSAPITests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        vapp.app.config["TESTING"] = True
        cls.client = vapp.app.test_client()
        cls.test_token = "VAPP-TEST-DEVICE-TOKEN-123"
        os.environ["VAPP_SMS_DEVICE_TOKEN"] = cls.test_token

        # Create the exact account expected by the mobile API,
        # but only in the temporary test database.
        connection = get_connection(TEST_DB)
        try:
            connection.execute(
                """
                INSERT OR IGNORE INTO users
                (name, email, password_hash)
                VALUES (?, ?, ?)
                """,
                (
                    "VAPP Mobile Test User",
                    "avaishnavi239@gmail.com",
                    "temporary-test-password-hash"
                )
            )
            connection.commit()
        finally:
            connection.close()

    @classmethod
    def tearDownClass(cls):
        os.environ.pop("VAPP_SMS_DEVICE_TOKEN", None)
        TEMP_DIR.cleanup()

    def test_01_missing_server_token(self):
        os.environ.pop("VAPP_SMS_DEVICE_TOKEN", None)

        response = self.client.post(
            "/api/mobile/sms",
            json={"sender": "TEST", "message": "Test message"}
        )
        self.assertEqual(response.status_code, 503)
        print("PASS: Missing server token rejected (503).")

        os.environ["VAPP_SMS_DEVICE_TOKEN"] = self.test_token

    def test_02_invalid_device_token(self):
        response = self.client.post(
            "/api/mobile/sms",
            json={"sender": "TEST", "message": "Test message"},
            headers={"Authorization": "Bearer WRONG-TOKEN"}
        )
        self.assertEqual(response.status_code, 401)
        print("PASS: Invalid device token rejected (401).")

    def test_03_missing_authorization(self):
        response = self.client.post(
            "/api/mobile/sms",
            json={"sender": "TEST", "message": "Test message"}
        )
        self.assertEqual(response.status_code, 401)
        print("PASS: Missing authorization rejected (401).")

    def test_04_invalid_json(self):
        response = self.client.post(
            "/api/mobile/sms",
            data="not-json",
            content_type="application/json",
            headers={"Authorization": f"Bearer {self.test_token}"}
        )
        self.assertEqual(response.status_code, 400)
        print("PASS: Invalid JSON rejected (400).")

    def test_05_empty_message(self):
        response = self.client.post(
            "/api/mobile/sms",
            json={"sender": "TEST", "message": "   "},
            headers={"Authorization": f"Bearer {self.test_token}"}
        )
        self.assertEqual(response.status_code, 400)
        print("PASS: Empty SMS rejected (400).")

    def test_06_message_too_long(self):
        response = self.client.post(
            "/api/mobile/sms",
            json={"sender": "TEST", "message": "A" * 4001},
            headers={"Authorization": f"Bearer {self.test_token}"}
        )
        self.assertEqual(response.status_code, 413)
        print("PASS: Oversized SMS rejected (413).")

    def test_07_successful_sms_and_database_save(self):
        response = self.client.post(
            "/api/mobile/sms",
            json={
                "sender": "VAPP-TEST-SENDER",
                "message": "Your appointment is confirmed for tomorrow."
            },
            headers={"Authorization": f"Bearer {self.test_token}"}
        )

        self.assertEqual(
            response.status_code, 200,
            msg=f"Expected 200, received {response.status_code}: {response.get_data(as_text=True)}"
        )

        result = response.get_json()
        self.assertTrue(result["success"])
        self.assertIn("event_id", result)

        connection = get_connection(TEST_DB)
        try:
            event = connection.execute(
                "SELECT * FROM security_events WHERE id = ?",
                (result["event_id"],)
            ).fetchone()

            analysis = connection.execute(
                "SELECT * FROM analysis_results WHERE event_id = ?",
                (result["event_id"],)
            ).fetchone()
        finally:
            connection.close()

        self.assertIsNotNone(event)
        self.assertIsNotNone(analysis)
        self.assertEqual(event["protocol"], "SMS")
        self.assertEqual(event["event_type"], "Incoming SMS (Android)")
        print("PASS: SMS analyzed and saved to both database tables.")

    def test_08_no_original_database_used(self):
        self.assertNotEqual(
            os.path.abspath(TEST_DB),
            os.path.abspath("vapp.db")
        )
        print("PASS: Verification uses a separate temporary database.")


if __name__ == "__main__":
    try:
        print("\n========== VAPP MOBILE SMS API VERIFICATION ==========\n")
        unittest.main(verbosity=2)
    finally:
        TEMP_DIR.cleanup()
