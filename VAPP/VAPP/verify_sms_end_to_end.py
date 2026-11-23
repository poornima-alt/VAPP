
import os
import tempfile
import hashlib
import unittest

TEMP_DIR = tempfile.TemporaryDirectory()
TEST_DB = os.path.join(TEMP_DIR.name, "sms_e2e_test.db")
os.environ["VAPP_DATABASE_PATH"] = TEST_DB

from database import get_connection
import app as vapp


class SMSEndToEndTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        vapp.app.config["TESTING"] = True
        cls.client_a = vapp.app.test_client()
        cls.client_b = vapp.app.test_client()

        cls.token = "VAPP-E2E-TEST-DEVICE-TOKEN"

        connection = get_connection(TEST_DB)
        try:
            connection.execute(
                """
                INSERT INTO users (name, email, password_hash)
                VALUES (?, ?, ?)
                """,
                ("E2E Test User", "e2e@test.local", "test-hash")
            )
            cls.user_id = connection.execute(
                "SELECT id FROM users WHERE email = ?",
                ("e2e@test.local",)
            ).fetchone()["id"]

            token_hash = hashlib.sha256(
                cls.token.encode("utf-8")
            ).hexdigest()

            connection.execute(
                """
                INSERT INTO user_devices
                (user_id, device_name, token_hash)
                VALUES (?, ?, ?)
                """,
                (cls.user_id, "E2E Test Phone", token_hash)
            )

            connection.commit()
        finally:
            connection.close()

    @classmethod
    def tearDownClass(cls):
        TEMP_DIR.cleanup()

    def test_sms_complete_workflow(self):
        message = (
            "Your bank account is suspended. "
            "Share your OTP immediately to restore access."
        )

        response = self.client_a.post(
            "/api/mobile/sms",
            json={
                "sender": "BANK-ALERT",
                "message": message
            },
            headers={
                "Authorization": f"Bearer {self.token}"
            }
        )

        self.assertEqual(
            response.status_code, 200,
            response.get_data(as_text=True)
        )

        result = response.get_json()
        self.assertTrue(result["success"])
        self.assertIn("event_id", result)
        self.assertIn("risk_level", result)
        self.assertIn("risk_score", result)
        self.assertIn("threat_type", result)

        event_id = result["event_id"]

        connection = get_connection(TEST_DB)
        try:
            event = connection.execute(
                "SELECT * FROM security_events WHERE id = ?",
                (event_id,)
            ).fetchone()

            analysis = connection.execute(
                "SELECT * FROM analysis_results WHERE event_id = ?",
                (event_id,)
            ).fetchone()

            device = connection.execute(
                "SELECT * FROM user_devices WHERE user_id = ?",
                (self.user_id,)
            ).fetchone()
        finally:
            connection.close()

        self.assertIsNotNone(event)
        self.assertIsNotNone(analysis)
        self.assertIsNotNone(device)

        self.assertEqual(event["user_id"], self.user_id)
        self.assertEqual(event["protocol"], "SMS")
        self.assertEqual(event["event_type"], "Incoming SMS (Android)")

        self.assertEqual(
            analysis["risk_level"], result["risk_level"]
        )
        self.assertEqual(
            analysis["risk_score"], result["risk_score"]
        )
        self.assertTrue(analysis["threat_type"])
        self.assertTrue(analysis["explanation"])
        self.assertTrue(analysis["recommendation"])

        self.assertIsNotNone(device["last_seen"])

        print("PASS: SMS accepted and analyzed.")
        print("PASS: Security event saved.")
        print("PASS: Analysis result saved.")
        print("PASS: Event linked to the correct user.")
        print("PASS: Paired device activity updated.")

        with self.client_a.session_transaction() as session:
            session["user_id"] = self.user_id
            session["user_name"] = "E2E Test User"

        dashboard_response = self.client_a.get("/api/all-events")
        self.assertEqual(dashboard_response.status_code, 200)

        saved_events = dashboard_response.get_json()["events"]
        self.assertTrue(
            any(item["id"] == event_id for item in saved_events)
        )

        print("PASS: SMS event appears in the owner's events API.")

        with self.client_b.session_transaction() as session:
            session["user_id"] = self.user_id + 99999
            session["user_name"] = "Different User"

        other_response = self.client_b.get("/api/all-events")
        self.assertEqual(other_response.status_code, 200)

        other_events = other_response.get_json()["events"]
        self.assertFalse(
            any(item["id"] == event_id for item in other_events)
        )

        print("PASS: Event is not exposed to another user.")

        print("\nSMS END-TO-END WORKFLOW VERIFIED.")


if __name__ == "__main__":
    try:
        unittest.main(verbosity=2)
    finally:
        TEMP_DIR.cleanup()
