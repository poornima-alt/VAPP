
import os
import tempfile
import unittest
import hashlib

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
        cls.client_a = vapp.app.test_client()
        cls.client_b = vapp.app.test_client()

        cls.token_a = "VAPP-TEST-DEVICE-TOKEN-A"
        cls.token_b = "VAPP-TEST-DEVICE-TOKEN-B"

        connection = get_connection(TEST_DB)
        try:
            for name, email in [
                ("Test User A", "user-a@test.local"),
                ("Test User B", "user-b@test.local"),
            ]:
                connection.execute(
                    """
                    INSERT INTO users (name, email, password_hash)
                    VALUES (?, ?, ?)
                    """,
                    (name, email, "test-password-hash")
                )

            users = connection.execute(
                "SELECT id, email FROM users WHERE email IN (?, ?)",
                ("user-a@test.local", "user-b@test.local")
            ).fetchall()

            cls.user_ids = {
                row["email"]: row["id"] for row in users
            }

            for user_email, device_name, token in [
                ("user-a@test.local", "Test Phone A", cls.token_a),
                ("user-b@test.local", "Test Phone B", cls.token_b),
            ]:
                token_hash = hashlib.sha256(
                    token.encode("utf-8")
                ).hexdigest()

                connection.execute(
                    """
                    INSERT INTO user_devices
                    (user_id, device_name, token_hash)
                    VALUES (?, ?, ?)
                    """,
                    (
                        cls.user_ids[user_email],
                        device_name,
                        token_hash
                    )
                )

            connection.commit()
        finally:
            connection.close()

    @classmethod
    def tearDownClass(cls):
        TEMP_DIR.cleanup()

    def post_sms(self, token, message="Your appointment is confirmed.",
                 sender="TEST-SENDER"):
        return self.client_a.post(
            "/api/mobile/sms",
            json={"sender": sender, "message": message},
            headers={"Authorization": f"Bearer {token}"}
        )

    def test_01_missing_token(self):
        response = self.client_a.post(
            "/api/mobile/sms",
            json={"sender": "TEST", "message": "Test message"}
        )
        self.assertEqual(response.status_code, 401)
        print("PASS: Missing device token rejected.")

    def test_02_invalid_token(self):
        response = self.post_sms("WRONG-TOKEN")
        self.assertEqual(response.status_code, 401)
        print("PASS: Invalid device token rejected.")

    def test_03_invalid_json(self):
        response = self.client_a.post(
            "/api/mobile/sms",
            data="not-json",
            content_type="application/json",
            headers={"Authorization": f"Bearer {self.token_a}"}
        )
        self.assertEqual(response.status_code, 400)
        print("PASS: Invalid JSON rejected.")

    def test_04_empty_message(self):
        response = self.post_sms(self.token_a, message="   ")
        self.assertEqual(response.status_code, 400)
        print("PASS: Empty SMS rejected.")

    def test_05_message_too_long(self):
        response = self.post_sms(self.token_a, message="A" * 4001)
        self.assertEqual(response.status_code, 413)
        print("PASS: Oversized SMS rejected.")

    def test_06_user_a_sms_saved_to_user_a(self):
        response = self.post_sms(
            self.token_a,
            message="Test message for user A"
        )
        self.assertEqual(
            response.status_code, 200,
            msg=response.get_data(as_text=True)
        )

        event_id = response.get_json()["event_id"]

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
        finally:
            connection.close()

        self.assertIsNotNone(event)
        self.assertIsNotNone(analysis)
        self.assertEqual(
            event["user_id"],
            self.user_ids["user-a@test.local"]
        )
        self.assertEqual(event["protocol"], "SMS")
        print("PASS: User A's SMS is saved under User A.")

    def test_07_user_b_sms_saved_to_user_b(self):
        response = self.post_sms(
            self.token_b,
            message="Test message for user B"
        )
        self.assertEqual(
            response.status_code, 200,
            msg=response.get_data(as_text=True)
        )

        event_id = response.get_json()["event_id"]

        connection = get_connection(TEST_DB)
        try:
            event = connection.execute(
                "SELECT * FROM security_events WHERE id = ?",
                (event_id,)
            ).fetchone()
        finally:
            connection.close()

        self.assertIsNotNone(event)
        self.assertEqual(
            event["user_id"],
            self.user_ids["user-b@test.local"]
        )
        print("PASS: User B's SMS is saved under User B.")

    def test_08_user_a_cannot_see_user_b_events(self):
        # Log in through the Flask session for User A.
        with self.client_a.session_transaction() as session:
            session["user_id"] = self.user_ids["user-a@test.local"]
            session["user_name"] = "Test User A"

        response = self.client_a.get("/api/events")
        self.assertEqual(response.status_code, 200)

        events = response.get_json()["events"]
        self.assertTrue(
            all(
                event["user_id"] == self.user_ids["user-a@test.local"]
                for event in events
            )
        )

        self.assertFalse(
            any(
                event["user_id"] == self.user_ids["user-b@test.local"]
                for event in events
            )
        )
        print("PASS: User A cannot retrieve User B's events.")

    def test_09_user_b_cannot_see_user_a_events(self):
        with self.client_b.session_transaction() as session:
            session["user_id"] = self.user_ids["user-b@test.local"]
            session["user_name"] = "Test User B"

        response = self.client_b.get("/api/events")
        self.assertEqual(response.status_code, 200)

        events = response.get_json()["events"]

        self.assertTrue(
            all(
                event["user_id"] == self.user_ids["user-b@test.local"]
                for event in events
            )
        )

        self.assertFalse(
            any(
                event["user_id"] == self.user_ids["user-a@test.local"]
                for event in events
            )
        )
        print("PASS: User B cannot retrieve User A's events.")
    
    def test_10_user_a_dashboard_access(self):
        with self.client_a.session_transaction() as session:
            session["user_id"] = self.user_ids["user-a@test.local"]
            session["user_name"] = "Test User A"

        response = self.client_a.get("/dashboard")
        self.assertEqual(response.status_code, 200)
        print("PASS: User A can access their dashboard.")

    def test_11_user_b_dashboard_access(self):
        with self.client_b.session_transaction() as session:
            session["user_id"] = self.user_ids["user-b@test.local"]
            session["user_name"] = "Test User B"

        response = self.client_b.get("/dashboard")
        self.assertEqual(response.status_code, 200)
        print("PASS: User B can access their dashboard.")

    def test_12_user_a_all_events_isolated(self):
        with self.client_a.session_transaction() as session:
            session["user_id"] = self.user_ids["user-a@test.local"]
            session["user_name"] = "Test User A"

        response = self.client_a.get("/api/all-events")
        self.assertEqual(response.status_code, 200)

        events = response.get_json()["events"]
        self.assertTrue(
            all(
                event["user_id"] == self.user_ids["user-a@test.local"]
                for event in events
            )
        )
        print("PASS: User A's all-events API is isolated.")

    def test_13_user_b_all_events_isolated(self):
        with self.client_b.session_transaction() as session:
            session["user_id"] = self.user_ids["user-b@test.local"]
            session["user_name"] = "Test User B"

        response = self.client_b.get("/api/all-events")
        self.assertEqual(response.status_code, 200)

        events = response.get_json()["events"]
        self.assertTrue(
            all(
                event["user_id"] == self.user_ids["user-b@test.local"]
                for event in events
            )
        )
        print("PASS: User B's all-events API is isolated.")
    
    def test_14_unauthorized_dashboard_rejected(self):
        with self.client_a.session_transaction() as session:
            session.clear()

        response = self.client_a.get("/dashboard")
        self.assertEqual(response.status_code, 302)
        print("PASS: Unauthenticated dashboard access rejected.")

    def test_15_unauthorized_all_events_rejected(self):
        with self.client_a.session_transaction() as session:
            session.clear()

        response = self.client_a.get("/api/all-events")
        self.assertEqual(response.status_code, 401)
        print("PASS: Unauthenticated all-events access rejected.")

    def test_16_cross_user_forensic_report_rejected(self):
        with self.client_a.session_transaction() as session:
            session["user_id"] = self.user_ids["user-a@test.local"]
            session["user_name"] = "Test User A"

        connection = get_connection(TEST_DB)
        try:
            event = connection.execute(
                "SELECT id FROM security_events WHERE user_id = ? LIMIT 1",
                (self.user_ids["user-b@test.local"],)
            ).fetchone()
        finally:
            connection.close()

        self.assertIsNotNone(
            event,
            "User B needs an event before testing report isolation."
        )

        response = self.client_a.get(
            f"/report/forensic/{event['id']}"
        )
        self.assertEqual(response.status_code, 404)
        print("PASS: User A cannot access User B's forensic report.")

        connection = get_connection(TEST_DB)
        try:
            event = connection.execute(
                "SELECT id FROM security_events WHERE user_id = ? LIMIT 1",
                (self.user_ids["user-b@test.local"],)
            ).fetchone()
        finally:
            connection.close()

        self.assertIsNotNone(
            event,
            "User B needs an event before testing report isolation."
        )

        response = self.client_a.get(
            f"/report/forensic/{event['id']}"
        )
        self.assertEqual(response.status_code, 404)
        print("PASS: User A cannot access User B's forensic report.")

    def test_10_revoked_device_rejected(self):
        token_hash = hashlib.sha256(
            self.token_a.encode("utf-8")
        ).hexdigest()

        connection = get_connection(TEST_DB)
        try:
            connection.execute(
                "UPDATE user_devices SET is_active = 0 WHERE token_hash = ?",
                (token_hash,)
            )
            connection.commit()
        finally:
            connection.close()

        response = self.post_sms(self.token_a)
        self.assertEqual(response.status_code, 401)
        print("PASS: Revoked device token rejected.")

    def test_11_database_is_isolated(self):
        self.assertNotEqual(
            os.path.abspath(TEST_DB),
            os.path.abspath("vapp.db")
        )
        print("PASS: Tests use a separate temporary database.")


if __name__ == "__main__":
    try:
        print("\n========== VAPP MULTI-USER SMS VERIFICATION ==========\n")
        unittest.main(verbosity=2)
    finally:
        TEMP_DIR.cleanup()
