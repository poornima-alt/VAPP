
import os
import tempfile
import unittest
import hashlib
import uuid

TEMP_DIR = tempfile.TemporaryDirectory()
TEST_DB = os.path.join(TEMP_DIR.name, "sms_metadata_test.db")

# Configure the isolated database before importing Flask.
os.environ["VAPP_DATABASE_PATH"] = TEST_DB

from database import get_connection
import app as vapp


class SMSMetadataSyncTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        vapp.app.config["TESTING"] = True
        cls.client = vapp.app.test_client()

        cls.tokens = {
            "a": "METADATA-TEST-DEVICE-A",
            "b": "METADATA-TEST-DEVICE-B",
        }

        connection = get_connection(TEST_DB)
        try:
            for name, email in [
                ("Metadata User A", "metadata-a@test.local"),
                ("Metadata User B", "metadata-b@test.local"),
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
                ("metadata-a@test.local", "metadata-b@test.local")
            ).fetchall()

            cls.user_ids = {
                row["email"]: row["id"] for row in users
            }

            for key, email in [
                ("a", "metadata-a@test.local"),
                ("b", "metadata-b@test.local"),
            ]:
                token_hash = hashlib.sha256(
                    cls.tokens[key].encode("utf-8")
                ).hexdigest()

                connection.execute(
                    """
                    INSERT INTO user_devices
                    (user_id, device_name, token_hash)
                    VALUES (?, ?, ?)
                    """,
                    (cls.user_ids[email], f"Metadata Phone {key.upper()}", token_hash)
                )

            connection.commit()
        finally:
            connection.close()

    @classmethod
    def tearDownClass(cls):
        TEMP_DIR.cleanup()

    def payload(self, **overrides):
        data = {
            "local_event_id": str(uuid.uuid4()),
            "risk_score": 75,
            "risk_level": "HIGH RISK",
            "reasons": ["Sensitive information or credential request detected"],
            "detected_urls": ["example.com"],
            "sender_type": "Unknown sender format",
            "timestamp": 1760000000000,
        }
        data.update(overrides)
        return data

    def post_metadata(self, token, payload=None):
        return self.client.post(
            "/api/mobile/sms/metadata",
            json=payload if payload is not None else self.payload(),
            headers={"Authorization": f"Bearer {token}"}
        )

    def test_01_valid_metadata_upload(self):
        payload = self.payload()
        response = self.post_metadata(self.tokens["a"], payload)

        self.assertEqual(
            response.status_code, 201,
            msg=response.get_data(as_text=True)
        )

        result = response.get_json()
        self.assertTrue(result["success"])
        self.assertFalse(result["duplicate"])

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

            mapping = connection.execute(
                """
                SELECT * FROM sms_sync_events
                WHERE device_id = ? AND local_event_id = ?
                """,
                (
                    1,
                    payload["local_event_id"]
                )
            ).fetchone()
        finally:
            connection.close()

        self.assertIsNotNone(event)
        self.assertIsNotNone(analysis)
        self.assertIsNotNone(mapping)
        self.assertEqual(event["user_id"], self.user_ids["metadata-a@test.local"])
        self.assertEqual(event["protocol"], "SMS")
        self.assertNotIn("phone number", event["description"].lower())
        self.assertNotIn("original sms body", event["description"].lower())

        print("PASS: Metadata upload creates dashboard event and UUID mapping.")

    def test_02_duplicate_uuid_does_not_create_another_event(self):
        payload = self.payload()
        first = self.post_metadata(self.tokens["a"], payload)
        second = self.post_metadata(self.tokens["a"], payload)

        self.assertEqual(first.status_code, 201)
        self.assertEqual(second.status_code, 200)

        first_result = first.get_json()
        second_result = second.get_json()

        self.assertEqual(
            first_result["event_id"],
            second_result["event_id"]
        )
        self.assertTrue(second_result["duplicate"])

        connection = get_connection(TEST_DB)
        try:
            count = connection.execute(
                """
                SELECT COUNT(*) FROM sms_sync_events
                WHERE local_event_id = ?
                """,
                (payload["local_event_id"],)
            ).fetchone()[0]
        finally:
            connection.close()

        self.assertEqual(count, 1)
        print("PASS: Duplicate retry returns original event without duplication.")

    def test_03_missing_token_rejected(self):
        response = self.client.post(
            "/api/mobile/sms/metadata",
            json=self.payload()
        )
        self.assertEqual(response.status_code, 401)
        print("PASS: Missing device token rejected.")

    def test_04_invalid_token_rejected(self):
        response = self.post_metadata("INVALID-TOKEN")
        self.assertEqual(response.status_code, 401)
        print("PASS: Invalid device token rejected.")

    def test_05_invalid_json_rejected(self):
        response = self.client.post(
            "/api/mobile/sms/metadata",
            data="not-json",
            content_type="application/json",
            headers={"Authorization": f"Bearer {self.tokens['a']}"}
        )
        self.assertEqual(response.status_code, 400)
        print("PASS: Invalid JSON rejected.")

    def test_06_invalid_uuid_rejected(self):
        response = self.post_metadata(
            self.tokens["a"],
            self.payload(local_event_id="not-a-uuid")
        )
        self.assertEqual(response.status_code, 400)
        print("PASS: Invalid event UUID rejected.")

    def test_07_invalid_risk_score_rejected(self):
        for score in [-1, 101, True, "75"]:
            response = self.post_metadata(
                self.tokens["a"],
                self.payload(risk_score=score)
            )
            self.assertEqual(response.status_code, 400)

        print("PASS: Invalid risk scores rejected.")

    def test_08_mismatched_risk_level_rejected(self):
        response = self.post_metadata(
            self.tokens["a"],
            self.payload(risk_score=75, risk_level="LOW RISK")
        )
        self.assertEqual(response.status_code, 400)
        print("PASS: Inconsistent risk score and level rejected.")

    def test_09_invalid_domain_rejected(self):
        response = self.post_metadata(
            self.tokens["a"],
            self.payload(detected_urls=["https://example.com/path"])
        )
        self.assertEqual(response.status_code, 400)
        print("PASS: Full URLs rejected; domain-only metadata required.")

    def test_10_user_b_event_belongs_to_user_b(self):
        payload = self.payload()
        response = self.post_metadata(self.tokens["b"], payload)

        self.assertEqual(
            response.status_code, 201,
            msg=response.get_data(as_text=True)
        )

        connection = get_connection(TEST_DB)
        try:
            event = connection.execute(
                "SELECT user_id FROM security_events WHERE id = ?",
                (response.get_json()["event_id"],)
            ).fetchone()
        finally:
            connection.close()

        self.assertEqual(event["user_id"], self.user_ids["metadata-b@test.local"])
        print("PASS: User B metadata belongs to User B.")

    def test_11_user_a_cannot_access_user_b_events(self):
        with self.client.session_transaction() as session:
            session["user_id"] = self.user_ids["metadata-a@test.local"]
            session["user_name"] = "Metadata User A"

        response = self.client.get("/api/events")
        self.assertEqual(response.status_code, 200)

        events = response.get_json()["events"]
        self.assertTrue(
            all(
                event["user_id"] == self.user_ids["metadata-a@test.local"]
                for event in events
            )
        )
        self.assertFalse(
            any(
                event["user_id"] == self.user_ids["metadata-b@test.local"]
                for event in events
            )
        )

        print("PASS: User A cannot access User B metadata events.")

    def test_12_database_is_isolated(self):
        self.assertNotEqual(
            os.path.abspath(TEST_DB),
            os.path.abspath("vapp.db")
        )
        print("PASS: Metadata tests use an isolated temporary database.")


if __name__ == "__main__":
    print("\n========== VAPP SMS METADATA SYNC TESTS ==========\n")
    unittest.main(verbosity=2)
