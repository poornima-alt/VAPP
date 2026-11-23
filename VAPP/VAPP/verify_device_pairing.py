
import os
import tempfile
import unittest
import hashlib

TEMP_DIR = tempfile.TemporaryDirectory()
TEST_DB = os.path.join(TEMP_DIR.name, "pairing_test.db")
os.environ["VAPP_DATABASE_PATH"] = TEST_DB

from database import get_connection
import app as vapp


class DevicePairingTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        vapp.app.config["TESTING"] = True
        cls.client_a = vapp.app.test_client()
        cls.client_b = vapp.app.test_client()

        connection = get_connection(TEST_DB)
        try:
            for name, email in [
                ("Pair User A", "pair-a@test.local"),
                ("Pair User B", "pair-b@test.local")
            ]:
                connection.execute(
                    """INSERT INTO users (name, email, password_hash)
                       VALUES (?, ?, ?)""",
                    (name, email, "test-hash")
                )
            connection.commit()

            users = connection.execute(
                "SELECT id, email FROM users"
            ).fetchall()

            cls.user_ids = {
                row["email"]: row["id"] for row in users
            }
        finally:
            connection.close()

    @classmethod
    def tearDownClass(cls):
        TEMP_DIR.cleanup()

    def login_a(self):
        with self.client_a.session_transaction() as session:
            session["user_id"] = self.user_ids["pair-a@test.local"]
            session["user_name"] = "Pair User A"

    def test_01_unauthenticated_pairing(self):
        response = self.client_a.post(
            "/api/devices/pair",
            json={"device_name": "Test Phone"}
        )
        self.assertEqual(response.status_code, 401)
        print("PASS: Unauthenticated pairing rejected.")

    def test_02_missing_csrf(self):
        self.login_a()
        response = self.client_a.post(
            "/api/devices/pair",
            json={"device_name": "Test Phone"}
        )
        self.assertEqual(response.status_code, 403)
        print("PASS: Missing CSRF token rejected.")

    def test_03_invalid_csrf(self):
        self.login_a()
        with self.client_a.session_transaction() as session:
            session["device_pairing_csrf"] = "VALID-TEST-CSRF"

        response = self.client_a.post(
            "/api/devices/pair",
            json={"device_name": "Test Phone"},
            headers={"X-CSRF-Token": "WRONG-CSRF"}
        )
        self.assertEqual(response.status_code, 403)
        print("PASS: Invalid CSRF token rejected.")

    def test_04_invalid_device_name(self):
        self.login_a()
        with self.client_a.session_transaction() as session:
            session["device_pairing_csrf"] = "VALID-TEST-CSRF"

        response = self.client_a.post(
            "/api/devices/pair",
            json={"device_name": " "},
            headers={"X-CSRF-Token": "VALID-TEST-CSRF"}
        )
        self.assertEqual(response.status_code, 400)
        print("PASS: Empty device name rejected.")

    def test_05_successful_pairing_and_hash_storage(self):
        self.login_a()

        csrf_response = self.client_a.get(
            "/api/device-pairing/csrf"
        )
        self.assertEqual(csrf_response.status_code, 200)
        csrf = csrf_response.get_json()["csrf_token"]

        response = self.client_a.post(
            "/api/devices/pair",
            json={"device_name": "Vaishnavi Test Phone"},
            headers={"X-CSRF-Token": csrf}
        )

        self.assertEqual(response.status_code, 201)
        result = response.get_json()
        raw_token = result["device_token"]
        expected_hash = hashlib.sha256(
            raw_token.encode("utf-8")
        ).hexdigest()

        connection = get_connection(TEST_DB)
        try:
            device = connection.execute(
                "SELECT * FROM user_devices WHERE id = ?",
                (result["device_id"],)
            ).fetchone()
        finally:
            connection.close()

        self.assertIsNotNone(device)
        self.assertEqual(device["token_hash"], expected_hash)
        self.assertNotEqual(device["token_hash"], raw_token)
        self.assertEqual(
            device["user_id"],
            self.user_ids["pair-a@test.local"]
        )
        print("PASS: Device paired; only token hash stored.")

    def test_06_pairing_uses_logged_in_user(self):
        self.login_a()

        csrf_response = self.client_a.get(
            "/api/device-pairing/csrf"
        )
        csrf = csrf_response.get_json()["csrf_token"]

        response = self.client_a.post(
            "/api/devices/pair",
            json={
                "device_name": "User A Device"
            },
            headers={"X-CSRF-Token": csrf}
        )

        self.assertEqual(response.status_code, 201)

        connection = get_connection(TEST_DB)
        try:
            device = connection.execute(
                "SELECT user_id FROM user_devices WHERE id = ?",
                (response.get_json()["device_id"],)
            ).fetchone()
        finally:
            connection.close()

        self.assertEqual(
            device["user_id"],
            self.user_ids["pair-a@test.local"]
        )
        print("PASS: Device linked to authenticated account.")


if __name__ == "__main__":
    print("\n========== VAPP DEVICE PAIRING VERIFICATION ==========\n")
    unittest.main(verbosity=2)
