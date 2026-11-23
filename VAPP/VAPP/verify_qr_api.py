import os
import io
import tempfile
import unittest

TEMP_DIR = tempfile.TemporaryDirectory()
TEST_DB = os.path.join(TEMP_DIR.name, "qr_api_test.db")
os.environ["VAPP_DATABASE_PATH"] = TEST_DB

import cv2
import numpy as np
from database import get_connection
import app as vapp


def make_qr_image(payload):
    qr = cv2.QRCodeEncoder.create()
    small_qr = qr.encode(payload)

    qr_image = cv2.copyMakeBorder(
        small_qr, 4, 4, 4, 4,
        cv2.BORDER_CONSTANT, value=255
    )

    qr_image = cv2.resize(
        qr_image, None,
        fx=10, fy=10,
        interpolation=cv2.INTER_NEAREST
    )

    success, encoded = cv2.imencode(".png", qr_image)
    assert success, "QR image generation failed."
    return encoded.tobytes()


class QRAPITests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        vapp.app.config["TESTING"] = True
        cls.client = vapp.app.test_client()

        connection = get_connection(TEST_DB)
        try:
            connection.execute(
                """
                INSERT INTO users (name, email, password_hash)
                VALUES (?, ?, ?)
                """,
                ("QR Test User", "qr-test@test.local", "test-password")
            )
            row = connection.execute(
                "SELECT id FROM users WHERE email = ?",
                ("qr-test@test.local",)
            ).fetchone()
            cls.user_id = row["id"]
            connection.commit()
        finally:
            connection.close()

        with cls.client.session_transaction() as session:
            session["user_id"] = cls.user_id
            session["user_name"] = "QR Test User"

    def test_01_unauthenticated_request(self):
        client = vapp.app.test_client()
        response = client.post("/api/qr-scan")
        self.assertEqual(response.status_code, 401)
        print("PASS: Unauthenticated QR request rejected.")

    def test_02_missing_file(self):
        response = self.client.post("/api/qr-scan")
        self.assertEqual(response.status_code, 400)
        print("PASS: Missing QR image rejected.")

    def test_03_invalid_image(self):
        response = self.client.post(
            "/api/qr-scan",
            data={"file": (io.BytesIO(b"not an image"), "invalid.png")},
            content_type="multipart/form-data"
        )
        self.assertEqual(response.status_code, 400)
        print("PASS: Invalid image rejected.")

    def test_04_oversized_image(self):
        response = self.client.post(
            "/api/qr-scan",
            data={"file": (
                io.BytesIO(b"A" * (2 * 1024 * 1024 + 1)),
                "large.png"
            )},
            content_type="multipart/form-data"
        )
        self.assertEqual(response.status_code, 413)
        print("PASS: Oversized image rejected.")

    def test_05_harmless_qr_payload(self):
        image_bytes = make_qr_image("VAPP-TEST-123")
        response = self.client.post(
            "/api/qr-scan",
            data={"file": (io.BytesIO(image_bytes), "harmless.png")},
            content_type="multipart/form-data"
        )

        self.assertEqual(response.status_code, 200, response.get_data(as_text=True))
        result = response.get_json()
        self.assertTrue(result["success"])
        self.assertEqual(result["payload"], "VAPP-TEST-123")
        self.assertEqual(result["urls"], [])
        self.assertEqual(result["url_intelligence"], [])
        print("PASS: Harmless QR payload extracted correctly.")

    def test_06_url_qr_dns_intelligence(self):
        image_bytes = make_qr_image("https://example.com")
        response = self.client.post(
            "/api/qr-scan",
            data={"file": (io.BytesIO(image_bytes), "url.png")},
            content_type="multipart/form-data"
        )

        self.assertEqual(response.status_code, 200, response.get_data(as_text=True))
        result = response.get_json()

        self.assertTrue(result["success"])
        self.assertIn("https://example.com", result["urls"])
        self.assertIn("example.com", result["domains"])
        self.assertTrue(result["url_intelligence"])

        intelligence = result["url_intelligence"][0]
        self.assertIn("dns_intelligence", intelligence)
        self.assertIsNotNone(intelligence["dns_intelligence"])
        self.assertIn("dns_status", intelligence["dns_intelligence"])

        self.assertIn("No links were opened", result["message"])
        print("PASS: QR URL extracted and DNS intelligence returned.")
        print("DNS status:", intelligence["dns_intelligence"]["dns_status"])

    @classmethod
    def tearDownClass(cls):
        TEMP_DIR.cleanup()


if __name__ == "__main__":
    try:
        print("\n========== VAPP QR API INTEGRATION TEST ==========\n")
        unittest.main(verbosity=2)
    finally:
        TEMP_DIR.cleanup()
