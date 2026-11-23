
import os
import tempfile
import unittest
import hashlib
from pypdf import PdfReader
from io import BytesIO

TEMP_DIR = tempfile.TemporaryDirectory()
TEST_DB = os.path.join(TEMP_DIR.name, "forensic_test.db")
os.environ["VAPP_DATABASE_PATH"] = TEST_DB

from database import get_connection
import app as vapp


class ForensicPDFTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        vapp.app.config["TESTING"] = True
        cls.client_a = vapp.app.test_client()
        cls.client_b = vapp.app.test_client()

        connection = get_connection(TEST_DB)
        try:
            connection.execute(
                """
                INSERT INTO users (name, email, password_hash)
                VALUES (?, ?, ?)
                """,
                ("Forensic User A", "forensic-a@test.local", "test-hash")
            )
            connection.execute(
                """
                INSERT INTO users (name, email, password_hash)
                VALUES (?, ?, ?)
                """,
                ("Forensic User B", "forensic-b@test.local", "test-hash")
            )

            cls.user_a = connection.execute(
                "SELECT id FROM users WHERE email = ?",
                ("forensic-a@test.local",)
            ).fetchone()["id"]

            cls.user_b = connection.execute(
                "SELECT id FROM users WHERE email = ?",
                ("forensic-b@test.local",)
            ).fetchone()["id"]

            cursor = connection.execute(
                """
                INSERT INTO security_events
                (user_id, timestamp, protocol, event_type, description, severity)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    cls.user_a,
                    "2026-11-16 10:00:00",
                    "SMS",
                    "Incoming SMS (Android)",
                    "Suspicious message: Your account is blocked. "
                    "Visit https://example.com/verify immediately. "
                    "Special characters: <script>alert('test')</script> & symbols.",
                    "HIGH"
                )
            )
            cls.event_id = cursor.lastrowid

            connection.execute(
                """
                INSERT INTO analysis_results
                (event_id, threat_type, confidence, risk_score,
                 risk_level, explanation, recommendation)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    cls.event_id,
                    "Suspicious SMS",
                    85,
                    72,
                    "HIGH",
                    "Credential request and urgent account warning detected.",
                    "Do not share OTP or banking credentials."
                )
            )

            cursor = connection.execute(
                """
                INSERT INTO security_events
                (user_id, timestamp, protocol, event_type, description, severity)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    cls.user_b,
                    "2026-11-16 10:05:00",
                    "SMS",
                    "Incoming SMS (Android)",
                    "User B private test event.",
                    "LOW"
                )
            )
            cls.user_b_event_id = cursor.lastrowid

            connection.commit()
        finally:
            connection.close()

    @classmethod
    def tearDownClass(cls):
        TEMP_DIR.cleanup()

    def test_01_unauthenticated_access_rejected(self):
        response = self.client_a.get(
            f"/report/forensic/{self.event_id}"
        )
        self.assertEqual(response.status_code, 401)
        print("PASS: Unauthenticated PDF access rejected.")

    def test_02_valid_pdf_download(self):
        with self.client_a.session_transaction() as session:
            session["user_id"] = self.user_a
            session["user_name"] = "Forensic User A"

        response = self.client_a.get(
            f"/report/forensic/{self.event_id}"
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.mimetype, "application/pdf")
        self.assertTrue(response.data.startswith(b"%PDF-"))

        self.assertIn(
            f"VAPP_Forensic_Event_{self.event_id}.pdf",
            response.headers.get("Content-Disposition", "")
        )

        print("PASS: Valid forensic PDF downloaded.")
        print("PASS: PDF signature and download headers verified.")

        reader = PdfReader(BytesIO(response.data))
        self.assertGreater(len(reader.pages), 0)

        text = "\n".join(
            page.extract_text() or "" for page in reader.pages
        )

        self.assertIn("VAPP FORENSIC EVENT REPORT", text)
        self.assertIn(str(self.event_id), text)
        self.assertIn("Suspicious SMS", text)
        self.assertIn("HIGH", text)
        self.assertIn("example.com", text)
        self.assertIn("Findings and Limitations", text)
        self.assertIn(
    "<script>alert('test')</script>",
    text
)

        print("PASS: PDF contains expected event and analysis details.")
        print("PASS: Special HTML markup is escaped in PDF output.")

    def test_03_missing_event_rejected(self):
        with self.client_a.session_transaction() as session:
            session["user_id"] = self.user_a

        response = self.client_a.get("/report/forensic/99999999")
        self.assertEqual(response.status_code, 404)
        print("PASS: Missing event report rejected.")

    def test_04_cross_user_report_rejected(self):
        with self.client_a.session_transaction() as session:
            session["user_id"] = self.user_a

        response = self.client_a.get(
            f"/report/forensic/{self.user_b_event_id}"
        )
        self.assertEqual(response.status_code, 404)
        print("PASS: Cross-user forensic report access rejected.")

    def test_05_report_belongs_to_correct_event(self):
        with self.client_a.session_transaction() as session:
            session["user_id"] = self.user_a

        response = self.client_a.get(
            f"/report/forensic/{self.event_id}"
        )
        self.assertEqual(response.status_code, 200)

        reader = PdfReader(BytesIO(response.data))
        text = "\n".join(
            page.extract_text() or "" for page in reader.pages
        )

        self.assertIn("forensic-a@test.local", text)
        self.assertNotIn("forensic-b@test.local", text)

        print("PASS: PDF contains only the correct account's details.")


if __name__ == "__main__":
    try:
        print("\n========== VAPP FORENSIC PDF VERIFICATION ==========\n")
        unittest.main(verbosity=2)
    finally:
        TEMP_DIR.cleanup()
