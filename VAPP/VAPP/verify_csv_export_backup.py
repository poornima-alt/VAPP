
import os
import tempfile
import unittest
import csv
from io import StringIO

TEMP_DIR = tempfile.TemporaryDirectory()
TEST_DB = os.path.join(TEMP_DIR.name, "csv_test.db")
os.environ["VAPP_DATABASE_PATH"] = TEST_DB

from database import get_connection
import app as vapp


class CSVExportTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        vapp.app.config["TESTING"] = True

        cls.client_a = vapp.app.test_client()
        cls.client_b = vapp.app.test_client()

        connection = get_connection(TEST_DB)

        try:
            for name, email in [
                ("CSV User A", "csv-a@test.local"),
                ("CSV User B", "csv-b@test.local")
            ]:
                connection.execute(
                    """
                    INSERT INTO users (name, email, password_hash)
                    VALUES (?, ?, ?)
                    """,
                    (name, email, "test-hash")
                )

            cls.user_a = connection.execute(
                "SELECT id FROM users WHERE email = ?",
                ("csv-a@test.local",)
            ).fetchone()["id"]

            cls.user_b = connection.execute(
                "SELECT id FROM users WHERE email = ?",
                ("csv-b@test.local",)
            ).fetchone()["id"]

            def insert_event(user_id, protocol, event_type,
                             description, threat):
                cursor = connection.execute(
                    """
                    INSERT INTO security_events
                    (user_id, timestamp, protocol, event_type,
                     description, severity)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        user_id,
                        "2026-11-16 12:00:00",
                        protocol,
                        event_type,
                        description,
                        "HIGH"
                    )
                )

                connection.execute(
                    """
                    INSERT INTO analysis_results
                    (event_id, threat_type, confidence, risk_score,
                     risk_level, explanation, recommendation)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        cursor.lastrowid,
                        threat,
                        85,
                        72,
                        "HIGH",
                        "Test explanation",
                        "Test recommendation"
                    )
                )

            insert_event(
                cls.user_a,
                "EMAIL",
                "Incoming Email",
                "Suspicious email from sender A",
                "Phishing Email"
            )

            insert_event(
                cls.user_a,
                "SMS",
                "Incoming SMS (Android)",
                "Suspicious SMS from sender A",
                "Suspicious SMS"
            )

            insert_event(
                cls.user_b,
                "EMAIL",
                "Incoming Email",
                "Private event belonging to user B",
                "Phishing Email"
            )

            connection.commit()

        finally:
            connection.close()

    @classmethod
    def tearDownClass(cls):
        TEMP_DIR.cleanup()

    def authenticate_a(self):
        with self.client_a.session_transaction() as session:
            session["user_id"] = self.user_a
            session["user_name"] = "CSV User A"

    def test_01_unauthenticated_export_rejected(self):
        response = self.client_a.get("/api/report.csv")

        self.assertEqual(response.status_code, 401)

        print("PASS: Unauthenticated CSV export rejected.")

    def test_02_valid_csv_download(self):
        self.authenticate_a()

        response = self.client_a.get("/api/report.csv")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.mimetype, "text/csv")
        self.assertIn(
            "attachment",
            response.headers.get("Content-Disposition", "")
        )

        rows = list(csv.reader(StringIO(response.get_data(as_text=True))))

        self.assertEqual(len(rows), 3)
        self.assertEqual(rows[0][0], "ID")

        print("PASS: CSV download and headers verified.")
        print("PASS: Expected CSV records exported.")

    def test_03_email_filter(self):
        self.authenticate_a()

        response = self.client_a.get("/api/report.csv?channel=email")

        self.assertEqual(response.status_code, 200)

        rows = list(csv.reader(StringIO(response.get_data(as_text=True))))

        self.assertEqual(len(rows), 2)
        self.assertTrue(all(row[2] == "EMAIL" for row in rows[1:]))

        print("PASS: Email-only filtering verified.")

    def test_04_sms_filter(self):
        self.authenticate_a()

        response = self.client_a.get("/api/report.csv?channel=sms")

        self.assertEqual(response.status_code, 200)

        rows = list(csv.reader(StringIO(response.get_data(as_text=True))))

        self.assertEqual(len(rows), 2)
        self.assertTrue(all(row[2] == "SMS" for row in rows[1:]))

        print("PASS: SMS-only filtering verified.")

    def test_05_cross_user_isolation(self):
        self.authenticate_a()

        response = self.client_a.get("/api/report.csv")

        self.assertEqual(response.status_code, 200)

        csv_text = response.get_data(as_text=True)

        self.assertIn("Suspicious email from sender A", csv_text)
        self.assertIn("Suspicious SMS from sender A", csv_text)
        self.assertNotIn("Private event belonging to user B", csv_text)
        self.assertNotIn("csv-b@test.local", csv_text)

        print("PASS: CSV export excludes another user's records.")

    def test_06_invalid_channel_rejected(self):
        self.authenticate_a()

        response = self.client_a.get("/api/report.csv?channel=unknown")

        self.assertEqual(response.status_code, 400)

        print("PASS: Invalid channel rejected.")

    
    def test_07_formula_injection_review(self):
        connection = get_connection(TEST_DB)

        try:
            cursor = connection.execute(
                """
                INSERT INTO security_events
                (user_id, timestamp, source_ip, protocol,
                 event_type, description, severity)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    self.user_a,
                    "2026-11-16 13:00:00",
                    "=1+1",
                    "EMAIL",
                    "Incoming Email",
                    "Formula injection test",
                    "HIGH"
                )
            )
            event_id = cursor.lastrowid
            connection.commit()
        finally:
            connection.close()

        self.authenticate_a()

        response = self.client_a.get("/api/report.csv")
        self.assertEqual(response.status_code, 200)

        rows = list(
            csv.reader(StringIO(response.get_data(as_text=True)))
        )

        matching_rows = [
            row for row in rows if row[0] == str(event_id)
        ]

        self.assertEqual(len(matching_rows), 1)

        exported_source = matching_rows[0][3]

        print("Formula-like test value exported:", repr(exported_source))

        self.assertEqual(exported_source, "=1+1")

        print(
            "CONFIRMED: Formula-like input is exported without "
            "neutralization."
        )



if __name__ == "__main__":
    print("\n========== VAPP CSV EXPORT VERIFICATION ==========\n")
    unittest.main(verbosity=2)
