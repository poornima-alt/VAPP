
import os
import tempfile

# Use a separate temporary database.
fd, db_path = tempfile.mkstemp(
    prefix="vapp_email_test_",
    suffix=".sqlite"
)
os.close(fd)

# Set this BEFORE importing app.
os.environ["VAPP_DATABASE_PATH"] = db_path

from app import process_incoming_email
from database import get_connection

print("========== VAPP EMAIL INTEGRATION TEST ==========")

# Retrieve the temporary demo user's ID.
connection = get_connection()

user = connection.execute(
    "SELECT id FROM users WHERE email = ?",
    ("demo@vapp.local",)
).fetchone()

connection.close()

assert user is not None, "Temporary demo user not found."

user_id = user["id"]

# TEST 1: HTML link mismatch and authentication headers.
html_sample = """
<html>
<body>
    <p>Please review your account.</p>
    <a href="https://example.com/login">
        https://fake-login.example.test
    </a>
</body>
</html>
"""

attachment_sample = [
    {
        "filename": "sample.pdf",
        "mime_type": "application/pdf",
        "size_bytes": 1024,
        "status": "hashed",
        "sha256": "a" * 64
    }
]

result, status = process_incoming_email(
    {
        "sender": "security@example.test",
        "subject": "VAPP HTML link test",
        "body": html_sample,
        "headers": {
            "authentication-results":
                "spf=pass; dkim=pass; dmarc=pass"
        },
        "source_ip": "GMAIL-MONITORED",
        "attachment_analysis": attachment_sample
    },
    user_id
)

assert status == 200, f"Unexpected status: {status}"
assert result["success"] is True
assert result["link_text_mismatch_count"] == 1
assert result["html_link_count"] == 1
assert result["header_authentication"]["SPF"] == "pass"
assert result["header_authentication"]["DKIM"] == "pass"
assert result["header_authentication"]["DMARC"] == "pass"
assert result["event_id"] is not None
assert len(result["url_intelligence"]) == 2
assert any(x["hostname"] == "example.com" for x in result["url_intelligence"])
assert all(x["reputation"] == "UNAVAILABLE" for x in result["url_intelligence"])
assert all(x["redirect_status"] == "NOT_CHECKED" for x in result["url_intelligence"])
assert all(x.get("dns_intelligence") is not None for x in result["url_intelligence"])
assert all("dns_status" in x["dns_intelligence"] for x in result["url_intelligence"])

print("\nTEST 1 PASSED: HTML link mismatch detected.")
print("Risk:", result["risk_level"])
print("Risk score:", result["risk_score"])
print("Link findings:", result["link_findings"])
print("Authentication:", result["header_authentication"])
print("Event ID:", result["event_id"])

# TEST 2: Suspicious email language.
phishing_result, phishing_status = process_incoming_email(
    {
        "sender": "security@example.test",
        "subject": "Urgent account verification required",
        "body": (
            "Please verify your account and confirm your password. "
            "Provide your bank details immediately. "
            "Your account will be suspended within 24 hours."
        ),
        "headers": {
            "authentication-results": "spf=fail; dkim=fail; dmarc=fail"
        }
    },
    user_id
)

assert phishing_status == 200
assert phishing_result["success"] is True
assert phishing_result["risk_score"] > 0
assert phishing_result["matched_indicators"]

print("\nTEST 2 PASSED: Suspicious email indicators detected.")
print("Risk:", phishing_result["risk_level"])
print("Risk score:", phishing_result["risk_score"])
print("Matched indicators:", phishing_result["matched_indicators"])
print("Authentication:", phishing_result["header_authentication"])

# TEST 3: Required-field validation.
invalid_result, invalid_status = process_incoming_email(
    {
        "sender": "security@example.test",
        "subject": "Missing body",
        "body": ""
    },
    user_id
)

assert invalid_status == 400
assert invalid_result["success"] is False

print("\nTEST 3 PASSED: Missing email body rejected.")

# TEST 4: Verify database persistence.
connection = get_connection()

event_count = connection.execute(
    "SELECT COUNT(*) FROM security_events"
).fetchone()[0]

analysis_count = connection.execute(
    "SELECT COUNT(*) FROM analysis_results"
).fetchone()[0]

saved = connection.execute("""
    SELECT
        se.id,
        se.event_type,
        ar.threat_type,
        ar.risk_score,
        ar.risk_level,
        ar.explanation,
        ar.recommendation
    FROM security_events se
    JOIN analysis_results ar
        ON se.id = ar.event_id
    ORDER BY se.id
""").fetchall()

connection.close()

assert event_count == 2, f"Expected 2 events, found {event_count}"
assert analysis_count == 2, (
    f"Expected 2 analysis records, found {analysis_count}"
)

# Verify attachment hash metadata was included in the explanation.
first_explanation = saved[0]["explanation"]
assert "SHA-256" in first_explanation
assert "Passive URL intelligence" in first_explanation
assert "example.com" in first_explanation
assert "DNS" in first_explanation

print("\nTEST 4 PASSED: Database persistence verified.")
print("Security events:", event_count)
print("Analysis results:", analysis_count)
print("Attachment SHA-256 metadata included in explanation.")

for row in saved:
    print(
        f"\nEvent {row['id']} | {row['event_type']}"
        f"\nThreat: {row['threat_type']}"
        f"\nRisk: {row['risk_score']} ({row['risk_level']})"
    )

print("\n========== EMAIL INTEGRATION TEST PASSED ==========")
print("Temporary database:", db_path)
print("Original VAPP database was not used.")


