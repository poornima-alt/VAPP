
import os
import tempfile

# Create an isolated temporary database.
fd, db_path = tempfile.mkstemp(
    prefix="vapp_integration_",
    suffix=".sqlite"
)
os.close(fd)

# IMPORTANT: Set this before importing app.
os.environ["VAPP_DATABASE_PATH"] = db_path

from app import app
from database import get_connection

print("========== VAPP INTEGRATION TEST ==========")

app.config["TESTING"] = True

# Find the automatically created demo user.
connection = get_connection()

user = connection.execute(
    "SELECT id FROM users WHERE email = ?",
    ("demo@vapp.local",)
).fetchone()

connection.close()

assert user is not None, "Demo user was not created."

user_id = user["id"]

client = app.test_client()

# TEST 1: Authentication protection
response = client.post("/simulate/normal")

assert response.status_code == 401, (
    f"Expected 401, received {response.status_code}"
)

print("\nTEST 1 PASSED: Unauthenticated access rejected.")

# Log in through the Flask test session.
with client.session_transaction() as session:
    session["user_id"] = user_id

# TEST 2: All four simulation scenarios
scenarios = [
    "normal",
    "suspicious",
    "port_scan",
    "brute_force"
]

event_ids = []

for scenario in scenarios:
    response = client.post(f"/simulate/{scenario}")

    assert response.status_code == 200, (
        f"{scenario} failed with status {response.status_code}: "
        f"{response.get_data(as_text=True)}"
    )

    result = response.get_json()

    assert result["success"] is True
    assert result["event_id"] is not None

    required_fields = [
        "threat_type",
        "confidence",
        "risk_score",
        "risk_level",
        "explanation",
        "recommendation"
    ]

    for field in required_fields:
        assert field in result, (
            f"{scenario}: Missing field {field}"
        )

    event_ids.append(result["event_id"])

    print(f"\nTEST PASSED: {scenario}")
    print("Threat:", result["threat_type"])
    print("Confidence:", result["confidence"])
    print("Risk:", result["risk_score"], result["risk_level"])
    print("Event ID:", result["event_id"])

# TEST 3: Invalid simulation type
response = client.post("/simulate/unknown")

assert response.status_code == 400

print("\nTEST 3 PASSED: Unknown simulation rejected.")

# TEST 4: Verify database persistence
connection = get_connection()

event_count = connection.execute(
    "SELECT COUNT(*) FROM security_events"
).fetchone()[0]

analysis_count = connection.execute(
    "SELECT COUNT(*) FROM analysis_results"
).fetchone()[0]

saved_results = connection.execute("""
    SELECT
        se.id,
        ar.threat_type,
        ar.risk_score,
        ar.risk_level
    FROM security_events se
    JOIN analysis_results ar
        ON se.id = ar.event_id
    ORDER BY se.id
""").fetchall()

connection.close()

assert event_count == 4, (
    f"Expected 4 security events, found {event_count}"
)

assert analysis_count == 4, (
    f"Expected 4 analysis results, found {analysis_count}"
)

assert len(saved_results) == 4

print("\nTEST 4 PASSED: Database persistence verified.")
print("Security events:", event_count)
print("Analysis results:", analysis_count)

for row in saved_results:
    print(
        f"Event {row['id']} | "
        f"{row['threat_type']} | "
        f"Risk: {row['risk_score']} | "
        f"{row['risk_level']}"
    )

print("\n========== INTEGRATION TEST PASSED ==========")
print("Temporary database:", db_path)
print("Original VAPP database was not used.")
