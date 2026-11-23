
import csv
import io
import os
import tempfile

# Configure a separate database BEFORE importing app.py
temp_dir = tempfile.TemporaryDirectory()
test_db = os.path.join(temp_dir.name, "vapp_sms_test.db")

os.environ["VAPP_DATABASE_PATH"] = test_db


import app as vapp
from database import initialize_database, create_demo_user, get_connection
from werkzeug.security import generate_password_hash


def check(condition, message):
    if not condition:
        raise AssertionError(message)
    print("PASS:", message)


def main():
    initialize_database(test_db)
    create_demo_user(test_db)

    # Add the account required by the Android endpoint.
    connection = get_connection(test_db)
    connection.execute(
        """
        INSERT INTO users (name, email, password_hash)
        VALUES (?, ?, ?)
        """,
        (
            "VAPP Integration Tester",
            "avaishnavi239@gmail.com",
            generate_password_hash("temporary-test-password"),
        ),
    )
    connection.commit()
    connection.close()

    # Redirect application database operations to the temporary database.
    vapp.get_connection = lambda: get_connection(test_db)

    client = vapp.app.test_client()
    android_client = vapp.app.test_client()
    connection = get_connection(test_db)
    user = connection.execute(
        "SELECT id FROM users WHERE email = ?",
        ("demo@vapp.local",),
    ).fetchone()
    android_user = connection.execute(
        "SELECT id FROM users WHERE email = ?",
        ("avaishnavi239@gmail.com",),
    ).fetchone()
    connection.close()
        # Pair a test Android device with the Android user's account.
    with android_client.session_transaction() as session:
        session["user_id"] = android_user["id"]
        session["user_name"] = "VAPP Integration Tester"

    csrf_response = android_client.get("/api/device-pairing/csrf")
    check(
        csrf_response.status_code == 200,
        "Android device pairing CSRF token generated"
    )

    csrf_token = csrf_response.get_json()["csrf_token"]

    pairing_response = android_client.post(
        "/api/devices/pair",
        json={"device_name": "VAPP Integration Test Phone"},
        headers={"X-CSRF-Token": csrf_token}
    )

    check(
        pairing_response.status_code == 201,
        "Android test device paired successfully"
    )

    device_token = pairing_response.get_json()["device_token"]
    # 1. CSV route must reject unauthenticated requests.
    response = client.post("/api/sms-import")
    check(response.status_code == 401, "CSV import rejects unauthenticated requests")

    # Log in using the demo account through the test session.
    with client.session_transaction() as session:
        session["user_id"] = user["id"]

    # 2. Import two SMS messages through CSV.
    csv_content = (
        "sender,message\n"
        "Friend,Your package is out for delivery today.\n"
        "UNKNOWN,Your bank account will be blocked. Share your OTP immediately.\n"
    )

    response = client.post(
        "/api/sms-import",
        data={
            "file": (
                io.BytesIO(csv_content.encode("utf-8")),
                "sms_test.csv",
            )
        },
        content_type="multipart/form-data",
    )

    check(response.status_code == 200, "CSV SMS import returns HTTP 200")

    csv_result = response.get_json()
    check(csv_result["success"], "CSV import reports success")
    check(csv_result["processed"] == 2, "CSV import processes two messages")

    # 3. Android route must reject an invalid token.
    response = client.post(
        "/api/mobile/sms",
        json={
            "sender": "UNKNOWN",
            "message": "Your account is suspended. Call immediately to restore access.",
        },
        headers={"Authorization": "Bearer wrong-token"},
    )

    check(response.status_code == 401, "Android endpoint rejects invalid token")

    # 4. Android route must accept the paired device token.
    response = client.post(
        "/api/mobile/sms",
        json={
            "sender": "UNKNOWN",
            "message": "Your account is suspended. Call this number immediately to restore access.",
        },
        headers={"Authorization": f"Bearer {device_token}"},
    )

    check(response.status_code == 200, "Android endpoint accepts valid token")

    android_result = response.get_json()
    check(android_result["success"], "Android SMS reports successful analysis")
    check(bool(android_result["event_id"]), "Android SMS returns an event ID")

    # 5. Verify database records and linked analysis results.
    connection = get_connection(test_db)

    rows = connection.execute(
        """
        SELECT se.id, se.user_id, se.protocol, se.event_type,
               se.severity, ar.threat_type, ar.risk_score,
               ar.risk_level
        FROM security_events se
        JOIN analysis_results ar ON se.id = ar.event_id
        ORDER BY se.id
        """
    ).fetchall()

    check(len(rows) == 3, "Three SMS events persisted with linked analysis results")
    check(
        sum(1 for row in rows if row["protocol"] == "SMS") == 3,
        "All saved events use SMS protocol",
    )

    android_row = connection.execute(
        """
        SELECT se.user_id, se.event_type, ar.risk_level
        FROM security_events se
        JOIN analysis_results ar ON se.id = ar.event_id
        WHERE se.id = ?
        """,
        (android_result["event_id"],),
    ).fetchone()

    check(android_row is not None, "Android event is linked to its analysis")
    check(
        android_row["user_id"] == android_user["id"],
        "Android event belongs to the configured account",
    )
    check(
        android_row["event_type"] == "Incoming SMS (Android)",
        "Android event type is stored correctly",
    )

    connection.close()

    # 6. Verify dashboard API retrieves the logged-in user's SMS events.
    response = client.get("/api/events")
    check(response.status_code == 200, "Dashboard events API returns HTTP 200")

    dashboard_data = response.get_json()
    sms_events = [
        event for event in dashboard_data["events"]
        if event["protocol"] == "SMS"
    ]

    check(len(sms_events) == 2, "Dashboard retrieves the two CSV SMS events")

    # Verify Android account events using a separate test client.
    android_client = vapp.app.test_client()
    with android_client.session_transaction() as session:
        session["user_id"] = android_user["id"]

    response = android_client.get("/api/events")
    check(response.status_code == 200, "Android account dashboard API returns HTTP 200")

    android_events = [
        event for event in response.get_json()["events"]
        if event["protocol"] == "SMS"
    ]

    check(len(android_events) == 1, "Dashboard retrieves the Android SMS event")

    print("\n==============================================")
    print("VAPP SMS INTEGRATION TESTS COMPLETED")
    print("ALL INTEGRATION ASSERTIONS PASSED")
    print("Temporary database only; original vapp.db untouched.")
    print("==============================================")


if __name__ == "__main__":
    try:
        main()
    finally:
        temp_dir.cleanup()
