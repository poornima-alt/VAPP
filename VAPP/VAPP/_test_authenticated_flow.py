import os
import tempfile
from pathlib import Path
from urllib.parse import urlsplit

with tempfile.TemporaryDirectory() as temp:
    os.environ["VAPP_DATABASE_PATH"] = str(Path(temp) / "vapp_test.db")

    import app
    app.app.config["TESTING"] = True
    client = app.app.test_client()

    r = client.post("/signup", data={
        "name": "VAPP Test One",
        "email": "testone@example.com",
        "password": "TestPassword!123"
    })
    print("User 1 signup:", r.status_code)

    r = client.post("/login", data={
        "email": "testone@example.com",
        "password": "TestPassword!123"
    })
    print("User 1 login:", r.status_code, r.location)

    r = client.get("/dashboard")
    print("User 1 dashboard:", r.status_code)

    r = client.get("/api/gmail-status")
    print("User 1 Gmail status:", r.status_code, r.get_json())

    r = client.get("/auth/google/connect")
    print("Google connect route:", r.status_code)
    print("OAuth state stored:", bool(client.get_cookie("session")))

    client.get("/logout")

    r = client.post("/signup", data={
        "name": "VAPP Test Two",
        "email": "testtwo@example.com",
        "password": "TestPassword!456"
    })
    print("User 2 signup:", r.status_code)

    client.post("/login", data={
        "email": "testtwo@example.com",
        "password": "TestPassword!456"
    })
    r = client.get("/api/gmail-status")
    print("User 2 Gmail status:", r.status_code, r.get_json())

print("Temporary test database removed.")
