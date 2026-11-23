import os
import tempfile
from pathlib import Path

with tempfile.TemporaryDirectory() as temp:
    os.environ["VAPP_DATABASE_PATH"] = str(Path(temp) / "oauth_test.db")

    import app
    app.app.config["TESTING"] = True
    client = app.app.test_client()

    client.post("/signup", data={
        "name": "OAuth Test",
        "email": "oauth_test@example.com",
        "password": "TestPassword!123"
    })
    client.post("/login", data={
        "email": "oauth_test@example.com",
        "password": "TestPassword!123"
    })

    response = client.get("/auth/google/connect", follow_redirects=False)

    print("Status:", response.status_code)
    print("Redirect destination:", response.headers.get("Location"))
    print("Response message:", response.get_data(as_text=True)[:500])
