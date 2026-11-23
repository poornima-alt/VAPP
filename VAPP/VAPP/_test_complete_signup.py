import os
import tempfile
import re
from pathlib import Path

with tempfile.TemporaryDirectory() as temp:
    os.environ["VAPP_DATABASE_PATH"] = str(Path(temp) / "signup_test.db")

    import app
    app.app.config["TESTING"] = True
    client = app.app.test_client()

    def signup(name, email, password, confirm):
        return client.post("/signup", data={
            "name": name,
            "email": email,
            "password": password,
            "confirm_password": confirm
        }, follow_redirects=True)

    mismatch = signup("Test One", "one@example.com", "Password!123", "Different!123")
    print("Password mismatch rejected:", b"do not match" in mismatch.data.lower())

    first = signup("Test One", "one@example.com", "Password!123", "Password!123")
    print("First account success page:", b"Account created successfully" in first.data)

    codes = re.findall(rb'id="registrationCode">(.*?)</div>', first.data)
    print("First registration code generated:", bool(codes))

    client.get("/logout")

    second = signup("Test Two", "two@example.com", "Password!456", "Password!456")
    codes2 = re.findall(rb'id="registrationCode">(.*?)</div>', second.data)

    print("Second account success page:", b"Account created successfully" in second.data)
    print("Second registration code generated:", bool(codes2))
    print("Registration codes unique:", bool(codes and codes2 and codes[0] != codes2[0]))

    client.post("/login", data={
        "email": "one@example.com",
        "password": "Password!123"
    })
    print("Login after registration:", client.get("/dashboard").status_code == 200)

print("Temporary registration tests completed.")
