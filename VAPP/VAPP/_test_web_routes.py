import app

client = app.app.test_client()

for path in ["/", "/login", "/signup", "/dashboard", "/api/gmail-status", "/auth/google/connect"]:
    response = client.get(path, follow_redirects=False)
    print(f"{path:25} Status: {response.status_code}  Type: {response.content_type}  Redirect: {response.location}")

print("\nUnauthenticated route checks completed.")
