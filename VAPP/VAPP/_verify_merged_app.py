import app

routes = {rule.rule for rule in app.app.url_map.iter_rules()}
required = {
    "/auth/google/connect",
    "/auth/google/callback",
    "/api/gmail-status",
    "/api/gmail/start",
    "/api/gmail/stop",
    "/api/gmail/disconnect",
    "/signup",
    "/login",
}

missing = required - routes
print("Required routes missing:", sorted(missing))
print("Gmail OAuth and registration routes preserved:", not missing)
