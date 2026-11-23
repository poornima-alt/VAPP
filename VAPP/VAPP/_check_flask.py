import app

print("Flask application imported successfully.")
print("\nRegistered routes:")
for rule in sorted(app.app.url_map.iter_rules(), key=lambda r: r.rule):
    print(rule.rule, sorted(rule.methods - {"HEAD", "OPTIONS"}))

print("\nSession secret configured:", bool(app.app.secret_key))
