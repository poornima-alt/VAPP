from pathlib import Path
import shutil

path = Path("sms_analyzer.py")
source = path.read_text(encoding="utf-8")

old_credential = '    if "credential_request" in sms_indicators:\n        contextual_score = max(contextual_score, 60)\n'
new_credential = (
    '    if (\n'
    '        "credential_request" in sms_indicators\n'
    '        or "credential_request" in result.get("matched_indicators", [])\n'
    '    ):\n'
    '        contextual_score = max(contextual_score, 60)\n'
)

old_payment_anchor = '    # Account suspension and recovery attempts\n'
new_payment_anchor = (
    '    # Explicit sensitive-payment requests, including multilingual matches\n'
    '    if (\n'
    '        "payment_or_sensitive_data" in result.get("matched_indicators", [])\n'
    '        or "payment_request" in sms_indicators\n'
    '    ):\n'
    '        contextual_score = max(contextual_score, 50)\n'
    '\n'
    '    # Account suspension and recovery attempts\n'
)

if old_credential not in source or old_payment_anchor not in source:
    raise SystemExit("Expected code not found. No changes made.")

backup = Path("sms_analyzer.py.before_multilingual_scoring_20261121.bak")
if backup.exists():
    raise SystemExit(f"Backup already exists: {backup}. No changes made.")

shutil.copy2(path, backup)
source = source.replace(old_credential, new_credential, 1)
source = source.replace(old_payment_anchor, new_payment_anchor, 1)
path.write_text(source, encoding="utf-8")

print("Updated SMS contextual scoring.")
print(f"Backup: {backup}")
