from pathlib import Path
import shutil
import re

path = Path("verify_multilingual_sms.py")
source = path.read_text(encoding="utf-8-sig")

backup = Path("verify_multilingual_sms.py.before_telugu_fix.bak")

if backup.exists():
    raise SystemExit("Backup already exists. No changes made.")

pattern = r'    \("Telugu", ".*?"\),'
replacement = '    ("Telugu", "మీ పాస్‌వర్డ్ నమోదు చేయండి"),'

updated, count = re.subn(pattern, lambda _: replacement, source, count=1)

if count != 1:
    raise SystemExit("Telugu entry not found uniquely. No changes made.")

shutil.copy2(path, backup)
path.write_text(updated, encoding="utf-8")

print("Telugu test entry corrected.")
print("Backup created:", backup)
