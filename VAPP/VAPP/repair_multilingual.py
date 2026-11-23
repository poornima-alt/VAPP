from pathlib import Path
import re

path = Path("email_analyzer.py")
source = path.read_text(encoding="utf-8")

start = source.index("MULTILINGUAL_CREDENTIAL_PHRASES = (")
end = source.index("\n\nBENIGN_MARKETING", start)

replacement = '''MULTILINGUAL_CREDENTIAL_PHRASES = (
    "अपना पासवर्ड दर्ज करें",
    "apna password darj karein",
    "ನಿಮ್ಮ ಪಾಸ್‌ವರ್ಡ್ ನಮೂದಿಸಿ",
    "nimma password namoodisi",
    "మీ పాస్‌వర్డ్ నమోదు చేయండి",
    "mee password namodu cheyandi",
    "உங்கள் கடவுச்சொல்லை உள்ளிடவும்",
    "ungal password enter pannunga",
    "നിങ്ങളുടെ പാസ്‌വേഡ് നൽകുക",
    "ningalude password nalkuka",
)'''

source = source[:start] + replacement + source[end:]

old = 'and any(phrase.casefold() in normalized for phrase in MULTILINGUAL_CREDENTIAL_PHRASES)'
new = '''and any(
            re.sub(r"[\\\\u200c\\\\u200d]", "", phrase.casefold())
            in re.sub(r"[\\\\u200c\\\\u200d]", "", normalized)
            for phrase in MULTILINGUAL_CREDENTIAL_PHRASES
        )'''

if source.count(old) != 1:
    raise SystemExit("STOP: Matching expression not found exactly once.")

source = source.replace(old, new, 1)
compile(source, str(path), "exec")
path.write_text(source, encoding="utf-8")
print("UTF-8 multilingual phrases restored and matching normalized.")
