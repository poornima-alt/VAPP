from pathlib import Path

path = Path("email_analyzer.py")
source = path.read_text(encoding="utf-8")

anchor = "MULTILINGUAL_CREDENTIAL_PHRASES = ("
urgent_rules = '''MULTILINGUAL_URGENT_PHRASES = (
    "आपका खाता तुरंत बंद हो जाएगा",
    "aapka khata turant band ho jayega",
    "ನಿಮ್ಮ ಖಾತೆಯನ್ನು ತಕ್ಷಣವೇ ಅಮಾನತುಗೊಳಿಸಲಾಗುತ್ತದೆ",
    "nimma khate takshanave amaanatugolisalaguttade",
    "మీ ఖాతా వెంటనే నిలిపివేయబడుతుంది",
    "mee khata ventane nilipiveyabadutundi",
    "உங்கள் கணக்கு உடனடியாக முடக்கப்படும்",
    "ungal kanakku udanadiyaga mudakkappadum",
    "നിങ്ങളുടെ അക്കൗണ്ട് ഉടൻ സസ്പെൻഡ് ചെയ്യും",
    "ningalude account udan suspend cheyyum",
)

'''

if "MULTILINGUAL_URGENT_PHRASES" in source:
    raise SystemExit("STOP: Urgent phrase rules already exist.")

if source.count(anchor) != 1:
    raise SystemExit("STOP: Credential phrase insertion point is not unique.")

source = source.replace(anchor, urgent_rules + anchor, 1)

match_point = "    def add_link_finding(name: str, weight: int):"
urgent_match = '''    normalized_for_multilingual = (
        normalized.replace("\\u200c", "").replace("\\u200d", "")
    )
    if (
        "urgent_action" not in matched
        and any(
            phrase.casefold().replace("\\u200c", "").replace("\\u200d", "")
            in normalized_for_multilingual
            for phrase in MULTILINGUAL_URGENT_PHRASES
        )
    ):
        score += 12
        matched.append("urgent_action")

'''

if source.count(match_point) != 1:
    raise SystemExit("STOP: Matching insertion point is not unique.")

source = source.replace(match_point, urgent_match + match_point, 1)
compile(source, str(path), "exec")
path.write_text(source, encoding="utf-8")
print("Urgent-action rules added successfully for five languages.")
