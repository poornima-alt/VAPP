from pathlib import Path

path = Path("email_analyzer.py")
source = path.read_text(encoding="utf-8")

anchor = "MULTILINGUAL_URGENT_PHRASES = ("

financial_rules = '''MULTILINGUAL_FINANCIAL_PHRASES = (
    "अपना यूपीआई पिन साझा करें",
    "apna upi pin share karein",
    "अपना पैसा तुरंत ट्रांसफर करें",
    "apna paisa turant transfer karein",
    "ನಿಮ್ಮ ಯುಪಿಐ ಪಿನ್ ಹಂಚಿಕೊಳ್ಳಿ",
    "nimma upi pin hanchikolli",
    "ನಿಮ್ಮ ಹಣವನ್ನು ತಕ್ಷಣ ವರ್ಗಾಯಿಸಿ",
    "nimma hanavannu takshana vargayisi",
    "మీ యూపీఐ పిన్ పంచుకోండి",
    "mee upi pin panchukondi",
    "మీ డబ్బును వెంటనే బదిలీ చేయండి",
    "mee dabbunu ventane badili cheyandi",
    "உங்கள் யுபிஐ பின்னைப் பகிரவும்",
    "ungal upi pinnai pagiravum",
    "உடனடியாக பணத்தை மாற்றவும்",
    "udanadiyaga panathai mattravum",
    "നിങ്ങളുടെ യുപിഐ പിൻ പങ്കിടുക",
    "ningalude upi pin pankiduka",
    "ഉടൻ പണം കൈമാറുക",
    "udan panam kaimaaruka",
)

'''

if source.count(anchor) != 1:
    raise SystemExit("STOP: Urgent phrase insertion point is not unique.")

if "MULTILINGUAL_FINANCIAL_PHRASES" in source:
    raise SystemExit("STOP: Financial phrase rules already exist.")

source = source.replace(anchor, financial_rules + anchor, 1)

match_point = "    def add_link_finding(name: str, weight: int):"

financial_match = '''    if (
        "payment_or_sensitive_data" not in matched
        and any(
            phrase.casefold().replace("\\u200c", "").replace("\\u200d", "")
            in normalized.replace("\\u200c", "").replace("\\u200d", "")
            for phrase in MULTILINGUAL_FINANCIAL_PHRASES
        )
    ):
        score += 30
        matched.append("payment_or_sensitive_data")

'''

if source.count(match_point) != 1:
    raise SystemExit("STOP: Financial matching insertion point is not unique.")

source = source.replace(match_point, financial_match + match_point, 1)

compile(source, str(path), "exec")
path.write_text(source, encoding="utf-8")
print("Added multilingual financial-fraud phrase rules for five languages.")
