from email_analyzer import analyze_email

samples = [
    ("Hindi", "अपना यूपीआई पिन साझा करें"),
    ("Hindi Romanized", "apna upi pin share karein"),
    ("Hindi transfer", "अपना पैसा तुरंत ट्रांसफर करें"),
    ("Hindi transfer Romanized", "apna paisa turant transfer karein"),
    ("Kannada", "ನಿಮ್ಮ ಯುಪಿಐ ಪಿನ್ ಹಂಚಿಕೊಳ್ಳಿ"),
    ("Kannada Romanized", "nimma upi pin hanchikolli"),
    ("Kannada transfer", "ನಿಮ್ಮ ಹಣವನ್ನು ತಕ್ಷಣ ವರ್ಗಾಯಿಸಿ"),
    ("Kannada transfer Romanized", "nimma hanavannu takshana vargayisi"),
    ("Telugu", "మీ యూపీఐ పిన్ పంచుకోండి"),
    ("Telugu Romanized", "mee upi pin panchukondi"),
    ("Telugu transfer", "మీ డబ్బును వెంటనే బదిలీ చేయండి"),
    ("Telugu transfer Romanized", "mee dabbunu ventane badili cheyandi"),
    ("Tamil", "உங்கள் யுபிஐ பின்னைப் பகிரவும்"),
    ("Tamil Romanized", "ungal upi pinnai pagiravum"),
    ("Tamil transfer", "உடனடியாக பணத்தை மாற்றவும்"),
    ("Tamil transfer Romanized", "udanadiyaga panathai mattravum"),
    ("Malayalam", "നിങ്ങളുടെ യുപിഐ പിൻ പങ്കിടുക"),
    ("Malayalam Romanized", "ningalude upi pin pankiduka"),
    ("Malayalam transfer", "ഉടൻ പണം കൈമാറുക"),
    ("Malayalam transfer Romanized", "udan panam kaimaaruka"),
]

passed = 0
for language, message in samples:
    result = analyze_email("test@example.test", "Test", message)
    ok = "payment_or_sensitive_data" in result["matched_indicators"]
    passed += ok
    print(f"{'PASS' if ok else 'FAIL'} | {language} | {result['matched_indicators']}")

print(f"\nFinancial phrase tests: {passed}/20")

harmless = [
    "कल मिलते हैं",
    "ನಾಳೆ ಭೇಟಿಯಾಗೋಣ",
    "రేపు కలుద్దాం",
    "நாளை சந்திப்போம்",
    "നാളെ കാണാം",
]

clean = 0
for message in harmless:
    result = analyze_email("friend@example.test", "Hello", message)
    ok = result["risk_score"] == 0
    clean += ok
    print(f"{'PASS' if ok else 'FAIL'} | Harmless | score={result['risk_score']}")

print(f"Harmless tests: {clean}/5")
