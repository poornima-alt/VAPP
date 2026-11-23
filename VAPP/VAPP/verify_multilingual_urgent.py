from email_analyzer import analyze_email

samples = [
    ("Hindi", "आपका खाता तुरंत बंद हो जाएगा"),
    ("Hindi Romanized", "aapka khata turant band ho jayega"),
    ("Kannada", "ನಿಮ್ಮ ಖಾತೆಯನ್ನು ತಕ್ಷಣವೇ ಅಮಾನತುಗೊಳಿಸಲಾಗುತ್ತದೆ"),
    ("Kannada Romanized", "nimma khate takshanave amaanatugolisalaguttade"),
    ("Telugu", "మీ ఖాతా వెంటనే నిలిపివేయబడుతుంది"),
    ("Telugu Romanized", "mee khata ventane nilipiveyabadutundi"),
    ("Tamil", "உங்கள் கணக்கு உடனடியாக முடக்கப்படும்"),
    ("Tamil Romanized", "ungal kanakku udanadiyaga mudakkappadum"),
    ("Malayalam", "നിങ്ങളുടെ അക്കൗണ്ട് ഉടൻ സസ്പെൻഡ് ചെയ്യും"),
    ("Malayalam Romanized", "ningalude account udan suspend cheyyum"),
]

passed = 0
for language, message in samples:
    result = analyze_email("test@example.test", "Test", message)
    ok = "urgent_action" in result["matched_indicators"]
    passed += ok
    print(f"{'PASS' if ok else 'FAIL'} | {language} | {result['matched_indicators']}")

print(f"\nUrgent phrase tests: {passed}/10")

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
