from email_analyzer import analyze_email

samples = [
    ("Hindi", "अपना पासवर्ड दर्ज करें"),
    ("Hindi Romanized", "apna password darj karein"),
    ("Kannada", "ನಿಮ್ಮ ಪಾಸ್‌ವರ್ಡ್ ನಮೂದಿಸಿ"),
    ("Kannada Romanized", "nimma password namoodisi"),
    ("Telugu", "మీ పాస్‌వర్డ్ నమోదు చేయండి"),
    ("Telugu Romanized", "mee password namodu cheyandi"),
    ("Tamil", "உங்கள் கடவுச்சொல்லை உள்ளிடவும்"),
    ("Tamil Romanized", "ungal password enter pannunga"),
    ("Malayalam", "നിങ്ങളുടെ പാസ്‌വേഡ് നൽകുക"),
    ("Malayalam Romanized", "ningalude password nalkuka"),
]

print("========== MULTILINGUAL DETECTION TEST ==========")

for language, message in samples:
    result = analyze_email("test@example.test", "Test", message)
    passed = "credential_request" in result["matched_indicators"]
    print(f"{'PASS' if passed else 'PENDING'} | {language} | {result['matched_indicators']}")

print("\n--- HARMLESS MESSAGE CHECK ---")
harmless = [
    "நாளை சந்திப்போம்",
    "ನಾಳೆ ಭೇಟಿಯಾಗೋಣ",
    "कल मिलते हैं",
    "రేపు కలుద్దాం",
    "നാളെ കാണാം",
]

for message in harmless:
    result = analyze_email("friend@example.test", "Hello", message)
    passed = result["risk_score"] == 0
    print(f"{'PASS' if passed else 'CHECK'} | {message} | score={result['risk_score']}")

print("\n========== TEST COMPLETED ==========")
