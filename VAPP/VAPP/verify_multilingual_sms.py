from sms_analyzer import analyze_sms

samples = [
    ("Hindi", "अपना पासवर्ड दर्ज करें"),
    ("Kannada", "ನಿಮ್ಮ ಪಾಸ್‌ವರ್ಡ್ ನಮೂದಿಸಿ"),
    ("Telugu", "మీ పాస్‌వర్డ్ నమోదు చేయండి"),
    ("Tamil", "உங்கள் கடவுச்சொல்லை உள்ளிடவும்"),
    ("Malayalam", "നിങ്ങളുടെ പാസ്‌വേഡ് നൽകുക"),
    ("Hindi urgent", "आपका खाता तुरंत बंद हो जाएगा"),
    ("Kannada urgent", "ನಿಮ್ಮ ಖಾತೆಯನ್ನು ತಕ್ಷಣವೇ ಅಮಾನತುಗೊಳಿಸಲಾಗುತ್ತದೆ"),
    ("Telugu financial", "మీ యూపీఐ పిన్ పంచుకోండి"),
    ("Tamil financial", "உங்கள் யுபிஐ பின்னைப் பகிரவும்"),
    ("Malayalam financial", "നിങ്ങളുടെ യുപിഐ പിൻ പങ്കിടുക"),
]

for label, message in samples:
    result = analyze_sms("Test sender", message)
    print(
        f"{label} | Score: {result['risk_score']} "
        f"| Risk: {result['risk_level']} "
        f"| Indicators: {result['matched_indicators']} "
        f"| SMS indicators: {result['sms_indicators']}"
    )
