import unicodedata

samples = [
    "ನಿಮ್ಮ ಪಾಸ್‌ವರ್ಡ್ ನಮೂದಿಸಿ",
    "మీ పాస్‌వర్డ్ నమోదు చేయండి",
    "നിങ്ങളുടെ പാസ്‌വേഡ് നൽകുക",
]

for text in samples:
    print("\nLanguage sample:")
    for char in text:
        if unicodedata.category(char) == "Cf":
            print(f"U+{ord(char):04X}: {unicodedata.name(char, 'UNKNOWN')}")
