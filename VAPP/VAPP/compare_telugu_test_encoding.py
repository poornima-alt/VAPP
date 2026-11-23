from pathlib import Path

for filename in ["verify_multilingual_sms.py", "diagnose_telugu_sms_again.py"]:
    source = Path(filename).read_text(encoding="utf-8-sig")
    print("\nFILE:", filename)
    for line in source.splitlines():
        if "పాస్" in line:
            phrase = line.split('"')[3] if line.count('"') >= 4 else line
            print("LINE:", repr(line))
            print("UNICODE:", [f"U+{ord(c):04X}" for c in line if ord(c) > 127])
