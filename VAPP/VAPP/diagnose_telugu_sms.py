from email_analyzer import analyze_email
from sms_analyzer import analyze_sms

message = "మీ పాస్‌వర్డ్ నమోదు చేయండి"

print("MESSAGE:", repr(message))
print("UNICODE:", [f"U+{ord(c):04X}" for c in message])

email_result = analyze_email("test@example.test", "Test", message)
sms_result = analyze_sms("test@example.test", message)

print("\nEMAIL:")
print("Indicators:", email_result["matched_indicators"])
print("Score:", email_result["risk_score"])

print("\nSMS:")
print("Indicators:", sms_result["matched_indicators"])
print("Score:", sms_result["risk_score"])
