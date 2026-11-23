from email_analyzer import analyze_email
from sms_analyzer import analyze_sms

message = "మీ పాస్‌వర్డ్ నమోదు చేయండి"

print("MESSAGE:", repr(message))
print("EMAIL:", analyze_email("test@example.test", "Test", message)["matched_indicators"])
print("EMAIL SCORE:", analyze_email("test@example.test", "Test", message)["risk_score"])

sms = analyze_sms("Test sender", message)
print("SMS:", sms["matched_indicators"])
print("SMS SCORE:", sms["risk_score"])
print("SMS RISK:", sms["risk_level"])
