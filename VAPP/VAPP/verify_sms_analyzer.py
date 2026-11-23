
from sms_analyzer import analyze_sms

print("========== VAPP SMS ANALYZER TEST ==========")

# Test 1: Empty SMS
result = analyze_sms("Unknown", "")

assert result["threat_type"] == "Invalid SMS"
assert result["risk_score"] == 0

print("TEST 1 PASSED: Empty SMS rejected.")

# Test 2: Harmless SMS
result = analyze_sms(
    "+919999999999",
    "Your appointment is confirmed for tomorrow at 10 AM."
)

assert isinstance(result["risk_score"], (int, float))
assert 0 <= result["risk_score"] <= 100
assert result["risk_level"] in (
    "LOW", "MEDIUM", "HIGH", "CRITICAL"
)

print("TEST 2 PASSED: Harmless SMS analyzed.")

# Test 3: Suspicious SMS
result = analyze_sms(
    "Unknown Sender",
    "URGENT! Verify your bank account immediately. "
    "Enter your password and banking details within 24 hours."
)

print("Suspicious SMS result:", result)

assert 0 <= result["risk_score"] <= 100
assert result["risk_level"] in (
    "LOW", "MEDIUM", "HIGH", "CRITICAL"
)
assert result["recommendation"]

print("TEST 3 PASSED: Suspicious SMS analyzed.")

# Test 4: URL extraction
result = analyze_sms(
    "Unknown Sender",
    "Please review this website https://example.com/account"
)

assert "https://example.com/account" in result["urls"]

print("TEST 4 PASSED: URL extraction verified.")

# Test 5: Output structure
required_fields = [
    "threat_type",
    "risk_level",
    "risk_score",
    "confidence",
    "matched_indicators",
    "explanation",
    "recommendation",
    "urls",
    "domains",
]

result = analyze_sms("Test Sender", "Hello VAPP")

for field in required_fields:
    assert field in result, f"Missing field: {field}"

print("TEST 5 PASSED: Required output fields verified.")

print("========== ALL SMS ANALYZER TESTS PASSED ==========")
