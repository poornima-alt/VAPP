from email_analyzer import analyze_email

print("========== VAPP EMAIL ANALYZER TEST ==========")

samples = [
    {
        "id": "E01",
        "category": "Harmless personal",
        "sender": "friend@example.test",
        "subject": "Weekend plans",
        "body": "Hello! Hope you are doing well. Let us catch up this weekend."
    },
    {
        "id": "E02",
        "category": "Promotional",
        "sender": "offers@example.test",
        "subject": "Weekend shopping offers",
        "body": "Explore our new collection and enjoy special discounts. Unsubscribe anytime."
    },
    {
        "id": "E03",
        "category": "Transactional",
        "sender": "orders@example.test",
        "subject": "Your order confirmation",
        "body": "Your order TEST2048 has been placed successfully. We will notify you when it ships."
    },
    {
        "id": "E04",
        "category": "Legitimate security notification",
        "sender": "security@example.test",
        "subject": "New sign-in notification",
        "body": "A new sign-in to your account was recorded. If this was you, no action is needed. Contact support if you do not recognize it."
    },
    {
        "id": "E05",
        "category": "Suspicious account notification",
        "sender": "notice@example.test",
        "subject": "Account review notification",
        "body": "We noticed unusual activity on your account. Please review your account details at your convenience."
    },
    {
        "id": "E06",
        "category": "Credential request",
        "sender": "security@example.test",
        "subject": "Verify your account",
        "body": "Please verify your account credentials and confirm your password.",
    },
    {
        
        "id": "E07",
        "category": "URL shortener",
        "sender": "notice@example.test",
        "subject": "Review your account",
        "body": "Please review your account at https://bit.ly/secure-account"

    },
    {
        "id": "E08",
        "category": "Fake bank notification",
        "sender": "bank-alert@example.test",
        "subject": "Bank account verification",
        "body": "Your bank account requires verification. Enter your bank details and card number and CVV to avoid payment interruption."
    },
    {
        "id": "E09",
        "category": "OTP-sharing request",
        "sender": "support@example.test",
        "subject": "OTP confirmation",
        "body": "Share your OTP with our support team to complete verification."
    },
    {
        "id": "E10",
        "category": "HTML link mismatch",
        "sender": "notice@example.test",
        "subject": "Review this notification",
        "body": '<a href="https://example.com/login">https://fake-login.example.test</a>'
    },
]

required_fields = [
    "threat_type",
    "risk_level",
    "risk_score",
    "confidence",
    "matched_indicators",
    "urls",
    "domains",
    "language",
    "explanation",
    "method",
    "link_findings",
    "header_authentication",
    "html_link_count",
    "hidden_link_count",
    "link_text_mismatch_count",
    "qr_context_detected",
    "evidence_limitations",
]

print("\n--- LABELLED SAMPLE RESULTS ---")

for sample in samples:
    result = analyze_email(
        sample["sender"],
        sample["subject"],
        sample["body"]
    )

    assert 0 <= result["risk_score"] <= 100
    assert result["risk_level"] in ("LOW", "MEDIUM", "HIGH", "CRITICAL")

    for field in required_fields:
        assert field in result, f"{sample['id']}: Missing {field}"

    print(
        f"\n{sample['id']} | {sample['category']}"
        f"\nRisk: {result['risk_level']} ({result['risk_score']}/100)"
        f"\nThreat type: {result['threat_type']}"
        f"\nConfidence: {result['confidence']}"
        f"\nIndicators: {result['matched_indicators']}"
    )

print("\n--- SPECIAL VALIDATION TESTS ---")

empty_result = analyze_email("", "", "")
assert 0 <= empty_result["risk_score"] <= 100
print("PASS: Empty input handled without crashing.")

auth_result = analyze_email(
    "security@example.test",
    "Authentication test",
    "A harmless test message.",
    headers={"authentication-results": "spf=pass; dkim=pass; dmarc=pass"}
)
assert auth_result["header_authentication"]["SPF"] == "pass"
assert auth_result["header_authentication"]["DKIM"] == "pass"
assert auth_result["header_authentication"]["DMARC"] == "pass"
print("PASS: SPF/DKIM/DMARC header parsing.")

html_result = analyze_email(
    "notice@example.test",
    "HTML test",
    '<a href="https://example.com/login">https://fake.example.test</a>'
)
assert html_result["link_text_mismatch_count"] == 1
print("PASS: HTML link mismatch detection.")

print("\n========== EMAIL ANALYZER TESTS COMPLETED ==========")
print("Sample count:", len(samples))
print("Output structure and special validation checks passed.")
print("Classification accuracy has NOT yet been established.")
